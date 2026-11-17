#!/usr/bin/env python3
"""Observe Linux UTC/time-namespace behavior in a tightly constrained Docker run.

This is a capability observation only. It does not establish epoch supervision,
common deployment configuration, or a production quota guarantee.
"""
from __future__ import annotations

import argparse
import datetime as _datetime
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Sequence

MAX_STDOUT = 8192
MAX_STDERR = 2048
COMMAND_TIMEOUT_SECONDS = 45
IMAGE_PULL_TIMEOUT_SECONDS = 120


class HarnessError(Exception):
    pass


def _drain(stream: Any, limit: int, result: dict[str, Any], key: str) -> None:
    kept = bytearray()
    truncated = False
    while True:
        chunk = stream.read(1024)
        if not chunk:
            break
        room = limit - len(kept)
        if room > 0:
            kept.extend(chunk[:room])
        if len(chunk) > room:
            truncated = True
    result[key] = bytes(kept).decode("utf-8", errors="replace")
    result[key + "_truncated"] = truncated


def run_capture(argv: Sequence[str], timeout: int = COMMAND_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run argv with capped, drained stdout/stderr and an explicit timeout."""
    try:
        proc = subprocess.Popen(
            list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
        )
    except FileNotFoundError:
        return {"started": False, "return_code": None, "timed_out": False,
                "stdout": "", "stderr": "", "error": "executable_not_found"}
    except OSError as exc:
        return {"started": False, "return_code": None, "timed_out": False,
                "stdout": "", "stderr": "", "error": f"spawn_error:{exc.errno}"}

    buffers: dict[str, Any] = {}
    out_thread = threading.Thread(target=_drain, args=(proc.stdout, MAX_STDOUT, buffers, "stdout"))
    err_thread = threading.Thread(target=_drain, args=(proc.stderr, MAX_STDERR, buffers, "stderr"))
    out_thread.start()
    err_thread.start()
    timed_out = False
    try:
        return_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        return_code = proc.wait()
    out_thread.join()
    err_thread.join()
    return {"started": True, "return_code": return_code, "timed_out": timed_out,
            "stdout": buffers.get("stdout", ""),
            "stdout_truncated": buffers.get("stdout_truncated", False),
            "stderr": buffers.get("stderr", ""),
            "stderr_truncated": buffers.get("stderr_truncated", False),
            "error": "timeout" if timed_out else None}


def _parse_json_stdout(result: dict[str, Any]) -> dict[str, Any] | None:
    if result.get("stdout_truncated"):
        return None
    try:
        value = json.loads(result.get("stdout", ""))
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _parse_clock_sample(result: dict[str, Any]) -> dict[str, Any] | None:
    if result.get("return_code") != 0 or result.get("stdout_truncated"):
        return None
    rows = result.get("stdout", "").splitlines()
    if len(rows) != 1:
        return None
    fields = rows[0].split("|")
    # Eight pipe-delimited identity fields followed by one monotonic timestamp.
    if len(fields) != 9 or not fields[0] or any(not field for field in fields):
        return None
    if not re.fullmatch(r"[0-9a-f]{32}", fields[0]):
        return None
    if any(not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value) for value in fields[1:]):
        return None
    if any(value == "-0" for value in fields[1:]):
        return None
    try:
        values = [int(value, 10) for value in fields[1:]]
    except ValueError:
        return None
    if values[0] < 0 or values[1] <= 0 or values[1] > (1 << 64) - 1:
        return None
    if values[0] > (1 << 64) - 1:
        return None
    if not (-(1 << 63) <= values[2] < (1 << 63)):
        return None
    if not (-(1 << 63) <= values[4] < (1 << 63)):
        return None
    if values[3] < 0 or values[5] < 0:
        return None
    if values[3] > 999_999_999 or values[5] > 999_999_999:
        return None
    if values[6] != 1:
        return None
    if values[7] < 0 or values[7] > (1 << 64) - 1:
        return None
    return {"identity_fields": fields[:8], "monotonic_ns": values[7]}


def _valid_probe_path(raw: str, label: str) -> str:
    path = Path(raw)
    if not path.is_absolute():
        raise HarnessError(f"{label} path must be absolute")
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise HarnessError(f"{label} path must be a regular executable, not a symlink")
    canonical = str(path.resolve(strict=True))
    if "," in canonical:
        raise HarnessError(f"{label} path cannot contain a comma for Docker mount syntax")
    return canonical


def _docker_base_args(image_ref: str, uid: int, gid: int,
                      wall_path: str, clock_path: str,
                      container_name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--pull=never",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--read-only", "--network=none", "--user", f"{uid}:{gid}",
        "--pids-limit=64", "--memory=256m", "--cpus=1",
        "--name", container_name,
        "--mount", f"type=bind,source={wall_path},target=/probes/wall,readonly",
        "--mount", f"type=bind,source={clock_path},target=/probes/clock,readonly",
        image_ref,
    ]


def _docker_run_probe(image_ref: str, uid: int, gid: int,
                      wall_path: str, clock_path: str, probe: str) -> dict[str, Any]:
    container_name = f"rateguard-preflight-{os.getpid()}-{uuid.uuid4().hex[:12]}"
    base = _docker_base_args(image_ref, uid, gid, wall_path, clock_path,
                             container_name)
    if probe == "wall":
        result = run_capture(base + ["/probes/wall"])
    else:
        result = run_capture(base + ["/probes/clock", "--child"])
    if result.get("timed_out"):
        cleanup = run_capture(["docker", "rm", "--force", container_name], timeout=15)
        result["cleanup_return_code"] = cleanup.get("return_code")
    return result


def _image_metadata(docker_bin: str, image: str) -> tuple[dict[str, Any], str | None]:
    inspect = run_capture([docker_bin, "image", "inspect", "--format",
                           "{{json .RepoDigests}}|{{.Id}}", image])
    if inspect.get("return_code") == 0 and not inspect.get("stdout_truncated"):
        parsed = _decode_image_metadata(inspect.get("stdout", ""))
        match = _matching_digest(image, parsed[0]) if parsed else None
        if parsed and match:
            return ({"inspect_return_code": inspect.get("return_code"),
                     "repo_digests": parsed[0], "image_id": parsed[1]}, match)

    pull = run_capture([docker_bin, "pull", "--quiet", image], timeout=IMAGE_PULL_TIMEOUT_SECONDS)
    inspect_after = run_capture([docker_bin, "image", "inspect", "--format",
                                 "{{json .RepoDigests}}|{{.Id}}", image])
    parsed = _decode_image_metadata(inspect_after.get("stdout", ""))
    metadata = {"inspect_before": _command_status(inspect),
                "pull": _command_status(pull),
                "inspect_after": _command_status(inspect_after),
                "repo_digests": parsed[0] if parsed else [],
                "image_id": parsed[1] if parsed else None}
    digest_ref = _matching_digest(image, parsed[0]) if parsed else None
    return metadata, digest_ref


def _command_status(result: dict[str, Any]) -> dict[str, Any]:
    return {"started": result.get("started"),
            "return_code": result.get("return_code"),
            "timed_out": result.get("timed_out"),
            "error": result.get("error")}


def _matching_digest(image: str, digests: list[str]) -> str | None:
    if any(not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", entry)
           for entry in digests):
        return None
    repository = image.split("@", 1)[0]
    colon = repository.rfind(":")
    slash = repository.rfind("/")
    if colon > slash:
        repository = repository[:colon]
    aliases = {repository}
    if repository.startswith("docker.io/library/"):
        aliases.add(repository[len("docker.io/library/"):])
    elif repository.startswith("docker.io/"):
        aliases.add("docker.io/library/" + repository[len("docker.io/"):])
    elif "/" not in repository:
        aliases.add("docker.io/library/" + repository)
    prefixes = tuple(alias + "@sha256:" for alias in aliases)
    return next((entry for entry in digests
                 if entry.startswith(prefixes)), None)


def _decode_image_metadata(text: str) -> tuple[list[str], str] | None:
    line = text.strip()
    if "|" not in line:
        return None
    digests_text, image_id = line.split("|", 1)
    try:
        digests = json.loads(digests_text)
    except json.JSONDecodeError:
        return None
    if digests is None:
        digests = []
    if not isinstance(digests, list) or not all(
            isinstance(item, str) and
            re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", item)
            for item in digests):
        return None
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        return None
    return digests, image_id


def _wall_summary(result: dict[str, Any]) -> dict[str, Any]:
    probe = _parse_json_stdout(result)
    if probe is None:
        return {"return_code": result.get("return_code"), "valid_json": False,
                "probe": None, "error": result.get("error") or "invalid_json_output"}
    return {"return_code": result.get("return_code"), "valid_json": True,
            "probe": probe, "error": result.get("error")}


def _clock_summary(result: dict[str, Any]) -> dict[str, Any]:
    parsed = _parse_clock_sample(result)
    return {"return_code": result.get("return_code"), "sample": parsed,
            "error": result.get("error") or (None if parsed else "invalid_clock_output")}


def _trusted_wall(summary: dict[str, Any]) -> bool:
    p = summary.get("probe")
    if not (summary.get("valid_json") and summary.get("return_code") == 0 and
            isinstance(p, dict) and p.get("platform") == "linux" and
            p.get("trusted") is True and p.get("failure_reason") is None):
        return False
    sync_state = p.get("sync_state")
    flags = p.get("status_flags")
    seconds = p.get("unix_seconds")
    nanoseconds = p.get("nanoseconds")
    return (type(sync_state) is int and 0 <= sync_state <= 4 and
            type(flags) is int and flags >= 0 and (flags & 0x1040) == 0 and
            type(seconds) is int and 0 <= seconds <= (1 << 63) - 1 and
            type(nanoseconds) is int and 0 <= nanoseconds < 1_000_000_000)


def _readiness(host_wall_before: dict[str, Any], host_wall_after: dict[str, Any],
               container_wall: dict[str, Any], host_clock_before: dict[str, Any],
               container_clock: dict[str, Any], host_clock_after: dict[str, Any],
               docker_run_errors: list[str]) -> tuple[str, dict[str, Any]]:
    if docker_run_errors:
        return "NOT_RUN", {"reason": docker_run_errors[0]}
    if not (_trusted_wall(host_wall_before) and _trusted_wall(host_wall_after) and
            _trusted_wall(container_wall)):
        return "NOT_READY", {"reason": "host_or_container_utc_untrusted"}
    clocks = [host_clock_before.get("sample"), container_clock.get("sample"),
              host_clock_after.get("sample")]
    if any(sample is None for sample in clocks):
        return "NOT_READY", {"reason": "clock_namespace_probe_failed"}
    before, inside, after = clocks
    identity_match = (before["identity_fields"] == inside["identity_fields"] ==
                      after["identity_fields"])
    time_ordered = before["monotonic_ns"] <= inside["monotonic_ns"] <= after["monotonic_ns"]
    comparison = {"identity_fields_match": identity_match,
                  "monotonic_samples_ordered": time_ordered,
                  "host_before_ns": before["monotonic_ns"],
                  "container_ns": inside["monotonic_ns"],
                  "host_after_ns": after["monotonic_ns"]}
    if not identity_match:
        return "NOT_READY", {"reason": "time_namespace_identity_mismatch",
                              "comparison": comparison}
    if not time_ordered:
        return "NOT_READY", {"reason": "monotonic_sample_order_mismatch",
                              "comparison": comparison}
    return "OBSERVATIONS_MATCHED", {"reason": None, "comparison": comparison}


def _docker_executable() -> str | None:
    return shutil.which("docker")


def collect(args: argparse.Namespace) -> dict[str, Any]:
    wall_path = _valid_probe_path(args.wall_probe, "wall probe")
    clock_path = _valid_probe_path(args.clock_probe, "clock probe")
    if wall_path == clock_path:
        raise HarnessError("wall and clock probes must be different executables")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}", args.image):
        raise HarnessError("image must be a bounded Docker image reference")

    artifact: dict[str, Any] = {
        "schema_version": 1,
        "observed_at_utc": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
        "scope": "capability observation only, not full deployment/epoch supervision",
        "requested_image_tag": args.image,
        "docker": {"available": False, "version": None, "repo_digest": None,
                   "image_id": None, "error": None},
        "host": {"wall_before": None, "wall_after": None,
                 "clock_before": None, "clock_after": None},
        "container": {"wall": None, "clock": None},
        "readiness": {"state": "NOT_RUN", "reason": "docker_not_checked",
                      "comparison": None},
        "limitations": [
            "A matched observation does not prove shared Docker deployment topology, epoch fencing, supervisor behavior, or a quota guarantee.",
            "The image tag is mutable; the observed RepoDigest and image ID are recorded for this run.",
            "No Docker permissions or capabilities are broadened to force a ready observation.",
        ],
    }

    docker_bin = _docker_executable()
    docker_run_errors: list[str] = []
    image_ref: str | None = None
    if docker_bin is None:
        artifact["docker"]["error"] = "docker_executable_not_found"
    else:
        version = run_capture([docker_bin, "version", "--format",
                               "{{.Client.Version}}|{{.Server.Version}}"])
        artifact["docker"]["version_result"] = {
            "return_code": version.get("return_code"),
            "stdout": version.get("stdout", "").strip()[:256],
            "error": version.get("error"),
        }
        if version.get("return_code") != 0 or version.get("timed_out"):
            artifact["docker"]["error"] = "docker_daemon_unavailable"
        else:
            artifact["docker"]["available"] = True
            artifact["docker"]["version"] = version.get("stdout", "").strip()[:256]
            meta, image_ref = _image_metadata(docker_bin, args.image)
            artifact["docker"]["image_metadata_result"] = meta
            artifact["docker"]["repo_digest"] = image_ref
            artifact["docker"]["image_id"] = meta.get("image_id")
            if image_ref is None:
                artifact["docker"]["error"] = "image_pull_or_digest_unavailable"

    # Host-only observations are still useful if Docker is absent or unsupported.
    artifact["host"]["wall_before"] = _wall_summary(
        run_capture([wall_path]))
    artifact["host"]["clock_before"] = _clock_summary(
        run_capture([clock_path, "--child"]))

    if docker_bin and artifact["docker"]["available"] and image_ref:
        uid, gid = os.getuid(), os.getgid()
        wall_container_raw = _docker_run_probe(image_ref, uid, gid,
                                               wall_path, clock_path, "wall")
        clock_container_raw = _docker_run_probe(image_ref, uid, gid,
                                                wall_path, clock_path, "clock")
        artifact["container"]["wall"] = _wall_summary(wall_container_raw)
        artifact["container"]["clock"] = _clock_summary(clock_container_raw)
        for label, raw in (("wall", wall_container_raw), ("clock", clock_container_raw)):
            if (not raw.get("started") or raw.get("timed_out") or
                    raw.get("return_code") in (125, 126, 127)):
                docker_run_errors.append(f"container_{label}_probe_not_run_or_failed")
    else:
        docker_run_errors.append(artifact["docker"].get("error") or "docker_not_available")

    artifact["host"]["wall_after"] = _wall_summary(run_capture([wall_path]))
    artifact["host"]["clock_after"] = _clock_summary(
        run_capture([clock_path, "--child"]))

    state, details = _readiness(
        artifact["host"]["wall_before"], artifact["host"]["wall_after"],
        artifact["container"]["wall"] or {}, artifact["host"]["clock_before"],
        artifact["container"]["clock"] or {}, artifact["host"]["clock_after"],
        docker_run_errors,
    )
    artifact["readiness"] = {"state": state, "reason": details.get("reason"),
                              "comparison": details.get("comparison")}
    return artifact


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wall-probe", required=True,
                        help="absolute path to the built trusted_wall_clock_probe executable")
    parser.add_argument("--clock-probe", required=True,
                        help="absolute path to the built rateguard_clock_linux_smoke executable")
    parser.add_argument("--image", default="ubuntu:24.04",
                        help="Docker image tag to observe (default: ubuntu:24.04)")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        artifact = collect(parse_args(argv))
    except HarnessError as exc:
        print(json.dumps({"error": str(exc), "readiness": "NOT_RUN"},
                         separators=(",", ":")))
        return 1
    except Exception as exc:  # bounded class name only; never dump environment data
        print(json.dumps({"error": f"harness_error:{type(exc).__name__}",
                          "readiness": "NOT_RUN"}, separators=(",", ":")))
        return 1
    encoded = json.dumps(artifact, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > 64 * 1024:
        print(json.dumps({"error": "artifact_size_limit_exceeded",
                          "readiness": "NOT_RUN"}, separators=(",", ":")))
        return 1
    print(encoded)
    # Exit zero means diagnostics were collected; readiness is an artifact field.
    return 0


if __name__ == "__main__":
    sys.exit(main())
