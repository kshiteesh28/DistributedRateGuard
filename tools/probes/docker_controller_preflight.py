#!/usr/bin/env python3
"""Narrow Linux qualification harness for the Docker process-controller probe.

This is a test driver, not a production supervisor. It creates one disposable,
constrained synthetic container and asks the supplied probe to inspect/stop it.
It never proves epoch fencing, durable recovery, or deployment readiness.
"""
from __future__ import annotations

import argparse
import http.client
import io
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

MAX_OBSERVATION = 256 * 1024
MAX_HTTP = 64 * 1024
MAX_FIXTURE = 16 * 1024
MAX_PROC_STAT = 16 * 1024
MAX_CHILD_OUTPUT = 64 * 1024
CHILD_TIMEOUT = 120.0
DOCKER_SOCKET = "/var/run/docker.sock"
LABELS = (
    "io.rateguard.domain", "io.rateguard.epoch", "io.rateguard.authority",
    "io.rateguard.policy", "io.rateguard.role", "io.rateguard.slot",
    "io.rateguard.participant", "io.rateguard.incarnation",
)


class PreflightError(Exception):
    def __init__(self, code: str, diagnostics: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.diagnostics = diagnostics or {}


def _read_json(path: str, limit: int) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise PreflightError("input_file_invalid_or_oversized")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise PreflightError("input_file_oversized")
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    finally:
        os.close(fd)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError("duplicate_json_key")
        result[key] = value
    return result


def _canonical_uint(text: Any, *, maximum: int = (1 << 64) - 1) -> int:
    if not isinstance(text, str) or not re.fullmatch(r"0|[1-9][0-9]*", text):
        raise PreflightError("clock_identity_invalid")
    value = int(text)
    if value > maximum:
        raise PreflightError("clock_identity_invalid")
    return value


def _canonical_int(text: Any, *, minimum: int = -(1 << 63), maximum: int = (1 << 63) - 1) -> int:
    if not isinstance(text, str) or not re.fullmatch(r"0|-?[1-9][0-9]*", text):
        raise PreflightError("clock_identity_invalid")
    value = int(text)
    if value < minimum or value > maximum:
        raise PreflightError("clock_identity_invalid")
    return value


def _clock_fields(obs: Any) -> tuple[list[str], dict[str, int | str]]:
    if not isinstance(obs, dict) or type(obs.get("schema_version")) is not int or obs.get("schema_version") != 1:
        raise PreflightError("clock_observation_invalid")
    if obs.get("readiness", {}).get("state") != "OBSERVATIONS_MATCHED":
        raise PreflightError("clock_observation_not_matched")
    if obs.get("readiness", {}).get("reason") is not None:
        raise PreflightError("clock_observation_not_matched")
    comparison = obs.get("readiness", {}).get("comparison", {})
    if comparison.get("identity_fields_match") is not True or comparison.get("monotonic_samples_ordered") is not True:
        raise PreflightError("clock_observation_not_matched")
    locations = (obs.get("host", {}).get("clock_before", {}).get("sample"),
                 obs.get("host", {}).get("clock_after", {}).get("sample"),
                 obs.get("container", {}).get("clock", {}).get("sample"))
    fields: list[list[str]] = []
    for loc in locations:
        if not isinstance(loc, dict) or not isinstance(loc.get("identity_fields"), list):
            raise PreflightError("clock_identity_missing")
        val = loc["identity_fields"]
        if len(val) != 8 or any(not isinstance(x, str) for x in val):
            raise PreflightError("clock_identity_invalid")
        fields.append(val)
    if not (fields[0] == fields[1] == fields[2]):
        raise PreflightError("clock_identity_mismatch")
    boot, dev, ino, mono_sec, mono_ns, boot_sec, boot_ns, clock_id = fields[0]
    if not re.fullmatch(r"[0-9a-f]{32}", boot):
        raise PreflightError("clock_identity_invalid")
    if _canonical_uint(dev) == 0 or _canonical_uint(ino) == 0:
        raise PreflightError("clock_identity_invalid")
    _canonical_int(mono_sec)
    if _canonical_uint(mono_ns, maximum=999_999_999) >= 1_000_000_000:
        raise PreflightError("clock_identity_invalid")
    _canonical_int(boot_sec)
    if _canonical_uint(boot_ns, maximum=999_999_999) >= 1_000_000_000:
        raise PreflightError("clock_identity_invalid")
    if clock_id != "1":
        raise PreflightError("clock_identity_invalid")
    for block in (obs.get("host", {}).get("clock_before"), obs.get("host", {}).get("clock_after"),
                  obs.get("container", {}).get("clock")):
        if block.get("return_code") != 0 or block.get("error") is not None:
            raise PreflightError("clock_observation_failed")
    for block in (obs.get("host", {}).get("wall_before"), obs.get("host", {}).get("wall_after"),
                  obs.get("container", {}).get("wall")):
        if (not isinstance(block, dict) or block.get("return_code") != 0 or block.get("error") is not None
                or block.get("valid_json") is not True):
            raise PreflightError("wall_observation_failed")
        probe = block.get("probe", {})
        if (probe.get("trusted") is not True or probe.get("failure_reason") is not None
                or type(probe.get("sync_state")) is not int or not 0 <= probe["sync_state"] <= 4
                or type(probe.get("status_flags")) is not int or probe["status_flags"] < 0
                or probe["status_flags"] & (0x40 | 0x1000)):
            raise PreflightError("wall_observation_untrusted")
    return fields[0], {
        "boot_uuid": boot, "namespace_device": int(dev), "namespace_inode": int(ino),
        "monotonic_offset_seconds": int(mono_sec), "monotonic_offset_nanoseconds": int(mono_ns),
        "boottime_offset_seconds": int(boot_sec), "boottime_offset_nanoseconds": int(boot_ns),
        "clock_id": 1,
    }


def _repo_digest(obs: Any) -> tuple[str, str]:
    docker = obs.get("docker", {})
    digest = docker.get("repo_digest")
    image_id = docker.get("image_id")
    if not isinstance(digest, str) or not re.fullmatch(r"[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}", digest):
        raise PreflightError("qualified_image_digest_invalid")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise PreflightError("qualified_image_id_invalid")
    return digest, image_id


def _version_tuple(value: str) -> tuple[int, int]:
    m = re.fullmatch(r"1\.([0-9]{1,3})", value)
    if not m:
        raise PreflightError("engine_api_version_invalid")
    return (1, int(m.group(1)))


def _http_get_version(sock_path: str) -> dict[str, Any]:
    st = os.stat(sock_path, follow_symlinks=False)
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0:
        raise PreflightError("docker_socket_not_root_owned")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.monotonic() + 5.0
    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise PreflightError("docker_version_deadline")
        return value
    try:
        s.settimeout(remaining())
        s.connect(sock_path)
        if hasattr(socket, "SO_PEERCRED"):
            import struct
            _, peer_uid, _ = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid != 0:
                raise PreflightError("docker_peer_not_root")
        else:
            raise PreflightError("docker_peer_credentials_unsupported")
        s.settimeout(remaining())
        s.sendall(b"GET /version HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")
        data = bytearray()
        while len(data) <= MAX_HTTP:
            s.settimeout(remaining())
            piece = s.recv(min(8192, MAX_HTTP + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
        if len(data) > MAX_HTTP:
            raise PreflightError("docker_version_response_too_large")
    except (OSError, TimeoutError):
        raise PreflightError("docker_version_transport_failed") from None
    finally:
        s.close()
    raw = bytes(data)
    class _MemorySocket:
        def __init__(self, payload: bytes):
            self.payload = payload
        def makefile(self, mode: str):
            if mode != "rb":
                raise PreflightError("docker_version_http_invalid")
            return io.BytesIO(self.payload)
        def close(self):
            pass
    try:
        response = http.client.HTTPResponse(_MemorySocket(raw))
        response.begin()
        if response.status != 200 or response.version not in (10, 11):
            raise PreflightError("docker_version_http_status")
        if len(response.headers.get_all("Content-Length", [])) > 1 or len(response.headers.get_all("Transfer-Encoding", [])) > 1:
            raise PreflightError("docker_version_http_invalid")
        transfer = response.getheader("Transfer-Encoding")
        length = response.getheader("Content-Length")
        if transfer is not None and length is not None:
            raise PreflightError("docker_version_http_invalid")
        if transfer is not None and transfer.lower().strip() != "chunked":
            raise PreflightError("docker_version_http_invalid")
        if length is not None and (not re.fullmatch(r"0|[1-9][0-9]*", length) or int(length) > MAX_HTTP):
            raise PreflightError("docker_version_response_too_large")
        if response.getheader("Content-Encoding") not in (None, "identity"):
            raise PreflightError("docker_version_http_invalid")
        body = response.read(MAX_HTTP + 1)
        if len(body) > MAX_HTTP:
            raise PreflightError("docker_version_response_too_large")
        if response.fp is not None and response.fp.read(1):
            raise PreflightError("docker_version_http_extra_bytes")
    except PreflightError:
        raise
    except (http.client.HTTPException, OSError, ValueError):
        raise PreflightError("docker_version_http_invalid") from None
    try:
        doc = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
    except Exception:
        raise PreflightError("docker_version_json_invalid") from None
    if not isinstance(doc, dict):
        raise PreflightError("docker_version_json_invalid")
    api, minimum = doc.get("ApiVersion"), doc.get("MinAPIVersion")
    if not isinstance(api, str) or not isinstance(minimum, str):
        raise PreflightError("docker_version_fields_invalid")
    if _version_tuple(api) < (1, 42) or _version_tuple(api) < _version_tuple(minimum):
        raise PreflightError("docker_api_below_required_floor")
    return {"api_version": api, "min_api_version": minimum, "engine_version": str(doc.get("Version", ""))[:64]}


def _run(argv: list[str], env: dict[str, str], timeout: float, limit: int = MAX_CHILD_OUTPUT) -> tuple[int, bytes, bytes]:
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=env, close_fds=True, start_new_session=True)
    assert p.stdout is not None and p.stderr is not None
    sel = selectors.DefaultSelector()
    for pipe, label in ((p.stdout, "out"), (p.stderr, "err")):
        os.set_blocking(pipe.fileno(), False)
        sel.register(pipe, selectors.EVENT_READ, label)
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    try:
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PreflightError("subprocess_timeout")
            for key, _ in sel.select(min(remaining, 0.25)):
                try:
                    chunk = os.read(key.fd, 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                dest = out if key.data == "out" else err
                if len(dest) + len(chunk) > limit:
                    raise PreflightError("subprocess_output_limit")
                dest.extend(chunk)
        code = p.wait(timeout=max(0.1, deadline - time.monotonic()))
        return code, bytes(out), bytes(err)
    except Exception:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            p.wait(timeout=3)
        except Exception:
            pass
        raise
    finally:
        sel.close()
        p.stdout.close()
        p.stderr.close()


def _docker(docker: str, env: dict[str, str], *args: str, timeout: float = 30) -> bytes:
    code, stdout, _ = _run([docker, "--host", "unix://" + DOCKER_SOCKET, *args], env, timeout)
    if code != 0:
        operation = {
            ("image", "inspect"): "image_inspect",
            ("inspect",): "container_inspect",
            ("create",): "container_create",
            ("start",): "container_start",
            ("rm",): "container_remove",
            ("ps",): "container_list",
        }.get(args[:2] if args[:1] == ("image",) else args[:1], "unknown")
        raise PreflightError("docker_command_failed", {
            "docker_operation": operation, "docker_exit_code": int(code),
        })
    return stdout


def _parse_start_ticks(pid: int) -> int:
    fd = os.open(f"/proc/{pid}/stat", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        raw = os.read(fd, MAX_PROC_STAT + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_PROC_STAT:
        raise PreflightError("process_stat_too_large")
    # comm is parenthesized and may itself contain ')' characters.
    close = raw.rfind(b")")
    if close < 0:
        raise PreflightError("process_stat_invalid")
    fields = raw[close + 1:].split()
    if len(fields) < 20:
        raise PreflightError("process_stat_invalid")
    try:
        value = int(fields[19], 10)  # field 22, token 0 is field 3
    except ValueError:
        raise PreflightError("process_stat_invalid") from None
    if value <= 0:
        raise PreflightError("process_start_ticks_invalid")
    return value


def _inspect(docker: str, env: dict[str, str], cid: str) -> dict[str, Any]:
    template = ("{{.Id}}|{{.Name}}|{{.State.Status}}|{{.State.Running}}|{{.State.Restarting}}|{{.State.Pid}}|"
                "{{.HostConfig.RestartPolicy.Name}}|" + "|".join(
                    '{{index .Config.Labels "' + k + '"}}' for k in LABELS))
    raw = _docker(docker, env, "inspect", "--format", template, cid)
    if len(raw) > MAX_CHILD_OUTPUT:
        raise PreflightError("docker_inspect_too_large")
    try:
        fields = raw.decode("utf-8").strip().split("|")
        if len(fields) != 7 + len(LABELS):
            raise ValueError
        if fields[2] not in ("created", "running", "paused", "restarting", "removing", "exited", "dead"):
            raise ValueError
        if fields[3] not in ("true", "false") or fields[4] not in ("true", "false"):
            raise ValueError
        if not re.fullmatch(r"0|[1-9][0-9]*", fields[5]) or int(fields[5]) > (1 << 64) - 1:
            raise ValueError
        obj = {"Id": fields[0], "Name": fields[1],
               "State": {"Status": fields[2], "Running": fields[3] == "true",
               "Restarting": fields[4] == "true", "Pid": int(fields[5])},
               "HostConfig": {"RestartPolicy": {"Name": fields[6]}},
               "Config": {"Labels": dict(zip(LABELS, fields[7:]))}}
    except Exception:
        raise PreflightError("docker_inspect_invalid") from None
    if obj["Id"] != cid:
        raise PreflightError("docker_inspect_identity_mismatch")
    return obj


def _labels(container: dict[str, Any], expected: dict[str, str]) -> bool:
    config = container.get("Config", {})
    labels = config.get("Labels", {}) if isinstance(config, dict) else {}
    return (isinstance(labels, dict) and len(expected) == 8
            and all(labels.get(k) == v for k, v in expected.items()))


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise PreflightError("file_write_failed")
        view = view[count:]


def _safe_probe_diagnostics(result: dict[str, Any]) -> dict[str, Any]:
    """Export fixed stage/status enums, never arbitrary child output."""
    stages = {"fixture_parse", "fixture_validation", "trusted_linux_clock_factory",
              "docker_controller_factory", "runtime_checks"}
    statuses = {"not_run", "matched_running", "matched_exited_runtime_and_process",
                "matched_exited_runtime_only", "acknowledged", "already_stopped",
                "reconciliation_deadline_unavailable", "reconciliation_clock_unhealthy",
                "reconciliation_clock_read_failed", "reconciliation_deadline_expired",
                "skipped_stop_not_acknowledged"}
    statuses.update(f"controller_error_{n}{suffix}" for n in range(14)
                    for suffix in ("", "_possibly_sent", "_unsent"))
    statuses.update(f"unknown_reason_{n}" for n in range(16))
    safe: dict[str, Any] = {}
    stage = result.get("setup_stage")
    if isinstance(stage, str) and stage in stages:
        safe["probe_setup_stage"] = stage
    checks = result.get("checks")
    raw = checks.get("status") if isinstance(checks, dict) else None
    if isinstance(raw, list) and len(raw) == 8:
        safe["probe_status_codes"] = [value if isinstance(value, str) and value in statuses
                                      else "unrecognized" for value in raw]
    return safe


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not sys.platform.startswith("linux"):
        raise PreflightError("linux_only")
    if not os.path.isabs(args.probe) or not os.path.isfile(args.probe) or not os.access(args.probe, os.X_OK):
        raise PreflightError("probe_must_be_absolute_executable")
    observation = _read_json(args.clock_observation, MAX_OBSERVATION)
    _, clock = _clock_fields(observation)
    repo_digest, expected_image_id = _repo_digest(observation)
    engine = _http_get_version(DOCKER_SOCKET)
    docker = shutil.which("docker")
    sudo = shutil.which("sudo")
    if not docker or not sudo:
        raise PreflightError("docker_or_sudo_missing")
    docker, sudo = os.path.realpath(docker), os.path.realpath(sudo)
    with tempfile.TemporaryDirectory(prefix="rateguard-controller-") as td:
        os.chmod(td, 0o700)
        config_dir = os.path.join(td, "docker-config")
        os.mkdir(config_dir, 0o700)
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
               "DOCKER_CONFIG": config_dir, "DOCKER_API_VERSION": engine["api_version"]}
        image_out = _docker(docker, env, "image", "inspect", "--format",
                            '{{.Id}}|{{json .RepoDigests}}', repo_digest)
        try:
            image_id, digest_json = image_out.decode("ascii").strip().split("|", 1)
            repo_digests = json.loads(digest_json)
            if not isinstance(repo_digests, list) or not all(isinstance(value, str) for value in repo_digests):
                raise ValueError
        except (ValueError, UnicodeError):
            raise PreflightError("qualified_image_inspect_invalid") from None
        if image_id != expected_image_id or repo_digest not in repo_digests:
            raise PreflightError("qualified_image_not_present_or_mismatched")

        domain = secrets.token_hex(16)
        epoch = secrets.token_hex(16)
        authority = secrets.token_hex(16)
        policy = secrets.token_hex(32)
        participant = secrets.token_hex(16)
        incarnation = secrets.token_hex(16)
        stop_op = secrets.token_hex(16)
        name = "rateguard-probe-" + secrets.token_hex(12)
        labels = {
            LABELS[0]: domain, LABELS[1]: epoch, LABELS[2]: authority, LABELS[3]: policy,
            LABELS[4]: "replica", LABELS[5]: "7", LABELS[6]: participant, LABELS[7]: incarnation,
        }
        create_args = ["create", "--name", name, "--restart=no", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "--read-only", "--network=none",
                       "--pids-limit=32", "--memory=64m", "--cpus=1"]
        for key, value in labels.items():
            create_args += ["--label", f"{key}={value}"]
        create_args += [repo_digest, "sleep", "infinity"]
        cid = ""
        removed = False
        try:
            cid_bytes = _docker(docker, env, *create_args)
            cid = cid_bytes.decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", cid):
                raise PreflightError("container_id_invalid")
            created = _inspect(docker, env, cid)
            if not _labels(created, labels) or created.get("HostConfig", {}).get("RestartPolicy", {}).get("Name") != "no":
                raise PreflightError("created_container_binding_mismatch")
            _docker(docker, env, "start", cid)
            running = _inspect(docker, env, cid)
            state = running.get("State", {})
            host_pid = state.get("Pid")
            if state.get("Running") is not True or type(host_pid) is not int or host_pid <= 0:
                raise PreflightError("container_not_running")
            if not _labels(running, labels):
                raise PreflightError("running_container_binding_mismatch")
            ticks = _parse_start_ticks(host_pid)
            ns = os.stat("/proc/self/ns/pid")
            binding = {"domain_id": domain, "epoch_id": epoch, "authority_incarnation": authority,
                       "policy_digest": policy, "role": "replica", "slot_id": 7,
                       "participant_id": participant, "incarnation": incarnation, "container_id": cid}
            fixture = {
                "schema_version": 1, "socket_path": DOCKER_SOCKET, "api_version": engine["api_version"],
                "binding": binding, "recorded_process": {"host_pid": host_pid, "pid_start_ticks": ticks},
                "expected_clock_identity": clock,
                "expected_observer_pid_namespace": {"device": ns.st_dev, "inode": ns.st_ino},
                "stop_operation_id": stop_op,
            }
            fixture_path = os.path.join(td, "fixture.json")
            fd = os.open(fixture_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                payload = json.dumps(fixture, sort_keys=True, separators=(",", ":")).encode("ascii")
                if len(payload) > MAX_FIXTURE:
                    raise PreflightError("fixture_too_large")
                _write_all(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            sudo_env = {"PATH": env["PATH"], "LANG": "C", "LC_ALL": "C"}
            code, probe_out, _ = _run([sudo, "-n", "env", "DOCKER_HOST=unix:///var/run/docker.sock",
                               "DOCKER_API_VERSION=" + engine["api_version"], "DOCKER_CONFIG=" + config_dir,
                               args.probe, "--fixture", os.path.abspath(fixture_path)], sudo_env, CHILD_TIMEOUT)
            try:
                probe_result = json.loads(probe_out.decode("utf-8"), object_pairs_hook=_unique_object)
            except Exception:
                raise PreflightError("probe_result_invalid") from None
            if not isinstance(probe_result, dict):
                raise PreflightError("probe_result_invalid")
            expected_checks = ("pending_running", "observed_running", "tampered_stop_rejected_unsent",
                               "original_still_running", "one_stop_acknowledged", "observed_runtime_and_process_exit",
                               "pending_runtime_exit", "repeat_stop_already_stopped")
            checks = probe_result.get("checks", {}) if isinstance(probe_result, dict) else {}
            safe_checks = {name: checks.get(name) is True for name in expected_checks}
            if (type(probe_result.get("schema_version")) is not int or probe_result.get("schema_version") != 1 or probe_result.get("passed") is not True
                    or probe_result.get("selected_api_version") != engine["api_version"]
                    or any(checks.get(name) is not True for name in expected_checks)):
                raise PreflightError("probe_assertions_failed", {
                    "probe_exit_code": int(code), "probe_checks": safe_checks,
                    **_safe_probe_diagnostics(probe_result),
                })
            terminal = _inspect(docker, env, cid)
            terminal_state = terminal.get("State", {})
            stopped = (_labels(terminal, labels) and terminal_state.get("Status") == "exited"
                       and terminal_state.get("Pid") == 0 and terminal_state.get("Running") is False
                       and terminal_state.get("Restarting") is False
                       and terminal.get("HostConfig", {}).get("RestartPolicy", {}).get("Name") == "no")
            if not stopped or code != 0:
                raise PreflightError("probe_or_independent_stop_verification_failed")
            result = {"schema_version": 1, "state": "OBSERVED_AND_STOPPED", "probe_exit_code": code,
                      "docker_engine_version": engine["engine_version"], "docker_api_version": engine["api_version"],
                      "image_repo_digest": repo_digest, "image_id": expected_image_id,
                      "host_uid": os.getuid(), "container_id": cid,
                      "independent_terminal_check": "MATCHED_EXITED_PID_ZERO_RESTART_DISABLED",
                      "probe_checks": {name: True for name in expected_checks},
                      "scope": "single synthetic process-controller preflight; not epoch fencing or deployment acceptance"}
            return result
        finally:
            # Remove only this exact full CID after rechecking the entire private label binding.
            if not cid:
                try:
                    discovered = _docker(docker, env, "ps", "--all", "--quiet", "--no-trunc",
                                         "--filter", "name=^/" + name + "$").decode("ascii").splitlines()
                    if len(discovered) == 1 and re.fullmatch(r"[0-9a-f]{64}", discovered[0]):
                        candidate = _inspect(docker, env, discovered[0])
                        if candidate.get("Name") == "/" + name and _labels(candidate, labels):
                            cid = discovered[0]
                except Exception:
                    cid = ""
            if cid and re.fullmatch(r"[0-9a-f]{64}", cid):
                try:
                    current = _inspect(docker, env, cid)
                    if current.get("Name") == "/" + name and _labels(current, labels):
                        _docker(docker, env, "rm", "--force", cid)
                        removed = True
                except Exception:
                    removed = False
            if "result" in locals():
                result["owned_container_removed"] = removed
                if not removed:
                    result["state"] = "CLEANUP_FAILED"
            active_error = sys.exc_info()[1]
            if isinstance(active_error, PreflightError):
                active_error.diagnostics["owned_container_removed"] = removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--clock-observation", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = run(args)
        status = 0 if result.get("state") == "OBSERVED_AND_STOPPED" else 2
    except PreflightError as exc:
        result = {"schema_version": 1, "state": "NOT_READY", "reason": exc.code,
                  "scope": "single synthetic process-controller preflight; not epoch fencing or deployment acceptance"}
        result.update(exc.diagnostics)
        status = 2
    except Exception:
        result = {"schema_version": 1, "state": "ERROR", "reason": "unexpected_harness_error",
                  "scope": "single synthetic process-controller preflight; not epoch fencing or deployment acceptance"}
        status = 1
    try:
        output = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        target = os.path.abspath(args.output)
        temp = target + ".tmp-" + secrets.token_hex(8)
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, output.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, target)
    except Exception:
        return 1
    print(output, end="")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
