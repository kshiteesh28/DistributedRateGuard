#!/usr/bin/env python3
"""Capture observed build inputs without asserting the candidate lock is validated."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


def command_output(args: list[str], cwd: Path | None = None) -> str | None:
    if not args or shutil.which(args[0]) is None:
        return None
    try:
        proc = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = proc.stdout.strip()
    return value if proc.returncode == 0 and value else None


def git_head(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    return command_output(["git", "-C", str(path), "rev-parse", "HEAD"])


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def load_lock(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"lock_status": "missing"}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"lock_status": "invalid", "error": str(exc)}



def build_configuration(source: Path, build: Path) -> dict[str, Any]:
    """Observe the compiler standard used by every project C++ translation unit."""
    flags_seen: set[str] = set()
    count = 0
    all_cpp20 = True
    try:
        entries = json.loads((build / "compile_commands.json").read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            raise ValueError("compile_commands root is not a list")
        for entry in entries:
            path = Path(entry["file"])
            if not path.is_absolute():
                path = Path(entry["directory"]) / path
            path = path.resolve()
            try:
                relative = path.relative_to(source)
            except ValueError:
                continue
            if "_deps" in relative.parts or path.suffix not in (".cpp", ".cc", ".cxx", ".C"):
                continue
            args = entry.get("arguments")
            if args is None:
                args = shlex.split(entry["command"])
            flags = [arg for arg in args if arg.startswith("-std=")]
            flags_seen.update(flags)
            all_cpp20 = all_cpp20 and flags == ["-std=c++20"]
            count += 1
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"cxx_standard": None, "project_compile_commands_count": 0,
                "error": str(exc)}
    return {"cxx_standard": "C++20" if count and all_cpp20 else None,
            "project_compile_commands_count": count,
            "project_cxx_standard_flags": sorted(flags_seen)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--grpc-source", type=Path, default=None)
    parser.add_argument("--protoc", type=Path, default=None)
    parser.add_argument("--grpc-plugin", type=Path, default=None)
    parser.add_argument("--codegen-tools", type=Path, default=None)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-result", choices=("not-yet-run", "passed", "failed"),
                        default="not-yet-run")
    args = parser.parse_args()
    source = args.source_root.resolve()
    build = args.build_dir.resolve()
    grpc_source = args.grpc_source.resolve() if args.grpc_source else None
    cmake_cache = build / "CMakeCache.txt"
    cache = cmake_cache.read_text(encoding="utf-8", errors="replace") if cmake_cache.exists() else ""
    compiler_path = None
    for line in cache.splitlines():
        if line.startswith("CMAKE_CXX_COMPILER:FILEPATH="):
            compiler_path = line.split("=", 1)[1]
            break
    compiler = [compiler_path or os.environ.get("CXX") or "c++", "--version"]
    lock = load_lock(source / "build-lock.json")
    codegen_tools: dict[str, str] = {}
    if args.codegen_tools and args.codegen_tools.exists():
        try:
            codegen_tools = json.loads(args.codegen_tools.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            codegen_tools = {}
    protoc_path = args.protoc or (Path(codegen_tools["protoc"]) if codegen_tools.get("protoc") else None)
    plugin_path = args.grpc_plugin or (Path(codegen_tools["grpc_cpp_plugin"]) if codegen_tools.get("grpc_cpp_plugin") else None)
    third_party = (grpc_source / "third_party") if grpc_source else None
    dependency_commits = {
        "grpc": git_head(grpc_source),
        "protobuf_submodule": git_head(third_party / "protobuf" if third_party else None),
        "abseil_submodule": git_head(third_party / "abseil-cpp" if third_party else None),
        "re2_submodule": git_head(third_party / "re2" if third_party else None),
        "cares_submodule": git_head(third_party / "cares" / "cares" if third_party else None),
    }
    manifest = {
        "manifest_schema_version": 1,
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "claim_status": "observed_environment_only",
        "build_result": args.build_result,
        "lock_status": lock.get("lock_status", "missing"),
        "source": {
            "git_commit": git_head(source),
            "github_sha": os.environ.get("GITHUB_SHA"),
            "github_ref": os.environ.get("GITHUB_REF"),
            "github_head_ref": os.environ.get("GITHUB_HEAD_REF"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
        },
        "runner": {
            "label_requested": "ubuntu-24.04",
            "run_os": os.environ.get("RUNNER_OS"),
            "run_arch": os.environ.get("RUNNER_ARCH"),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "os_release": read_os_release(),
            "image_digest": None,
            "image_digest_note": "GitHub-hosted runner image digest is not asserted; use ImageOS/ImageVersion and observed package versions.",
        },
        "tools": {
            "python": sys.version.splitlines()[0],
            "cmake": command_output(["cmake", "--version"]),
            "ninja": command_output(["ninja", "--version"]),
            "cxx_compiler": command_output(compiler),
            "protoc_path": str(protoc_path) if protoc_path else None,
            "protoc": command_output([str(protoc_path), "--version"]) if protoc_path else command_output(["protoc", "--version"]),
            "grpc_cpp_plugin_path": str(plugin_path) if plugin_path else None,
            "grpc_cpp_plugin": command_output([str(plugin_path), "--version"]) if plugin_path else shutil.which("grpc_cpp_plugin"),
            "git": command_output(["git", "--version"]),
        },
        "system_packages": {
            "libssl_dev": command_output(["dpkg-query", "-W", "-f=${Version}", "libssl-dev"]),
            "zlib1g_dev": command_output(["dpkg-query", "-W", "-f=${Version}", "zlib1g-dev"]),
            "nlohmann_json_dev": command_output(["dpkg-query", "-W", "-f=${Version}", "nlohmann-json3-dev"]),
            "libgrpc_dev": command_output(["dpkg-query", "-W", "-f=${Version}", "libgrpc-dev"]),
            "libgrpcpp_dev": command_output(["dpkg-query", "-W", "-f=${Version}", "libgrpc++-dev"]),
            "libprotobuf_dev": command_output(["dpkg-query", "-W", "-f=${Version}", "libprotobuf-dev"]),
            "protobuf_compiler": command_output(["dpkg-query", "-W", "-f=${Version}", "protobuf-compiler"]),
            "protobuf_compiler_grpc": command_output(["dpkg-query", "-W", "-f=${Version}", "protobuf-compiler-grpc"]),
        },
        "dependency_mode": "system_packages" if not grpc_source else "grpc_source",
        "dependency_commits": dependency_commits,
        "candidate_lock": lock,
        "build_configuration": build_configuration(source, build),
        "limitations": [
            "This manifest records one observed run; it does not by itself prove bit-for-bit reproducibility.",
            "Do not promote lock_status until CI succeeds and requested refs are compared with captured immutable commits.",
            "A missing commit/tool/package value is recorded as null, not inferred.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote observed build manifest: {args.output}")
    print(f"Build result: {args.build_result}; lock status: {manifest['lock_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
