#!/usr/bin/env python3
"""Fail closed unless an observed build manifest matches the validated build lock."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PACKAGE_FIELDS = {
    "libgrpc++-dev": "libgrpcpp_dev",
    "libgrpc-dev": "libgrpc_dev",
    "libprotobuf-dev": "libprotobuf_dev",
    "protobuf-compiler": "protobuf_compiler",
    "protobuf-compiler-grpc": "protobuf_compiler_grpc",
    "libssl-dev": "libssl_dev",
    "zlib1g-dev": "zlib1g_dev",
}


def _get(data: dict[str, Any], *path: str) -> Any:
    value: Any = data
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _cmake_version(value: Any) -> str | None:
    if not _nonempty_string(value):
        return None
    match = re.search(r"(?:cmake version\s+)?(\d+\.\d+(?:\.\d+)+)", value, re.IGNORECASE)
    return match.group(1) if match else None


def verify(lock: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    """Return every mismatch; an empty result means exact validated-lock match."""
    errors: list[str] = []

    if lock.get("schema_version") != 1:
        errors.append("lock.schema_version must be 1")
    lock_status = lock.get("lock_status")
    if lock_status not in ("frozen_pending_verification", "validated"):
        errors.append("lock.lock_status must be 'frozen_pending_verification' or 'validated'; candidate locks cannot pass")
    validation_flag = _get(lock, "validation", "validated")
    if lock_status == "validated" and validation_flag is not True:
        errors.append("validated lock requires lock.validation.validated=true")
    if lock_status == "frozen_pending_verification" and validation_flag is not False:
        errors.append("frozen_pending_verification lock requires lock.validation.validated=false")
    if manifest.get("manifest_schema_version") != 1:
        errors.append("manifest.manifest_schema_version must be 1")
    if manifest.get("build_result") != "passed":
        errors.append("manifest.build_result must be 'passed'")
    if manifest.get("lock_status") != lock_status:
        errors.append(f"manifest.lock_status must match lock status {lock_status!r}")
    if not _nonempty_string(_get(manifest, "source", "git_commit")):
        errors.append("manifest.source.git_commit is required")

    target = lock.get("target")
    if not isinstance(target, dict):
        errors.append("lock.target must be an object")
        target = {}
    runner = manifest.get("runner")
    if not isinstance(runner, dict):
        errors.append("manifest.runner must be an object")
        runner = {}
    expected_runner = target.get("runner_label")
    observed_runner = runner.get("label_requested")
    if not _nonempty_string(expected_runner) or not _nonempty_string(observed_runner):
        errors.append("target.runner_label and runner.label_requested are required")
    elif expected_runner != observed_runner:
        errors.append(f"runner label mismatch: expected {expected_runner!r}, observed {observed_runner!r}")

    expected_os = target.get("os_id")
    observed_os = _get(runner, "os_release", "ID")
    if not _nonempty_string(expected_os) or not _nonempty_string(observed_os):
        errors.append("target.os_id and runner.os_release.ID are required")
    elif expected_os.lower() != observed_os.lower():
        errors.append(f"OS ID mismatch: expected {expected_os!r}, observed {observed_os!r}")

    expected_os_version = target.get("os_version_id")
    observed_os_version = _get(runner, "os_release", "VERSION_ID")
    if not _nonempty_string(expected_os_version) or not _nonempty_string(observed_os_version):
        errors.append("target.os_version_id and runner.os_release.VERSION_ID are required")
    elif expected_os_version != observed_os_version:
        errors.append(f"OS version mismatch: expected {expected_os_version!r}, observed {observed_os_version!r}")

    expected_arch = target.get("architecture")
    observed_arch = runner.get("machine")
    if not _nonempty_string(expected_arch) or not _nonempty_string(observed_arch):
        errors.append("target.architecture and runner.machine are required")
    elif expected_arch != observed_arch:
        errors.append(f"architecture mismatch: expected {expected_arch!r}, observed {observed_arch!r}")

    expected_standard = target.get("language_standard")
    observed_build = manifest.get("build_configuration")
    if not isinstance(observed_build, dict):
        errors.append("manifest.build_configuration must be an object")
        observed_build = {}
    observed_standard = observed_build.get("cxx_standard")
    if expected_standard != "C++20" or observed_standard != "C++20":
        errors.append("lock.target.language_standard and manifest.build_configuration.cxx_standard must both be 'C++20'")
    compile_count = observed_build.get("project_compile_commands_count")
    if not isinstance(compile_count, int) or isinstance(compile_count, bool) or compile_count <= 0:
        errors.append("manifest.build_configuration.project_compile_commands_count must be a positive integer")

    # The current lock keeps CMake/Ninja under target; a future top-level
    # tools object is also accepted without weakening required values.
    tools = lock.get("tools", target)
    observed_tools = manifest.get("tools")
    if not isinstance(tools, dict):
        errors.append("lock.tools must contain exact cmake, ninja, cxx_compiler and protoc values")
        tools = {}
    if not isinstance(observed_tools, dict):
        errors.append("manifest.tools must be an object")
        observed_tools = {}
    for name in ("cmake", "ninja", "cxx_compiler", "protoc"):
        expected = tools.get(name)
        observed = observed_tools.get(name)
        if not _nonempty_string(expected) or not _nonempty_string(observed):
            errors.append(f"tool version {name} is missing from lock or manifest")
            continue
        if name == "cmake":
            expected_value = _cmake_version(expected)
            observed_value = _cmake_version(observed)
            if not expected_value or not observed_value:
                errors.append("cmake version could not be parsed")
            elif expected_value != observed_value:
                errors.append(f"cmake version mismatch: expected {expected_value!r}, observed {observed_value!r}")
        elif expected != observed:
            errors.append(f"{name} version mismatch: expected {expected!r}, observed {observed!r}")

    dependencies = lock.get("dependencies")
    if not isinstance(dependencies, dict):
        errors.append("lock.dependencies must be an object")
        dependencies = {}
    expected_packages = dependencies.get("package_versions")
    observed_packages = manifest.get("system_packages")
    if not isinstance(expected_packages, dict) or not expected_packages:
        errors.append("lock.dependencies.package_versions must be populated; an empty candidate cannot pass")
        expected_packages = {}
    if set(expected_packages) != set(PACKAGE_FIELDS):
        missing = sorted(set(PACKAGE_FIELDS) - set(expected_packages))
        extra = sorted(set(expected_packages) - set(PACKAGE_FIELDS))
        if missing:
            errors.append("lock package_versions missing: " + ", ".join(missing))
        if extra:
            errors.append("lock package_versions has unsupported keys: " + ", ".join(extra))
    if not isinstance(observed_packages, dict):
        errors.append("manifest.system_packages must be an object")
        observed_packages = {}
    for package, field in PACKAGE_FIELDS.items():
        expected = expected_packages.get(package)
        observed = observed_packages.get(field)
        if not _nonempty_string(expected) or not _nonempty_string(observed):
            errors.append(f"package version {package} is missing from lock or manifest")
        elif expected != observed:
            errors.append(f"package version mismatch for {package}: expected {expected!r}, observed {observed!r}")

    if _get(lock, "target", "dependency_mode") != "ubuntu-packages":
        errors.append("lock.target.dependency_mode must be 'ubuntu-packages'")
    if manifest.get("dependency_mode") != "system_packages":
        errors.append("manifest.dependency_mode must be 'system_packages'")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        lock = json.loads(args.lock.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: unable to read JSON input: {exc}", file=sys.stderr)
        return 2
    if not isinstance(lock, dict) or not isinstance(manifest, dict):
        print("ERROR: lock and manifest roots must be JSON objects", file=sys.stderr)
        return 2
    errors = verify(lock, manifest)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Build manifest exactly matches the {lock['lock_status']} build lock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
