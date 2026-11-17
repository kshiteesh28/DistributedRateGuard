from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_build_manifest import verify  # noqa: E402


def valid_inputs() -> tuple[dict, dict]:
    # Deliberately synthetic versions; these tests do not assert an environment.
    packages = {
        "nlohmann-json3-dev": "3.11.3-fixture",
        "libgrpc++-dev": "1.51.1-3build1",
        "libgrpc-dev": "1.51.1-3build1",
        "libprotobuf-dev": "3.21.12-8.2ubuntu0.2",
        "protobuf-compiler": "3.21.12-8.2ubuntu0.2",
        "protobuf-compiler-grpc": "1.51.1-3build1",
        "libssl-dev": "3.0.13-0ubuntu3.1",
        "zlib1g-dev": "1:1.3.dfsg-3.1ubuntu2",
    }
    lock = {
        "schema_version": 1,
        "lock_status": "frozen_pending_verification",
        "target": {
            "runner_label": "ubuntu-24.04",
            "os_id": "ubuntu",
            "os_version_id": "24.04",
            "architecture": "x86_64",
            "language_standard": "C++20",
            "dependency_mode": "ubuntu-packages",
        },
        "tools": {
            "cmake": "cmake version 3.31.6",
            "ninja": "1.11.1",
            "cxx_compiler": "c++ (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
            "protoc": "libprotoc 3.21.12",
        },
        "dependencies": {"package_versions": packages},
        "validation": {"validated": False},
    }
    manifest = {
        "manifest_schema_version": 1,
        "lock_status": "frozen_pending_verification",
        "build_result": "passed",
        "source": {"git_commit": "a" * 40},
        "build_configuration": {
            "cxx_standard": "C++20",
            "project_compile_commands_count": 3,
        },
        "runner": {
            "label_requested": "ubuntu-24.04",
            "machine": "x86_64",
            "os_release": {"ID": "ubuntu", "VERSION_ID": "24.04"},
        },
        "tools": {
            "cmake": "cmake version 3.31.6",
            "ninja": "1.11.1",
            "cxx_compiler": "c++ (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
            "protoc": "libprotoc 3.21.12",
        },
        "system_packages": {
            "nlohmann_json_dev": packages["nlohmann-json3-dev"],
            "libgrpcpp_dev": packages["libgrpc++-dev"],
            "libgrpc_dev": packages["libgrpc-dev"],
            "libprotobuf_dev": packages["libprotobuf-dev"],
            "protobuf_compiler": packages["protobuf-compiler"],
            "protobuf_compiler_grpc": packages["protobuf-compiler-grpc"],
            "libssl_dev": packages["libssl-dev"],
            "zlib1g_dev": packages["zlib1g-dev"],
        },
        "dependency_mode": "system_packages",
    }
    return lock, manifest


class VerifyBuildManifestTests(unittest.TestCase):
    def test_matching_manifest_passes(self) -> None:
        lock, manifest = valid_inputs()
        self.assertEqual(verify(lock, manifest), [])

    def test_package_version_drift_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["system_packages"]["libgrpc_dev"] = "different-version"
        self.assertTrue(any("package version mismatch for libgrpc-dev" in e for e in verify(lock, manifest)))

    def test_json_package_version_drift_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["system_packages"]["nlohmann_json_dev"] = "different-version"
        self.assertTrue(any("package version mismatch for nlohmann-json3-dev" in e for e in verify(lock, manifest)))

    def test_tool_version_drift_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["tools"]["protoc"] = "libprotoc 99.0"
        self.assertTrue(any("protoc version mismatch" in e for e in verify(lock, manifest)))

    def test_target_os_or_arch_drift_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["runner"]["machine"] = "aarch64"
        self.assertTrue(any("architecture mismatch" in e for e in verify(lock, manifest)))

    def test_language_standard_mismatch_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["build_configuration"]["cxx_standard"] = "gnu++17"
        self.assertTrue(any("must both be 'C++20'" in e for e in verify(lock, manifest)))

    def test_missing_or_zero_project_compile_commands_fail(self) -> None:
        lock, manifest = valid_inputs()
        manifest["build_configuration"]["project_compile_commands_count"] = 0
        self.assertTrue(any("must be a positive integer" in e for e in verify(lock, manifest)))
        del manifest["build_configuration"]["cxx_standard"]
        self.assertTrue(any("must both be 'C++20'" in e for e in verify(lock, manifest)))

    def test_missing_expected_or_observed_values_fail(self) -> None:
        lock, manifest = valid_inputs()
        del lock["tools"]["cxx_compiler"]
        manifest["system_packages"]["protobuf_compiler"] = None
        errors = verify(lock, manifest)
        self.assertTrue(any("tool version cxx_compiler is missing" in e for e in errors))
        self.assertTrue(any("package version protobuf-compiler is missing" in e for e in errors))

    def test_failed_build_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["build_result"] = "failed"
        self.assertTrue(any("build_result must be 'passed'" in e for e in verify(lock, manifest)))

    def test_missing_source_commit_fails(self) -> None:
        lock, manifest = valid_inputs()
        manifest["source"]["git_commit"] = None
        self.assertTrue(any("source.git_commit is required" in e for e in verify(lock, manifest)))

    def test_frozen_complete_lock_can_match_before_repeat_validation(self) -> None:
        lock, manifest = valid_inputs()
        self.assertEqual(verify(lock, manifest), [])

    def test_candidate_or_empty_lock_fails_closed(self) -> None:
        lock, manifest = valid_inputs()
        lock["lock_status"] = "candidate_unvalidated"
        lock["dependencies"]["package_versions"] = {}
        errors = verify(lock, manifest)
        self.assertTrue(any("candidate locks cannot pass" in e for e in errors))
        self.assertTrue(any("package_versions must be populated" in e for e in errors))

    def test_inconsistent_validation_flags_fail(self) -> None:
        lock, manifest = valid_inputs()
        lock["lock_status"] = "validated"
        lock["validation"]["validated"] = False
        manifest["lock_status"] = "validated"
        self.assertTrue(any("validated lock requires" in e for e in verify(lock, manifest)))


if __name__ == "__main__":
    unittest.main()
