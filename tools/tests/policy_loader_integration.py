"""End-to-end Python oracle for the CMake-built PolicyLoader/Codec/Digest driver."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_v1_oracle import digest, encode_policy, load_fixture

QA_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = Path(os.environ.get("RATEGUARD_REPO_ROOT", QA_ROOT))
DRIVER = Path(os.environ.get("RATEGUARD_POLICY_DRIVER", REPO_ROOT / "build" / "policy_driver"))
FIXTURE = Path(os.environ.get(
    "RATEGUARD_POLICY_FIXTURE", QA_ROOT / "tests" / "fixtures" / "policy_v1.json"))
CANONICAL_FIXTURE = Path(os.environ.get(
    "RATEGUARD_CANONICAL_FIXTURE",
    QA_ROOT / "tests" / "fixtures" / "policy_v1.canonical.hex"))


def run_driver(raw: str) -> tuple[int, dict]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as file:
        file.write(raw)
        file.flush()
        process = subprocess.run([str(DRIVER), file.name], capture_output=True,
                                  text=True, timeout=15, check=False)
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"driver emitted invalid JSON (exit {process.returncode}): "
            f"{process.stdout!r}; stderr={process.stderr!r}") from exc
    return process.returncode, result


def call_valid(policy: dict) -> dict:
    status, result = run_driver(json.dumps(policy, separators=(",", ":"), ensure_ascii=True))
    if status != 0 or result.get("status") != "ok":
        raise AssertionError(f"valid policy rejected: rc={status}, result={result}")
    expected_hex = encode_policy(policy).hex()
    expected_digest = digest(policy)
    if result.get("canonical_hex") != expected_hex:
        raise AssertionError("production canonical bytes differ from independent oracle")
    if result.get("sha256") != expected_digest:
        raise AssertionError("production digest differs from independent SHA-256 oracle")
    return result


def assert_rejected(test: unittest.TestCase, raw: str, label: str) -> None:
    status, result = run_driver(raw)
    test.assertNotEqual(status, 0, f"{label}: driver unexpectedly returned success")
    test.assertEqual(result.get("status"), "error", f"{label}: expected structured error")
    test.assertIn("code", result, f"{label}: error code absent")
    test.assertLessEqual(len(result.get("message", "")), 256, f"{label}: unbounded diagnostic")


def authority(policy: dict) -> dict:
    return next(p for p in policy["principals"] if p["role"] == "authority")


def replica(policy: dict, slot: int) -> dict:
    return next(p for p in policy["principals"]
                if p["role"] == "replica" and p["slot_id"] == slot)


def adapter(policy: dict) -> dict:
    return next(p for p in policy["principals"] if p["role"] == "adapter")


class PolicyLoaderIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not DRIVER.is_file():
            raise FileNotFoundError(f"CMake-built production policy_driver is required: {DRIVER}")
        if not FIXTURE.is_file():
            raise FileNotFoundError(f"policy fixture is required: {FIXTURE}")
        if not CANONICAL_FIXTURE.is_file():
            raise FileNotFoundError(f"independent canonical hex fixture is required: {CANONICAL_FIXTURE}")
        cls.policy = load_fixture(FIXTURE)
        cls.expected_hex = encode_policy(cls.policy).hex()
        cls.expected_sha = hashlib.sha256(bytes.fromhex(cls.expected_hex)).hexdigest()
        frozen_hex = CANONICAL_FIXTURE.read_text(encoding="ascii").strip()
        if not frozen_hex or any(c not in "0123456789abcdef" for c in frozen_hex):
            raise ValueError(f"canonical fixture must be one lowercase hex line: {CANONICAL_FIXTURE}")
        if frozen_hex != cls.expected_hex:
            raise AssertionError("independent canonical hex fixture is stale or corrupt")
        if cls.expected_sha != digest(cls.policy):
            raise AssertionError("oracle digest cross-check failed")

    def test_aggregate_fixture_bytes_and_digest(self) -> None:
        result = call_valid(self.policy)
        self.assertEqual(result["canonical_hex"], self.expected_hex)
        self.assertEqual(result["sha256"], self.expected_sha)
        self.assertEqual(len(bytes.fromhex(result["canonical_hex"])), 580)

    def test_input_array_order_is_irrelevant(self) -> None:
        changed = copy.deepcopy(self.policy)
        changed["replica_slots"].reverse()
        changed["tenants"].reverse()
        changed["principals"].reverse()
        for tenant in changed["tenants"]:
            tenant["operations"].reverse()
        adapter(changed)["permissions"].reverse()
        result = call_valid(changed)
        self.assertEqual(result["canonical_hex"], self.expected_hex)
        self.assertEqual(result["sha256"], self.expected_sha)

    def test_valid_identity_authorization_and_quota_changes_change_digest(self) -> None:
        candidates: list[tuple[str, dict]] = []

        changed = copy.deepcopy(self.policy)
        changed["epoch_id"] = "100102030405060708090a0b0c0d0e0f"
        candidates.append(("epoch_id", changed))

        changed = copy.deepcopy(self.policy)
        changed["authority_incarnation"] = "111112131415161718191a1b1c1d1e1f"
        authority(changed)["uri"] = (
            "spiffe://rateguard.local/authority/" + changed["authority_incarnation"])
        candidates.append(("authority incarnation/URI", changed))

        changed = copy.deepcopy(self.policy)
        changed["trust_root_sha256"] = (
            "0ee742f3d97b519e6b7a8ee84b88b019cea856aadcd44d0dc2ac113852a6432f")
        candidates.append(("trust root fingerprint", changed))

        changed = copy.deepcopy(self.policy)
        slot = next(x for x in changed["replica_slots"] if x["slot_id"] == 7)
        slot["incarnation_id"] = "404142434445464748494a4b4c4d4e4f"
        replica(changed, 7)["uri"] = (
            "spiffe://rateguard.local/replica/7/" + slot["incarnation_id"])
        candidates.append(("slot incarnation", changed))

        changed = copy.deepcopy(self.policy)
        slot = next(x for x in changed["replica_slots"] if x["slot_id"] == 7)
        slot["slot_id"] = 8
        replica(changed, 7)["slot_id"] = 8
        replica(changed, 8)["uri"] = (
            "spiffe://rateguard.local/replica/8/" + slot["incarnation_id"])
        candidates.append(("slot identity", changed))

        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        zeta["tenant_id"] = "omega"
        for principal in changed["principals"]:
            for permission in principal["permissions"]:
                if permission["tenant_id"] == "zeta":
                    permission["tenant_id"] = "omega"
        candidates.append(("tenant identity", changed))

        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        next(x for x in zeta["operations"] if x["operation_id"] == "list")["operation_id"] = "browse"
        for permission in adapter(changed)["permissions"]:
            if permission["tenant_id"] == "zeta" and permission["operation_id"] == "list":
                permission["operation_id"] = "browse"
        candidates.append(("operation identity", changed))

        changed = copy.deepcopy(self.policy)
        old_replica = replica(changed, 7)
        changed["principals"].remove(old_replica)
        former_adapter = adapter(changed)
        incarnation = next(x for x in changed["replica_slots"] if x["slot_id"] == 7)["incarnation_id"]
        former_adapter["role"] = "replica"
        former_adapter["slot_id"] = 7
        former_adapter["uri"] = f"spiffe://rateguard.local/replica/7/{incarnation}"
        changed["principals"].append({
            "uri": "spiffe://rateguard.local/adapter/ingress2",
            "role": "adapter",
            "permissions": [],
        })
        candidates.append(("principal role", changed))

        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        zeta["capacity_units"] = "21"
        candidates.append(("capacity", changed))

        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        zeta["rate_units_per_second"] = "4"
        candidates.append(("rate", changed))

        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        zeta["credit_batch_units"] = "7"
        candidates.append(("credit batch", changed))

        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        operation = next(x for x in zeta["operations"] if x["operation_id"] == "list")
        operation["cost_units"] = "3"
        candidates.append(("operation cost", changed))

        changed = copy.deepcopy(self.policy)
        adapter(changed)["uri"] = "spiffe://rateguard.local/adapter/ingress2"
        candidates.append(("adapter principal URI", changed))

        changed = copy.deepcopy(self.policy)
        permission = adapter(changed)["permissions"][0]
        permission["tenant_id"] = "alpha"
        permission["operation_id"] = "write"
        candidates.append(("permission", changed))

        for label, candidate in candidates:
            with self.subTest(field=label):
                result = call_valid(candidate)
                self.assertNotEqual(result["sha256"], self.expected_sha)

    def test_strict_policy_has_q_presence_zero_and_matches_oracle(self) -> None:
        strict = copy.deepcopy(self.policy)
        strict["mode"] = "strict"
        for tenant in strict["tenants"]:
            del tenant["credit_batch_units"]
        result = call_valid(strict)
        self.assertNotEqual(result["sha256"], self.expected_sha)
        self.assertEqual(result["canonical_hex"], encode_policy(strict).hex())

    def test_rejects_duplicate_unknown_and_malformed_json(self) -> None:
        original = FIXTURE.read_text(encoding="utf-8")
        duplicate_key = original.replace(
            '"mode": "credit",', '"mode": "credit",\n  "mode": "credit",', 1)
        assert_rejected(self, duplicate_key, "duplicate root key")
        assert_rejected(self, original[:-1] + ', "extra": true}', "unknown root field")
        assert_rejected(self, original + "\n{}", "trailing JSON value")
        assert_rejected(self, '{"schema_version":', "truncated malformed JSON")
        assert_rejected(self, original.replace('"schema_version": 1', '"schema_version": 2'),
                        "unsupported schema version")
        assert_rejected(self, original.replace('"schema_version": 1', '"schema_version": true'),
                        "boolean schema version")
        assert_rejected(self, original.replace('"capacity_units": "20"', '"capacity_units": 20.0'),
                        "float policy value")
        assert_rejected(self, original.replace('"capacity_units": "20"', '"capacity_units": "020"'),
                        "noncanonical decimal")

    def test_rejects_unknown_permission_and_operation_cost_bounds(self) -> None:
        changed = copy.deepcopy(self.policy)
        adapter(changed)["permissions"][0]["tenant_id"] = "missing"
        assert_rejected(self, json.dumps(changed), "unknown permission tenant")
        changed = copy.deepcopy(self.policy)
        adapter(changed)["permissions"][0]["operation_id"] = "missing"
        assert_rejected(self, json.dumps(changed), "unknown permission operation")
        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        next(x for x in zeta["operations"] if x["operation_id"] == "list")["cost_units"] = "21"
        assert_rejected(self, json.dumps(changed), "operation cost exceeds capacity")
        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        zeta["credit_batch_units"] = "5"
        assert_rejected(self, json.dumps(changed), "batch below maximum operation cost")
        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        zeta["credit_batch_units"] = "21"
        assert_rejected(self, json.dumps(changed), "batch above capacity")
        changed = copy.deepcopy(self.policy)
        zeta = next(x for x in changed["tenants"] if x["tenant_id"] == "zeta")
        next(x for x in zeta["operations"] if x["operation_id"] == "list")["cost_units"] = "0"
        assert_rejected(self, json.dumps(changed), "zero operation cost")

    def test_rejects_duplicate_slots_unknown_slots_and_identity_mismatches(self) -> None:
        changed = copy.deepcopy(self.policy)
        changed["replica_slots"].append(copy.deepcopy(changed["replica_slots"][0]))
        assert_rejected(self, json.dumps(changed), "duplicate slot")
        changed = copy.deepcopy(self.policy)
        replica(changed, 7)["slot_id"] = 99
        assert_rejected(self, json.dumps(changed), "unknown replica slot")
        changed = copy.deepcopy(self.policy)
        replica(changed, 7)["uri"] = "spiffe://rateguard.local/replica/7/" + "f" * 32
        assert_rejected(self, json.dumps(changed), "replica URI incarnation mismatch")
        changed = copy.deepcopy(self.policy)
        slot = next(x for x in changed["replica_slots"] if x["slot_id"] == 7)
        slot["incarnation_id"] = "404142434445464748494a4b4c4d4e4f"
        assert_rejected(self, json.dumps(changed), "slot incarnation and replica URI mismatch")
        changed = copy.deepcopy(self.policy)
        authority(changed)["uri"] = "spiffe://rateguard.local/authority/" + "f" * 32
        assert_rejected(self, json.dumps(changed), "authority URI mismatch")
        changed = copy.deepcopy(self.policy)
        adapter(changed)["uri"] = "spiffe://other.local/adapter/ingress1"
        assert_rejected(self, json.dumps(changed), "adapter URI mismatch")
        changed = copy.deepcopy(self.policy)
        replica(changed, 7)["slot_id"] = 7.0
        assert_rejected(self, json.dumps(changed), "float replica slot id")
        changed = copy.deepcopy(self.policy)
        replica(changed, 7)["slot_id"] = True
        assert_rejected(self, json.dumps(changed), "boolean replica slot id")
        changed = copy.deepcopy(self.policy)
        changed["tenants"][0]["unknown"] = 1
        assert_rejected(self, json.dumps(changed), "unknown nested field")
        changed = copy.deepcopy(self.policy)
        changed["principals"].append(copy.deepcopy(changed["principals"][0]))
        assert_rejected(self, json.dumps(changed), "duplicate principal URI")
        changed = copy.deepcopy(self.policy)
        adapter(changed)["permissions"].append(copy.deepcopy(adapter(changed)["permissions"][0]))
        assert_rejected(self, json.dumps(changed), "duplicate permission")
        changed = copy.deepcopy(self.policy)
        changed["tenants"].append(copy.deepcopy(changed["tenants"][0]))
        assert_rejected(self, json.dumps(changed), "duplicate tenant")

    def test_rejects_strict_credit_q_presence_mismatch_and_depth_limit(self) -> None:
        strict_with_q = copy.deepcopy(self.policy)
        strict_with_q["mode"] = "strict"
        assert_rejected(self, json.dumps(strict_with_q), "strict tenant has credit batch")
        credit_without_q = copy.deepcopy(self.policy)
        for tenant in credit_without_q["tenants"]:
            del tenant["credit_batch_units"]
        assert_rejected(self, json.dumps(credit_without_q), "credit tenant missing batch")
        too_deep = '{"outer":' * 34 + '0' + '}' * 34
        assert_rejected(self, too_deep, "excessive nesting")


if __name__ == "__main__":
    unittest.main()
