from __future__ import annotations

import copy
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_v1_oracle import digest, encode_policy, load_fixture  # noqa: E402

FIXTURE = Path(os.environ.get(
    "RATEGUARD_POLICY_FIXTURE",
    str(Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "policy_v1.json")))
EXPECTED_LENGTH = 580
EXPECTED_SHA256 = "0fa75c3373b71fc7c21ce0417258ea6545986d884c69c16f2ee8d6d9fefe00ff"


class IndependentPolicyOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not FIXTURE.is_file():
            raise FileNotFoundError(f"aggregate policy fixture missing: {FIXTURE}")
        cls.policy = load_fixture(FIXTURE)
        cls.encoded = encode_policy(cls.policy)

    def test_frozen_aggregate_golden(self) -> None:
        self.assertEqual(len(self.encoded), EXPECTED_LENGTH)
        self.assertEqual(digest(self.policy), EXPECTED_SHA256)

    def test_input_table_order_does_not_change_canonical_bytes(self) -> None:
        changed = copy.deepcopy(self.policy)
        changed["replica_slots"].reverse()
        changed["tenants"].reverse()
        changed["principals"].reverse()
        for tenant in changed["tenants"]:
            tenant["operations"].reverse()
        next(p for p in changed["principals"] if p["role"] == "adapter")["permissions"].reverse()
        self.assertEqual(encode_policy(changed), self.encoded)

    def test_identity_quota_and_permission_changes_affect_digest(self) -> None:
        variations = []

        def alter(name, path, value):
            candidate = copy.deepcopy(self.policy)
            target = candidate
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            variations.append((name, candidate))

        alter("epoch", ["epoch_id"], "100102030405060708090a0b0c0d0e0f")
        alter("trust root", ["trust_root_sha256"],
              "0ee742f3d97b519e6b7a8ee84b88b019cea856aadcd44d0dc2ac113852a6432f")
        alter("tenant capacity", ["tenants", 0, "capacity_units"], "21")
        alter("tenant rate", ["tenants", 0, "rate_units_per_second"], "4")
        alter("credit batch", ["tenants", 0, "credit_batch_units"], "7")
        alter("operation cost", ["tenants", 0, "operations", 0, "cost_units"], "3")
        alter("adapter URI", ["principals", 1, "uri"],
              "spiffe://rateguard.local/adapter/ingress2")
        permission_change = copy.deepcopy(self.policy)
        permission_change["principals"][1]["permissions"][0] = {
            "tenant_id": "alpha", "operation_id": "write"}
        variations.append(("permission", permission_change))

        for label, candidate in variations:
            with self.subTest(field=label):
                self.assertNotEqual(digest(candidate), EXPECTED_SHA256)


if __name__ == "__main__":
    unittest.main()
