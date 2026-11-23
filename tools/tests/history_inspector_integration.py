#!/usr/bin/env python3
"""Independent end-to-end fixture for the offline history inspector."""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

MASK64 = (1 << 64) - 1
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211


def u8(value):
    return struct.pack(">B", value)


def u32(value):
    return struct.pack(">I", value)


def u64(value):
    return struct.pack(">Q", value)


def fnv(data):
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & MASK64
    return value


def make_history():
    epoch = bytes.fromhex("00112233445566778899aabbccddeeff")
    policy_digest = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff"
    )
    # owner, stage, outcome: every strict Release A producer role is represented.
    producers = [
        (1, 1, 0),  # generator / offered
        (2, 2, 1),  # authority / strict decision
        (3, 3, 1),  # replica / response
        (4, 4, 1),  # adapter / received
        (5, 6, 1),  # backend / completed
    ]
    planned_bytes = 80 + 17 + len(producers) * (13 + 51 + 26)
    budget_bytes = planned_bytes
    producer_rows = []
    for owner, stage, outcome in producers:
        attempt_id = bytes([owner]) * 16
        timestamp = owner * 100
        cost = 1
        event = (b"RGEV1" + u8(stage) + u8(outcome) + attempt_id
                 + u64(timestamp) + u64(cost))
        event_checksum = fnv(event)
        slot = {
            "status": 2,
            "sequence": 1,
            "stage": stage,
            "outcome": outcome,
            "attempt_id": attempt_id,
            "timestamp": timestamp,
            "cost": cost,
            "checksum": event_checksum,
        }
        seal = (b"RGPS1" + u8(owner) + u32(0) + u64(1) + u64(1) + u64(1)
                + u8(1) + u8(0) + u8(slot["status"]) + u64(slot["sequence"])
                + u64(event_checksum))
        producer_rows.append({
            "owner": owner,
            "index": 0,
            "capacity": 1,
            "slot": slot,
            "seal_checksum": fnv(seal),
        })

    run_data = (b"RGRN1" + u32(1) + epoch + policy_digest + u32(len(producers))
                + u64(planned_bytes) + u64(budget_bytes))
    for producer in producer_rows:
        run_data += (u8(producer["owner"]) + u32(producer["index"])
                     + u64(producer["capacity"]) + u64(producer["seal_checksum"]))
    run_checksum = fnv(run_data + u8(1))

    output = bytearray(b"RGHIST01")
    output += u32(1) + epoch + policy_digest + u32(len(producers))
    output += u64(planned_bytes) + u64(budget_bytes)
    for producer in producer_rows:
        slot = producer["slot"]
        output += u8(producer["owner"]) + u32(producer["index"])
        output += u64(producer["capacity"])
        output += (u8(slot["status"]) + u64(slot["sequence"]) + u8(slot["stage"])
                   + u8(slot["outcome"]) + slot["attempt_id"] + u64(slot["timestamp"])
                   + u64(slot["cost"]) + u64(slot["checksum"]))
        output += (u8(1) + u8(0) + u64(1) + u64(1)
                   + u64(producer["seal_checksum"]))
    output += u8(1) + u64(planned_bytes) + u64(run_checksum)

    plan = {
        "schema_version": 1,
        "epoch_id": epoch.hex(),
        "policy_digest": policy_digest.hex(),
        "budget_bytes": str(budget_bytes),
        # Deliberately unsorted: inspector must bind the roster independent of input order.
        "producers": [
            {"producer_owner": owner, "producer_index": 0, "event_capacity": "1"}
            for owner, _stage, _outcome in reversed(producers)
        ],
    }
    return plan, bytes(output)


def invoke(binary, plan_path, history_path):
    result = subprocess.run(
        [str(binary), str(plan_path), str(history_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.stderr:
        raise AssertionError(f"unexpected stderr: {result.stderr!r}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"non-JSON output: {result.stdout!r}") from exc
    return result.returncode, payload


def expect_error(binary, plan_path, history_path, expected):
    code, payload = invoke(binary, plan_path, history_path)
    assert code != 0, (expected, payload)
    assert payload["status"] == "error", payload
    assert payload["error"] == expected, (expected, payload)
    assert payload["safety_verdict"] == "UNKNOWN", payload


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: history_inspector_integration.py INSPECTOR_BINARY")
    binary = pathlib.Path(sys.argv[1]).resolve()
    assert binary.is_file() and binary.stat().st_mode & 0o111, binary

    plan, good_history = make_history()
    with tempfile.TemporaryDirectory(prefix="rateguard-history-inspect-") as tmp:
        root = pathlib.Path(tmp)
        plan_path = root / "plan.json"
        history_path = root / "history.bin"
        plan_path.write_text(json.dumps(plan, separators=(",", ":")), encoding="utf-8")
        history_path.write_bytes(good_history)

        code, payload = invoke(binary, plan_path, history_path)
        assert code == 0, payload
        assert payload["status"] == "structurally_complete", payload
        assert payload["safety_verdict"] == "UNKNOWN", payload
        assert payload["event_count"] == "5", payload
        assert payload["history_bytes"] == str(len(good_history)), payload
        assert payload["budget_bytes"] == str(plan["budget_bytes"]), payload

        missing_history = root / "missing.bin"
        expect_error(binary, plan_path, missing_history, "history_file_unavailable")

        corrupt = bytearray(good_history)
        corrupt[-1] ^= 1
        history_path.write_bytes(corrupt)
        expect_error(binary, plan_path, history_path, "history_incomplete")

        history_path.write_bytes(good_history[:-1])
        expect_error(binary, plan_path, history_path, "history_size_mismatch")

        history_path.write_bytes(good_history + b"\x00")
        expect_error(binary, plan_path, history_path, "history_size_mismatch")

        history_path.write_bytes(good_history)
        plan_path.write_text(
            '{"schema_version":1,"schema_version":1,'
            '"epoch_id":"' + plan["epoch_id"] + '",'
            '"policy_digest":"' + plan["policy_digest"] + '",'
            '"budget_bytes":"' + plan["budget_bytes"] + '","producers":[]}',
            encoding="utf-8",
        )
        expect_error(binary, plan_path, history_path, "json_duplicate_key")

        plan_path.write_text(json.dumps({**plan, "unexpected": 1}), encoding="utf-8")
        expect_error(binary, plan_path, history_path, "plan_unknown_key")

        float_plan = dict(plan)
        float_plan["schema_version"] = 1.0
        plan_path.write_text(json.dumps(float_plan), encoding="utf-8")
        expect_error(binary, plan_path, history_path, "json_float")

        plan_path.write_bytes(b"{" + b" " * (1024 * 1024))
        expect_error(binary, plan_path, history_path, "plan_too_large")

        # Each producer extent fits uint64 individually, but their sum does not.
        # This guards against unsigned subtraction underflow during accumulation.
        overflow_plan = {
            "schema_version": 1,
            "epoch_id": plan["epoch_id"],
            "policy_digest": plan["policy_digest"],
            "budget_bytes": str((1 << 30) - 1),
            "producers": [
                {"producer_owner": owner, "producer_index": 0,
                 "event_capacity": "190000000000000000"}
                for owner in (1, 2)
            ],
        }
        plan_path.write_text(json.dumps(overflow_plan), encoding="utf-8")
        expect_error(binary, plan_path, history_path, "plan_extent_overflow")

    print("history inspector integration cases passed")


if __name__ == "__main__":
    main()
