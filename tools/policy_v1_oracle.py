"""Independent policy-v1 canonical encoder.

This is an oracle derived from docs/contracts/policy-v1.md, not a wrapper around
or shared implementation with the C++ codec. It handles the frozen valid JSON
fixture so its bytes and digest can be compared directly with production output.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
HEX16_RE = re.compile(r"[0-9a-f]{32}\Z")
HEX32_RE = re.compile(r"[0-9a-f]{64}\Z")
ROLE_VALUE = {"adapter": 1, "replica": 2, "authority": 3}


def u8(value: int) -> bytes:
    if not 0 <= value <= 0xff:
        raise ValueError("u8 out of range")
    return struct.pack(">B", value)


def u32(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= U32_MAX:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def decimal_u64(value: Any) -> int:
    if not isinstance(value, str) or not DECIMAL_RE.fullmatch(value):
        raise ValueError("uint64 must be canonical decimal text")
    result = int(value)
    if result > U64_MAX:
        raise ValueError("uint64 out of range")
    return result


def u64_decimal(value: Any) -> bytes:
    return struct.pack(">Q", decimal_u64(value))


def ascii_string(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected string")
    encoded = value.encode("ascii")
    if len(encoded) > U32_MAX:
        raise ValueError("string too long")
    return u32(len(encoded)) + encoded


def fixed_hex(value: Any, regex: re.Pattern[str]) -> bytes:
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise ValueError("invalid lower-case fixed-width hex")
    return bytes.fromhex(value)


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"invalid identifier: {value!r}")
    return value


def bounded_policy_units(value: Any) -> bytes:
    numeric = decimal_u64(value)
    if not 1 <= numeric <= 1_000_000_000:
        raise ValueError("policy units outside 1..1e9")
    return struct.pack(">Q", numeric)


def encode_policy(policy: dict[str, Any]) -> bytes:
    """Encode a valid schema-v1 policy in canonical byte order."""
    schema_version = policy["schema_version"]
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError("unsupported schema version")
    mode = policy["mode"]
    if mode not in ("strict", "credit"):
        raise ValueError("unsupported mode")

    epoch = fixed_hex(policy["epoch_id"], HEX16_RE)
    authority_incarnation = fixed_hex(policy["authority_incarnation"], HEX16_RE)
    trust_root = fixed_hex(policy["trust_root_sha256"], HEX32_RE)

    slots = sorted(policy["replica_slots"], key=lambda slot: slot["slot_id"])
    slot_rows: list[bytes] = []
    slot_ids: set[int] = set()
    slot_incarnations: dict[int, str] = {}
    for slot in slots:
        slot_id = slot["slot_id"]
        if isinstance(slot_id, bool) or not isinstance(slot_id, int) or not 0 <= slot_id <= U32_MAX:
            raise ValueError("slot_id is not uint32")
        if slot_id in slot_ids:
            raise ValueError("duplicate slot")
        incarnation = fixed_hex(slot["incarnation_id"], HEX16_RE)
        slot_ids.add(slot_id)
        slot_incarnations[slot_id] = slot["incarnation_id"]
        slot_rows.append(u32(slot_id) + incarnation)

    tenants = sorted(policy["tenants"], key=lambda tenant: identifier(tenant["tenant_id"]).encode("ascii"))
    if not 1 <= len(tenants) <= 10_000:
        raise ValueError("tenant count outside limit")
    tenant_indices: dict[str, int] = {}
    operation_indices: dict[tuple[str, str], int] = {}
    tenant_rows: list[bytes] = []
    for tenant_index, tenant in enumerate(tenants):
        tenant_id = identifier(tenant["tenant_id"])
        if tenant_id in tenant_indices:
            raise ValueError("duplicate tenant")
        tenant_indices[tenant_id] = tenant_index
        capacity = decimal_u64(tenant["capacity_units"])
        rate = decimal_u64(tenant["rate_units_per_second"])
        if not 1 <= capacity <= 1_000_000_000 or not 1 <= rate <= 1_000_000_000:
            raise ValueError("tenant capacity/rate out of bounds")
        operations = sorted(tenant["operations"],
                            key=lambda operation: identifier(operation["operation_id"]).encode("ascii"))
        if not 1 <= len(operations) <= 64:
            raise ValueError("operation count outside limit")
        operation_rows: list[bytes] = []
        max_cost = 0
        for operation_index, operation in enumerate(operations):
            operation_id = identifier(operation["operation_id"])
            key = (tenant_id, operation_id)
            if key in operation_indices:
                raise ValueError("duplicate operation")
            operation_indices[key] = operation_index
            cost = decimal_u64(operation["cost_units"])
            if not 1 <= cost <= capacity:
                raise ValueError("operation cost out of bounds")
            max_cost = max(max_cost, cost)
            operation_rows.append(ascii_string(operation_id) + struct.pack(">Q", cost))

        has_q = mode == "credit"
        if has_q != ("credit_batch_units" in tenant):
            raise ValueError("credit_batch_units presence disagrees with mode")
        if has_q:
            q = decimal_u64(tenant["credit_batch_units"])
            if not max_cost <= q <= capacity:
                raise ValueError("credit batch outside max operation cost..capacity")
        encoded_tenant = (ascii_string(tenant_id) +
                          struct.pack(">Q", capacity) +
                          struct.pack(">Q", rate) +
                          u8(1 if has_q else 0))
        if has_q:
            encoded_tenant += struct.pack(">Q", q)
        tenant_rows.append(encoded_tenant + u32(len(operation_rows)) + b"".join(operation_rows))

    principals = sorted(policy["principals"], key=lambda principal: principal["uri"].encode("ascii"))
    uris: set[str] = set()
    authorities = 0
    adapters = 0
    replica_slots: set[int] = set()
    principal_rows: list[bytes] = []
    for principal in principals:
        uri = principal["uri"]
        uri_bytes = uri.encode("ascii")
        if uri in uris:
            raise ValueError("duplicate principal URI")
        uris.add(uri)
        role_name = principal["role"]
        if role_name not in ROLE_VALUE:
            raise ValueError("unknown principal role")
        role = ROLE_VALUE[role_name]
        expected_slot = None
        if role_name == "adapter":
            adapters += 1
            if not uri.startswith("spiffe://rateguard.local/adapter/"):
                raise ValueError("adapter URI mismatch")
            identifier(uri.rsplit("/", 1)[-1])
        elif role_name == "authority":
            authorities += 1
            expected_uri = ("spiffe://rateguard.local/authority/" +
                            policy["authority_incarnation"])
            if uri != expected_uri or principal.get("permissions", []):
                raise ValueError("authority URI/permissions mismatch")
        else:
            expected_slot = principal.get("slot_id")
            if expected_slot not in slot_ids or expected_slot in replica_slots:
                raise ValueError("replica slot absent or duplicate")
            replica_slots.add(expected_slot)
            incarnation = slot_incarnations[expected_slot]
            expected_uri = (f"spiffe://rateguard.local/replica/{expected_slot}/{incarnation}")
            if uri != expected_uri:
                raise ValueError("replica URI and slot incarnation disagree")

        permissions = []
        for permission in principal.get("permissions", []):
            key = (identifier(permission["tenant_id"]),
                   identifier(permission["operation_id"]))
            if key not in operation_indices:
                raise ValueError("permission references unknown tenant/operation")
            permissions.append((key, tenant_indices[key[0]], operation_indices[key]))
        permissions.sort(key=lambda item: (item[0][0].encode("ascii"), item[0][1].encode("ascii")))
        if len({item[0] for item in permissions}) != len(permissions):
            raise ValueError("duplicate permission")
        row = ascii_string(uri) + u32(role)
        if role_name == "replica":
            row += u32(expected_slot)
        row += u32(len(permissions))
        row += b"".join(u32(tenant_i) + u32(operation_i)
                        for _, tenant_i, operation_i in permissions)
        principal_rows.append(row)

    if adapters < 1 or authorities != 1 or replica_slots != slot_ids:
        raise ValueError("principal inventory incomplete or invalid")

    return (u32(1) + u32(1 if mode == "strict" else 2) +
            epoch + authority_incarnation + trust_root +
            u32(len(slot_rows)) + b"".join(slot_rows) +
            u32(len(tenant_rows)) + b"".join(tenant_rows) +
            u32(len(principal_rows)) + b"".join(principal_rows))


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(policy: dict[str, Any]) -> str:
    return hashlib.sha256(encode_policy(policy)).hexdigest()
