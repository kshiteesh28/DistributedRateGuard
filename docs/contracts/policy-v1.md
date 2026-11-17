# Canonical policy v1 — implementation decision record

**Revision:** 1 · **Date:** 2026-11-12 · **Decision owner:** Master technical lead  
**Status:** Frozen for RG-002 implementation and independent verification.  
**Sources:** PRD 8; SRD 5 D3/D6/D9; LLD 5 §§4,5,16.4,17. This fixes representation/startup limits, not a new quota algorithm or release gate.

## Accepted decisions

An epoch has one immutable mode (strict or credit), authority incarnation, trust-root fingerprint and registered replica set. Tenant buckets initialize **full B**, already specified by LLD §5; there is no configurable initial-balance override. Replay initial state is a separate artifact.

Slot IDs are unique uint32 identities, with at most eight entries; they need not be contiguous or zero-based. Policy/transport compares configured membership and exact incarnation. The CA root is bound by SHA-256 of its DER certificate, not PEM formatting or private material. RG-004 must verify the actual CA matches this fingerprint before readiness.

The loader accepts table/object order variation and sorts validated records for encoding. It rejects duplicates rather than overwriting or silently collapsing them. JSON uint64 values are canonical decimal **strings** and never pass through floating point.

## Bounds and startup rejection

Existing limits remain: 1..10,000 tenants, 1..8 registered replica slots, identifier length 1..128 ASCII [A-Za-z0-9_.-], B/r 1..10^9, operation cost 1..B, and credit Q between maximum operation cost and B. Every tenant has at least one operation.

Additional finite v1 implementation limits are: 64 operations/tenant; 100,000 operations total; 10,000 principals; 100,000 permission pairs total; 256 ASCII bytes per principal URI; 64 MiB JSON input and canonical output; JSON nesting depth 32. These are independent ceilings, not a promise that every maximum-sized combination fits. Exceeding any limit rejects configuration before epoch readiness or quota-state creation. The values cover the frozen benchmark policies while bounding parser/registry memory. Raising them requires explicit configuration-schema review and new boundary evidence.

## JSON schema

All listed fields are required except credit_batch_units (required only in credit mode) and principal slot_id (required only for replica role). Unknown fields, duplicate keys, float/bool integer fields, trailing non-whitespace data and unsupported schema versions reject the whole input.

```text
root: schema_version=1, mode="strict"|"credit", epoch_id,
      authority_incarnation, trust_root_sha256,
      replica_slots[], tenants[], principals[]
slot: slot_id (JSON uint32 integer), incarnation_id
tenant: tenant_id, capacity_units, rate_units_per_second,
        [credit_batch_units], operations[]
operation: operation_id, cost_units
principal: uri, role="adapter"|"replica"|"authority", [slot_id],
           permissions[]
permission: tenant_id, operation_id
```

Epoch/incarnation fields are exactly 32 lowercase hexadecimal characters (16 bytes); root fingerprint is 64 lowercase hexadecimal characters (32 bytes). All uint64 fields are decimal strings matching 0|[1-9][0-9]*, then range checked. schema_version and slot_id are nonnegative JSON integers, with no float conversion.

Principal URIs follow the accepted A-02 identities:
- adapter: spiffe://rateguard.local/adapter/<identifier>
- replica: spiffe://rateguard.local/replica/<decimal-slot-id>/<lowercase-incarnation-hex>
- authority: spiffe://rateguard.local/authority/<lowercase-authority-incarnation-hex>

Require at least one adapter, exactly one authority, and exactly one replica principal per registered slot. Replica URI, slot_id and incarnation must agree. Authority URI must match the root authority incarnation. URI identities are unique and compare exactly. Adapter/replica permissions reference existing tenant/operation pairs and may be empty (deny all); authority permissions must be empty. Each principal has one role. Supervisor Unix peer-credential identity is manifest-owned, not an invented mTLS principal role.

Strict tenants omit credit_batch_units; credit tenants provide it. Strict-mode replicas still have inventory/identity records, but no local quota credits.

## Canonical bytes

Unsigned integers are big-endian fixed-width values. str means u32 byte length followed by ASCII bytes. The digest is SHA-256 of all bytes below; the digest is not embedded in the input.

```text
u32 schema_version (=1)
u32 mode (STRICT=1, CREDIT=2)
16 bytes epoch_id
16 bytes authority_incarnation
32 bytes trust_root_sha256
u32 slot_count
  slots sorted by numeric slot_id:
    u32 slot_id; 16 bytes incarnation_id
u32 tenant_count
  tenants sorted by ASCII tenant_id:
    str tenant_id; u64 capacity_units; u64 rate_units_per_second
    u8 q_present (0 strict, 1 credit); [u64 credit_batch_units if 1]
    u32 operation_count
      operations sorted by ASCII operation_id:
        str operation_id; u64 cost_units
u32 principal_count
  principals sorted by ASCII uri:
    str uri; u32 role (ADAPTER=1, REPLICA=2, AUTHORITY=3)
    [u32 slot_id only for replica]
    u32 permission_count
      permissions sorted by (tenant_id, operation_id):
        u32 tenant_index; u32 operation_index
```

Indices are zero-based positions in the canonical tenant table and that tenant's canonical operation table. JSON supplies names, never indices. All lengths/counts and output growth are checked before appending; no narrowing/wrap is permitted. Permissions and IDs are checked before producing bytes or a digest. Immutable snapshots preserve ownership for returned views and never create entries for unknown lookups.

The current implementation only needs JSON loading plus Encode/Digest. A future binary decoder must reject noncanonical order, unsupported versions, truncation and trailing bytes; no decoder or extension support is claimed here. New policy fields require a new canonical schema version.

## Required independent evidence

A separate Python encoder computes aggregate golden bytes and SHA-256 from the JSON schema; it must not call the C++ codec. Verify order invariance, each identity/authorization/quota field's effect on the digest, duplicate/unknown references, slot/incarnation/URI mismatch, strict/credit Q presence, numeric boundaries, resource caps, malformed/deep input and fail-closed crypto errors. This record does not claim those checks or the policy implementation already exist.
