# Strict history inspection

Source contracts are PRD revision 8, SRD revision 5 (FR-009), HLD revision 4 and LLD revision 5 §16. The executable extends the existing RG-005 component.

This RG-005 increment exposes the existing version-1 binary reader as an offline command. It supports FR-009 evidence diagnosis. The tool reports structural evidence only; semantic quota and clock-provenance validation remain RG-011A work.

## Invocation and input

The executable is `rateguard_history_inspect PLAN.json HISTORY.bin`. Build it with `cmake --build build --target rateguard_history_inspect` after the repository's standard CMake configuration. Run `build/rateguard_history_inspect PLAN.json HISTORY.bin`. Both paths must be supplied explicitly. The plan comes from the trusted run configuration, independently of the history being inspected. The tool never derives its expected plan from history bytes.

The plan is a JSON object with exactly these fields.

```json
{
  "schema_version": 1,
  "epoch_id": "00000000000000000000000000000001",
  "policy_digest": "0000000000000000000000000000000000000000000000000000000000000002",
  "budget_bytes": "4096",
  "producers": [
    {"producer_owner": 2, "producer_index": 0, "event_capacity": "2"}
  ]
}
```

Epoch and policy identifiers use exact-length lowercase hexadecimal. Owner is an integer from 1 through 5, following the recorder's registered owner enum. Producer index is a uint32 JSON integer. Capacity and byte budget use canonical decimal-string uint64 values, as specified for artifacts in LLD §16. Duplicate keys, unknown fields, duplicate producer identities, floating-point integers and unsupported schemas fail validation.

The CLI limits plan input to 1 MiB before JSON parsing. This bounds this tool's configuration input. It adds no product tenant or participant limit. The existing reader checks plan arithmetic, run ceiling, expected roster, seals, checksums and complete binary extent. A plan reaching 1 GiB is invalid under the existing D6 contract.

## Results and lifecycle

Successful structural validation returns machine-readable JSON with schema version, complete status and published-event count. Its safety verdict is UNKNOWN. Missing files, malformed plans, truncated/corrupt histories and trailing bytes return a nonzero process status with an explicit diagnostic.

This command reads existing artifacts. Service shutdown, output publication, retention invocation, incomplete-run summaries and semantic release acceptance remain separate runtime work. See [RG-005 evidence](../evidence/RG-005.md).
