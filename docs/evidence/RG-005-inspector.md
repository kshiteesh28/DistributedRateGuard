# RG-005 history inspector evidence

This component extends [RG-005](RG-005.md) with an offline inspection command. PR #15 targets the integration feature. Full RG-005 runtime acceptance remains open.

## Behavior

Build target `rateguard_history_inspect` accepts `PLAN.json HISTORY.bin`. The independently supplied plan has the [versioned contract](../contracts/history-inspector.md). Parsing rejects duplicate or unknown keys, unsupported schema, floating-point integers, invalid decimal-string uint64 fields, bad identifiers, duplicate producers and checked-size overflow. The 1 MiB plan-input limit is CLI-specific.

The command reuses the existing binary reader and structural validator. Success reports structural completeness and a safety verdict of UNKNOWN. Error output uses bounded error codes; it does not echo input contents. Exit status is nonzero on invalid evidence.

## Verification

Junior developer built the CLI with strict C++20 Clang warnings and wrote a Python end-to-end fixture that independently encodes event, seal and run checksums. The driver exercises a valid multi-producer history, roster-order differences, malformed/duplicate/unknown JSON, floats, oversized plans, missing/corrupt/truncated/trailing history and aggregate extent overflow.

Root independently built the current source with ASan/UBSan and ran the driver successfully. Root also checked an independently constructed empty sealed history. Tester independently rebuilt and ran the driver, then verified escaped duplicate JSON keys and diagnostic redaction using sentinel input. No findings remain from these component checks.

Root review corrected owned diagnostic lifetimes, checked aggregate arithmetic, the `producer_owner` field and failed-output handling before publication. Source implementation and tests are separate GitHub commits.

## Remaining scope

The inspector does not supply actual clock/commit provenance or semantic quota validation. Those remain RG-011A work. Service recording, stop propagation, retention invocation and incomplete-run persistence still need runtime integration.

## Linux CI

Pending observation for the current review-branch source. Local checks are scoped above.
