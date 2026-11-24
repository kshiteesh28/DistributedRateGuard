# Epoch artifact layout v1

**Status:** Selected implementation layout; integration in progress. Sources: PRD 8 / SRD 5, HLD 5 A-03 and LLD 8 §21. These choices preserve product behavior and release gates.

## Directory contract

```text
<configured runtime root>/
  owner.lock
  runtime-anchor.json
  epoch-<32 lowercase hexadecimal digits>/
    intent.json
    manifest-store/                 # optional until manifest creation
      owner.lock                    # empty
      manifest.json
```

Epoch IDs are nonzero. Shared `epoch_layout_v1` constants and checked parse/format helpers define these exact names. Helpers do not access the filesystem or confer ownership. Root ownership remains RuntimeOwner's responsibility.

BootstrapStore creates the epoch directory and durable intent before process start. ManifestStore creates a separate, new `manifest-store` directory after the complete observed candidate is available. It does not initialize over an existing directory or adopt an existing ACTIVE epoch. Creation/phase persistence remain separate transitions; this layout does not make them one transaction.

Witness/journal and recovery-operation artifacts are not yet recognized. Their paths and validators must be added before those modules are integrated. An unknown directory is never accepted merely because a future feature might use it.

## Recovery interpretation

The recovery reader independently examines the bootstrap intent and optional manifest store. A missing manifest directory is valid for a bootstrap-only structural scan and proves no activation state. If a manifest directory was observed, missing or changed contents are uncertainty.

The manifest directory must be owned/private 0700. Its only accepted entries are an empty, owned regular single-link 0600 `owner.lock` and an owned regular single-link 0600 `manifest.json`. Known files are opened no-follow/nonblocking. `manifest.tmp`, `intent.tmp`, unknown entries, unsafe types, wrong modes, nonempty locks, missing files and detected mutations make the scan incomplete. Safely readable known artifacts remain diagnostic evidence.

A manifest is decoded by the existing canonical schema/checksum codec within its 4 MiB limit. The reader never calls writable store reopening or acquires a serving capability. It retains a safely decoded immutable manifest even when the intent is missing, corrupt or inconsistent, where other budgets permit.

A matching manifest requires the exact complete BootstrapInventory ReadyCandidate, including epoch, authority incarnation, policy digest, common clock provenance and every participant identity. Canonical ordering in both codecs is role, participant ID and slot. Missing/incomplete comparison data or a difference makes the scan incomplete. All manifest phases—Prepared, Active, Draining and Closed—are metadata only. CLOSED is not independent process-exit evidence.

Historical clock/boot provenance is retained. Checksums are corruption checks, not authentication, rollback freshness or proof of prior fsync completion. No scan result permits adoption, stop, reset or successor activation.

## Bounded evidence and consistency

Root and epoch entry caps remain 4,096 and 16. The manifest-store entry cap is also 16. Epoch count remains 1,024; global/per-epoch issue caps remain 256/16, with explicit truncation and incomplete output.

All attempted intent and manifest sizes consume the same 64 MiB input budget before allocation/read. Failed reads/decodes never refund it. Both retained bootstrap and manifest participant records consume the same 16,384-record budget, including matching duplicated representations, because both models occupy memory.

Matching records in two artifacts within one epoch are expected representations, not cross-epoch collisions. Duplicate container/process identities across epoch directories remain conflicts. Inconsistent same-epoch candidate data is also incomplete; never select the latest artifact or silently replace one with the other.

Validate directory, lock and manifest identities, owner UID/link count/mode/size/time metadata and bounded entry listings around reads. Validate epoch/root ownership again. This detects observed changes, not an atomic filesystem snapshot or hostile same-UID mutation.

## Verification and remaining work

Keep all bootstrap-only reader tests. Add independent matching-phase, incomplete/mismatched-candidate, missing/corrupt intent with readable manifest, file-type/mode/link, unknown/temp/missing entry, nested-limit, mutation and shared-budget cases. Pure grammar/name tests cover lowercase/nonzero canonical IDs and round trips. Require pinned real Linux/OpenSSL clean builds and sanitizers before integration acceptance.

Real Docker/OS control, pending-identity stop targets, durable recovery orchestration, authenticated readiness/activation, witness integration and verified successor-epoch authorization remain separate requirements. This layout does not implement or prove them.
