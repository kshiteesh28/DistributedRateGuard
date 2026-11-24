# Bootstrap recovery reader v1

**Status:** Proposed RG-006 component contract, 2026-11-23. Sources: PRD 8 / SRD 5, HLD 5 A-03, LLD 7 §21. This contract supplies the bounded read-only reader needed by the future EpochSupervisor recovery path. It does not complete that path.

## Boundary and result

`BootstrapRecoveryReader::Read(const RuntimeOwner&, IRecoveryReaderIo*)` requires validated RecoveryRequired-mode root ownership. Fresh ownership, invalid ownership or inability to obtain the root descriptor returns a typed fatal result. Other uncertainty is represented in an immutable shared diagnostic snapshot where possible; allocation failure is fatal and implies unknown evidence.

The snapshot binds the runtime domain and contains per-epoch decoded inventories, canonical digests, file/directory identity evidence and typed issues. It includes every planned container in a securely decoded inventory, including entries without a recorded PID/start identity. Persisted historical clock/boot provenance is retained; recovery decoding does not require it to match the current host boot.

`scan_complete` means only that the bounded scan was structurally stable and all examined artifacts were valid. It does not prove past fsync completion, activation state, current process identity, cessation, absence of rollback or permission to stop, serve, reset or create a successor. No candidate, claim or fencing token is returned. Empty/no-valid-intent scans are incomplete.

## Scan and validation

1. Validate owner mode/domain/identity, duplicate a CLOEXEC root descriptor, and enumerate all root names, not merely a chosen latest epoch.
2. Check exact `epoch-<32 lowercase hex digits>` directories. The root's ownership anchor/lock are validated by RuntimeOwner. Unknown entries, noncanonical epoch names, unsafe types or resource exhaustion make the snapshot incomplete.
3. Inspect every bounded epoch-directory entry. Open only no-follow, nonblocking descriptors. Directories must be private owned directories; `intent.json` must be an owned regular 0600 single-link bounded file. Missing, special, symlinked, hard-linked or substituted artifacts are errors.
4. Decode with the existing bounded canonical schema/checksum codec. Bind payload domain to owner domain and epoch to the directory basename. Preserve every safe sibling inventory even when another child is bad. Unknown/temp child artifacts make the scan incomplete; they are not silently interpreted as an empty or trusted inventory.
5. Revalidate entry/file/directory identities, relevant size/mode/mtime/ctime metadata, and root/child entry snapshots before returning. Validate owner again. A detected change makes evidence incomplete. These checks narrow races; they are not an atomic filesystem snapshot and do not protect against a hostile same-UID writer.
6. Report duplicate container identities across decoded epochs as conflicts; never select the newest epoch or silently merge conflicting identities. Recovery-required inventories remain diagnostic and keep the scan incomplete.

No directory/file mutation, removal, repair, fsync, process action or store adoption occurs. Raw arbitrary filesystem names and file contents are excluded from diagnostics; directory names are canonical known epoch names or empty.

## Finite implementation limits

| Resource | Limit / overflow |
| --- | --- |
| Each intent | Existing 4 MiB codec cap; reject before allocation/read |
| All root entries | 4,096 excluding dot entries; incomplete on overflow |
| All entries per epoch child | 16; incomplete on overflow |
| Epoch directories | 1,024; incomplete on overflow |
| Aggregate attempted input | 64 MiB; reserve file-size budget before reading, including failed reads/decodes; never refund it |
| Retained participants | 16,384 across inventories; incomplete on overflow |
| Global/per-epoch issues | 256 / 16; nonallocating truncation flags always force incomplete |

These are reader implementation bounds, not amended SRD deployment or quota limits. At any limit, preserve previously collected known records and expose uncertainty; no overflow permits reset.

## Verification and remaining gates

Independent developer and tester suites must exercise pending and complete inventories, historical provenance, fresh-owner rejection, empty/missing/unknown artifacts, temp siblings, malformed/digest/domain/name mismatches, file types/permissions, detected races, duplicate identities and resource bounds. Tests must remain active under NDEBUG. Repeat-read results must be stable without changing files.

Real pinned Linux/OpenSSL and sanitizer evidence is required before component acceptance. Local digest shims are smoke only. Actual controller inspection/stop, authenticated participant readiness, full recovery orchestration and a verified successor-epoch authorization remain unimplemented integration requirements. Incomplete inventory blocks reset pending reconciliation or the source contracts' controlled complete-VM shutdown evidence.
