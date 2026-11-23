# Durable epoch manifest store

Source contracts are PRD 8 (PRD-007/024/025), SRD 5 (FR-008/022 and D5), and LLD 5 §8/A-03. This RG-006 increment implements local manifest serialization, atomic replacement and exclusive ownership of one configured store directory. Full supervisor and process-controller acceptance remains open.

## Persisted record

Schema 1 contains one immutable epoch candidate, a PREPARED/ACTIVE/DRAINING/CLOSED phase, a positive non-wrapping uint64 generation and a nonzero transition operation ID. The epoch candidate reuses the existing gate inventory and clock identity types. Participants are sorted by role and participant ID. Artifact uint64 values use canonical decimal strings; signed clock offsets use signed canonical decimal strings. Required keys and encodings are versioned and strict.

The JSON envelope contains exactly `manifest` and `sha256`. SHA-256 covers the compact, sorted-key canonical manifest payload. Canonical encoding, exact widths, duplicate/unknown-key rejection and bounded decoding make corrupted or partial records explicit failures. The encoded file is limited to 4 MiB, an internal artifact limit shared by codec and store. The digest detects corruption; it does not authenticate an adversarially rewritten record or prove absence of historical rollback.

## Ownership and writes

CreateNew requires a new owner-only directory. An existing directory, even an empty one, cannot be treated as an unused epoch. OpenExisting requires its existing lock and manifest, obtains exclusive nonblocking ownership of that directory, and returns inventory for recovery inspection. Missing records never initialize default state.

A store-directory lock cannot exclude supervisors configured with different directories. A real supervisor still needs one trusted global runtime ownership path. Lock/inventory loss or uncertainty prevents further writes on the affected handle.

Updates compare the expected generation and digest, retain the same epoch candidate, advance generation without wrap and obey PREPARED→ACTIVE→DRAINING→CLOSED or PREPARED→DRAINING cleanup. CLOSED remains terminal. Reopening existing state never restores ACTIVE service or grants successor-epoch authority.

A bounded temporary file is written and file-synced before atomic rename. Directory sync follows publication. Results distinguish prepublication failure from a visible update whose crash durability is uncertain. A failure or uncertain result latches the writer unavailable. Recovery requires independent fencing; a prior file is never used to resume admission automatically. Manifest and lock files are private owner-owned regular files; symlinks and identity replacement fail validation.

## Verification boundary

Developer and independent tests must cover generation/digest conflicts, unchanged inventory, interrupted writes, file/directory sync errors, missing/replaced files, locking and reopen behavior. Fake I/O tests establish transition/error handling. Real local filesystem tests establish observed write/lock behavior. Neither proves Docker process termination or power-loss durability on every storage device.

## Launcher integration gap

LLD A-03 asks for exact PID-start identity to be durably recorded before launching each participant. The PID-start identity becomes available after process creation. Before implementing a launcher, resolve this with a durable launch-intent record plus a non-serving bootstrap identity barrier, or an equivalent explicit staged protocol. This store accepts a complete supplied inventory; it does not satisfy that launch-order clause by itself.

Global supervisor ownership, validated launch intents, actual OS/runtime observations, no-restart enforcement, channel closure, fenced recovery and successor activation remain full RG-006 work.
