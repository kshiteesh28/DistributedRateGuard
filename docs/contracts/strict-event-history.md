# RG-005 strict history recorder

This increment provides opt-in event recording for Release A correctness runs. FR-009, FR-010 and NFR-008 require stage ownership, bounded storage and visible evidence loss. Performance runs keep aggregate metrics and leave detailed recording disabled by default.

## Run budget

At startup the run owner assigns a fixed number of slots to each expected producer. Validate the entire plan using checked arithmetic. The sum of the header, producer metadata, all slot allowances and terminal records must stay below 1 GiB. A plan reaching 1 GiB fails before slot allocation because D6 would invalidate the resulting correctness run. A smaller test budget permits an exact fit. Partitions cannot borrow slots from another producer. Exhausting one partition ends collection for the run, even if another partition has space. This trades utilization for an upper bound that can later be enforced across processes without a network call on each reservation.

## Reservation and evidence

Reserve before a state transition. A producer publishes each reservation once, using the immutable attempt identity and the monotonic timestamp supplied by the stage owner. The generator owns offered records, the authority owns strict decisions, the replica owns responses, the adapter owns receipt and forwarding, and the backend owns completion. Keep arbitrary request bytes, certificates and credentials out of records. Local spend and grant events belong to Release C.

Quiesce producers before taking a final snapshot. Compare it to the independently supplied expected roster and epoch/policy binding. A gap, unfilled reservation, corrupted checksum, missing producer or missing seal makes the evidence incomplete. A structurally complete snapshot still requires a separate semantic checker. No recorder failure may undo a committed debit.

## Version 1 binary format

Integers use big-endian encoding. The 80-byte header contains the eight ASCII bytes `RGHIST01`, schema version (4), epoch ID (16), policy digest (32), producer count (4), encoded size (8) and budget (8). Producers appear in ascending (owner, index) order.

Each producer has a 13-byte envelope (owner, index, capacity), a 51-byte record for every allocated slot, and a 26-byte seal (sealed, incomplete, reserved count, published count, checksum). Each slot carries status, local sequence, stage, outcome, attempt ID, monotonic time, cost and checksum. The 17-byte trailer contains the completion flag, encoded size and run checksum. The extent is `97 + 39 × producers + 51 × total slots` bytes. Fixed-width FNV-1a checksums detect accidental corruption. Files belong in a private synthetic-history directory.

The exporter accepts a quiescent, structurally complete snapshot and an independent run plan. The offline reader requires the same plan, rejects trailing bytes and truncated files, and validates all seals before returning evidence. A failed write or incomplete snapshot cannot produce a successful export result. A complete structure alone establishes neither quota safety nor clock provenance.

## Integration boundary

The generator, adapter, authority, replica and backend must supply their own events. A supervisor must bind producer ownership, propagate stop signals across processes and reject runs with missing participants or evidence. Seven-day cleanup applies to managed final and partial regular files in the private output directory. Run-level acceptance requires the real services. See the [LLD](../LLD.md) and [story criteria](../STORIES.md#rg-005).
