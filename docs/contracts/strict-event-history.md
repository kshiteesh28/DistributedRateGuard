# RG-005 strict history recorder

This increment provides opt-in event recording for Release A correctness runs. FR-009, FR-010 and NFR-008 require stage ownership, bounded storage and visible evidence loss. Performance runs keep aggregate metrics and leave detailed recording disabled by default.

## Run budget

At startup the run owner assigns a fixed number of slots to each expected producer. Validate the entire plan using checked arithmetic. The sum of the header, producer metadata, all slot allowances and terminal records must fit the single run budget of 1 GiB. A smaller budget is valid for a test. Partitions cannot borrow slots from another producer. Exhausting one partition ends collection for the run, even if another partition has space. This trades utilization for an upper bound that can later be enforced across processes without a network call on each reservation.

## Reservation and evidence

Reserve before a state transition. A producer publishes each reservation once, using the immutable attempt identity and the monotonic timestamp supplied by the stage owner. The generator owns offered records, the authority owns strict decisions, the replica owns responses, the adapter owns receipt and forwarding, and the backend owns completion. Keep arbitrary request bytes, certificates and credentials out of records. Local spend and grant events belong to Release C.

Quiesce producers before taking a final snapshot. Compare it to the independently supplied expected roster and epoch/policy binding. A gap, unfilled reservation, corrupted checksum, missing producer or missing seal makes the evidence incomplete. A structurally complete snapshot still requires a separate semantic checker. No recorder failure may undo a committed debit.

## Integration boundary

This increment covers the in-memory recorder and structural validation. Service wiring must propagate stop signals across processes, and the supervisor must bind unique producer ownership to its inventory. Durable export, retention, stage reconciliation and end-to-end traffic stopping have separate acceptance evidence. Follow the existing [LLD](../LLD.md) and [story criteria](../STORIES.md#rg-005).
