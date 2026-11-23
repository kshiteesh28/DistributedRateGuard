# Bootstrap inventory and durable registration

Sources are PRD 8, SRD 5 and the HLD 5 / LLD 6 A-03 clarification in [PR #18](https://github.com/kshiteesh28/DistributedRateGuard/pull/18). This increment depends on runtime-root ownership; implementation and process-control acceptance are tracked separately.

A fixed plan binds runtime domain, epoch, authority incarnation, policy digest, expected common clock identity and every participant's role, slot, incarnation and exact stopped-container ID. Every container belongs to the plan before start. Pending process identities use an explicit pending state; they do not become fake complete manifests.

The value model records observed host PID/start/clock identity for each exact planned participant. Equal observations replay unchanged. Unknown participants, changed identities, PID collisions and revision exhaustion require recovery. Revisions never wrap. The complete candidate requires the full roster, identical clock provenance and the existing gate's pure validation.

Model output describes data. Actual controller verification, durable storage and participant acknowledgement must supply their own evidence. The durable store consumes a move-only initial-epoch claim and binds its domain/epoch before writing the plan. It may expose a complete durable candidate only after every required record is synced and ownership remains valid. A failed or uncertain write prevents readiness; existing state cannot be adopted into serving automatically.

Artifacts use a versioned strict canonical JSON envelope and SHA-256, the existing decimal-string integer rules and a 4 MiB encoded limit. Checksums detect corruption and do not establish writer authorization or rollback freshness.

Full serving activation still requires policy, trust, witness, clock and epoch readiness. Container/process launch, authenticated bootstrap acknowledgement, positive fencing and successor-epoch recovery remain separate integration work.
