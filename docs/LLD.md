# DistributedRateGuard — Low-Level Design

**Revision:** 5 · **Date:** 2026-11-12 · **Status:** Proposed design; implementation/evidence pending  
**Current source branch:** `main` (the review design has been merged)  
**Binding sources:** [PRD revision 8](PRD.md), [SRD revision 5](SRD.md)  
**Architecture input:** [proposed HLD revision 4](HLD.md), delivered with this LLD.  
**Input blob identities before principal review (historical):** PRD `04456d95ed2474700198361db2314c50a73cb300`; SRD `dd82770809e1a56900336070404360c33b3b08a2`; HLD `fb835c70b4d53f1f4bf980dde1f0cd3065212cf3`.

## 1. Scope and implementation status

This LLD serves implementers and reviewers of a tenant admission service. A delivers strict quota decisions, B delivers deterministic replay and evaluation, and C delivers fixed-Q credits and independent model/history validation. PRD-013 live policy changes and PRD-014 long-operation permits remain deferred. Multi-host operation, transparent failover, automatic credit reclamation, and continuous cross-epoch quota guarantees are excluded.

The repository root inspected on main contains README and docs; all implementation paths below are proposed. There is no established build layout to preserve. PRD/SRD are binding; SRD §8 explicitly supersedes historical open decisions. The HLD's in-memory authority is a proposal conditional on integrity/fencing decisions. This LLD proposes interfaces and synchronization; §15 lists implementation gates rather than silently resolving product behavior. No code, tests, model checks, benchmarks, or deployment are claimed.

## 2. Modules and dependency graph

All paths in this table are **proposed**. Public means a process boundary; internal means a C++ library boundary.

| Module/path | Boundary; dependencies | State owned; source |
| --- | --- | --- |
| `proto/rateguard/v1/*.proto` | Public gRPC, Protocol Buffers | Versioned wire contract; FR-005/015 |
| `src/policy/` | Internal; digest/codec | Immutable policy/authorization snapshot; FR-001/003 |
| `src/platform/clock_linux.*` | Internal Linux API | Clock provenance; D3/D4, PRD-024 |
| `src/security/` | Public peer identity + internal resolver; gRPC TLS | Authorized principals, synthetic tenant/operation bindings; FR-003 |
| `src/admission/` | Public CheckAdmission; policy, authority client, credits | Bounded in-flight calls; FR-005/006/010 |
| `src/authority/` | Internal strict/grant engine plus internal gRPC | Buckets, grant journal, tenant transition order; FR-002/015 |
| `src/credits/` | Internal; authority client, clock | Fixed-slot confirmed credit and pending sequence; FR-014–018 |
| `src/supervisor/` and `src/supervisor/witness.*` | Local CLI/control and authenticated witness protocol; process controller, manifest, journal | Independent expected image, journal, inventory and epoch lifecycle; FR-001/007/008 |
| `adapter/` | Public sample API; admission client | Forwarding attempt state; FR-006 |
| `src/events/` | Internal; bounded recorder/export | Event buffers and bounded aggregate metrics; FR-009 |
| `tools/loadgen/`, `tools/report/` | Offline CLI; traces and manifest | Schedule, paired samples, gate calculations; FR-013/019 |
| `tools/replay/` | Offline CLI; independent arithmetic/model | Comparison output; FR-011/012 |
| `model/`, `tools/history_checker/` | Offline; event schema only | Explored model states and counterexamples; FR-021 |

Proposed C++ libraries own state using RAII; configuration snapshots use immutable shared ownership; tenant/slot state has process lifetime and is never evicted during an epoch. Requests own buffers, cancellation tokens and bounded event reservations. Background threads use joined shutdown, not detached access to destroyed state. gRPC/protobuf are required; crypto hashing support and test/model tooling versions must be pinned before build work. No additional storage service or queue is selected.

```mermaid
flowchart LR
  P["Immutable policy"] --> S["Admission service"]
  I["Peer authentication"] --> S
  S --> A["Authority client"]
  S --> C["Credit manager"]
  C --> A
  A --> Q["Authority engine"]
  K["Clock and provenance"] --> Q
  K --> C
  E["Epoch supervisor"] --> S
  E --> Q
  Q --> H["Bounded histories"]
  C --> H
  H --> V["Independent checker"]
  T["Offered trace"] --> R["Independent replay"]
```

## 3. Types, ownership, units and lifetime

Illustrative domain declarations below are design notation, not compiling production interfaces.

```cpp
struct CheckInput { TrustedPrincipal principal; TenantId tenant;
  OperationId operation; AttemptId attempt; EpochId epoch; Deadline deadline; };
struct GrantInput { TenantId tenant; SlotId slot; Incarnation incarnation;
  EpochId epoch; PolicyDigest digest; uint64_t sequence; Units trigger_cost; };
struct Bucket { uint64_t balance_subunits; uint64_t last_refill_ns;
  uint64_t transition_order; };
enum class Outcome { Allow, Limited, Invalid, Unauthenticated,
                     Unavailable, Overloaded };
struct Decision { Outcome outcome; EpochId epoch; PolicyDigest digest;
  Mode mode; AttemptId attempt; OptionalDuration retry_after; };
```

TrustedPrincipal is constructed only from validated transport identity, never deserialized from an untrusted override. Tenant/operation selectors are accepted only against immutable principal authorization; cost/rate/mode come from policy.

| Type/state | Validation; mutation/owner | Lifetime, serialization and reuse |
| --- | --- | --- |
| TenantId / OperationId | Exact configured identifier, bounded by message/config limits; immutable policy | Epoch; serialized in authorized request/history; no lazy creation |
| Principal | Registered URI SAN, role and permitted pair; security resolver | Connection + epoch snapshot; log pseudonym only |
| PolicyDigest | Proposed SHA-256 of canonical validated policy; immutable | Manifest/wire/artifacts; A-05 encoding |
| EpochId | Supervisor-generated unique value, never reused; immutable | Manifest, every result/event |
| SlotId / incarnation | Registered fixed slot ≤8; exact incarnation match | One epoch; no credit-slot reuse after restart |
| AttemptId | Adapter-generated unique attempt identity; duplicate active IDs rejected by adapter | Wire/history; no idempotency/refund semantics; new application retry uses new ID |
| GrantId / sequence | Unique within epoch, tuple binds tenant/slot/incarnation/sequence | Last result per tenant/slot; uint64 starts 1, no wrap |
| Units / subunits | Positive integer input units, internal 10^9 subunits/unit | Wire uses explicit units; state stores subunits |
| Deadline / commit time | Trusted service deadline conversion; monotonic ns at commit | Request lifetime/history; caller timestamps cannot mint refill |
| Bucket | balance≤B×10^9, time nondecreasing, ordered transitions | Authority memory; no same-epoch reconstruction after loss |
| Pending grant | Exact input fingerprint, sequence, pending/unknown status | Replica epoch; one per tenant/slot |
| Confirmed credit | Grant provenance, activated once, remaining≤grant | Replica memory; no transfer, refund, or resurrection |
| Retired / unresolved | Monotonic accounting counters and pending identity | History; unknown outcome is not zero spend |
| Event / checker result | Version, epoch, owner/order, timestamp, complete flag | Export; verdict PASS/FAIL/UNKNOWN plus provenance |
| Manifest / replay input | Version, validated policy and identity/provenance hashes | Durable file / versioned artifact; no silent field defaults |

Numeric bounds from D3: 1≤B,r≤10^9; 1≤c≤B; max_cost≤Q≤B. B_sub=B×10^9≤10^18 fits uint64. Let S=10^9 subunits/unit and T=10^9 ns/s:
`refill_sub = r(unit/s) × elapsed(ns) × S/T = r × elapsed`.
Compute product and sum in checked unsigned 128-bit, cap at B_sub, then narrow. No floating-point enforcement arithmetic. floor(available_sub/S) gives whole grant units; fractional bucket balance stays at authority. Never round grants upward. Sequence max is usable once; after its recorded result no next grant sequence exists.

Examples for independent golden tests: B=r=c=1, balance=0, elapsed=1 ns adds 1 subunit and cannot admit one unit; elapsed=10^9 ns adds 10^9 subunits and admits exactly one. B=r=10^9, balance=0, elapsed=10^9 ns yields 10^18 subunits. B=3,r=2,balance=2 units,elapsed=1 s caps at 3; cost 3 then leaves zero. available=5S−1 cannot admit c=5. Rate/B=10^9+1 or c=0 rejects policy/input without mutation. Checked arithmetic failure never wraps: stop affected enforcement and report integrity failure. Product at legal uint64 elapsed remains below 2^128; overflow guard is still required before conversion/addition and malformed-range inputs are rejected.

## 4. Interfaces and outcome mapping

Signatures below express lifetime and cancellation; A-05 allocates the proposed v1 wire fields.

```cpp
Result<Decision, ServiceError> CheckAdmission(
    const CheckInput&, const CancellationToken&);
Result<GrantResult, ServiceError> AcquireCredit(
    const AuthorizedReplica&, const GrantInput&, Deadline,
    const CancellationToken&);
ReadinessSnapshot Readiness(); // liveness is separate
ControlResult StartEpoch(const SupervisorCommand&);
ControlResult StopEpoch(const SupervisorCommand&);
ExportResult ExportHistory(const ExportSpec&);
ReplayReport Replay(const CompleteTrace&, const PolicyPair&);
CheckReport ValidateHistory(const CompleteHistory&, const ModelConfig&);
```

Common validation order: transport identity/role → bounded request decoding → active epoch/digest/incarnation → configured authorization/policy → numeric/sequence syntax → queue/deadline → state transition. Invalid input never creates quota state. Transport failures may occur before a structured response exists. Data RPCs cap at 16 KiB and pending checks at 1,024/replica. Offline exports/inputs stream under explicit run size limits; they do not pretend to fit one data RPC.

| Interface | Caller, input/output; commit | Deadline, retry and emitted record |
| --- | --- | --- |
| CheckAdmission | Adapter role; trusted selector, operation, attempt, deadline → outcome/epoch/digest/mode/correlation and advisory delay. Strict authority debit or local spend commits. | Expiry observed precommit: no debit. Lost/late result may conceal debit; application repeat is a new attempt. Offered/response/commit events distinct. |
| AcquireCredit | Replica role bound to slot/incarnation; grant tuple + trigger + deadline → grant or LIMITED plus provenance. Debit+result commit together. | Duplicate current seq returns recorded identical result; stale/skipped rejects; unknown retries same tuple/seq only. Record allocation and replay events separately. |
| Readiness/health | Authenticated operator/local supervisor; readiness snapshot lists epoch/clock/state/authority checks; health only says process alive. | Read-only, bounded poll; safe retry, no quota commit. Partitioned credit replica may serve confirmed units despite inability to obtain grants; publish degraded state. |
| StartEpoch | Supervisor only; fresh identity/policy/provenance/inventory → activation record or blocked reason. | Not complete until all fencing/start checks pass. Retry command ID retrieves operation state; cannot mint second epoch. |
| StopEpoch | Supervisor only; epoch+command ID → quiescing/stopped/unknown inventory. | Timeout means unknown, never stopped. Repeat observes same stop operation. |
| ExportHistory | Local authorized tool; epoch/run + destination → count/hash/complete flag. | Read-only streaming; cap/write failure marks incomplete; retry must not claim missing records recovered. |
| Replay | Local tool; complete trace, initial state, two policies → deterministic decisions/comparison or validation errors. | No enforcement mutation; cancellation yields incomplete result; repeat immutable inputs is safe. |
| ValidateHistory | Local tool; complete events/model bounds → PASS/FAIL/UNKNOWN and counterexample. | Missing clocks/events yields UNKNOWN. Resource exhaustion is not PASS; repeat same model/config reproducible. |

Binding D1/D2 from SRD §8: invalid→INVALID_ARGUMENT, unauthenticated→UNAUTHENTICATED, unauthorized→PERMISSION_DENIED; none charge. ALLOW/LIMITED are explicit application outcomes over successful transport. UNAVAILABLE/OVERLOADED are distinct application outcomes when the service can return them. Raw transport UNAVAILABLE/DEADLINE_EXCEEDED/CANCELLED after dispatch leaves commitment uncertain. A-05 settles structured overload versus predecode transport rejection. Earlier SRD sections still mention open D1/D2; §8 supersedes them for the three settled mappings. A late ALLOW cannot authorize forwarding.

**A-05 — wire and canonical identity decisions:** Keep ALLOW/LIMITED/UNAVAILABLE/OVERLOADED as explicit application outcomes over gRPC OK when a structured response is available. Invalid fields use INVALID_ARGUMENT, missing identity UNAUTHENTICATED, wrong role/permission PERMISSION_DENIED. Transport RESOURCE_EXHAUSTED is reserved for rejection before application decoding (e.g. message size); raw transport loss after dispatch always leaves commitment uncertain. Enum zero is UNSPECIFIED and never permits forwarding. Disable automatic retry/hedging for strict calls; a new application call is a fresh chargeable attempt. Retrying AcquireCredit always retains the same sequence and fingerprint.

Proposed v1 wire field allocation: CheckAdmission tenant=1, operation=2, attempt_id=3, epoch=4, policy_digest=5; no client cost/time/mode field. Decision outcome=1, epoch=2, digest=3, mode=4, attempt_id=5, optional retry_delay_ns=6. AcquireCredit tenant=1, slot=2, incarnation=3, epoch=4, digest=5, sequence=6, trigger_cost_units=7, trigger_operation_id=8; authority derives cost from immutable policy and rejects a mismatched cost or unauthorized operation; role is derived from transport. GrantResult grant_outcome=1, sequence=2, composite_grant_id=3, grant_units=4, epoch=5, digest=6. GrantOutcome is a separate enum: UNSPECIFIED, GRANTED, LIMITED, INVALID, UNAVAILABLE, OVERLOADED. GRANTED allocates credits and is never a forwarding ALLOW. Zero-valued grant amount is valid only for a known non-grant result; distinguish field presence. Preserve retired field numbers, reject unknown enum values, never reinterpret field units. Deadline comes from the gRPC deadline context, converted once to local monotonic remaining budget; no caller wall timestamp enters refill. Delay after conversion can only shorten eligibility.

Configured identifiers use nonempty ASCII [A-Za-z0-9_.-], at most 128 bytes; fixed binary digests/IDs have explicit versioned lengths. Canonical policy encoding v1 uses sorted tenant/principal/operation records, fixed-width big-endian integers and length-prefixed UTF-8/ASCII bytes, includes mode/Q/slots and every authorization field, and hashes with SHA-256. Reject duplicate names/keys. Human JSON is parsed to this typed form; object iteration order is never hashed. Artifact schemas retain explicit versions, units, order and completeness; uint64 JSON values are decimal strings to avoid floating-point loss. Golden encoding and compatibility vectors are acceptance evidence, not generated code.

## 5. Strict bucket algorithm

Preload every configured tenant at explicit epoch initialization with full B. Request handling uses find-only lookup. Validate canonical policy digest at startup and compare immutable snapshot identity, not untrusted request cost. Each tenant has a stable owning object with a mutex; no request inserts/evicts entries. Only one supervisor-registered authority incarnation serves an epoch. Local locks give no safety across two authority processes.

Illustrative pseudocode; proposed event reservation fails before spend if correctness evidence cannot be bounded:

```text
validate request, authorization, policy, epoch
reserve bounded event space if correctness run enabled
reserve tenant exclusively; validate pre-state/version with witness outside mutex
lock tenant
  verify epoch still admitting and independently witnessed tenant version (A-01)
  now := verified CLOCK_MONOTONIC
  if observed deadline expired: exit without mutation
  if now < last_refill: mark integrity failure; exit unavailable
  available := min(B*S, checked128(balance + r*(now-last_refill)))
  if available >= c*S: next := available-c*S; outcome := ALLOW
  else: next := available; outcome := LIMITED
  commit balance, last_refill=now, transition_order++, event slot
unlock tenant
journal/witness the exact transition; await matching durable acknowledgment
on failure: mark epoch DRAINING, preserve uncertainty, never roll back and resume
release logical tenant reservation
return decision only after acknowledgment; receipt may still time out
```

Sampling inside the mutex is the proposed logical linearization instant: no observer can see intermediate state; all result-relevant fields transition together. LLD-07 requires a demonstrable mapping between that instant and history timestamps; a timestamp taken at RPC ingress is insufficient. A clock read/system failure stops the transition. LIMITED advances refill time but charges no cost.

Advisory retry for c≤B: if deficit=cS−available>0, delay_ns=ceil(deficit/r), using integer quotient/remainder; this is not a reservation. No refund follows downstream failure. At exactly available=cS admit; at cS−1 deny. Equal timestamps get a monotonic per-tenant order; model tests exercise both event boundaries. On [t0,t1), committed strict cost ≤B+r(t1−t0) within the same epoch. Ledger order validates state transitions, and interval checks independently validate the envelope. Uncertain calls reconcile against ledger events; reject-all mutants must fail eligible serial fixtures.

## 6. Credit algorithm and retry state

Authority record keyed by (tenant,slot) contains incarnation, current sequence, exact request fingerprint, outcome, granted units, grant ID and commit metadata. Retain the last result until the next sequence commits; older sequences reject as stale per SRD. Current-sequence retries with different content reject without debit. This fingerprint rule prevents changing the triggering cost under an idempotency key.

| State/event | Required transition |
| --- | --- |
| EMPTY + attempt | Designate one pending caller/sequence, request grant outside lock |
| ACTIVE + sufficient balance | Atomically spend and record grant-linked commit; remain ACTIVE |
| ACTIVE + insufficient balance | Retire remainder exactly once; enter EMPTY/PENDING |
| PENDING + concurrent attempt | Wait bounded by caller deadline or overload; no second grant |
| PENDING + known grant | Validate tuple, activate once, spend only if triggering caller still eligible |
| PENDING + known LIMITED | Consume sequence, return LIMITED; future new attempt may advance |
| PENDING + lost response | UNKNOWN(seq,input); prohibit next sequence |
| UNKNOWN + retry | Same sequence and fingerprint only; resolve same result |
| Any + epoch/fatal mismatch | STOPPED; never recreate allowance |

Authority grant transition under tenant lock:
```text
authenticate registered replica/slot; validate tuple and trigger
if seq == recorded.seq: return identical result iff fingerprint matches
if seq != expected_next: reject
refill via strict arithmetic at authority linearization point
g := min(Q, floor(available/S))
if g < trigger: result := LIMITED, amount=0
else: result := GRANT(unique tuple-derived id), amount=g
atomically record balance debit (g*S or zero), refill time and result
witness/journal exact transition under reservation; respond only after acknowledgment
```

Known LIMITED is replayed after refill; it is not reevaluated under the same sequence. Grant activation verifies full provenance and is protected by a per-tenant replica mutex; duplicate network callbacks cannot activate twice. The sequence coordinator holds no lock across RPC. On grant success after the initiating check deadline, retain the confirmed batch without spending for that expired check; later eligible calls can spend it. A lost grant response stays UNKNOWN, and a subsequent same-sequence resolution cannot turn the expired check into a forward.

Local spend checks epoch, incarnation, deadline and sufficient remaining under one lock, samples the common clock, subtracts cS, and fills pre-reserved event storage. Crash before/after commit may make exact accounting unknowable; no refund. Authority partition permits already confirmed credits, then unavailable after exhaustion. No prefetch, transfer, reclamation or automatic slot replacement.

Conservation: every spent unit belongs to exactly one unique confirmed grant and no unit is spent twice. For one epoch, carried confirmed credits ≤NQ, new grant debits satisfy authority bucket envelope, hence committed cost ≤B+rΔt+NQ. This is a conservative bound, not strict-equivalent behavior. Verify history and common-clock provenance before reporting PASS.

**A-04 — commit, evidence and forwarding:** A tenant transition has an exclusive logical reservation across witness operations, without holding a C++ mutex over RPC or file I/O. Capture pre-state under lock, release it for witness validation, reacquire and verify the same reserved version before computing/committing; all other operations for this tenant wait with bounded deadlines. Sample CLOCK_MONOTONIC inside the serialized transition. The timestamp defines the logical state change; witness flush/ack determines whether a successful result can be delivered. If the witness fails after the transition, retain the possible debit as uncertain and terminate the epoch; do not roll back and resume. Duplicate transition records replay without another debit.

For local credits, inspect/retire/check at the same protected point as the clock sample and subtraction. A process pause or deadline expiry after this point can conceal a commit but never makes a late ALLOW usable. Allocate bounded event slots before spending; recording includes reserved/published state so a torn/unpublished event is visibly incomplete. Shared run buffers may survive an individual process crash but are not host-crash durability. Exact post-crash accounting requires complete verified durable export; otherwise report ranges/UNKNOWN.

Adapter forwarding uses one Pending→ForwardStarted compare-and-swap, conditioned on receipt before deadline and locally active epoch. Each application retry gets a new attempt ID. On adapter crash, do not replay old pending/forward-started attempts. Backend invocation may remain uncertain; no exactly-once backend execution guarantee is claimed. Fencing stops every old replica, so stale local credits cannot survive into a fresh epoch.

## 7. Synchronization and C++ lifetime rules

| Shared object | Proposed protection, ordering and shutdown |
| --- | --- |
| Immutable policy/identity registry | Publish before readiness, read-only shared ownership. No live replacement within epoch. |
| Tenant table | Fixed indexed collection after startup; stable unique owners, no request-time insert/erase. Exact ID map is immutable. |
| Bucket + tenant grant records | One tenant mutex, covering refill/debit/result/order/event state; unrelated tenants proceed independently. |
| Replica tenant/slot state | One mutex/condition for active batch, coordinator, sequence and local accounting. Network continuation validates generation before applying. |
| Epoch readiness | Atomic gate plus supervisor lifecycle. Authority transition checks under its state synchronization; local credit spends check local gate. Isolated replicas cannot be instantaneously notified. |
| Adapter attempt | Single atomic transition Pending→ForwardStarted or Pending→Expired/Failed. ForwardStarted is never entered twice. No automatic replay after adapter crash. |
| Events/metrics | Preallocated event reservations; fixed atomic counters; bounded exporter. Never invoke external callback while holding tenant lock. |
| Supervisor manifest/inventory | Single owner control thread and exclusive process-control lock; ID-keyed command state. Persisted recovery and exit evidence follow A-03. |

No tenant lock is held across RPC, disk I/O, user callbacks, or blocking log export. Acquire configuration snapshot and locate stable tenant before locking; never hold authority and replica locks together. Reserve bounded recorder space before state lock; fill an exclusive reservation inside the transition and publish nonblocking. If reserve fails, do not start commit; if publication/integrity fails after commit, invalidate run, stop affected service and report uncertainty. Event evidence follows A-04; incomplete records invalidate exact claims.

Cancellation stops waiting and forwarding; it does not undo a committed debit or grant. Shutdown closes admission gate, wakes waiters, cancels bounded outbound waits, joins all workers, exports/marks incomplete histories and reports process exit. A supervisor timeout cannot substitute for exit confirmation. Race checks target duplicate callbacks, simultaneous local spends, lock acquisition at deadline, stop concurrent with spend, and two simultaneous requests for one grant sequence.

## 8. Manifest, integrity and fencing

Proposed manifest v1 fields: schema version; never-reused epoch ID; mode; canonical policy bytes/digest; authority incarnation; kernel boot and time-namespace identities; clock ID; fixed slot/incarnation bindings; expected tenant IDs/count; supervisor operation ID; container IDs/PID start identities; lifecycle state and activation generation. File permissions: supervisor write-only ownership, participants read-only, secret keys stored separately. Unknown versions or mismatched digests fail startup. Canonical policy proposal is sorted typed records with explicit lengths, UTF-8 identifiers and integer quantities; A-05 defines encoding; golden vectors must precede code generation. No unspecified JSON serialization order may define a digest.

Proposed write procedure: construct a complete validated temporary file on the same filesystem, write and fsync it, rename atomically, then fsync the directory. This protects against torn replacement; it does not prove rollback absence. Manifest activation/fencing recovery follows A-01/A-03; never restore an active epoch after supervisor loss.

Startup: validate complete manifest/policy, clock provenance, registered process identities and unique authority ownership; initialize authority state only during explicit new epoch; validate expected tenant inventory/grant state; start replicas with fixed slots; start adapter last. Readiness stays false until checks pass. Prohibit two supervisors using exclusive OS ownership and exact persisted container IDs; supervisor lock loss stops new activation. A lock alone cannot fence processes after supervisor failure.

Stop/reset: persist quiescing intent, stop ingress, stop adapters and every old replica, wait for OS/container-runtime exited evidence tied to exact container/PID identity, close channels and stop authority, then record terminal epoch. Fresh activation requires a completed inventory, new authority incarnation and new epoch. Unknown/unreachable container, PID reuse, partial shutdown or missing manifest evidence leaves BLOCKED. Host reboot changes boot identity and mandates a new fenced epoch; previous activation cannot resume automatically. Supervisor crash never authorizes adopting a guessed fresh inventory.

**Reviewed architecture decision A-01:** The authority keeps its hot state in memory, with an independently owned supervisor witness. Before every tenant transition or cached grant response, a bounded witness exchange compares the complete current tenant state/version and all fixed-slot grant records with the supervisor-owned expected image. Missing, older, or mismatched records fail closed. The authority reserves the tenant, commits a transition at the shared monotonic timestamp, and sends a versioned before/after record to the witness. It returns a usable result only after the witness records and acknowledges that exact transition. Until acknowledgment, that tenant admits no later transition. A lost acknowledgment retries the identical transition ID; an unavailable witness stops new authority work. Local confirmed credits remain governed by the partition contract.

The witness appends an ordered hash-chained journal, with flush before acknowledgment, and retains an independent expected-state image. A complete checkpoint contains policy, epoch and every tenant/slot state; no eviction or reconstruction of missing live state is allowed. Checkpoints are audit exports at CLOSED, never an input to restart an old epoch. Journal cap is a proposed 2 GiB per epoch; reaching it stops new authority transitions and triggers fenced shutdown. This is separate from the 1 GiB correctness-history cap. A single writer may batch flushes without acknowledging an unflushed transition. No same-epoch recovery or automatic replay is introduced.

The witness detects declared single-record deletion, version rollback and inconsistent grant results before subsequent authority use. It is not a claim to detect coordinated corruption of both independent images or malicious rollback of the whole host; such evidence is UNKNOWN. Witness/supervisor loss terminates the authority incarnation and blocks reset until all old processes are confirmed stopped. Crash-window, acknowledgment-loss, journal corruption and record-rollback checks are mandatory evidence before this mechanism can satisfy FR-008/AT-09. Added coordination and flush cost may miss performance gates; thresholds must not be reduced to conceal it.

**A-03 — lifecycle recovery:** One supervisor holds an exclusive local runtime lock and durably records exact container IDs, boot identity and PID start identities before launching each participant. No participant is unregistered or automatically restarted. Confirm stop with runtime inspect plus OS exit evidence for the recorded identity; a reused PID or an absent response is not proof. Supervisor death does not permit a new supervisor to resume service: recovery loads the last inventory, fences/stops every recorded participant including the old authority and witness, confirms exit, then creates a new epoch. On host reboot, verified changed kernel boot identity proves old kernel processes cannot survive, but the supervisor still inventories/stops any newly auto-started containers before activation. Unreadable or untrusted inventory blocks reset until a controlled complete VM shutdown provides positive fencing evidence. A stop command is monotonic and idempotent by operation ID; activation is never inferred from a partially written manifest.


## 9. mTLS and authorization

**Reviewed decision A-02 — service identity:** Use a local epoch-scoped CA and separate leaf/key per process. URI SAN roles are `spiffe://rateguard.local/adapter/<id>`, `.../replica/<slot>/<incarnation>` and `.../authority/<incarnation>`; the epoch manifest binds each registered identity to its role and policy permissions. Server leafs require serverAuth, clients clientAuth; verify chain, exact expected server SAN, client role, validity and manifest allowlist. Authority checks require authenticated replica roles bound to their slot; adapter principals cannot acquire credits. Witness control uses a supervisor-owned local Unix socket with OS peer credentials bound to the authority inventory entry, not an arbitrary caller-supplied PID.

Provision keys outside the repo with owner-only permissions and read-only process mounts. Disable automatic gRPC application retries/hedging; grant retries are managed explicitly by sequence. Every RPC, including a reused connection, rechecks peer authorization and certificate validity using trusted system wall time; wall time never refills quota. Reject calls when wall-clock trust is lost or a leaf expires; do not let an established channel bypass expiry. Certificate rotation/revocation means closing old channels and starting a fenced new epoch with a rebuilt trust registry. No online revocation or live rotation is claimed. Never export private keys, credentials or full certificates in run artifacts. Proposed negative fixtures cover wrong role/SAN/EKU, expiry on a reused channel, stale epoch leaf and forged tenant headers.

## 10. Persistence, journals and telemetry

| Record | Durability/write boundary; failure behavior | Bound/lifetime |
| --- | --- | --- |
| Policy/epoch manifest | Durable supervisor file proposed; failed validation/fsync/rename prevents activation | Finite configured tenants/slots; active manifest plus explicitly retained artifacts |
| Bucket/grant result | Authority volatile epoch state; mutation protected together; missing record stops epoch | 10k tenants × at most 8 last grant results; no same-epoch reconstruction |
| Local confirmed/pending credit | Volatile replica state; atomic spend/activation; crash strands units | One batch and one pending result per configured tenant/slot |
| Correctness event history | Reserved bounded in-memory events then exported; crash may lose unpublished history | Proposed global run budget ≤1 GiB across producers; no per-process multiplication |
| Aggregate metrics | Volatile counters/gauges; exporter failure visible, no quota refund | Fixed labels only; no tenant/grant/attempt/correlation labels |
| Trace/replay/model output | Versioned artifacts with input/output hashes and complete flag; write failure produces incomplete report | Explicit streamed limits, cleanup; no unlimited model output |

Proposed global history budget allocates bounded producer reservations before the run; a consumer cannot allocate beyond its share. If cap/write failure occurs, stop correctness traffic and mark run INCOMPLETE, not PASS. Performance runs omit full histories but retain bounded aggregate metrics and manifest. Any rejection caused by evidence limits is reported, never hidden as quota denial.

Owners and reconciliation: generator OFFERED; authority STRICT_COMMIT/GRANT_COMMIT; replica LOCAL_COMMIT/RESPONDED; adapter RECEIVED/FORWARDED; backend COMPLETED. Every event has schema version, epoch, attempt/grant tuple, monotonic timestamp, component and per-component order, policy digest, outcome and cost when applicable. IDs identify events, not authorization. Separate each application retry's attempt ID; repeated grant RPCs reuse grant sequence and input fingerprint.

At quiescence: completed⊆forwarded⊆timely received ALLOW⊆committed ALLOW; LIMITED has no cost debit. A commit may lack received/responded events. Classify offered attempts as known responded, expired/cancelled, or unresolved. Grant ledger totals reconcile consumed+remaining+retired+stranded, with unresolved allocations separate. Complete durable local history permits exact stranded cost; otherwise report a conservative range [0, granted−last verified consumed−last verified retired], tightened only by sound evidence. Missing grant/clock provenance can make the result UNKNOWN. Never treat zero observed local consumption as proof that credits are unused.

D7: only synthetic/pseudonymized published data, explicit correctness export disabled by default, local artifacts retained seven days with cleanup at next tool startup/run. Published versioned synthetic benchmark artifacts are retained under project control and distinguished from local exports. Cleanup errors are visible; no claim of immediate timed deletion when tools are not running.

## 11. Replay, model and history validation

Artifact schemas follow A-05's version/units/completeness and integer encoding:
- OfferedTraceV1: initial state, relative arrival_ns, stable row order, tenant, operation, schema/model version, seed, policy hashes, row count and content hash. No historical-admissions-only trace qualifies.
- ReplayReportV1: per-policy row decisions, per-tenant offered/admitted counts/cost, changed decisions, first divergence with explanation, full input/hash provenance.
- HistoryV1: invocation/response and commit/grant/spend/lifecycle events, clock provenance, per-source ordering and completeness/truncation markers.
- ModelConfigV1: N, B/r/Q/cost domains, time/horizon bounds, allowed fault actions, fairness assumptions, expected invariants and tool version.
- CheckReportV1: PASS/FAIL/UNKNOWN, explored bounds/state count or search timeout, invariant, witness/counterexample and deterministic reproduction command.

Replay uses a separate model implementation and exact integer or rational reasoning; production policy decision/arithmetic routines are not imported as the oracle. Run hand-calculated fixtures for equal arrivals, exact eligibility, partial refill, weighted costs, malformed row, unknown policy identity, first divergence and maximum values. Invalid source rows fail rather than disappear.

AT-26 explores valid combinations of two replicas/two tenants, B∈{2,3}, Q∈{1,2}, costs∈{1,2} constrained max_cost≤Q≤B; include retry, loss, crash, partition and epoch actions, with a declared finite time/horizon. Tool choice (e.g. TLA+/TLC plus independent trace checker) is proposed, not an implemented dependency. Archive complete config, state counts, model version and counterexamples. Absence of faults in a bounded model does not establish correctness for all executions.

Concurrent checker: validate schema/complete clock provenance, reconcile ledger events, find a legal per-tenant order respecting completed nonoverlapping calls and committed event order; uncertain calls can be committed/uncommitted only consistently with known ledger. Check all event-induced half-open intervals with tie order and empty-interval conventions; zero-duration empty intervals contain no work, tied timestamps require declared ordering. Missing history or exhausted search budget yields UNKNOWN. Full interval enumeration can be quadratic: use small exhaustive histories for equivalence and a separately validated efficient prefix/envelope checker for million-attempt histories. Do not claim feasible exhaustive state search at that scale without a complexity plan.

Required mutations: double debit/spend, duplicate grant on retry, reject-all, stale epoch reuse, lost-response replacement and violated bound. A reproducible failing history includes seed, minimized schedule where supported, inputs, model/checker versions and affected invariant. Ordinary model/pseudocode is not production code.

## 12. Failure matrix

All rows require no forwarding without timely received ALLOW. Evidence IDs refer to planned SRD checks, not existing tests.

| Trigger / detection | Already committed? | Outcome, retry and forwarding | Event / evidence |
| --- | --- | --- | --- |
| Deadline observed before transition | No | Expiry; no debit; new attempt only if caller chooses | Expired-precommit; AT-07 |
| Deadline races during/after transition | Possible/yes | Unknown or late ALLOW; do not forward/refund | Commit plus expired receipt; AT-07 |
| Strict response lost before commit | Unknown to client | No forward; repeat is new attempt, not deduplication | Unresolved; ledger establishes truth; AT-07/08 |
| Strict response lost after commit | Yes | Same uncertainty; no refund | Committed-unanswered; AT-07 |
| Duplicate current grant | Same recorded result | Replay without debit; activate once | Grant replay; AT-15/21 |
| Stale/skipped or tuple-changed sequence | No new commit | Reject; cannot advance unknown sequence | Validation failure; AT-15 |
| Grant response lost | Possible | UNKNOWN(k), retry exact k/tuple; no replacement | Pending/unresolved allocation; AT-15/18 |
| Credit replica crash | Earlier grants/spends possible | Slot not reused; conservative stranded range; reset requires fencing | Crash/incomplete local history; AT-18 |
| Authority crash | Existing commit possible | Terminal authority incarnation; supervisor stops/reset, no promotion | Epoch terminal/unknown; AT-08/09 |
| Record missing/rollback suspicion | Unknown | Stop before further spend if detectable; A-01 witness check must fail closed | Integrity failure; AT-09; LLD-01 |
| Partition with confirmed credit | Granted earlier | Local eligible spends allowed within old epoch; no new grants | Degraded/local commit; AT-18 |
| Partition without credit | None usable | UNAVAILABLE, not LIMITED unless authority confirmed quota denial | Dependency error; AT-18 |
| Stale epoch/slot process | Possible old credit | Reject new mismatches; do not activate fresh epoch until old process stopped | Fencing evidence; AT-14/18/26 |
| Boot/time namespace mismatch | No new eligible commit | Readiness false, safety UNKNOWN; no bound pass | Provenance failure; AT-01/17 |
| Unknown/expired/wrong-role certificate | No | UNAUTHENTICATED/PERMISSION_DENIED or handshake failure | Bounded auth counter; AT-04 |
| Unknown tenant/operation | No | INVALID/PERMISSION_DENIED per validation boundary; no allocation | Invalid attempt; AT-04 |
| Queue saturation / oversized request | No | OVERLOADED / INVALID or agreed transport mapping | Rejection counts; AT-11 |
| History cap/write failure | Before or after commit | Stop correctness run as incomplete; no refund for past commits | Truncated/incomplete flag; AT-10/11 |
| Supervisor failure during reset | Old processes uncertain | New epoch blocked until complete positive inventory/fence recovery | Control operation state; AT-09 |

**Resolved LLD-08:** Authority failure stops new authority transitions and moves the epoch to DRAINING. Participants that observe DRAINING stop new local spends and forwarding. Isolated replicas/adapters may still act on confirmed old-epoch credits under their last observed ACTIVE state; these events remain part of the old epoch. CLOSED means every registered old adapter, replica and authority has been positively confirmed exited. A fresh epoch may activate only after CLOSED. Guarantees cover the entire old epoch through its final commit, including partitioned spending during DRAINING; no instantaneous remote-stop guarantee or cross-epoch envelope is claimed.

## 13. Test seams and requirement traceability

Inject internal ClockSource/ProvenanceProvider, authority port, fault-capable RPC transport, immutable policy fixture, ProcessController, TraceSource and bounded EventRecorder. No public test-only RPC. Failpoints occur before/after authority transition, before response dispatch, before/after local subtraction/event publication, before grant activation and before/after each manifest/fencing step. Fake clock tests deterministic logic; real-kernel provenance and process tests are separate.

| PRD | FR / NFR | Owner, invariant/interface | Planned evidence |
| --- | --- | --- | --- |
| 001 | FR-001; NFR-001 | Supervisor/authority; same policy and budget across replicas | AT-01–03 |
| 002–003 | FR-002/003; NFR-001 | Strict engine/D3, exact permissive bucket decision | AT-02–04/21 |
| 004 | FR-004; NFR-002 | Separate tenant state, noisy-tenant service | AT-05/22 |
| 005 | FR-005/006 | API/adapter, deadlines and forwarding CAS | AT-06/07 |
| 006 | FR-011/012 | Independent replay, complete trace/comparison | AT-12 |
| 007–008 | FR-001/003/007/008 | Lifecycle/identity, no unsafe restart | AT-01/04/08/09 |
| 009 | FR-009 | Event owners and reconciliation | AT-10 |
| 010–012 | FR-013; NFR-003/006/007 | Generator/report, p99 and clean reproductions | AT-13/23/25 |
| 013–014 | Deferred | No live policy or permits | New design required |
| 015 | FR-008/010; NFR-008 | Bounded state and integrity | AT-09/11 |
| 016 | FR-014 | Epoch/slot fixed, no mode mixing | AT-14 |
| 017 | FR-015/016; NFR-001 | Atomic grants and unique local spends | AT-15/16/21 |
| 018 | FR-017; NFR-001 | Provenance and interval bound | AT-17/21 |
| 019 | FR-018 | Unknown/stranded state, no refunds | AT-18 |
| 020 | FR-019; NFR-003–005 | Paired authority-op ratio/admitted cost | AT-19/23/24 |
| 021 | FR-020 | Contract→module→independent checks before generation | AT-20 |
| 022 | NFR-009 | Delivered terminal ALLOW/LIMITED numerator | AT-27 |
| 023 | FR-021 | Independent model/history checker and mutants | AT-26 |
| 024 | FR-001/003/008/017 | Clock identity, authentication, positive fencing | AT-01/04/09/17/18 |
| 025 | FR-022 | Supervisor/participants, ACTIVE/DRAINING/CLOSED | AT-28 |
| 026 | FR-023 | Generator, exact uniform and labeled skew traces | AT-29 |

Numerical acceptance remains unchanged: zero observed model/bound violations in ≥1 million attempts per mode with defect detection; noisy-tenant ≥99% timely ALLOW in each of five runs; nearest-rank p99≤5 ms at 5,000 offered checks/s over all delivered attempts, 1,000 tenants, N=3, 50 ms deadline; ≥99% delivered checks receive timely ALLOW/LIMITED; generator delivery≥99.5%. Credit efficiency requires ≥50% fewer authority operations/1,000 admitted units, ≥95% strict admitted cost, same policy/trace/budget and other gates; compare five-run medians, publish each sample and zero-denominator failure. Two clean pinned reproductions must recalculate results. N=1/3/8 and clamped Q sensitivity are not alternate pass configurations. Correctness/fault histories and performance runs remain separate. No gate is claimed passed.

Measure every attempted authority check/grant RPC, including retries and failures, not just unique successful grants. Report witness calls, journal records/bytes, flushes and wait time separately plus total coordination traffic, so batching cannot hide work moved to the supervisor. Freeze exact metric definitions in the manifest before comparison; never exclude retries from the efficiency accounting.

## 14. Complexity, bounds and ordered increments

Proposed immutable hash ID lookup: average O(1), worst O(T) collision chain; validate finite T≤10,000. Once resolved, bucket and local spend computation are O(1), excluding mutex queueing. Grant-result lookup can use fixed slot array O(1), ≤8 records/tenant. Pending queue wait bounded by deadline and configured count; no worst-case latency is implied by O(1) arithmetic. Replica credit storage O(TN) system-wide ≤80,000 tenant/slot states, with one batch/pending state each. A replica holds ≤1,024 in-flight checks; all eight can hold ≤8,192. Request payload allowance alone can total 128 MiB (8,192×16 KiB); object/transport/TLS overhead is additional and measured before freezing host budget. Histories share ≤1 GiB/run. Configuration key/string lengths and exact memory are part of LLD-04 capacity/schema work.

Replay is O(M) decision work for M sorted offered rows, plus per-tenant aggregates and streamed output; unsorted input is rejected rather than sorted invisibly. Exhaustive ordering/model search is exponential in concurrency/state bounds; pairwise interval enumeration O(M²). Large history validation requires a separate bounded-memory efficient checker verified against the exhaustive small checker. Publish resource-limit UNKNOWN rather than claiming completion.

| Increment / proposed files | Prerequisites, sources | Acceptance and stop condition |
| --- | --- | --- |
| 1 Contract/build: proto, policy, toolchain manifest | LLD-04 mapping/schema; PRD-005/008/021 | Versioned encoding and config golden vectors; missing contracts block network code |
| 2 Pure arithmetic/clock: policy, platform, independent model | D3/D4, PRD-001–003/024 | Boundary/refill/overflow tests AT-01–04; clock provenance prototype LLD-07; arithmetic/model disagreement blocks |
| 3 Lifecycle/identity: supervisor/security/manifest | LLD-01/02/06/08; PRD-007/008/015/024 | Positive fencing and state-fault checks AT-04/08/09/11; witness evidence failure blocks serving |
| 4 Strict A: authority/admission/adapter/events | Independent serial oracle, lifecycle/auth and record completeness | AT-01–11/21 and ≥1m attempts; no release A completion on integrity/accounting miss |
| 5 Evaluation B: replay/loadgen/report | Strict baseline, PRD-026 trace validation and frozen manifest | AT-12/13/22/23/25/27, five runs and two clean reproductions; missed gate remains incomplete |
| 6 Credits C: credits/grant service | Strict correctness, LLD-05/07 event/clock design | AT-14–19/21/24; ≥1m credit attempts, no duplication/refund/unsafe slot reset |
| 7 Formal assurance: model/checker | Stable schema, independently implemented oracle | AT-20/26 seeded mutants and reproducible counterexamples; incomplete search cannot PASS |
| 8 Release evidence review | All applicable source gates | Link requirements→contracts→design→checks→observed results; no threshold adjustment after results |

## 15. Principal review disposition and implementation gates

This revision incorporates HLD revision 3 as its co-delivered architecture. The previous list of open implementation choices is superseded by A-01 through A-05; source wording conflicts are resolved by PRD-025/026.

| Finding | Principal review disposition |
| --- | --- |
| HLD-01 / LLD-01: state integrity | Design mechanism selected in A-01: independent supervisor witness, pre-state validation, versioned journal and acknowledgment barrier. Missing/corrupt witness fails closed; implementation/fault evidence pending. |
| HLD-02 / LLD-02: internal identity | A-02 fixes roles, endpoint SAN checks, local provisioning, per-RPC expiry and fenced epoch rotation. Negative certificate evidence pending. |
| HLD-03 / LLD-03: routing | Resolved by PRD-026/FR-023/AT-29; exact uniform trace and distinct block-skew sensitivity trace. |
| HLD-04 / LLD-07: time | A-04 locates logical timestamps within reserved serialized transitions, separates durability acknowledgment, and preserves unknown results. Kernel/protocol validation pending. |
| HLD-05 / LLD-06: supervisor recovery | A-03 requires exact inventory/OS exit evidence, prohibits adopting a running epoch after supervisor loss, and blocks unknown processes. Crash-recovery evidence pending. |
| HLD-06 / LLD-04/05: wire/events/forwarding | A-04/A-05 define bounded precommit event reservations, incomplete-history verdicts, forwarding CAS, explicit outcomes and versioned fields/encoding. No exact host-crash accounting claim. |
| LLD-08: epoch lifecycle | Resolved by PRD-025/FR-022/AT-28: ACTIVE, DRAINING and positively fenced CLOSED. |
| HLD-07: operating targets | All gates retained. Witness RPC/journal flush cost is measured, not assumed to fit 5 ms. No optional cheaper path may bypass integrity to pass benchmarks. |

A-01 is deliberately conservative: per-tenant reservations prevent later work until witness acknowledgment; a witness/journal error ends service rather than replaying uncertain spend. Journal cap is proposed 2 GiB/epoch, separate from correctness histories. Add witness expected-state/journal memory O(TN) and journal bytes to capacity reporting; prototypes must include this overhead. No durability acknowledgment permits mutation of clock timestamps after the fact.

Review invariants: every spend has one owner/provenance; no unknown result authorizes forward/refund; each active grant has one activation; all old replica processes stop before new epoch; no lock spans RPC/I/O, although logical reservations span witness work. Volatile histories require incomplete/UNKNOWN after missing publications; exact accounting needs durable complete evidence. Every gate in §13 remains binding.

Before compiling, RG-001 freezes the numbered wire schema, canonicalization golden vectors, and a machine-readable build lock using versions observed on the actual build host. Do not invent or mark versions validated without a successful build. Implement the remaining modules in §14 order; use clock/commit, witness fail-stop, process-fencing/recovery, and mTLS fixtures as gates before enabling the affected service or claiming its safety properties. Validate PRD-025/026 with AT-28/29; no immediate remote-stop behavior is promised. The documents remain proposed; executable evidence and measured performance are outstanding.

See [principal review record](reviews/principal-design-review-2026-11-04.md). This revision aligns with PRD 7 and SRD 4, whose changes are included in this review.

## 16. Principal contract closure: executable design rules

These rules complete A-01–A-05 and supersede earlier descriptions where a sequencing detail was unspecified. They are design contracts with pending executable evidence.

### 16.1 Witness protocol and failure boundaries

One logical reservation per tenant serializes all strict decisions, grant allocation and cached-grant replies. No C++ mutex remains held across witness IPC or I/O. Transaction identity is (epoch, tenant, next_transition_version); transition versions and journal indices are uint64 starting at 1, never wrap, and exhaustion stops new authority work and initiates DRAINING; request fingerprint covers mode, operation, cost, sequence/slot/incarnation if applicable, previous-state hash and policy digest. Transport request deadlines are not part of an idempotency fingerprint.

1. Reserve tenant, snapshot full bucket plus all ≤8 grant records under mutex, release mutex. Witness Validate compares complete snapshot/version with its independently owned image. Missing/rollback/mismatch ends new authority work; do not recreate state.
2. Reacquire mutex and compare full snapshot again. Check epoch phase and caller deadline, sample CLOCK_MONOTONIC, compute candidate and record event/order in a reserved slot. This is the logical commit instant. Record the candidate as pending visibility; block every successor on this tenant.
3. Send Commit(transaction ID, exact fingerprint, old/new state, commit timestamp). Witness independently recomputes refill/debit/sequence transition from its prior image and immutable policy, rejecting invalid transitions. Do not merely trust the authority's new-state hash.
4. Witness validates expected version, appends a length-delimited record with schema/version, prior-chain hash, payload hash and monotonically increasing journal index, then flushes before publishing new expected state and acknowledgment. Single writer serializes records; batching may combine records from different reserved tenants without acknowledging before flush.
5. On acknowledgment, expose completed result and release reservation. Retry of the same pending transaction must match full fingerprint; witness returns the same acknowledgment for an already committed transaction, with no new append/debit. Older version/different fingerprint rejects. Keep the current transaction result per tenant until a successor completes.
6. Caller cancellation before step 2 releases the reservation without mutation or consuming a grant sequence. After step 2, cancellation only abandons the response; finish internal persistence or fail closed. Caller expiry never rolls back the candidate. Hard witness completion timeout is 20 ms from commit submission; a client can time out sooner. Timeout/failure after possible write enters DRAINING; no successor/reconstruction is allowed.
7. Witness or supervisor crash, torn journal, missing/invalid checksum/index, disk-full, fsync failure, or 2 GiB epoch-journal exhaustion blocks acknowledgments/new work and triggers fencing. Startup never resumes this journal as an ACTIVE epoch. Common-mode rollback of the entire VM and both images is outside the detectable single-record failure model; evidence is UNKNOWN, never a safe pass.

The cached-grant response path performs witness state validation but creates no new debit/transaction. It returns only a previously acknowledged result. Pre-reserve response/event memory to avoid allocation failure halfway through a state mutation. Any postcommit allocation/publication failure follows the uncertain-result/fence rule. Record every witness message, disk write/flush and byte for coordination reports.

### 16.2 Grant concurrency and retry completion

The first eligible waiting request becomes coordinator. Store its exact operation/cost and sequence fingerprint until a known result; changing caller, deadline or operation cannot change an unresolved grant's semantic tuple. Other callers remain bounded by their own deadlines, at most the configured total pending checks; no polling loop spins indefinitely. Same-sequence resolution uses a new transport deadline, exactly the original semantic fingerprint, at most one resolution RPC at a time, and no detached retry worker after epoch shutdown.

Upon a known grant, activate once and atomically reserve/spend the initiating caller's cost before waking unrelated waiters if that caller is still eligible. If the initiating caller has expired, preserve the confirmed batch and return no ALLOW for that caller. A known LIMITED completes the sequence; future attempts may use the next sequence. If UINT64_MAX is consumed, mark EXHAUSTED; it never wraps, while existing confirmed units can still be spent. Return UNAVAILABLE for attempts needing an impossible new sequence and require fenced reset to regain grant issuance.

A grant ID is the canonical composite (epoch UUID16, tenant ID, slot uint32, incarnation UUID16, sequence uint64). It is never used as an admission response. Verify complete tuple, actual granted amount and policy digest before activation. Strict and credit mode are immutable and cannot share one tenant bucket in an epoch.

### 16.3 Timing and response rules

Only trusted internal code converts a gRPC remaining deadline into local monotonic duration on receipt. Clamp internal authority waits to min(20 ms, caller remaining budget); do not propagate an absolute client-supplied clock. After queueing or witness validation, recheck expiry under state protection at the commit instant. A late reply is discarded by the adapter even if server-side work completed.

CLOCK_MONOTONIC provenance is kernel boot ID, identical time-namespace inode/offset and clock ID across authority, replicas and witness. A sampled backwards value or failed syscall fails closed. Wall time is used only for TLS validity; it never determines quota refill. Historical UNKNOWN real-time verdicts cannot be turned into PASS by sorting incomparable clocks.

### 16.4 Wire, values and canonical bytes

Package rateguard.v1. Check strings tenant/operation are configured ASCII identifiers ≤128 bytes. Epoch/incarnation/attempt IDs are exactly 16 bytes; policy digest exactly 32 bytes. Slot is uint32 with configured range, costs/rates/capacity/sequence/retry delay are uint64 with D3 validation. No uint64 JSON number is decoded through floating point. Reply epoch/digest/mode must match the request's active configuration before an adapter considers ALLOW.

Enum numbers: DecisionOutcome {UNSPECIFIED=0, ALLOW=1, LIMITED=2, INVALID=3, UNAUTHENTICATED=4, UNAVAILABLE=5, OVERLOADED=6}; GrantOutcome {UNSPECIFIED=0, GRANTED=1, LIMITED=2, INVALID=3, UNAVAILABLE=4, OVERLOADED=5}; Mode {UNSPECIFIED=0, STRICT=1, CREDIT=2}. Invalid/auth failures use settled transport statuses; reserved application enum values are never mistaken for success. Duplicate scalar protobuf fields and unknown fields follow protobuf parsing rules, but cannot override any trusted transport identity/cost; decoded values still undergo validation. Reuse of removed field numbers is forbidden.

The earlier A-05 field numbering is retained. AcquireCredit operation ID=8 resolves the gap between a trusted operation policy and an unverified numeric trigger cost. No independent requested-batch field is needed: Q comes from policy. SRD §2 reflects this fixed-Q contract. Retry estimate is optional uint64 nanoseconds; absent means unavailable, zero is valid only for immediately eligible/advisory conditions.

Canonical policy bytes begin with schema version u32 big endian. Encode all integral policy fields in their explicit fixed widths, sorted identifier tables using bytewise ASCII order, arrays as u32 count plus records, strings as u32 length plus bytes. Bind tenant B/r/operation costs/Q, mode, slot/incarnation/role/authorization tables and epoch identity. Hash these bytes with SHA-256. Reject duplicate IDs/authorization keys and unknown mandatory fields. Artifact JSON uses named units, decimal-string uint64 values and versioned completeness/count/hash fields. Identifier count limits and 16 KiB decoded protobuf-message limit are checked before new quota state or large dynamic allocation; message framing/compression is outside the 16 KiB protobuf payload but decompression must enforce that bound.

### 16.5 Event completeness and scalable interval checking

Correctness event slots carry Reserved, Published or Incomplete status and a monotonically increasing producer index. Reserve before commit; publish after filling immutable event bytes with checksum. A missing sequence, Reserved slot at crash, truncation, checksum failure or missing producer termination marker prevents an exact complete-history claim. Counters alone never prove that no local spend occurred. Durable acknowledged authority journal supplies grant/strict state evidence; exact local spending requires complete local evidence. Partial histories may establish a concrete violation, but absence of one is UNKNOWN.

Efficient interval check for complete histories: group committed costs at each distinct monotonic integer-nanosecond time t_i, in epoch-relative time. Let P_i be cumulative committed cost in subunits after group i, P_0=0, and K=B*S (strict) or (B+NQ)*S (credit). For all representable half-open integer-nanosecond intervals, maintain m=min over starts i≤j of (P_(i-1)−r*t_i). At each end group j verify P_j−r*(t_j+1)≤K+m. The endpoint t_j+1 includes the entire group; empty intervals contain no events. Use signed checked 128-bit intermediates and reject time+1 overflow. This checks every relevant interval without O(M²) enumeration after sorting; sorting costs O(M log M), scanning O(M), state O(tenants). Compare against independently enumerated small histories and boundary fixtures before using it on million-attempt evidence. The sequential bucket/reference-model check remains separately required: interval bounds alone do not detect reject-all or every illegal state transition.

### 16.6 Frozen workloads and release evidence

PRD-026 defines uniform routing, cost and time exactly; start attempt index j=0 at epoch traffic start, preserve it through 30-second warmup and 60-second measurement, and classify by scheduled arrival time. Wait at most the 50 ms caller deadline after measurement end to settle outcomes; the extra wait creates no new measured arrivals. For three-tenant service load, schedule the two conforming streams every 20 ms and the hot stream every 1 ms; at ties use tenant-ID order, and route each tenant's consecutive attempts round robin. All use cost 1, B=r=100. Each conforming tenant schedules 3,000 measured attempts; hot schedules 60,000.

Performance schedules 450,000 attempts including warmup, 300,000 measured. Every measured block of ten costs is nine unit-1 and one unit-5 overall. Define nearest-rank p99 on all delivered measured attempts, sorted ascending, index ceil(0.99*n); n=0 fails. Measure from adapter receipt to terminal response, include application errors, use cancellation time for caller-cancelled attempts, and record the caller-deadline duration for attempts with no response by deadline. Report outcome-specific distributions and all missed/error counts. Timely means adapter receives ALLOW/LIMITED strictly before its 50 ms deadline; errors/timeouts are failures. Required service ≥99% ALLOW uses offered conforming attempts, not only delivered ones. Generator gate uses delivered/scheduled≥99.5%; terminal gate uses timely valid responses/delivered≥99%. A delivered check is one the generator submitted to the adapter at the scheduled service boundary; mere scheduling is not delivery.

Efficiency uses median of each mode's five per-run operations-per-1000-admitted-cost values; reduction=1−median_credit/median_strict, preserve=median_credit_admitted/median_strict_admitted. Zero baseline or zero admitted cost invalidates comparison. Count every attempted authority RPC including failed/duplicate retries; disclose witness messages/flushes and total coordination separately. All paired runs use identical trace and host/resource limits. No hardware value or capacity-knee evidence is invented: record actual CPU/RAM/container limits before the first benchmark; if delivery or below-knee conditions fail, the run is invalid rather than a reason to relax thresholds.

### 16.7 Generation checklist

Before each module is generated, its inputs, validation, failure path, ownership, algorithm and acceptance evidence must point to these contracts. Generate pure policy/arithmetic plus independent fixtures first; then lifecycle/security/witness, strict A, replay B, credits C and independent model/checker. Pin compiler/CMake/gRPC/protobuf/crypto/model-tool versions in a machine-readable build lock using versions available on the actual build host before compiling; this records environment evidence and never changes runtime semantics. Any discovered inconsistency becomes a failing review gate, not an implicit implementation choice.

The recorded semantic findings are resolved in this revision. Conformance tests, fault experiments, model exploration and performance measurement are still required; neither this checklist nor a zero-findings review can guarantee bug-free generated code.

## 17. Class design and construction contracts

All classes/files below are **planned**. C++20 is the implementation language baseline; use std::variant<T,Error> as Result<T>, not an undeclared exception convention or C++23-only std::expected. Error has category, stable code, retry disposition, commitment (NotCommitted/Possible/Committed) and optional bounded diagnostics; no credential values. Constructors return validated factories when validation can fail. Runtime dependencies outlive services and are injected by reference; no hidden global mutable state.

### 17.1 Class ownership and interfaces

Signatures are contract sketches; strong domain types and cancellation/deadline arguments refer to §§3–4/16.

| Class / planned file | Owned state and dependencies | Public operations and invariant |
| --- | --- | --- |
| PolicySnapshot / src/policy/policy_snapshot.h | Immutable tenants, operations, role permissions, mode/Q/slots; shared_ptr<const PolicySnapshot> | FindTenant, ResolveOperation, Authorize; lookup never inserts, returns immutable view with snapshot lifetime |
| PolicyLoader / src/policy/policy_loader.h | No runtime state; bounded parser + CanonicalPolicyCodec | Load(ConfigBytes)→Result<PolicySnapshot>; reject duplicate/malformed/out-of-range config before readiness |
| CanonicalPolicyCodec / src/policy/canonical_codec.h | Stateless | Encode, Digest; §16.4 fixed canonical order/widths, independent golden vectors |
| IClock / src/platform/clock.h | Abstract dependency | Now→Result<MonoNanos>, Provenance→ClockIdentity; fake clock internal only |
| LinuxMonotonicClock / src/platform/clock_linux.h | Verified boot/namespace/clock identity | Implements IClock; syscall/provenance/backwards failures return typed integrity error |
| PeerAuthenticator / src/security/peer_authenticator.h | Immutable trust registry + trusted wall-time provider | Authenticate(TransportPeer)→Result<AuthenticatedPeer>; role/SAN/EKU/expiry checked every RPC |
| AuthorizationResolver / src/security/authorization.h | PolicySnapshot reference | Resolve(peer,tenant,operation)→Result<AuthorizedOperation>; sole constructor of trusted operation/cost |
| EpochGate / src/supervisor/epoch_gate.h | Atomic observed phase + epoch identity | ObserveDrain, PermitCommit(expectedEpoch), Phase; transitions monotonic ACTIVE→DRAINING→CLOSED |
| TenantLedger / src/authority/tenant_ledger.h | Mutex, immutable identity, bucket, fixed grant-result array, version, reservation state | BeginReservation→Result<TenantReservation>; ReadSnapshot; no public balance setter |
| TenantReservation / src/authority/tenant_reservation.h | Move-only reservation token, original version/snapshot, phase | ValidateSnapshot, CommitCandidate, CompleteAck, Fail; only this token can change the reserved tenant |
| BucketMath / src/authority/bucket_math.h | Stateless production arithmetic | Refill, Decide, RetryDelay; checked 128-bit D3 arithmetic, never accesses clock or global state |
| IStateWitness / src/authority/witness_port.h | Abstract authority boundary | Validate, Commit, QueryAck; exact identity/fingerprint/version per §16.1 |
| LocalStateWitnessClient / src/authority/local_witness_client.h | Unix-socket client bound to supervisor identity; implements IStateWitness | Validate, Commit, QueryAck; authenticates expected server and keeps exact transaction fingerprint |
| WitnessServer / src/supervisor/witness_server.h | Supervisor-owned local socket; refs peer identity, WitnessStateMachine and JournalWriter | Dispatch validated authority requests; reject unrelated process identity before touching witness state |
| DockerProcessController / src/supervisor/docker_process_controller.h | Implements IProcessController using local runtime API and recorded identities | Start, InspectIdentity, Stop, ConfirmExited; never infer exit from missing network reply |
| WitnessStateMachine / src/supervisor/witness_state.h | Independent expected tenant images and last acknowledgments; own arithmetic validator | ValidateSnapshot, ValidateTransition, PublishAck; cannot import BucketMath as its validator |
| JournalWriter / src/supervisor/journal_writer.h | Single joined worker, append fd, chain/index, fixed queue and 2 GiB budget | AppendAndFlush→Result<DurableAck>; ack only after flush; no active-epoch recovery |
| AuthorityEngine / src/authority/authority_engine.h | Preloaded TenantLedger objects; refs clock, witness, policy, gate, recorder | StrictCheck, AllocateCredit, ReplayGrant; private shared ExecuteTransition follows reservation/ack protocol |
| IAuthorityClient / src/admission/authority_client.h | Abstract replica dependency | Check, Acquire, ResolveGrant; deadline/cancel propagation; automatic transport retry disabled |
| GrpcAuthorityClient / src/admission/grpc_authority_client.h | RAII channel/stub + registered identity | Implements client; maps raw transport loss to Possible commitment |
| ReplicaTenantCredits / src/credits/tenant_credits.h | Mutex/CV, active batch, seq/fingerprint, pending coordinator, remainder counters | TrySpend, BeginAcquire, Resolve, Stop; state transitions exactly §6/16.2 |
| CreditManager / src/credits/credit_manager.h | Fixed map of ReplicaTenantCredits, slot/incarnation; refs client/policy/clock/gate | Check; one coordinator and one grant RPC at a time per tenant; no prefetch or cross-slot reuse |
| AdmissionService / src/admission/admission_service.h | gRPC handler, bounded pending-slot pool; refs auth/authority/credits/events | CheckAdmission; mode routing immutable, decodes/validates before state allocation |
| AuthorityService / src/authority/authority_service.h | Internal gRPC facade; refs auth and AuthorityEngine | StrictCheck and AcquireCredit RPCs; only registered replica identity can call |
| ForwardAttempt / adapter/forward_attempt.h | Attempt ID, deadline, atomic Pending/ForwardStarted/Expired/Failed | TryForwardTransition; exactly one CAS winner; does not retry backend automatically |
| SampleAdapter / adapter/sample_adapter.h | Trusted fixture mapping and bounded active ForwardAttempt objects | Handle; derive authorized context, call admission, enforce receipt/epoch/deadline, never replay after crash |
| ManifestStore / src/supervisor/manifest_store.h | Supervisor-owned directory/lock fd; immutable validated manifest snapshots | Load, AtomicReplace; fsync/rename/dir-fsync failures prevent activation; no anti-rollback claim from rename |
| IProcessController / src/supervisor/process_controller.h | Abstract local runtime boundary | Start, InspectIdentity, Stop, ConfirmExited; identity includes boot/container/PID-start values |
| EpochSupervisor / src/supervisor/epoch_supervisor.h | Exclusive control thread, inventory/operation state, WitnessStateMachine, JournalWriter | StartEpoch, Drain, FenceAndClose, RecoverAfterCrash; never adopts old ACTIVE epoch |
| EventRecorder / src/events/event_recorder.h | Fixed run-wide budget, producer sequences and reserved slots | Reserve→Result<EventReservation>, Publish, SealIncomplete; no identifiers as metric labels |
| HistoryExporter / src/events/history_exporter.h | Bounded streaming file writer | Export with count/hash/complete markers; cleanup follows D7; missing producer seal yields incomplete |
| TraceGenerator / tools/loadgen/trace_generator.h | Immutable workload spec and integer index | Next; exact PRD-026 schedule, no output-dependent retry/routing |
| BenchmarkRunner / tools/loadgen/runner.h | Open-loop scheduler and pinned manifest | RunPair; scheduled membership, 50 ms settlement, counts and invalid-run reasons |
| ReplayModel / tools/replay/reference_model.h | Independent pure model state | ApplyOffered, ComparePolicies; no production BucketMath/AuthorityEngine imports |
| HistoryChecker / tools/history_checker/checker.h | Independent parser/model/config | Check, ExplainCounterexample; prefix interval check plus serial/provenance validation; UNKNOWN on missing evidence/resource limit |
| ModelHarness / model/runner | Pinned external model-check tool/config | EnumerateDeclaredBounds, Mutate, ExportCounterexample; tool output cannot self-certify production code |

### 17.2 Construction, lifetime and threading

ServiceRuntime owns instances in dependency order: validated policy/trust/clock → gate/recorder → ledger/witness/client → engines/services → servers. Stop reverses admission: reject new RPCs, mark DRAINING, wake CV waiters, cancel bounded transport waits, join workers, seal/export available histories, destroy services, then dependencies. A crash bypassing graceful shutdown triggers incomplete evidence and supervisor fencing. No detached task may retain raw pointers to destroyed services; pending operations hold owned request buffers and validated snapshot shared_ptrs.

TenantReservation is move-only. Destruction before CommitCandidate cancels reservation without mutating state. Destruction after CommitCandidate without durable acknowledgment calls Fail, enters DRAINING and preserves Possible commitment; it must never undo the debit or release the ledger for successors. CompleteAck checks exact tenant/version/fingerprint, then clears reservation and wakes waiters. No recursive calls into the ledger while its mutex is held. Only one reservation is active per tenant across strict/grant/read-replay paths.

JournalWriter owns its descriptor and joined worker exclusively. Queue capacity is fixed at 1,024 transition records, each bounded to 16 KiB; reservation/queue acquisition occurs before commit so overload cannot silently strand a postcommit append. Per-tenant ordering and durable indices are maintained; batching never changes commit timestamps. Grant result snapshots contain ≤8 fixed-slot records, so encoding must be size-validated at startup; configuration whose transition record cannot fit is rejected before traffic. Existing in-flight records finish or become uncertain when the 2 GiB cap/IO failure occurs. Supervisor continues to account old credit holders until CLOSED.

AuthorityService exposes both the strict internal check and credit grant port. AdmissionService never exposes the witness socket or a balance-reset endpoint. Only Supervisor constructs a new epoch and authority identity; local mutexes cannot authorize a second authority instance. IProcessController positively verifies identity/exit; container names alone cannot prove fencing.

### 17.3 Class collaboration

```mermaid
classDiagram
  AdmissionService --> AuthorizationResolver
  AdmissionService --> IAuthorityClient
  AdmissionService --> CreditManager
  CreditManager *-- ReplicaTenantCredits
  AuthorityService --> AuthorityEngine
  AuthorityEngine *-- TenantLedger
  TenantLedger --> TenantReservation
  AuthorityEngine --> IStateWitness
  IStateWitness <|.. LocalStateWitnessClient
  LocalStateWitnessClient --> WitnessServer
  WitnessServer --> WitnessStateMachine
  IAuthorityClient <|.. GrpcAuthorityClient
  IProcessController <|.. DockerProcessController
  EpochSupervisor *-- WitnessStateMachine
  EpochSupervisor *-- JournalWriter
  EpochSupervisor --> ManifestStore
  EpochSupervisor --> IProcessController
  AuthorityEngine --> IClock
  CreditManager --> IClock
  SampleAdapter *-- ForwardAttempt
  AuthorityEngine --> EventRecorder
  CreditManager --> EventRecorder
```

Class-level seam acceptance: substitute IClock, IAuthorityClient, IStateWitness and IProcessController through constructors only. Test duplicate RPC callbacks against ReplicaTenantCredits; injected mutation during reservation against TenantLedger/WitnessStateMachine; fsync/ack loss against JournalWriter/AuthorityEngine; forwarding races against ForwardAttempt; all stop/fencing outcomes against EpochSupervisor. Independent ReplayModel/HistoryChecker use only versioned artifacts and policy input, not production decision functions. Every proposed class maps to a story in [implementation stories](STORIES.md) and the machine-readable [context blocks](context-blocks.json).

### 17.4 Per-process composition

SupervisorRuntime owns ManifestStore, DockerProcessController, EpochSupervisor, WitnessServer, WitnessStateMachine and JournalWriter. AuthorityRuntime owns TenantLedgers, AuthorityEngine/AuthorityService and LocalStateWitnessClient; it never shares a pointer to supervisor witness memory. ReplicaRuntime owns AdmissionService, CreditManager and GrpcAuthorityClient. AdapterRuntime owns SampleAdapter and its gRPC admission client. Evaluation tools own independent ReplayModel/HistoryChecker. ServiceRuntime refers to this per-process construction pattern; it is not one address space for all components. All cross-process transitions use the explicit authenticated ports.

Witness Validate pre-reserves a bounded journal queue slot and maximum record byte budget before returning permission to prepare a transition; no automatic eviction/lease expiry can remove it while the authority may commit. It is released only on explicit precommit abort, committed acknowledgment, or fenced epoch shutdown. This prevents postcommit capacity rejection from becoming an unrecorded ordinary overload. Duplicate Validate with identical transaction identity returns its existing reservation. Only crashes/I/O/integrity failures can invalidate a postcommit reservation, and those follow DRAINING/uncertainty rules.


## 18. Revision 5 — metric and implementation-readiness closure

PRD 8 / SRD 5 define the p99 population as all delivered attempts, including error responses; a missing response contributes the caller-deadline duration. The latency measurement begins at adapter receipt and ends at the first terminal application response or deadline. This prevents completion-only sampling from hiding timed-out calls.

The implementation toolchain is intentionally not pre-pinned in this document: the current local path has documentation only and no verified Git checkout or Linux build environment. RG-001 must capture compiler, CMake, gRPC, Protocol Buffers, crypto, and model-tool versions from the actual supported build host and produce a successful reproducible build before the lock is treated as validated. This is a sequencing decision, not a guessed compatibility matrix. Clock, witness, fencing, and certificate tests remain required before activating enforcement services or claiming acceptance. No implementation or evidence is claimed here.
