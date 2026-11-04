# DistributedRateGuard — Low-Level Design

**Revision:** 1 · **Date:** 2026-11-04 · **Status:** Proposed implementation design  
**Normative sources:** PRD revision 6 and SRD revision 3 on `main`.  
**Architecture input:** [Proposed HLD revision 1](https://github.com/kshiteesh28/DistributedRateGuard/blob/docs/hld-design-review-v2/docs/HLD.md), currently on its review branch.  
**Implementation status:** No implementation or test result is claimed by this document.

## 1. Purpose and design boundaries

This document turns the PRD/SRD contracts into proposed modules, interfaces, state transitions, synchronization and build increments. It does not authorize implementation. Release order remains A strict core, B replay/evaluation, C fixed-Q credits and independent model checking. PRD-013 live policy changes and PRD-014 long-operation permits remain excluded.

Target is one Docker Linux VM with a shared verified kernel time namespace and `CLOCK_MONOTONIC`. Multi-host enforcement and transparent authority failover remain unsupported. The fixed-Q credit rule, per-epoch bound `B+rΔt+NQ`, 50 ms caller deadline, 5 ms p99 goal, 99% timely ALLOW/LIMITED goal, 99.5% generator delivery, 1,000,000 attempts per mode, and all caps are requirements, not achieved results.

## 2. Module map

Proposed paths; repository currently has no implementation layout to preserve.

| Module | Proposed file(s) | Responsibility / dependencies |
| --- | --- | --- |
| Wire contract | `proto/rateguard/v1/admission.proto` | Versioned CheckAdmission, AcquireCredit and explicit Outcome messages. Depends on D1/D2 schema decision. |
| Configuration | `include/rateguard/policy.h`, `src/policy.cpp` | Parse/validate immutable epoch config, numeric ranges, operation costs and canonical digest. No runtime mutation. |
| Clock | `include/rateguard/clock.h`, `src/clock_linux.cpp` | Return monotonic nanoseconds and provenance (boot, namespace, clock ID); reject unsupported/mismatched contexts. |
| Identity | `src/identity.cpp` | Map authenticated mTLS URI SAN principal and operation to configured tenant and cost. Never accept user override. |
| Strict authority | `include/rateguard/authority.h`, `src/authority.cpp` | Own tenant buckets; atomic refill, decision and grant journal operations. |
| Replica service | `src/admission_service.cpp` | Validate, deadline handling, call strict authority or credit manager, map domain outcomes to gRPC. |
| Credit manager | `include/rateguard/credits.h`, `src/credits.cpp` | Per-replica/tenant grant state, sequence calls, local spending, retirement and accounting. |
| Supervisor | `src/epoch_supervisor.cpp` | Inventory and lifecycle orchestration, startup validation, terminal epoch and positive fencing. |
| Adapter | `adapter/sample_adapter.cpp` | Trusted upstream context, gRPC client and forwarding gate. |
| Replay/model | `tools/replay/`, `model/` | Independent deterministic replay, bounded state model, implementation history checker. Must not call production decision logic as oracle. |
| Telemetry | `include/rateguard/events.h`, `src/events.cpp` | Bounded event records, counters and reconciliation exports. |

Suggested library dependencies are standard C++ RAII, gRPC/Protocol Buffers and a JSON parser; exact versions/build wiring remain to be pinned in the implementation manifest. No Redis/DB dependency is introduced.

## 3. Domain types and ownership

Illustrative C++ types; these are design sketches, not compile-ready declarations.

```cpp
using TenantId = std::string;
using OperationId = std::string;
using EpochId = std::array<std::byte, 16>;
using PolicyDigest = std::array<std::byte, 32>;
using AttemptId = std::array<std::byte, 16>;
using GrantId = std::array<std::byte, 16>;
using Sequence = std::uint64_t;
using MonoNanos = std::uint64_t;
using CostSubunits = std::uint64_t; // 10^9 subunits per policy unit

enum class Outcome {
  Allow, Limited, Invalid, Unauthenticated, Unavailable, Overloaded
};

struct BucketState {
  CostSubunits balance;
  MonoNanos last_refill;
};

struct GrantResult {
  Sequence sequence;
  Outcome outcome;
  GrantId grant_id;
  CostSubunits granted;
  MonoNanos commit_time;
};

struct ReplicaCredit {
  GrantId grant_id;
  CostSubunits remaining;
  Sequence sequence;
  EpochId epoch;
  std::uint32_t slot;
  std::uint64_t incarnation;
};
```

The authority exclusively owns bucket and grant-result maps for one epoch. Replica credit state belongs to one fixed slot/incarnation and is never transferable. Policy is immutable and shared by digest. Adapter identity resolution owns the trusted tenant/operation mapping. Events carry attempt/grant IDs, epoch and monotonic time; sensitive certificate contents and raw upstream identities are not event fields.

All amount arithmetic uses D3 fixed-point units (10^9 subunits per unit), nanosecond time, checked 128-bit intermediates, and explicit caps: B/r up to 10^9 units, cost positive and no greater than B, Q within [max_cost,B]. Reject overflow or sequence exhaustion; never wrap. Refill is:
`added_subunits = rate_units_per_second × elapsed_nanoseconds`;
because the scale is 10^9 subunits/unit and 10^9 nanoseconds/second, the product is numerically subunits. Cap at `B × 10^9`. Preserve integer arithmetic exactly; do not round upward. This unit cancellation and representation must be independently reviewed before implementation.

## 4. Interfaces and error mapping

Proposed domain-level interfaces:

```cpp
DecisionResult check(const TrustedContext&, const OperationId&,
                     AttemptId, MonoNanos deadline);
GrantResult acquire(const TenantId&, SlotId, Incarnation, EpochId,
                   PolicyDigest, Sequence, CostSubunits trigger_cost,
                   MonoNanos deadline);
LocalSpendResult spend(const TenantId&, CostSubunits cost,
                       AttemptId, MonoNanos now);
```

Only the service constructs `TrustedContext` after successful peer certificate validation and policy mapping. Callers cannot pass cost, tenant, timestamp or mode overrides. Validation of unknown principal, tenant, operation, digest, epoch, slot or invalid cost occurs before state mutation. Unknown tenant never creates a bucket.

| Domain result | gRPC application/transport behavior | Quota mutation | Adapter action |
| --- | --- | --- | --- |
| ALLOW | Explicit application outcome | Debit at commit | Forward once only if received by deadline and epoch remains active |
| LIMITED | Explicit application outcome; retry estimate advisory | No cost debit (bucket refill timestamp may advance); a valid grant LIMITED result consumes its sequence | Do not forward |
| INVALID | INVALID_ARGUMENT | None | Do not forward |
| UNAUTHENTICATED | UNAUTHENTICATED | None | Do not forward |
| Unauthorized principal | PERMISSION_DENIED | None | Do not forward |
| UNAVAILABLE | UNAVAILABLE or uncertain transport result | May have committed if response lost | Do not forward or assume refund |
| OVERLOADED | RESOURCE_EXHAUSTED mapping proposed; exact mapping D2 check | None before commit | Do not forward |

**D2 conflict:** SRD D2 says exact gRPC status mapping remains a blocking decision, while PRD 6/ SRD 3 accepted D1/D2 and PRD-024 requires registered adapters. The mappings above are proposed defaults, not settled contract. Confirm mapping in source SRD before protobuf implementation; transport failure after dispatch is always potentially uncertain.

## 5. Strict token bucket algorithm and concurrency

For each tenant, the authority protects a bucket with one per-tenant mutex. A map-level shared mutex protects lookup/creation only; acquire the map lock, obtain a stable shared pointer to the tenant state, release the map lock, then lock tenant state. No path may acquire map lock while holding tenant lock. This lets independent tenants proceed concurrently while serializing one hot tenant. Tenant entries are preloaded from finite policy; request traffic cannot create them.

At the critical section, sample CLOCK_MONOTONIC exactly once as the transition time; reject if deadline has passed. Require now ≥ last_refill; otherwise stop the epoch and report clock integrity failure. Compute elapsed, refill, compare and update balance plus last_refill as one protected transition. For cost c:

```text
available = min(B_subunits, balance + r × (now - last_refill))
if available >= c_subunits:
    balance = available - c_subunits
    outcome = ALLOW
else:
    balance = available
    outcome = LIMITED
last_refill = now
```

Timestamp capture must correspond to the state transition's linearization point, not be sampled at the RPC edge. The HLD has not selected an atomic storage mechanism. Per-process mutexes are insufficient if more than one authority process can own state; startup must enforce exactly one authority identity.

## 6. Credit grant and spending state machine

For each (tenant, slot), authority tracks next expected sequence and the latest committed result. Replica tracks at most one active batch plus one pending request.

```text
EMPTY -> REQUEST_PENDING(k)
REQUEST_PENDING(k) --known grant--> ACTIVE(grant,k,remaining)
REQUEST_PENDING(k) --known LIMITED--> EMPTY with k recorded as consumed
REQUEST_PENDING(k) --timeout/unknown--> UNKNOWN(k)
UNKNOWN(k) --retry same k--> known result
ACTIVE --remaining >= cost--> ACTIVE with atomic subtraction; ALLOW
ACTIVE --remaining < cost--> RETIRE remainder -> EMPTY -> request next sequence
Any state --epoch mismatch/fatal integrity--> STOPPED
```

The next sequence is permitted only after a known result for k. Duplicate k returns that exact result, including LIMITED after refill. A skipped/stale sequence is rejected without bucket debit. Grant allocation under tenant lock uses the same bucket refill as strict mode: grant Q if available ≥Q; else grant floor(available) whole units if ≥trigger cost; else LIMITED. Store result and debit under the same transition. A result with zero grant is not created. Replica activates a grant once after validating epoch/slot/incarnation/digest/sequence and unique grant ID.

Local spend is one critical section per tenant/slot: ensure ACTIVE, matching epoch and incarnation, sufficient integer subunits; subtract cost then append the local committed event before returning ALLOW. If event storage cannot record a committed spend, stop that slot; do not claim exact spend history. Retire a remainder smaller than the triggering operation before attempting another grant. No refund or transfer operation exists.

**Uncertain result:** On timeout after AcquireCredit dispatch, keep UNKNOWN(k), do not request k+1, do not use a grant whose response was not confirmed, and retry k only while same epoch is active. A known grant response lost after authority commit is recovered by duplicate k. If authority process dies, epoch ends; no retry crosses epochs.

## 7. Clock, deadlines, and epoch APIs

A `ClockSource` returns monotonic nanoseconds and a provenance tuple (kernel boot identity, time namespace identity, clock ID). Startup compares authority/replica provenance. It refuses readiness on mismatch, backwards time, boot change, or unknown identity. Server commit times—not caller timestamps—feed safety checking. The service checks caller deadline before entering the critical transition and checks active epoch before returning. If expiry races after commit, return no usable ALLOW to adapter, emit committed-but-unforwarded, and never refund.

Supervisor transitions:

```text
STOPPED -> VALIDATING -> STARTING_AUTHORITY -> STARTING_REPLICAS
        -> STARTING_ADAPTER -> ACTIVE
ACTIVE -> QUIESCING -> STOPPING_ADAPTER -> STOPPING_REPLICAS
       -> STOPPING_AUTHORITY -> VERIFY_ALL_EXITED -> EPOCH_TERMINAL
EPOCH_TERMINAL -> WRITE_NEW_MANIFEST -> VALIDATING
Any unknown participant/process state -> BLOCKED
```

Manifest replacement uses write-temp, fsync file, atomic rename and fsync directory. However, independent anti-rollback/integrity witness for each volatile authority record is not designed: HLD-01 remains a blocker. A file manifest alone cannot detect a record lost while the authority process still runs. Implementation of epoch recovery must wait for an accepted HLD/PRD/SRD resolution.

## 8. mTLS and service authorization

At each gRPC connection, validate certificate chain, validity interval, EKU and registered URI SAN principal. Map principal to configured roles: adapter, replica, supervisor-control or generator. Admission RPCs accept adapter principals only; authority RPCs accept replica principals only; lifecycle control accepts supervisor only. The exact certificate authority, key distribution, rotation protocol, revocation and local secret storage remain HLD-02 and must be decided before implementation. Never log private keys, full certificates or secret material. Tests use generated short-lived certificates and cover unknown SAN, expired certificate, wrong role, forged tenant header and allowed mapping.

## 9. Resources, event journal and retention

Apply SRD D6: ≤10,000 configured tenants; ≤8 slots; ≤1,024 pending requests per replica; ≤16 KiB request; authority wait ≤20 ms and ≤remaining caller deadline; correctness history ≤1 GiB/run. Reject excess tenant/config at startup, return OVERLOADED at queue saturation, reject oversized messages, and return UNAVAILABLE on authority wait expiry. Do not evict active tenant buckets or credit state. If history hits cap, stop and mark the run incomplete; never drop events silently.

Events have immutable AttemptId/GrantId, epoch, source component, event kind, monotonic timestamp, outcome and units where relevant. Owners: generator offered; authority strict commit/grant charge; replica local commit/response; adapter received/forwarded; backend completed. Metrics use bounded labels only. At quiescence require completed ⊆ forwarded ⊆ timely received ALLOW ⊆ committed ALLOW; committed can exceed responded after a lost response. Grant accounting is consumed + remaining + retired + stranded; after crash with incomplete local events report a conservative interval. D7 synthetic-only artifacts remain locally seven days and cleanup occurs at next startup/run. Exact event encoding and durable export are implementation details; event completeness is an unresolved gate if crash can occur before append.

## 10. Replay and independent verification

Replay input: schema version, policy digests, complete offered attempts, relative arrivals, stable tie order, tenant/operation, initial state and trace hash. Reject missing/ambiguous rows. Replay has an independent implementation of the token bucket and credit ledger and never imports production decision code.

Release C model checker explores at least the SRD AT-26 bounded configurations, legal state transitions, deadlines, repeated/lost grants, local spending, partition, crash and epoch stop. Check grant uniqueness, conservation, no cross-epoch spend, per-epoch interval bound, and sequence semantics. The implementation-history checker consumes stage events, searches for a legal serial order respecting non-overlap, and checks every interval induced by commit timestamps. Missing clock provenance or missing history yields UNKNOWN/invalid, never PASS. Mutants for double spend, duplicate grant and stale epoch must produce deterministic counterexample traces. This is bounded evidence, not universal proof.

**HLD-03 conflict:** SRD D8's 1,000-request blocks route to a single replica, while NFR-003 requires uniform routing. Preserve both inputs as conflicting until product documents resolve the intended trace. Do not write a single expected replay/benchmark result for the conflicting case.

## 11. Complexity, synchronization, and failure propagation

Policy lookup is O(1) average by tenant/operation maps; each tenant decision is O(1), protected by its tenant mutex. Grant journal lookup is O(1) average by (tenant,slot,sequence). Replica credit lookup/spend is O(1) average, serialized per tenant/slot. Replay and model exploration depend on trace/state count; enforce documented bounds and stream output. No global lock is held across RPC or disk I/O. Never call authority while holding local credit lock. Lock order is configuration snapshot → map lookup → tenant state; release outer locks before taking tenant locks.

Errors propagate as typed domain outcomes; transport failures after dispatch are marked uncertain, not converted to LIMITED. Shutdown stops admission of new work, drains only until bounded deadlines, records unresolved calls, and marks epoch terminal; a timeout does not mean a participant stopped. Supervisor requires observed process exit.

## 12. Test seams and requirement mapping

Test seams are injected ClockSource, in-process Authority interface, fake gRPC transport capable of dropping messages before/after commit, deterministic policy/trace fixtures, and process supervisor adapter. Keep these behind internal interfaces; do not expose test-only RPCs.

| Requirements | Implementation owner | Planned acceptance |
| --- | --- | --- |
| PRD-001–003; FR-001–003; NFR-001 | policy, clock, authority | AT-01–04, AT-21, boundary/fixed-point oracle |
| PRD-004–005; FR-004–006; NFR-002/009 | identity, service, adapter | AT-05–07, AT-22/27 |
| PRD-006; FR-011/012 | replay | AT-12 golden trace/hash repeat |
| PRD-007/008/015/024; FR-007–010 | supervisor, events | AT-08–11; missing state and stale epoch faults |
| PRD-010–012; FR-013; NFR-003/006/007 | generator/runner | AT-13/23/25; frozen manifests |
| PRD-016–019; FR-014–018; NFR-001 | credits, authority, checker | AT-14–18/21; fixed Q and failure matrix |
| PRD-020/022; FR-019; NFR-004/005/009 | benchmark runner | AT-19/22–24/27 |
| PRD-021/023; FR-020/021 | model/checker | AT-20/26, seeded counterexample evidence |
| PRD-013/014 | deferred | No release implementation |

## 13. Ordered implementation increments

1. **Contract and build skeleton:** resolve D1/D2 wire mapping; pin C++/gRPC/compiler/dependency versions; compile generated protobuf and service shell. Acceptance: schema compatibility and build manifest are reproducible.
2. **Pure policy and arithmetic:** validated immutable config, canonical digest, fixed-point bucket reference model and clock abstraction. Acceptance: numeric boundary, overflow, rounding and model tests; no RPC or persistence.
3. **Strict authority and RPC:** single authority identity, per-tenant serialization, deadline checks, explicit outcomes, trusted mTLS adapter. Acceptance: AT-01–11 for A and one/three replicas.
4. **Evaluation:** deterministic open-loop generator, trace format, independent replay, reports, manifest and clean setup. Acceptance: AT-12/13/22/23/25/27. Resolve HLD-03 before certifying workload gates.
5. **Credit baseline:** fixed slots, grant sequence journal, idempotent result, local atomic spend, retirement and conservative stranded accounting. Acceptance: AT-14–19/24 and one million attempts per mode.
6. **Independent assurance:** bounded state model, history checker, seeded mutants and reproducible traces. Acceptance: AT-20/21/26 and PRD-023 evidence. Do not claim universal proof.
7. **Release review:** reconcile all PRD/SRD gates, raw results, unresolved failures and two clean reproductions. Misses keep release incomplete.

## 14. Blocking decisions and consistency review

- **LLD-01 (blocking):** resolve HLD-01 authority record integrity. Volatile per-process state plus a manifest cannot independently detect a lost individual record. This prevents a truthful fail-closed AT-09 implementation.
- **LLD-02 (blocking):** resolve HLD-02 internal mTLS certificate identity, provisioning, rotation and revocation before service-to-service code.
- **LLD-03 (blocking gate):** resolve HLD-03 routing conflict in source requirements before benchmark gate certification.
- **LLD-04:** finalize D2 gRPC status mapping and protobuf compatibility policy.
- **LLD-05:** define whether event append occurs synchronously with local spend and what durable evidence survives process kill; otherwise exact event reconciliation must be UNKNOWN after loss.
- **LLD-06:** pin toolchain/dependency versions and actual host CPU/RAM before capacity run.

Consistency check: strict mode consults authority for each decision; credit mode spends only confirmed unique grants. Credits do not make the mode strict-equivalent; the additional NQ burst allowance is explicit. Both bounds are per epoch. Unknown RPC results never authorize forwarding or refunds. A state-integrity or clock failure fails closed. PRD-022's 99% timely outcome gate and PRD-020's credit-efficiency gate are separate and both must pass.

## 15. Status

This LLD is a proposed implementation design derived from the PRD, SRD and HLD review branch. HLD-01, HLD-02 and HLD-03 remain blockers. No code, tests, benchmark, model check, or production readiness is claimed. Resolve blockers before implementing affected modules.
