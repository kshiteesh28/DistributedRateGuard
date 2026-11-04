# RateGuard — Product Requirements Document

**Revision:** 4 · **Status:** Proposed · **Date:** 2026-11-03  
**Owner:** Kshiteesh · **Target:** Backend and infrastructure engineers operating multi-tenant APIs

## Decision in one minute

RateGuard will enforce per-tenant API budgets across service replicas and compare two admission modes:

- **Strict:** every attempt makes one authoritative quota decision. This is the correctness baseline.
- **Distributed credits:** replicas admit requests from credits allocated in advance. This reduces authority calls but permits a larger, explicitly bounded burst.

An offline replay tool will show how a policy change affects a fixed offered-traffic trace. The project succeeds when another engineer can reproduce the correctness results, see the performance trade-off, and understand where the guarantees stop. It does not need to outperform existing rate limiters to be useful.

## Problem and user workflow

A SaaS backend serves several tenants through multiple gateways. A batch client can create a burst while other tenants continue normal traffic. Instance-local counters multiply the effective quota as gateways scale. A single shared bucket protects aggregate capacity but cannot express individual tenant reservations. Operators also need to understand the effect of a quota change before enabling it.

The backend engineer integrates an admission check before forwarding work. The platform engineer configures tenant budgets and evaluates candidate policies. The application receives a distinct quota, validation, or dependency-failure response. Tenant identity and operation cost come from a trusted integration, never an arbitrary client-supplied value.

The intended workflow is: configure a policy → reproduce a traffic scenario → inspect decisions and customer impact → compare a candidate policy offline → select a mode with a stated guarantee → verify the behavior under contention and failure.

Existing infrastructure already covers much of this use case. The [Envoy rate-limit service](https://github.com/envoyproxy/ratelimit) provides gRPC and Redis integration; [Gubernator](https://github.com/gubernator-io/gubernator) uses key ownership and batching, with an optional eventually consistent global mode. RateGuard's contribution is a small, inspectable comparison of consistency, coordination cost, and policy impact. This is a product hypothesis; no user interviews or adoption data exist yet.

## Scope and release sequence

| Release | Deliverable | Exit condition |
| --- | --- | --- |
| **A — strict core** | C++/gRPC service, static policy, one logical authority, multiple replicas, trusted sample adapter, independent model, fault tests | Quota, error, and restart contracts pass their evidence gates. |
| **B — evaluation** | Deterministic replay, comparable baselines, workload generator, raw results | An engineer can reproduce the policy comparison and measured operating envelope. |
| **C — distributed credits** | Allocated-credit mode and a strict-versus-credit experiment | Credit conservation, burst bound, failure behavior, and cost of unused credits are demonstrated. |

One policy and mode are fixed for each epoch. An epoch is an explicitly initialized enforcement run with one authority identity and initial state. A new epoch is an operational reset, not seamless failover. V1 excludes live policy changes, automatic credit reclamation, multi-region enforcement, compound quotas, long-operation permits, and production availability claims. Docker is the local deployment target. The README's earlier Redis Cluster and etcd references are historical project context, not requirements for these releases.

## Contract and guarantees

**Common contract.** Each preconfigured tenant has a replenishment rate `r`, burst capacity `B`, and trusted operation costs in positive integer units. Cost must not exceed `B`. Unknown tenants, operations, invalid policies, and unauthenticated calls consume no quota. A response identifies outcome, policy, mode, epoch, and correlation ID. Received `ALLOW` permits forwarding only within the caller deadline and active epoch. `LIMITED` means no cost was charged for that attempt; `UNAVAILABLE` and `OVERLOADED` are distinct from quota exhaustion. A lost response may conceal a committed spend, so the caller does not forward or assume a refund. Retry estimates are advisory, not reservations. Downstream failure does not refund quota.

**Strict mode.** The authority refills a tenant balance to at most `B`, then atomically decides and spends the request cost. Concurrent attempts must admit according to a legal sequential order. For any interval of duration `Δt`, admitted cost cannot exceed `B + rΔt` under the documented time boundary. Correctness also requires admitting eligible requests in serial tests; reject-all is not acceptable. Caller timestamps cannot create allowance.

**Credit mode.** Fix `N` replica slots for an epoch and a per-tenant batch size `Q`, where `maximum operation cost ≤ Q ≤ B`. An atomic authority grant spends up to `Q` units from the same budget. A grant belongs to one tenant, epoch, replica incarnation, and sequence. A replica holds no more than one batch per tenant; local spending is atomic. Before obtaining another grant, it permanently discards a remainder too small for the triggering cost. Retired and lost credits are never automatically refunded. A retry of the same grant sequence returns the same result without another charge. Unknown grant outcomes block a new sequence until resolved. An old slot cannot be reused during the epoch.

The conservative credit-mode envelope is `admitted cost ≤ B + rΔt + NQ`: at most `NQ` previously allocated units can be carried into the interval, and new grants follow the authority's bucket. This is a bounded additional burst, not strict-mode equivalence. The bound assumes unique grants, fixed slots, no refunds, atomic local spending, and the specified clock convention. Record measured excess and unused credits alongside the bound.

**Faults.** A strict-mode replica with no authority response does not admit. A disconnected credit-mode replica may spend already confirmed credits, then stops admitting. A crashed replica strands its remaining credits. Lost authority state, changed authority identity, suspected rollback, or mismatched policy/epoch stops new admissions or grants. Restarted replicas never recreate full buckets. A new epoch requires quiescing and fencing all old participants; a timeout alone does not prove an old replica stopped. Transparent authority promotion is unsupported. Redis atomic operations do not make replicated acknowledged writes durable across failover. [Redis replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/), [Redis scripting](https://redis.io/docs/latest/develop/programmability/eval-intro/).

**Isolation limit.** Separate quotas prevent one tenant from spending another's units. They do not reserve limiter CPU, storage throughput, or backend workers. Claims about service quality apply only below a measured capacity knee. Weighted costs are policy units until calibrated against actual backend work.

## Policy replay

Input is a versioned, complete trace of *offered* attempts: relative arrival time, tie-break order, tenant, and operation. Replay runs the same trace and initial state against two immutable policies using an independent reference model. Reject missing/ambiguous inputs rather than silently skipping them.

The report gives per-tenant offered/admitted counts and cost, changed-decision counts, first divergence, and examples explaining the decision. Include trace and policy hashes and the evaluated-input count. Replay is a fixed-stream comparison: it does not predict new retries, backend latency, future demand, or distributed execution order. A separate concurrency checker must validate live histories.

## Requirements and acceptance evidence

Requirement IDs are stable across revisions. Release C uses the common contract plus its additional credit requirements.

| IDs | Release | Required evidence |
| --- | --- | --- |
| **PRD-001–003** | A | Same quota envelope with one and three replicas; atomic decisions; refill, weighted costs, numeric boundaries, and permissiveness match an independent model. |
| **PRD-004–005** | A | Tenant budgets stay separate within the declared load envelope; all outcomes, deadlines, uncertain responses, and forwarding rules have contract checks. |
| **PRD-007–008** | A | Replica restart, partition, lost response, and authority-loss tests match the failure contract; spoofed identity or operation cannot mint allowance. |
| **PRD-009, 015** | A | Offered, committed, responded, forwarded, and completed work are separately counted; queues and state are bounded; unknown tenants create no state. |
| **PRD-006, 010–012** | B | Replay is deterministic and reconciles changed decisions; two clean runs, raw data, a correct baseline, architecture diagram, and failure walkthrough are published. |
| **PRD-016–019** | C | Mode is immutable per epoch; grant provenance proves conservation; concurrent histories respect `B + rΔt + NQ`; duplicates, timeouts, crashes, and stranded credits are accounted for. |
| **PRD-020–021** | C | Comparison reports coordination cost and observed trade-offs; every generated module links to resolved contracts, invariants, and independent acceptance tests. |
| **PRD-013–014** | Deferred | Live policy changes and long-operation permits require separate designs before implementation. |

No requirement is complete because a document says it is. The release record links each requirement to an executable check and observed result.

## Measurement protocol

Compare strict and credit modes with the same policy, offered trace, resource budget, routing, deadlines, and instrumentation. Run at `N = 1, 3, 8`. For each tenant, test valid batch sizes drawn from `{max_cost, ceil(B/8), ceil(B/2), B}` after clamping and deduplication. Include uniform and skewed routing, one hot tenant, many tenants, simultaneous bursts, idle periods, lost responses, replica crashes, disconnection, and authority restart.

Use a correct strict implementation as the engineering baseline. Instance-local counters and a deliberately non-atomic update are diagnostic failures, not performance competitors. A shared global bucket is a different policy used to show the isolation/utilization trade-off. Compare external systems only when their semantics and configuration can be aligned.

Freeze a benchmark manifest: source revision, build mode, dependency versions, hardware, container limits, policies, operation mix, trace/seed, deadline, and time resolution. Use open-loop arrivals, 30-second warmup, five 60-second runs, and no automatic retries. Report generator delay, offered and achieved rate, p50/p95/p99, timeout and error rates, CPU/memory, authority operations and bytes per admitted cost unit, unused/stranded credits, and observed burst deviation. Report individual runs and raw data. Instrumented correctness runs are separate from performance runs.

**Correctness gates:** zero observed model violations across boundary cases and at least one million decision attempts in declared concurrency tests; a seeded double-spend and reject-all defect must be detected. Credit-mode tests additionally detect duplicate grant application and a violated burst bound. This is test evidence, not a mathematical proof of every execution.

**Service objective:** in a healthy test below the measured limiter knee, at least 99% of attempts from two tenants offering 50% of their reserved rates receive timely `ALLOW` while a third offers 10× its rate. Count timeouts and unavailability as failures. Report synchronized bursts separately.

**Proposed performance objective:** p99 decision latency ≤5 ms at 5,000 offered checks/s, 1,000 tenants, three replicas, and a 50 ms caller deadline on one documented host, using a disclosed 90% cost-1/10% cost-5 mix. It is not a release gate or measured result. A miss is reported, not hidden by changing the workload.

A speedup claim needs the correct baseline and must include changes in allowed work, burst precision, and stranded credits. Correctly throttled requests are not product failures.

## How research improved the decisions

| Source | Decision it changed | Resulting test or boundary |
| --- | --- | --- |
| [Raghavan et al., *Cloud Control with Distributed Rate Limiting*, SIGCOMM 2007](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf) | Made coordination cost versus enforcement accuracy the central experiment. The paper studies network/TCP traffic; its performance numbers do not transfer to this API service. | Compare authority traffic, admission accuracy, throughput, and bursts for both modes. |
| [Li et al., *Impact of Distributed Rate Limiting on Load Distribution*, 2021](https://arxiv.org/abs/2101.05865) | Added routing skew and lost capacity to the experiment. Distribution decisions can change rate-limiting outcomes. | Measure per-replica demand and unused credits under uniform and skewed traces. |
| [Envoy ratelimit](https://github.com/envoyproxy/ratelimit) | Removed any novelty claim for gRPC plus Redis; made existing integration and over-limit caching a reference point. | Compare capability and failure semantics before attempting any performance ranking. |
| [Gubernator](https://github.com/gubernator-io/gubernator) | Confirmed that key ownership, batching, and weaker-consistency global behavior are established alternatives. Chose a distinct, bounded-credit contract for comparison. | Publish the guarantee difference; no equivalent-semantics speedup claim for credit mode. |
| [UIUC CS 425 Fall 2026 lectures](https://courses.grainger.illinois.edu/cs425/fa2026/lectures.html) | Made ordering, failure detection, membership, and global state explicit instead of adding consensus for appearance. | Test uncertain RPC outcomes, grant ordering, fixed membership, and in-flight credits. Raft/failover remain outside scope. |

These references motivate design choices; none verifies RateGuard's proposed bound or measurements. The bound must be reviewed and tested against the implemented contract.

## Spec-to-code gate

AI-assisted implementation begins module by module only when that module has no unresolved behavior-changing decision. The SRD must define wire types, units, bounds, outcome mapping, deadlines, and grant sequences. The HLD must define authority identity, clock, epoch fencing, state integrity, and resource limits. The LLD must define atomic spending and the grant retry state machine.

For each generated module, record `requirement → contract → design decision → independent test → observed result`. Test oracles must not simply reuse production decision logic. Seed double-spend, duplicate grant, invalid reset, lost-response replacement, and reject-all defects to show the checks can fail. The present PRD defines intent; it does not claim those downstream specifications or tests exist.

**Status:** no public implementation or reproducible benchmark has been verified for this release. Historical performance numbers in earlier project descriptions are not treated as current results. This document is ready to drive SRD/HLD work. Those documents must resolve clock behavior, numeric representation, and epoch fencing before implementation.
