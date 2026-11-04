# DistributedRateGuard — Product Requirements Document

**Revision:** 3 · **Date:** 2026-11-03 · **Status:** Proposed; ready for scoped design, not a validated product  
**Product:** RateGuard · **Repository:** https://github.com/kshiteesh28/DistributedRateGuard  
**Owner:** Kshiteesh · **Evidence:** documentation research and author experience; no customer interviews, implementation verification, or benchmark results for this release.

## 1. Product decision

Build a C++ admission service that enforces a customer's request budget across service replicas, plus an offline tool that explains how a proposed quota policy changes admission decisions for a fixed traffic trace.

**Primary promise:** strict mode preserves the exact tenant allowance; distributed-credit mode reduces coordination using a separately specified bounded burst allowance. Every completed decision identifies its mode and meaning.

**Differentiating workflow:** a developer can reproduce an undesirable throttling scenario, compare policies, inspect which tenants gain or lose admissions, and verify the selected policy against executable correctness checks.

**Conditional customer outcome:** within a measured operating envelope, a bursting tenant does not consume other tenants' reserved quota. Whether their requests arrive on time and complete successfully is measured separately. Quota separation cannot guarantee scheduler fairness, backend capacity, or protection against an attacker who saturates the limiter itself.

### Release thesis and falsification

The smallest valuable release connects three artifacts: an enforced policy, an independently checked decision history, and an understandable comparison report. More algorithms, a large dashboard, or additional infrastructure do not establish this value.

The thesis is weakened if a backend developer cannot identify a useful policy change from the report, cannot reproduce its results, or cannot understand its assumptions. Test this with two independent backend engineers after a runnable prototype exists. Record their tasks, interpretation errors, and objections; do not count positive reactions as adoption. If replay provides no actionable insight, narrow the claim to an engineering correctness demonstrator.

## 2. Problem, users, and alternatives

### Concrete scenario

A shared SaaS API serves several authenticated customer applications. Most traffic consists of small operations; a batch client periodically generates a burst. Multiple gateway or application instances check allowance before forwarding work.

Three decisions are difficult to get right:

1. How is the same customer's budget enforced when instances are added or restarted?
2. Which customers lose admissions when a policy changes?
3. What does the caller do when the admission service times out or loses its state?

The primary user is the backend engineer responsible for that integration. A platform engineer owns policy configuration and diagnosis. Customer applications consume the resulting behavior; they do not control their own quota or operation cost.

### Existing solutions and reason to build

Managed gateways, Envoy's rate-limit integration, and a service backed by atomic Redis operations are credible existing options. Envoy already documents a gRPC rate-limit service with a Redis reference implementation and combining local and global limiting. The project must not claim these capabilities are novel. [S3]

Choose an existing product for normal production adoption unless a documented requirement justifies ownership of a custom service. RateGuard's initial purpose is a small, inspectable engineering artifact combining policy semantics, repeatable evaluation, and failure evidence. A production replacement business case remains unvalidated.

AWS's discussion of tenant fairness and Stripe's rate-limit behavior support the problem class. They do not prove demand for RateGuard. [S1–S2]

### Alternatives evaluated

| Direction | Decision | Reason |
| --- | --- | --- |
| Generic limiter with several algorithms | Reject as primary scope | Algorithm count does not demonstrate a useful customer outcome. |
| AI inference budget gateway | Defer | Token estimation, reservation/reconciliation, streaming, and billing would require a different contract. |
| Tenant quota enforcement with policy evaluation | Select | Connects a bounded backend problem to reproducible correctness and decision evidence. |
| Multi-region quota platform | Exclude from v1 | Adds replication and availability guarantees beyond a credible first release. |

## 3. Scope and terminology

**Tenant:** a preconfigured customer identity supplied by a trusted integration.  
**Policy version:** immutable mapping of tenant rates, burst limits, and operation costs.  
**Epoch:** an explicit enforcement run with one policy version, authority identity, initial state, and time origin.  
**Attempt:** one call for an admission decision; retries are new attempts.  
**Admission commit:** in strict mode, the authoritative transition charging an attempt; in credit mode, the local atomic consumption of previously granted units. A lost response does not undo spending. Authority allocation and local admission are separate events.  
**Forwarded request:** work sent downstream after a successful admission response. This can differ from committed admissions.  
**Conforming trace:** offered cost that the specified reference policy would admit in isolation, from the same initial state and timestamps.

### Included in the first comparative release

Two separately gated modes (strict and distributed-credit); one logical authority; one immutable policy and mode per epoch; multiple C++ admission-service replicas; gRPC contract and sample integration; preconfigured tenants; weighted request costs; deterministic offline replay; metrics and experiment artifacts. Docker is the reproducible local deployment target.

### Excluded

Transparent authority failover; cross-region limits; live policy changes; budget borrowing; priority scheduling; long-operation concurrency permits; end-to-end deduplication; billing guarantees; Internet DDoS defense; runtime tenant provisioning; Kubernetes; production certification; and a mandatory GUI.

Only one tenant budget is charged per attempt. Compound tenant-plus-global transactions and cross-shard atomic charging are excluded. Costs are synthetic policy units, not measured CPU, dollars, or LLM tokens.

## 4. Product contract

### 4.1 Identity, configuration, and lifecycle

- The sample integration maps a synthetic credential to a tenant. A request's tenant header cannot override that mapping. The admission endpoint accepts calls only within the documented trusted boundary; local network placement alone is not a general authentication claim.
- Unknown tenants or operations are rejected without creating state. Cost is resolved from the trusted operation map, never supplied as a customer discount.
- Rate and burst are positive, finite, bounded values; cost is a positive integer no greater than the applicable burst limit. Configuration rejects invalid values before serving.
- Every replica checks the active policy digest and epoch against the authority before becoming ready. A mismatch makes that replica unavailable; it must not create a parallel allowance namespace.
- A new explicitly initialized epoch starts with each tenant's burst allowance. A restarted strict-mode service replica joins existing state and cannot reinitialize it. Credit-mode restart handling is defined in section 4.5.
- Missing state for an enrolled tenant, authority restart/identity change, or suspected rollback is an integrity failure. No lazy recreation of a full bucket. Tenant-state eviction/expiration is disabled in v1; state capacity is bounded by the configured tenant set.
- Policy changes and tenant removal occur only through a stopped, drained, explicitly initialized epoch. An epoch reset is a new experimental run, not seamless recovery or continuity of prior guarantees.

### 4.2 Strict-mode allowance semantics

Specify a weighted token-bucket contract, irrespective of the eventual storage mechanism. For tenant i, capacity is B_i cost units and refill rate is r_i units/second. Given the previous balance b and authoritative elapsed time Δt:

`available = min(B_i, b + r_i × Δt)`

An attempt of cost c is allowed only if `available ≥ c`; an allowed attempt leaves `available − c`. A limited attempt spends nothing, although it may advance refill bookkeeping. Invalid or unauthenticated attempts spend nothing.

The decision and spending operation are indivisible with respect to competing attempts for that tenant. There must be a sequential ordering compatible with completed calls' real-time order that explains the observed outcomes. The decision history must also satisfy the envelope: admitted cost in an interval of duration Δt cannot exceed `B_i + r_i × Δt`, under the declared boundary/time convention. Checking this envelope alone is insufficient: an implementation that rejects everything would satisfy it.

Time is authority-controlled; caller timestamps cannot mint allowance. HLD must specify resolution, rounding, clock source, rollback/forward-jump handling, numeric limits, and the exact interval boundary convention. Rounding cannot grant more than the documented model permits. A restarted authority cannot silently substitute a new clock origin into existing claims.

Within a tenant, v1 does not reserve service for expensive operations: many cheap attempts may prevent a larger cost from accumulating. Expose this limitation in reports; do not describe weighted charging as request scheduling.

### 4.3 Responses and uncertain outcomes

Every received response includes a correlation ID, outcome, mode, and applicable policy/epoch identifiers. IDs are diagnostic, not deduplication keys. Unknown identifiers are explicitly absent rather than fabricated.

| Outcome | Meaning | Integration behavior |
| --- | --- | --- |
| ALLOW | Allowance was committed for this attempt | Forward at most once for that successful call, within its deadline and active epoch. |
| LIMITED | Insufficient allowance; no cost charged for this attempt | Do not forward; expose throttling and a retry estimate. |
| INVALID / UNAUTHENTICATED | Identity, operation, or configuration is unusable | Do not forward; correct input/configuration rather than retry blindly. |
| UNAVAILABLE / OVERLOADED | No usable admission result can be delivered | Do not forward; expose a dependency/capacity failure, not quota exhaustion. |
| Transport timeout / cancellation | Caller cannot know whether a commit occurred | Do not forward on this attempt; do not refund optimistically. |

The sample HTTP-facing explanation distinguishes quota exhaustion (429) from limiter/dependency failure (503); the normative gRPC mapping is defined in the SRD. No response can be promised after transport loss.

The retry estimate is the earliest eligibility under no intervening consumption and the same policy, not a reservation. Concurrent traffic may invalidate it. Client retries use bounded backoff/jitter; core comparative experiments disable retries to avoid feedback obscuring results. Late responses are ignored after deadline/epoch change. Downstream failure does not refund allowance in v1.

### 4.4 Strict-mode failure model and guarantee boundary

The strict-mode guarantee assumes a single authoritative state history with no rollback, one active epoch, correct trusted integration, and the documented clock model. Replicas are stateless with respect to allowance. Atomic state mutation and durable preservation of that mutation are separate concerns: Redis documents both atomic script execution and possible acknowledged-write loss with replication/failover. [S7–S8]

| Fault | Required behavior | What the experiment may claim |
| --- | --- | --- |
| Admission replica restarts | Rejoin unchanged epoch; no new allowance | Replica restart safety. |
| Replica loses connection to a still-running authority | Its undecidable calls fail closed; connected replicas may continue | Quota safety during partial connectivity, with reduced availability. |
| Commit occurs but response is lost | Spend may remain; caller does not forward | Conservative uncertainty handling, not exactly-once execution. |
| Authority process restarts, state disappears, or identity changes | Stop useful admission; remain unavailable until an explicit new epoch | Detection and safe stop, not transparent state recovery. |
| Authority rollback, split-brain, or transparent replica promotion | Unsupported configuration for v1; do not enable it | No continuity claim under these faults. |
| Excess load on the limiter | Bound queues/resources; return overload within deadlines where the transport permits | Controlled overload behavior; no universal per-tenant latency guarantee. |

A fault injected at time t does not invalidate a commit that already happened. Fault tests classify attempts by commit and response timing, not simply by when the client noticed an outage. An unavailable response or timeout may correspond to a committed attempt; the evidence must retain that distinction.

### 4.5 Distributed-credit contract

This mode is an explicit alternative to section 4.2, not an optimization that preserves identical per-attempt admission semantics. An epoch cannot mix strict admissions and credit grants against the same tenant bucket.

**Configuration:** fix N registered replica slots for the epoch. For each tenant configure integer batch size Q with `maximum operation cost ≤ Q ≤ B`. Each slot is bound to a unique process incarnation. No membership replacement, runtime mode change, or credit transfer during an epoch. Reject invalid configuration before readiness.

**Allocation:** the authority atomically removes granted units from the same refill/burst bucket used in strict mode. Each grant is identified by tenant, epoch, slot, incarnation, and monotonically increasing sequence. At most one allocation may be in flight per tenant/slot; a slot holds at most Q unspent units and never prefetches. Request Q units; the authority may grant fewer whole units only if the grant covers the triggering operation's cost. If fewer than that cost are available, allocation is limited and no units are charged.

**Local admission:** consume cost units with an atomic operation before returning ALLOW. If the remainder cannot cover an operation, retire that remainder permanently before requesting another grant. Discarding is recorded as waste; it never refunds authority allowance. Concurrent requests cannot both spend the same local units. Requests may wait only within the configured bounded queue/deadline.

**Duplicate and uncertain grants:** the authority stores the current sequence and result per tenant/slot. Retrying the same sequence returns the same allocation without charging again; stale sequences are rejected and sequence advancement is accepted only after the previous result is known. The replica activates a response once; duplicate/late responses cannot add credit. A timeout with unknown allocation status blocks a new sequence until the same sequence is resolved. No timeout-based refund or replacement grant. State and numeric sequence limits must be fixed in the SRD; no wraparound.

**Failure:** a disconnected replica may consume confirmed credits, then returns UNAVAILABLE when it cannot obtain a usable grant. An allocation LIMITED remains distinct from authority unavailability. A replica crash strands its remaining credits; its slot/incarnation cannot be reused until a quiesced new epoch. Authority restart/state loss prevents new grants. An isolated old replica may still spend previously confirmed units; the integration must drain/fence all old incarnations before activating another epoch. A timeout is not proof that an old replica has stopped. There is no automatic failover or credit reclamation.

**Conservation:** every admitted unit belongs to one uniquely allocated grant; no cross-tenant or cross-epoch spending. Allocation may exceed actual consumption because of lost responses, discarded remainders, and crashes. These are measured costs of the design.

**Burst bound:** for an interval of duration Δt within one epoch, admitted cost is at most `B + r × Δt + N × Q`. At the interval start, locally held or in-flight previously allocated credits total at most NQ. New grants in the interval are bounded by the authoritative token-bucket envelope B + rΔt. Admissions can spend only those two sets. This argument assumes unique grants, atomic local spending, fixed slots, no refunds/reset, and the declared common measurement-time convention. The bound is conservative; publish measured excess as well as the bound. It is not the strict B + rΔt guarantee.

**Correctness evidence:** implement an independent grant/consumption model, track grant provenance, and check both conservation and the interval bound. A strict token-bucket oracle alone cannot judge this mode. Confirmed credits have no time-based reclamation in this release; clock or lease-expiry assumptions must not be silently introduced.

## 5. Isolation, capacity, and the supported envelope

Fixed tenant budgets prevent cross-tenant quota spending. They do not partition CPU, sockets, storage execution, or backend workers. A hot tenant can still consume shared admission capacity even when all its attempts are denied.

The claimed operating envelope therefore names both **offered checks/second** and **admitted cost/second**, along with burst size, tenant count, operation mix, hardware, and deadline. The first release must publish its capacity knee: the point at which achieved throughput, errors, or tail latency fail the declared criteria.

Use bounded outstanding work, bounded storage waits, and explicit overload responses. Do not add tenant-specific queues or a scheduler unless an experiment demonstrates their necessity and the scope is revised. Envoy's local/global pattern is an available future defense against excessive offered load, not a capability to imply before implementation. [S3]

For the backend demonstration, calibrate synthetic operation costs against a fixed worker/queue model and publish that model. Sum of refill rates below backend average capacity is insufficient: test synchronized bursts too. If weighted costs fail to predict resource consumption, reduce the claim to quota isolation and document the mismatch.

Idle tenant allowance is not borrowed. Report unused capacity and the throughput cost of that choice. A global shared policy may deliver higher utilization; that is a valid result.

## 6. Policy evaluation workflow

**Input:** a versioned trace of offered attempts captured before limiting, containing relative arrival time, sequence/tie-break index, pseudonymous tenant, and operation class; plus complete initial state and policies A/B. Do not reconstruct demand from successful requests alone.

**Contract:** repeat the same serialized trace and initial state through an independent reference model. Ties use the recorded index. Malformed traces, unknown operations, ambiguous units, or incomplete initial state fail validation rather than silently skipping rows.

**Output:** per-tenant offered and admitted request counts, admitted cost, limit counts, A-allow/B-deny and A-deny/B-allow transitions, first divergence, and selected examples explaining policy, cost, time, and prior balance. Include policy hashes, trace digest, model version, and the fraction of the trace actually evaluated. Explain that lost admissions can be intentional.

**Boundary:** replay is counterfactual accounting for a fixed offered stream. Different policies may change client retries, user behavior, downstream execution, and later arrivals. It cannot forecast those changes, latency, cost savings, production fairness, or adoption. Serial replay equality does not validate a distributed execution with a different order.

For live correctness, record authoritative order and timestamps in a correctness-only mode or use bounded concurrent histories with a checker. Checkers must be capable of rejecting a seeded over-admission defect; sharing the exact production decision function with the oracle is inadequate evidence of independence.

## 7. Requirements and release evidence

P0 requirements retain their v1 IDs. PRD-001 through PRD-015 define the strict-core milestone; shared identity, reporting, overload, and integration requirements also apply to credit mode. Credit-specific semantics supersede strict ordering/restart behavior only where section 4.5 explicitly says so. P1 items remain deferred. Each P0 must have an artifact linked in the release checklist; a heading or intended test is not evidence.

| ID | Priority | Required behavior | Acceptance evidence |
| --- | --- | --- | --- |
| PRD-001 | P0 | Shared quota and policy identity across replicas | One/three-replica scenarios preserve the same envelope; joining/restarting replicas creates no credit; mismatched policy/epoch prevents readiness. Exact request-level outcomes may differ with scheduling. |
| PRD-002 | P0 | Atomic, sufficiently permissive admission | Controlled boundary cases and concurrent histories match a valid model order; serial cases admit whenever the contract permits. Seeded double-spend and reject-all defects are detected. |
| PRD-003 | P0 | Weighted refill semantics | Full/empty/idle buckets, fractional refill, exact boundary, costs 1 and B, overflow, invalid inputs, and clock behavior match documented semantics. |
| PRD-004 | P0 | Tenant quota isolation within a declared envelope | No cross-tenant spending; under-budget tenants meet the admission goal below the measured capacity knee; overload and synchronized-burst results are reported separately. |
| PRD-005 | P0 | Actionable outcome contract | Contract checks cover every outcome, retry estimates, transport loss, late responses, and downstream failure; the adapter never forwards without timely ALLOW. |
| PRD-006 | P0 | Reproducible, bounded policy comparison | Identical inputs produce identical results; incomplete traces fail; changed-decision examples reconcile to counts; model limitations appear in the report. |
| PRD-007 | P0 | Conservative behavior across supported faults | Fault matrix tests distinguish pre-fault commits, uncertain outcomes, reconnect to intact authority, and authority restart safe-stop. Unsupported failover is disabled. |
| PRD-008 | P0 | Trusted integration boundary | Spoofed tenant/operation data cannot increase allowance; unknown tenants cannot create state; sample integration and trust assumptions are documented. |
| PRD-009 | P0 | Bounded, reconcilable telemetry | Counts distinguish offered, committed, responded, forwarded, and completed work; overload/dependency/limit outcomes remain separate. Unreconciled attempts are explicit. No tenant/attempt IDs in metric labels. |
| PRD-010 | P0 | Clean reproducibility | Pinned dependencies, declared resources, startup/readiness checks, deterministic seed, and machine-readable output support two fresh runs without hidden credentials or manual repair. |
| PRD-011 | P0 | Credible comparison | Same resource budget and workload for equivalent configurations; report baseline differences, five runs, raw data, errors, and all acceptance misses. No optimization claim from broken baselines. |
| PRD-012 | P0 | Inspectable engineering result | Source, one architecture diagram, contract, failure walkthrough, release checklist, and a concise demo link to the relevant implementation and evidence. |
| PRD-013 | P1 | Safe live policy changes | Separate future contract for mixed versions, reduced limits, in-flight attempts, activation, and rollback. No runtime policy switching in v1. |
| PRD-014 | P1 | Concurrent-operation protection | Separate future contract for permit lifetime, completion, cancellation, expiry, and crash recovery before any claim about long-running jobs. |
| PRD-015 | P0 | Bounded load and state | Queue/deadline/resource caps are specified and exercised; unknown identities allocate no buckets; state loss/eviction does not recreate credit. Hot-key and many-tenant stress results are distinct. |

### Comparative-release requirements

| ID | Priority | Required behavior | Acceptance evidence |
| --- | --- | --- | --- |
| PRD-016 | Comparative release | Explicit mode contract | Mode is immutable per epoch and appears in decisions and reports; cross-mode spending and mode/policy mismatches are rejected. |
| PRD-017 | Comparative release | Credit conservation | Duplicate, delayed, concurrent, and timed-out grants cannot create units; unknown allocation blocks new sequences; every consumed unit maps to a unique grant. |
| PRD-018 | Comparative release | Bounded extra burst | Independently check admitted cost against B + rΔt + NQ; demonstrate a trace where strict and credit admission differ without calling it a strict-mode success. |
| PRD-019 | Comparative release | Failure and wasted-credit accounting | Crash, partition, authority restart, and lost responses preserve grant accounting; no timeout reclamation or slot reuse; wasted and uncertain credits remain visible. |
| PRD-020 | Comparative release | Quantified efficiency trade-off | Report authority operations, bytes, CPU, latency, useful admissions, deviation, and wasted credits for every compared setting, including negative results. |
| PRD-021 | Comparative release | Spec-to-code readiness | Each generated module links to resolved normative contracts, invariants, failure cases, and independent acceptance tests; no unresolved behavior-affecting decision is delegated implicitly to code generation. |

## 8. Experimental protocol and success criteria

**Current state:** all baselines unknown; all numeric objectives below are proposed engineering targets, not measured results or customer SLAs.

### 8.1 Workloads

| Scenario | Purpose and controls |
| --- | --- |
| Accounting oracle | Deterministic, authority-time-driven traces including weighted boundaries, idle periods, and adversarial sequences. Test permissiveness as well as safety. |
| Quiet tenants plus noisy neighbor | Two tenants offer conforming traffic at 50% of their reserved rates; the third offers 10× its rate. Configure and disclose burst sizes, operation mix, and total offered load below the measured limiter knee. |
| Synchronized bursts | All tenants spend their bursts together; observe backend queueing/completions. Test separately from steady-state isolation. |
| Single hot tenant | Drive contention on one authority key as offered load rises. Do not hide hot-key throughput in an aggregate across many keys. |
| Many tenants | Sweep declared tenant cardinality with uniform and skewed demand; report state memory and storage latency. |
| Fault timeline | Restart a service replica; isolate one replica; lose a response after commit; restart/lose authority state. Record injection points and expected behavior from section 4.4. |

### 8.2 Baselines

- **Diagnostic only:** per-instance buckets with full per-tenant budgets demonstrate budget multiplication. A deliberately non-atomic shared update demonstrates a race. Neither supports performance-superiority claims.
- **Fairness trade-off:** a correct shared global bucket with total rate/burst equal to the sum of tenant allocations. Show utilization and per-tenant effects; do not call it incorrect for having different policy semantics.
- **Engineering baseline:** a straightforward correct implementation of the same per-tenant policy through the same RPC path and state backend. This is the baseline for any later contention/latency optimization. If the initial RateGuard implementation is this baseline, report absolute performance without inventing a speedup.
- **Integration overhead:** a no-op RPC path helps attribute network/serialization cost; it is not a substitute for the correct enforcement baseline.

### 8.3 Measurement rules

Freeze a benchmark manifest before a reported run: source revision, compiler/build mode, dependency and image versions, host CPU/architecture/RAM/OS, container limits, replica/authority placement, tenant policies, time resolution, client deadlines, trace/seed, and operation mix. Run on a declared dedicated environment; if a laptop has competing workloads, record that limitation.

Use open-loop arrivals independent of response time. Measure schedule delay as well as RPC latency; if the generator cannot deliver the offered rate, label the run generator-limited. Disable automatic retries for comparisons. Separate cold start, 30-second warmup, and 60-second measurement; use five runs and report each plus dispersion. Freeze policies and initial-state procedures across comparisons.

Report p50/p95/p99 with sample counts, offered/achieved rates, CPU/memory, and each error rate. Do not drop failed/timed-out calls from the account: show completed-call latency alongside deadline-miss fractions. Instrumented correctness histories and performance runs are separate; disclose instrumentation differences. Publish raw or losslessly aggregated data sufficient to recalculate each reported metric.

### 8.4 Strict-core gates versus performance objectives

| Criterion | Classification | Decision rule |
| --- | --- | --- |
| Model conformance | Correctness gate | No observed violations in deterministic edge cases, seeded-defect checks, and at least 1 million attempts across declared concurrency cases; enough successful and limited outcomes to exercise both paths. Not a proof over untested executions. |
| Conforming-tenant service | Scoped outcome gate | ≥99% of conforming attempts receive ALLOW within the deadline in each of five healthy, below-knee noisy-neighbor trials. Count timeouts/unavailable as failures. Report 100% expected model eligibility and investigate any unexplained gap. |
| Failure semantics | Correctness gate | Every supported matrix case has explicit expected and observed outcomes. No forwarding without timely ALLOW; uncertain attempts remain uncertain in accounting. |
| RPC overhead | Performance objective | Initial goal: p99 ≤5 ms at 5,000 offered checks/s, 1,000 tenants, 90% cost-1/10% cost-5 attempts, three replicas on one documented host, 50 ms caller deadline. Declare policy/burst values and achieved ALLOW/LIMITED mix; report all errors and test other mixes separately. |
| Replay | Functional gate | Determinism, complete-input validation, changed-decision reconciliation, and independent model checks pass. |
| Reproducibility | Delivery gate | Two clean runs complete from the published instructions and preserve enough evidence to recalculate reported outcomes. |

Correctness and integration gates cannot be traded for throughput. Missing a performance objective requires an explanation and revised, versioned positioning; it does not justify silently lowering the target or suppressing the run. Backend completions and latency are reported outcomes until a calibrated backend model supports a justified target.

### 8.5 Two-mode efficiency study

Research question: how much authority coordination can credits remove, and what does that cost in burst precision, useful admissions, and failure behavior? Strict mode must pass its gates independently; the complete comparative release also requires PRD-016 through PRD-021.

For each tenant, choose valid batch sizes from `{max_cost, ceil(B/8), ceil(B/2), B}`, clamped to `[max_cost, B]` and deduplicated. Sweep N = 1, 3, 8, uniform routing, and a declared skewed routing trace. Use identical base rates, burst values, costs, resource budgets, arrivals, deadlines, warmup, and five-run procedure across modes. Add idle-then-synchronized spending, low utilization, hot tenants, crashes, duplicate grant responses, unknown allocations, and authority disconnection. No membership changes inside an epoch.

Report authority operations/network bytes per admitted cost unit, CPU/memory, p50/p95/p99, achieved rates/errors, additional burst relative to B + rΔt, bound utilization, discarded/stranded units, and policy-eligible attempts lost to allocation placement. Include offered and admitted work denominators so rejecting extra traffic cannot masquerade as an efficiency gain. Publish the accuracy/availability costs beside every throughput claim.

Keep the straightforward correct strict implementation as the optimization baseline. Pool connections, bound work, and reduce serialization/allocation overhead only after profiling; measure each change independently. Do not cache strict ALLOW decisions or use stale denials without changing and testing the permissiveness contract. Credit mode changes semantics and must never be advertised as an equivalent-semantics speedup.

External projects are capability references first. Pin source revisions and configuration before any performance comparison. If rate-window semantics, weighted costs, durability, or failure guarantees cannot be aligned, report the mismatch and omit a speedup ranking. Upstream benchmark numbers are not measurements of this project.

## 9. Delivery and design decisions

### Stage A — contract and trustworthy core

Resolve the SRD/HLD blockers below; implement static policies, one authority, multiple replicas, the sample client/adapter, an independent model, and accounting/failure checks. This is a useful intermediate engineering artifact but not the complete policy-evaluation release.

### Stage B — strict evaluation and operating envelope

Add trace validation/comparison reports, the correct baseline, workload/fault harness, telemetry accounting, and overload limits. Demonstrate the gates in section 8. Publish failures as findings.

### Stage C — distributed-credit comparison

Specify and implement the grant state machine and local spending contract, then run section 8.5 with an independent model. Pass PRD-016 through PRD-020. Deliver the strict core even if the credit experiment is not yet ready. No claim of improvement is required for a valid negative result.

### Stage D — evidence and external review

Produce a concise demo, reproducible artifacts, and two engineer usability reviews. Complete the strict P0 and comparative-release checklists. A dashboard, cloud deployment, or extra algorithm is added only if it solves a demonstrated evaluation problem.

### Decisions required before claiming implementation readiness

| Decision | Owner / deadline | Required answer |
| --- | --- | --- |
| Authority and clock model | Author, before core implementation | How are atomic decisions, authority identity/restarts, time behavior, and missing-state failures enforced? |
| Numeric policy representation | Author, SRD | Bounds, fixed-point/rounding behavior, overflow handling, and retry estimate semantics. |
| Transport and identity contract | Author, SRD | Deadline propagation, outcome mapping, trusted credential boundary, and late-response handling. |
| Limits and evidence schema | Author, HLD | Bounded queues/state, telemetry accounting, history/trace schema, and privacy limits. |
| Backend and host model | Author, before benchmark freeze | Synthetic work/cost relationship, capacity measurements, and reproducible resource allocation. |
| Time and previous work | Author, before scheduling | Available hours and whether prior RateGuard code/results can be reused. No calendar promise until known. |

C++ and gRPC preserve a direct connection to the author's experience. Redis is a plausible authority backend; clustering and etcd are not v1 requirements. A single authority is an explicit throughput/availability limitation even though clients and admission-service replicas are distributed. HLD must justify every additional component against a requirement.

## 10. Risks and scope-change triggers

| Risk | Consequence | Response / trigger |
| --- | --- | --- |
| Hot tenant saturates limiter before its quota check | Quiet tenants lose service despite separate budgets | Publish the knee, enforce resource bounds, narrow the envelope; evaluate upstream coarse limiting only if required. |
| Replay ignores feedback | A candidate looks better offline but behaves differently live | Label the fixed-stream assumption; use a separate closed-loop experiment before claims about retrying clients. |
| Reference and implementation share a defect | Impressive tests validate the same mistake | Independent model, handwritten boundary cases, seeded faults, and concurrent-history checks. |
| State reset or rollback mints allowance | Safety claim fails across restart | Fail unavailable on integrity loss; explicit stopped epoch reset; no transparent failover claim. |
| Fixed reservations strand capacity | Higher rejection rate than global pooling | Report the utilization cost; borrowing requires a new contract, not a hidden optimization. |
| Costs misrepresent backend work | Quota safety is mistaken for resource protection | Limit claims to cost-unit accounting until workload calibration supports more. |
| No developer finds replay useful | Differentiation is only a presentation choice | Record usability findings and reposition as a correctness demonstrator or revise the workflow. |

## 11. Research foundation and existing implementations

**Primary paper:** Raghavan, Vishwanath, Ramabhadran, Yocum, and Snoeren, *Cloud Control with Distributed Rate Limiting*, ACM SIGCOMM 2007, pp. 337–348. It studies coordinated network rate limits and the trade-off between communication, accuracy, efficiency, and scalability. Its network/TCP setting motivates this project but does not prove this API contract, credit bound, or expected performance. [S9]

**Additional research:** Li, Liu, Lu, Guerin, and Gill, *Impact of Distributed Rate Limiting on Load Distribution in a Latency-sensitive Messaging Service* (2021 arXiv record). It motivates evaluating workload distribution alongside rate limiting. Use it to motivate skew and stranded-capacity experiments; do not assert an unverified venue or transfer its results. [S10]

| Existing project | Verified documented capability | Implication |
| --- | --- | --- |
| envoyproxy/ratelimit | Go/gRPC, Redis, configurable local caching of over-limit keys | The broad use case already exists. Study integration and denial-traffic optimization without assuming identical policy semantics. |
| gubernator-io/gubernator | Ownership through consistent hashing, peer batching, optional eventually consistent GLOBAL mode | Coordination reduction is established practice; compare guarantees and workload sensitivity, not language labels. |

The former mailgun/gubernator repository is archived; the successor is the comparison reference. [S11–S12]

**Proposed contribution:** an inspectable strict-versus-bounded-credit comparison with grant provenance, independent correctness checks, policy replay, and failure/waste accounting. This is an engineering hypothesis, not a claim of a new algorithm or superiority over these systems. Record repository revisions when freezing a benchmark; do not fabricate a pin before implementation.

## 12. CS 425 concept mapping

Mapping uses the public Fall 2026 CS 425/ECE 428 lecture schedule. It identifies concepts relevant to the proposed design, not concepts already implemented. [S13]

| Course concept | Use and required improvement |
| --- | --- |
| Consistency models | Strict mode checks authoritative sequential decisions; credit mode checks grant conservation and its separate bound. Do not claim equivalent linearizability for both. |
| Time and ordering | Authority time controls refill; sequence numbers order grants. Logical timestamps cannot measure elapsed seconds. Define clock and rounding assumptions explicitly. |
| Failure detection and membership | Timeout means uncertainty, not death. Fixed slots and no timeout reclamation prevent duplicate allocation to presumed-dead replicas. |
| RPC and marshalling | Specify retry, duplicate response, lost commit response, deadline, and late-response behavior; test each separately. |
| Mutual exclusion and concurrency control | Atomic authority allocation and atomic local consumption protect different boundaries; a local mutex cannot synchronize replicas. |
| Snapshots/global state | A correctness history includes in-flight grants, uncertain allocations, and local credits. A sum of response counters is not a complete global state. No claim to implement a distributed snapshot protocol. |
| Leader election, Paxos, Raft | Election alone cannot preserve spent quota. Replicated authority requires a durable state-machine/fencing contract and remains deferred. |
| Scheduling | Tenant accounting does not reserve CPU or ensure service fairness. Measure skew and saturation before proposing extra scheduling mechanisms. |

Gossip, consensus, and consistent hashing are not added solely to increase syllabus coverage.

## 13. Specification-to-code readiness gate

The required standard is **no unresolved behavior-affecting decision for the module being generated**, not a claim that prose is perfect.

Before generating a module, provide requirement IDs, normative inputs/outputs, units/ranges, state transitions, invariants, dependency/failure assumptions, test oracles, and explicit acceptance commands. Maintain `requirement → SRD contract → HLD/LLD decision → test → observed result` traceability. Missing artifacts or unresolved decisions block that module, not independent completed work.

SRD must settle RPC types and outcome mapping, numeric representation, clock/boundary conventions, queue/deadline bounds, and grant sequence semantics. HLD must settle authority identity, fencing/draining at epoch boundaries, state-integrity detection, and resource limits. LLD must settle atomic local spending and the grant retry state machine. Neither a model nor generated tests may import the production decision function as its sole oracle.

Use seeded counterexamples for double-spend, duplicate grant activation, illegal epoch reset, lost-response replacement grants, reject-all behavior, and a deliberately violated credit bound. Generate in small slices with independent verification; an AI assertion that a requirement is satisfied is not a test result. The current PRD supplies product contracts; it does not claim the required SRD/HLD/LLD artifacts already exist.

## 14. Sources and status

Sources were inspected during drafting on 2026-11-03. Contracts and targets are project proposals. No implementation, performance, adoption, or production-safety claim is made by this document.

- **S1:** [AWS — Fairness in multi-tenant systems](https://aws.amazon.com/builders-library/fairness-in-multi-tenant-systems/).
- **S2:** [Stripe — Rate limits](https://docs.stripe.com/rate-limits).
- **S3:** [Envoy — Global rate limiting](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/other_features/global_rate_limiting).
- **S7:** [Redis — Replication and failover limitations](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/).
- **S8:** [Redis — Atomic script execution](https://redis.io/docs/latest/develop/programmability/eval-intro/).
- **S9:** [Cloud Control with Distributed Rate Limiting — SIGCOMM 2007](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf).
- **S10:** [Impact of Distributed Rate Limiting on Load Distribution — 2021](https://arxiv.org/abs/2101.05865).
- **S11:** [Envoy rate-limit service](https://github.com/envoyproxy/ratelimit).
- **S12:** [Gubernator](https://github.com/gubernator-io/gubernator).
- **S13:** [UIUC CS 425 — Fall 2026 lectures](https://courses.grainger.illinois.edu/cs425/fa2026/lectures.html).

Source identifiers S4–S6 belonged to private career-positioning material in earlier local drafts and are intentionally unused in this public product document.
