# Agile Sprint Plan — DistributedRateGuard

**Date:** 2026-11-12  
**Status:** RG-001 component verified; Sprint 0 deployment gate open. RG-002 component verified; RG-003 component verified; integration pending. Product Owner authorized development and testing on 2026-11-12.  
**Source of truth:** `main` — [PRD 8](PRD.md), [SRD 5](SRD.md), [HLD 4](HLD.md), [LLD 5](LLD.md), [stories](STORIES.md), and [JSON context blocks](context-blocks.json).

## Team and control

The user is Product Owner and controls priority and the command to proceed. The Master agent coordinates the work and reports status. Four independent role agents contribute under the Master/Scrum Master:

- **Scrum Master:** owns the dependency board, story readiness, sprint coordination, blocker tracking, review, and retrospective.
- **Senior developer:** leads architecture-sensitive work (wire contract, shared clock, supervisor, witness, concurrency, and integration); reviews junior changes.
- **Junior developer:** implements bounded, ready stories and records requirement links, failure behavior, and PR evidence.
- **Tester:** independently prepares/runs acceptance and fault checks, reviews evidence against the requirements, and never uses production decision code as its only oracle.

The tester’s findings are independent of the developer’s completion claim. Scrum Master coordinates; the Master resolves cross-role conflicts and submits the integrated result to the Product Owner.

## Estimate rules

All estimates below are **active agent minutes**, not elapsed time, calendar duration, or T-shirt sizing. Sprint boundaries are dependency and acceptance gates, not promised dates. Concurrent work may reduce elapsed time but does not reduce summed agent-minutes. The baseline includes story work and the coordination allocation shown below; it excludes unattended build, CI, download, model-checking, and benchmark runtime, external environment delays, major scope changes, and defect-rework beyond a normal review pass.

The current local path was observed to contain documentation only, without verified Git metadata, source code, or build output. Estimates therefore have high uncertainty. Re-estimate after RG-001 and the first two implementation PRs. Toolchain versions are selected from the actual target Linux environment and are not guessed in advance.

## Sprint sequence and effort

Role order in the table: **Scrum Master / Senior Dev / Junior Dev / Tester**.

| Sprint | Stories and objective | Active minutes by role | Total |
| --- | --- | ---: | ---: |
| **0 — Bootstrap** | RG-001: verify/sync a real checkout, freeze v1 wire and canonical encodings, build the C++20 target environment, record the tested toolchain/image lock. | 120 / 180 / 200 / 150 | **650** |
| **1 — Foundations and oracle** | RG-002–005 plus RG-011A: policy/arithmetic, Linux clock provenance, mTLS authorization, bounded event history, and the minimal independent strict oracle/golden fixtures needed before A acceptance. Run a short clock+witness feasibility spike after bootstrap. | 235 / 915 / 1,110 / 1,125, **plus 120–240 Senior Dev minutes for the spike** | **3,385 + 120–240** |
| **2 — Lifecycle and strict A** | RG-006 → RG-007 → RG-008 → RG-009: supervisor and positive fencing, independent witness/journal, strict authority/admission, then adapter forwarding. Enforce dependencies in order; no late or uncertain ALLOW may forward. | 275 / 1,335 / 1,530 / 1,650 | **4,790** |
| **3 — Evaluation B** | RG-011B and RG-012: full deterministic replay CLI, workload generator, and comparative reports. Keep the full replay deliverable in B; RG-011A is only A test support. | 165 / 510 / 750 / 705 | **2,130** |
| **4 — Credits and assurance C** | RG-010 → RG-013 → RG-014: fixed-Q credit spending, independent bounded model/history checker, then release evidence and reproducible handoff. Do not start credits until strict behavior and its oracle are accepted. | 260 / 1,065 / 1,290 / 1,680 | **4,295** |

**Baseline total:** 15,250 active agent-minutes. The feasibility spike adds 120–240 minutes, for **15,370–15,490 minutes**. This is effort, not a wall-clock completion forecast.

### Story effort reference

Combined agent-minutes from the Scrum Master’s role allocation; coordination is added once per sprint above.

| Sprint | Story estimates |
| --- | --- |
| 0 | RG-001: 480 |
| 1 | RG-002: 620; RG-003: 590; RG-004: 720; RG-005: 650; RG-011A: 565 |
| 2 | RG-006: 935; RG-007: 1,245; RG-008: 1,605; RG-009: 750 |
| 3 | RG-011B: 750; RG-012: 1,185 |
| 4 | RG-010: 1,850; RG-013: 1,665; RG-014: 525 |

The independent Junior Dev estimate is 4,260–7,620 active minutes for its implementation share. The Tester’s independent QA estimate is 2,800–4,550 minutes before defect-rework contingency; this plan uses a conservative 5,310-minute tester allocation including coordination. The Senior Dev supplied a 4,740–8,100-minute engineering estimate assuming the senior owns all implementation, plus review allowance; it is not added to this role-split baseline. Reconcile estimates after bootstrap rather than treating these different ownership assumptions as additive commitments.

## Sprint goals and exit gates

### Sprint 0 — Bootstrap

Complete RG-001 only after the actual target Linux/Docker environment is available. Freeze protobuf numbers/enums, error and retry contract, canonical policy encoding vectors, dependency versions, compiler/CMake versions, and image digest. A lock is considered valid only after a reproducible build succeeds. No service is enabled by an untested lock.

### Sprint 1 — Foundations and oracle

Implement the independent policy/arithmetic, clock-provenance, identity, and event foundations in dependency order. The early feasibility spike measures one strict transition through the shared clock, witness validate/commit, and durable journal flush on the target VM. It is diagnostic, not a release-gate pass. If it threatens p99 ≤5 ms, stop for design review; do not bypass witness integrity.

The independent strict oracle and fixtures are a **Release A acceptance prerequisite**. Full trace replay, policy comparison, and user-facing replay CLI remain **Release B**.

### Sprint 2 — Lifecycle and strict A

Prove the supervisor’s process inventory and positive exit confirmation, then witness transaction and fail-stop behavior, before serving strict requests. Release A exits only after the required strict correctness and fault evidence is recorded; failures, uncertain commitments, and incomplete histories cannot be counted as passes.

### Sprint 3 — Evaluation B

Run the frozen open-loop workload only after the strict baseline and trace/report schemas are accepted. Preserve all denominators and raw run artifacts. The p99 is nearest-rank over all delivered attempts, including errors; caller cancellation uses cancellation time and counts as a failure; no-response timeout uses the caller-deadline duration. The 99% timely ALLOW/LIMITED gate and 99.5% generator-delivery gate remain separate.

### Sprint 4 — Credits and assurance C

Implement credits only after Release A acceptance. Keep fixed-Q grants, same-sequence retry for uncertain outcomes, no refund/reclaim, fencing, and per-epoch bound semantics. The model checker must be independent of production decision functions. Release C remains incomplete until the required million-attempt correctness evidence, seeded-fault counterexamples, efficiency/service gates, and two clean reproductions are published.

## Workflow, acceptance, and PR rules

- A story is **Ready** only when its explicitly named input dependency contracts are verified, its source requirements/design are linked, failure behavior is explicit, and acceptance evidence is identified.
- A story is **Done** only when code is reviewed, required tests have actually run, independent evidence is recorded against the commit and environment, and the story/context status is updated. Planned tests or documentation alone are not evidence.
- After the Product Owner’s proceed command, use a separate feature branch and PR for each coherent story or vertical slice, based on current `main` or a verified prerequisite feature branch for a stacked PR. Stacked PRs target that feature branch so their diff remains independent; main merge requires Product Owner authorization. Rebase/retarget and rerun checks after the base changes. PRs include story IDs, PRD/SRD IDs, failure cases, evidence IDs, and observed results.
- Senior Dev reviews implementation and concurrency; Tester independently reviews acceptance; Scrum Master tracks dependencies and status; Master reviews integration. Do not merge or mark releases complete without the Product Owner’s authorization.
- Track work as **Ready → In Progress → Review → Acceptance → Done**, or **Blocked** with the unmet dependency/evidence stated. Do not pull blocked credit work forward to fill capacity.

## Current gates and work log

RG-001 API/helpers and the primary hosted Ubuntu package build are verified in [PR #5](https://github.com/kshiteesh28/DistributedRateGuard/pull/5); this is component acceptance. **Sprint 0 remains open for the actual Docker target, image digest and topology evidence**, owned by Master/Senior Dev. The optional gRPC source-build experiment remains unverified.

RG-002 policy/arithmetic is implemented on a stacked branch in [PR #6](https://github.com/kshiteesh28/DistributedRateGuard/pull/6); its final cap/crypto extensions passed both clean builds in run 43353832066 and independent Tester acceptance. See [RG-002 evidence](evidence/RG-002.md). RG-003-A clock component passed Linux/sanitizer checks and independent review; full RG-003 integration remains pending. Pure foundations may proceed; enforcement cannot activate until its runtime prerequisites pass. Full-system tests, benchmarks, model checking, witness durability, process fencing and certificates remain pending.

The [per-agent scrum work log](SCRUM-WORK-LOG.md) records handoffs, findings, failures, corrections and exact evidence. Earlier agent-minute estimates remain estimates; actual historical effort was not recorded. No release completion or main merge is claimed.

## Named dependency contracts

Implementation readiness depends on verified input deliverables rather than completion of their entire parent stories. Each contract identifies interface, tested revision/evidence, permitted consumers and excluded guarantees. Component acceptance permits dependent development only; system activation, story completion and release acceptance still require all applicable integration/product gates. Changes to a consumed contract require affected consumers to be reviewed and retested.

**RG-003-A** supplies IClock/LinuxMonotonicClock at `2d55c6e032ae75947f045ac76ffa383b2b1dd9d8`, [run 43355987772](https://github.com/kshiteesh28/DistributedRateGuard/actions/runs/43355987772). RG-006/007/008 may consume its verified startup identity, initial sample, serialized sampling and sticky failure behavior. **RG-003-B** (RG-006) still must prove every participant's topology; **RG-003-C** (RG-007/008) must complete actual commit/deadline mapping; **RG-003-D** (RG-013) must complete UNKNOWN evidence behavior. Full RG-003 remains incomplete. This removes a scheduling dependency cycle without changing any acceptance criterion or release gate.
