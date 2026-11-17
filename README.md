# DistributedRateGuard

A proposed C++20/gRPC service for per-tenant API admission across replicas. It compares strict per-request authority checks with fixed-Q credits spent locally, measuring coordination cost against a bounded additional burst.

## Current specification bundle

Read in this order:

1. [PRD revision 8](docs/PRD.md) — product goals and release gates.
2. [SRD revision 5](docs/SRD.md) — normative behavior and test obligations.
3. [HLD revision 4](docs/HLD.md) — proposed process and deployment architecture.
4. [LLD revision 5](docs/LLD.md) — proposed interfaces, state transitions, classes, and implementation order.
5. [Implementation stories](docs/STORIES.md) and [JSON context blocks](docs/context-blocks.json) — planned work and acceptance evidence.
6. [Agile sprint plan](docs/SPRINT-PLAN.md) — minute-based effort estimates, sequence, roles, and acceptance gates.

## Release plan

- **A — strict quota core:** authenticated admission, exact per-request authority decisions, and safe adapter forwarding.
- **B — evaluation:** deterministic replay, open-loop workloads, and reproducible reports.
- **C — distributed credits:** fixed-Q local spending, bounded burst accounting, and independent state-machine/history checks.

Live policy changes (PRD-013) and long-operation permits (PRD-014) are deferred.

## Status and implementation notes

RG-001 contracts/build ([PR #5](https://github.com/kshiteesh28/DistributedRateGuard/pull/5)) and RG-002 immutable policy/checked arithmetic ([PR #6](https://github.com/kshiteesh28/DistributedRateGuard/pull/6)) have passing component evidence and await review; neither is merged to main. RG-003 clock component ([PR #8](https://github.com/kshiteesh28/DistributedRateGuard/pull/8)) passed Linux/sanitizer checks; full service/checker integration remains pending. Read the [live per-agent scrum log](https://github.com/kshiteesh28/DistributedRateGuard/blob/docs/scrum-work-log/docs/SCRUM-WORK-LOG.md), [build instructions](docs/build.md), [RG-001 evidence](docs/evidence/RG-001.md), and [RG-002 evidence](docs/evidence/RG-002.md) for scope and observed results. Quota enforcement, release benchmarks, and model checking are not implemented or claimed. All product thresholds remain goals.

The source of truth is the current `main` branch. The local path hint in the context file currently contains documentation only and is not a verified Git checkout. Use the relevant review branch for implementation; dependent PRs may stack on a verified feature branch. The primary Ubuntu package lock is based on observed CI. Actual Docker target/image-digest evidence remains open; hosted component tests do not satisfy that deployment gate. Keep enforcement services fail-closed until shared-clock provenance, witness durability, process fencing, and identity fixtures pass.

## Research foundation

The design is informed by [Cloud Control with Distributed Rate Limiting (SIGCOMM 2007)](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf), and compares its proposed fixed-credit contract with established systems such as [Envoy ratelimit](https://github.com/envoyproxy/ratelimit) and [Gubernator](https://github.com/gubernator-io/gubernator). No novelty, equivalent-semantics speedup, or production-readiness claim is made.
