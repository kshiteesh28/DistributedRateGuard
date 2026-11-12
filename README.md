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

The repository currently contains proposed specifications and handoff material; no implementation, tests, benchmarks, or model-checking results are claimed. All product thresholds are goals, not achieved results.

The source of truth is the current `main` branch. The local path hint in the context file currently contains documentation only and is not a verified Git checkout. Clone or sync `main` before implementation. Start at **RG-001**. Capture toolchain versions on the actual build host before compiling instead of guessing or claiming an untested lock. Keep enforcement services fail-closed until shared-clock provenance, witness durability, process fencing, and identity fixtures pass.

## Research foundation

The design is informed by [Cloud Control with Distributed Rate Limiting (SIGCOMM 2007)](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf), and compares its proposed fixed-credit contract with established systems such as [Envoy ratelimit](https://github.com/envoyproxy/ratelimit) and [Gubernator](https://github.com/gubernator-io/gubernator). No novelty, equivalent-semantics speedup, or production-readiness claim is made.
