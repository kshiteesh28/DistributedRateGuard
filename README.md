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

RG-001 implementation has started in [PR #5](https://github.com/kshiteesh28/DistributedRateGuard/pull/5): versioned API schemas, contract validation/tests, and C++20 build infrastructure. See [build instructions](docs/build.md) and [RG-001 evidence](docs/evidence/RG-001.md) for the exact scope and verification status. Quota enforcement, release benchmarks, and model checking are not implemented or claimed. All product thresholds remain goals.

The source of truth is the current `main` branch. The local path hint in the context file currently contains documentation only and is not a verified Git checkout. Clone or sync `main` before implementation. Start at **RG-001**. Capture toolchain versions on the actual build host before compiling instead of guessing or claiming an untested lock. Keep enforcement services fail-closed until shared-clock provenance, witness durability, process fencing, and identity fixtures pass.

## Research foundation

The design is informed by [Cloud Control with Distributed Rate Limiting (SIGCOMM 2007)](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf), and compares its proposed fixed-credit contract with established systems such as [Envoy ratelimit](https://github.com/envoyproxy/ratelimit) and [Gubernator](https://github.com/gubernator-io/gubernator). No novelty, equivalent-semantics speedup, or production-readiness claim is made.
