# DistributedRateGuard

## About

DistributedRateGuard explores how replicated services can enforce per-tenant API quotas with less coordination. It compares strict authority checks with fixed-Q credits held by replicas, measuring the trade-off between authority traffic and bounded burst allowance. The project includes specifications for deterministic replay and correctness evaluation; quota enforcement and release-level guarantees are still in development.

## Implementation status

PR23 Docker inspect/stop and Linux recorded-process probe component qualification passed [exact-source Linux qualification](docs/evidence/RG-006-H.md) on run46103748414. This does not launch or activate participants or authorize epoch fencing; full RG-006 remains open.

## Current specification bundle

Read in this order:

1. [PRD revision 8](docs/PRD.md) — product goals and release gates.
2. [SRD revision 5](docs/SRD.md) — normative behavior and test obligations.
3. [HLD revision 5](docs/HLD.md) — proposed process and deployment architecture.
4. [LLD revision 11](docs/LLD.md) — proposed interfaces, state transitions, classes, and implementation order.
5. [Implementation stories](docs/STORIES.md) and [JSON context blocks](docs/context-blocks.json) — planned work and acceptance evidence.
6. [Agile sprint plan](docs/SPRINT-PLAN.md) — minute-based effort estimates, sequence, roles, and acceptance gates.

## Release plan

- **A — strict quota core:** authenticated admission, exact per-request authority decisions, and safe adapter forwarding.
- **B — evaluation:** deterministic replay, open-loop workloads, and reproducible reports.
- **C — distributed credits:** fixed-Q local spending, bounded burst accounting, and independent state-machine/history checks.

Live policy changes (PRD-013) and long-operation permits (PRD-014) are deferred.

## Status and implementation notes

Component implementations are integrated on `feature/distributed-rateguard`: wire/build contracts, immutable policy and fixed-point arithmetic, clock provenance, security/client guards, bounded history and inspection, local lifecycle, durable manifests/intents, runtime ownership and recovery-artifact diagnostics bounded local Unix HTTP transport and Docker inspect/stop with recorded-process evidence. Read the [per-agent scrum log](https://github.com/kshiteesh28/DistributedRateGuard/blob/feature/distributed-rateguard/docs/SCRUM-WORK-LOG.md), [build instructions](docs/build.md) and [latest component evidence](docs/evidence/RG-006-H.md). The [final PR to main](https://github.com/kshiteesh28/DistributedRateGuard/pull/13) remains unmerged. Live quota/forwarding services, process-control orchestration, witness integration, release benchmarks and model checking remain pending. All product thresholds remain goals.

PRD 8 and SRD 5 on `main` remain the product/behavior contracts; current HLD/LLD and implementation evidence are on `feature/distributed-rateguard` until final promotion. The local path hint in the context file currently contains documentation only and is not a verified Git checkout. Use the relevant review branch for implementation; dependent PRs may stack on a verified feature branch. The primary Ubuntu package lock is based on observed CI. A component fixture records the actual Docker/image profile; complete deployment qualification remains open; hosted component tests do not satisfy that deployment gate. Keep enforcement services fail-closed until shared-clock provenance, witness durability, process fencing, and identity fixtures pass.

## Research foundation

The design is informed by [Cloud Control with Distributed Rate Limiting (SIGCOMM 2007)](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf), and compares its proposed fixed-credit contract with established systems such as [Envoy ratelimit](https://github.com/envoyproxy/ratelimit) and [Gubernator](https://github.com/gubernator-io/gubernator). No novelty, equivalent-semantics speedup, or production-readiness claim is made.
