# RateGuard

A proposed C++ distributed rate limiter comparing exact per-request coordination with distributed credits and an explicit bounded burst allowance.

## Specification

Read the [Product Requirements Document — revision 5](docs/PRD.md) for the product contract, numerical release goals, research references, failure model, experiment plan, and specification-to-code readiness gates.

## Planned capabilities

- **Strict mode:** authoritative quota decisions for each request.
- **Distributed-credit mode:** local admission from allocated batches, with credit conservation and a documented burst bound.
- **Policy replay:** explain how policies change admissions for a fixed traffic trace.
- **Reproducible evaluation:** measure coordination overhead, latency, burst deviation, wasted credits, and failure behavior.

## Research foundation

The design draws on [Cloud Control with Distributed Rate Limiting (SIGCOMM 2007)](https://cseweb.ucsd.edu/~kvishwanath/papers/fp076-raghavan.pdf) and studies existing implementations such as [Envoy ratelimit](https://github.com/envoyproxy/ratelimit) and [Gubernator](https://github.com/gubernator-io/gubernator).

## Status

Specification stage. Implementation source and reproducible benchmark results are not included yet. Performance targets and design improvements in the PRD are proposals, not measured results.
