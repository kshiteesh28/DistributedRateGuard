# RG011A Hand-Calculated Strict Sequence Fixtures

These vectors are independent expected results for the proposed pure C++20 sequence model (`StrictSequenceOracle`). Values are hand-calculated, not produced by production code. Attempts use contiguous ordinals and nondecreasing global synthetic timestamps. Every valid scenario produces one step row for every attempt, including `Invalid` selector rows; malformed scenarios return only a model error, with no partial result.

## Shared units and model rule

- `S = 1,000,000,000` subunits per policy unit; times and retry delays are integer nanoseconds.
- Policy operation costs come from the immutable tenant operation table. The attempt does not supply cost.
- For a known tenant and operation at `t >= last`, `available = min(B*S, balance + r*(t-last))`. The unit/ns conversion makes `r*(t-last)` subunits.
- ALLOW iff `available >= cost*S`; debit exactly `cost*S`. Otherwise LIMITED with no debit. Both outcomes set `last=t`; LIMITED retains fractional subunits. Retry is `ceil((cost*S-available)/r)` ns.
- Same-time attempts follow contiguous input ordinal, never cost or ID sorting. Tenant state is independent.

## F1 — Equal-time weighted order is observable

Tenant policy: `B=5`, `r=1`, operations `heavy=5`, `light=1`; initial `(balance=5*S,last=0)`. Both attempts use `t=0` and ordinals 0,1.

| Input order | Ordinal | Operation | Result | Balance after | last after | Retry |
|---|---:|---|---|---:|---:|---:|
| heavy, light | 0 | heavy | ALLOW | 0 | 0 | — |
|  | 1 | light | LIMITED | 0 | 0 | 1,000,000,000 ns |
| light, heavy | 0 | light | ALLOW | 4*S | 0 | — |
|  | 1 | heavy | LIMITED | 4*S | 0 | 1,000,000,000 ns |

Use two fresh scenarios for the opposite orders. The outcomes and final states differ. A reject-all mutation fails ordinal 0 in both scenarios; reordering ties changes their expected rows.

## F2 — LIMITED advances time and retains fractional refill

Tenant policy: `B=5`, `r=2`, operations `heavy=2`, `light=1`; initial `(0,0)`.

| Ordinal | `t` ns | Operation | Available before decision | Result | Balance after | last after | Retry |
|---:|---:|---|---:|---|---:|---:|---:|
| 0 | 499,999,999 | heavy | 999,999,998 subunits | LIMITED | 999,999,998 | 499,999,999 | 500,000,001 ns |
| 1 | 500,000,002 | heavy | prior + `2*3=6` = 1,000,000,004 subunits | LIMITED | 1,000,000,004 | 500,000,002 | 499,999,998 ns |
| 2 | 1,000,000,000 | light | prior + `2*499,999,998` = 2,000,000,000 subunits | ALLOW | 1,000,000,000 | 1,000,000,000 | — |

If ordinal 0 does not advance `last`, ordinal 1 double-counts elapsed time: it sees 2,000,000,002 subunits and incorrectly ALLOWs the cost-2 operation. Dropping fractional subunits on LIMITED also changes ordinal 1's exact result/state.

## F3 — Exact boundary and one-subunit-short

Tenant policy `B=2`, `r=2`, operation `one=1`. Each bullet is a fresh scenario.

1. Initial `(S-1,0)`, attempt at `t=0`, cost 1: LIMITED; after `(S-1,0)`; retry 1 ns.
2. Initial `(0,0)`, attempt at `t=500,000,000`, cost 1: ALLOW exactly at `S`; after `(0,500,000,000)`.
3. Initial `(0,0)`, attempt at `t=499,999,999`, cost 1: LIMITED at `999,999,998`; after `(999,999,998,499,999,999)`; retry 1 ns.

This distinguishes `>=` from `>` and catches early rounding to whole units.

## F4 — Saturation at maximum legal policy and elapsed time

Tenant policy `B=1,000,000,000`, `r=1,000,000,000`, operation `max=1,000,000,000`; initial `(0,0)`. One attempt at `t=UINT64_MAX`, ordinal 0, operation `max`.

Refill saturates at `B*S = 10^18` subunits, so result is ALLOW, after balance 0, and `last=UINT64_MAX`. No wraparound may reduce available balance or reject this legal input.

## F5 — Tenant isolation

Tenants A and B each have `B=1`, `r=1`, operation `one=1`, initial `(S,0)`. One scenario; attempts are globally ordered as listed.

| Ordinal | Tenant | `t` | Operation | Result | Balance after | last after |
|---:|---|---:|---|---|---:|---:|
| 0 | A | 0 | one | ALLOW | 0 | 0 |
| 1 | B | 0 | one | ALLOW | 0 | 0 |
| 2 | A | 0 | one | LIMITED | 0 | 0 |
| 3 | B | 1,000,000,000 | one | ALLOW | 0 | 1,000,000,000 |

A shared global bucket would incorrectly deny B's initial request; cross-tenant refill/debit also changes these rows.

## F6 — Unknown selectors produce rows without state mutation

Tenant policy `B=2`, `r=1`, known operation `two=2`; initial `(2*S,10)`. Attempts, all at `t=10`, have ordinals 0–2:

| Ordinal | Tenant selector | Operation selector | Result | Before | After |
|---:|---|---|---|---|---|
| 0 | `tenant` | `missing-op` | Invalid | `(2*S,10)` | `(2*S,10)` |
| 1 | `missing-tenant` | `two` | Invalid | absent | absent |
| 2 | `tenant` | `two` | ALLOW | `(2*S,10)` | `(0,10)` |

The model emits all three results, creates no state for the unknown tenant, and leaves the known tenant unchanged on unknown operation. A later valid request still runs against the original state.

## F7 — Whole-scenario validation is atomic

Each invalid input below rejects the entire scenario with its typed `ModelError`; no prefix of `steps` is returned:

- Attempt ordinals `0,2`: `InvalidAttemptOrder`.
- Global time decreases from 10 to 9: `TimeRegression`.
- Same tenant has a previous known transition at 10 and a later attempt at 9: `TimeRegression`.
- Initial balance greater than `B*S`: `InvalidInitialBalance`.
- Duplicate tenant/operation IDs, missing initial bucket, illegal policy cost/rate/capacity: the corresponding validation error.

These are malformed model inputs, unlike F6's well-formed unknown selectors that return per-step `Invalid` decisions.

## Evidence boundary

Passing these fixtures establishes only the pure sequence model's behavior on synthetic inputs. It does not establish production authority conformance, concurrent serialization, true linearization timestamps, interval guarantees from runtime history, trusted-clock provenance, deadline-safe forwarding, or release gates. Runtime mapping must be specified separately; missing/untrusted provenance or incomplete history remains UNKNOWN, never PASS.
