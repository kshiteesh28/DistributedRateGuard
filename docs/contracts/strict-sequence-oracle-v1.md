# Strict Sequence Oracle v1

**Status:** Selected RG-011A test-support contract, revision 2 (2026-11-28). Component code is present on the review branch; Linux acceptance is pending. No runtime conformance or release gate is claimed.

**Sources:** PRD 8, SRD 5 (D3/D4, FR-011/012/020, AT-12, strict arithmetic FR-002/003 and AT-02/03), [HLD 5](../HLD.md) and [LLD 11](../LLD.md). Existing arithmetic is `src/authority/bucket_math.h`; the independent secondary reference is `tools/tests/bucket_math_oracle.py`. Proposed new C++ path: `tools/replay/reference_model.h`.

## Scope

Implement one pure C++20 model for an already ordered **synthetic strict-mode sequence**. It owns typed policy and initial state, validation, per-tenant transitions, and per-step expected results. It must not import production `BucketMath`, `PolicyLoader`, `AuthorityEngine`, clock, event recorder, or service code. No I/O, hashes, wire format, CLI, or real runtime timestamps.

This models deterministic sequential decisions, including tenant isolation and invalid selectors. It is not a concurrent-history checker, interval-bound checker, full replay CLI, production-vs-model adapter, or trusted-provenance verifier. Synthetic inputs cannot establish that runtime events came from real authority commits. Full PRD-006 replay comparison remains Release B work.

## Typed API

Identifiers use policy-v1 ASCII `[A-Za-z0-9_.-]`, 1–128 bytes. `Run` synchronously borrows a const scenario, which callers must not mutate concurrently; it does not copy the full input trace. It copies only result-owned selectors/state. No caller-owned view escapes. Types are compiling-interface guidance, not serialization.

```cpp
namespace rateguard::replay {
using Units = std::uint64_t;
using Subunits = std::uint64_t;
using TimeNs = std::uint64_t;
struct OperationSpec { std::string id; Units cost_units; };
struct TenantSpec {
  std::string id; Units rate_units_per_second; Units capacity_units;
  std::vector<OperationSpec> operations;
};
struct InitialBucket { std::string tenant_id; Subunits balance_subunits; TimeNs last_refill_ns; };
struct SyntheticAttempt {
  std::uint64_t ordinal; // contiguous from zero; breaks equal-time ties
  TimeNs logical_time_ns; // synthetic only
  std::string tenant_id; std::string operation_id; // cost comes from policy
};
struct StrictScenario {
  std::vector<TenantSpec> tenants;
  std::vector<InitialBucket> initial_buckets; // exactly one per tenant
  std::vector<SyntheticAttempt> attempts; // caller-supplied linearization order
};
enum class Decision { Allow, Limited, Invalid };
enum class InvalidReason { MalformedTenantId, UnknownTenant,
  MalformedOperationId, UnknownOperation };
struct BucketView { Subunits balance_subunits; TimeNs last_refill_ns; };
struct StepResult {
  std::uint64_t ordinal; TimeNs logical_time_ns;
  std::string tenant_id; std::string operation_id; Decision decision;
  std::optional<InvalidReason> invalid_reason;
  std::optional<BucketView> before, after;
  std::optional<TimeNs> retry_delay_ns; // LIMITED only
};
struct StrictSequenceResult { std::vector<StepResult> steps; };
enum class ModelError { InvalidScenario, DuplicateIdentifier, MissingInitialState,
  InvalidInitialBalance, InvalidAttemptOrder, TimeRegression, ResourceLimit,
  ArithmeticInvariant, AllocationFailure, InternalFailure };
using RunResult = std::variant<StrictSequenceResult, ModelError>;
class StrictSequenceOracle final {
 public: static RunResult Run(const StrictScenario&) noexcept;
};
}
```

Malformed selector syntax (empty/bad ASCII within 128 bytes) and valid unknown tenant/operation each yield per-step `Invalid` with a specific reason. They create no state and never refill/debit an existing bucket. Selectors longer than 128 bytes are a structural `ResourceLimit` before result copying. Validate scenario structure, policy, IDs, operation costs, initial states, count limits, contiguous ordinals, and global time ordering before emitting any result. Decreasing global time, or time earlier than a known tenant's current `last_refill_ns` (including when its operation selector is invalid), rejects the **whole** run with `TimeRegression`; invalid selectors do not hide chronology errors. No partial result escapes a `ModelError`. A `std::bad_alloc` maps to `AllocationFailure`, a `std::length_error` to `ResourceLimit`, and any unexpected implementation exception to `InternalFailure`; an unexpected exception must not be mislabeled as a failed arithmetic invariant.

Selector classification order is malformed tenant, unknown tenant, malformed operation, unknown operation. A known tenant has identical before/after views for either invalid-operation outcome; an unresolved tenant has neither view. Structural validation precedes this classification. Empty attempt sequences are valid model inputs and yield empty results; they establish no acceptance evidence.

For isolated validation faults, malformed policy/initial identifiers and illegal policy numeric values return `InvalidScenario`; duplicate tenant, per-tenant operation or initial-state keys return `DuplicateIdentifier`; a missing/extra/unknown initial tenant returns `MissingInitialState`; an excessive initial balance returns `InvalidInitialBalance`; noncontiguous ordinals return `InvalidAttemptOrder`. Check resource caps first, then policy, then initial-state membership/balances, then attempt ordering/time. Within an attempt, ordinal validation precedes time validation. If several faults coexist, the first detected in those phases is returned; no partial trace is exposed.

Initial balances are explicit and never inferred. Each lies in `[0,B×S]`; a scenario representing new-epoch initialization uses full `B×S` per LLD §5, while a replayed mid-epoch state may be partial. Errors are model/input errors, not quota outcomes. The model omits unavailable/overloaded outcomes, deadline races, transport uncertainty, forwarding, and request-supplied cost.

## D3 arithmetic and step semantics

Use SRD D3: `S=10^9` subunits/unit; integer units and nanoseconds; `1≤B,r≤10^9`; `1≤c≤B`; balance is uint64 subunits with `balance≤B×S`; timestamps/retry delays are uint64 nanoseconds. Cost always comes from the operation table. Refill time advances on `ALLOW` and `LIMITED`; LIMITED has no debit.

Use divide-before-multiply saturation, independent from production `BucketMath`'s direct refill product, while checking arithmetic with unsigned 128-bit intermediates as D3 requires:

```text
cap = B×S; headroom = cap − balance; elapsed = now − last_refill
ns_to_full = headroom/r + (headroom%r != 0)
if elapsed >= ns_to_full: available = cap
else:
    refill = checked_u128(r × elapsed) // by branch proof, refill < headroom ≤ 10^18
    total = checked_u128(balance + refill)
    available = checked_u64(total)
if available >= c×S: ALLOW; next_balance = available − c×S
else: LIMITED; next_balance = available
      retry_ns = deficit/r + (deficit%r != 0)
next_refill_ns = now
```

Every multiplication, addition and narrowing conversion is checked; no floating point. Ceilings use quotient/remainder, avoiding `x+divisor−1`. `B×S` and `c×S` are at most `10^18`; the nonsaturating product is strictly below headroom. Violated preconditions return a model error, never wrap or invent a result. Each result gives ordinal/time, selector, decision/reason, before-state, after-refill/post-decision state, and retry delay when LIMITED. Equal timestamps follow ordinal and are never reordered.

## Bounds and tests

Reuse policy-v1 limits: 1–10,000 tenants, 1–64 operations/tenant, ≤100,000 operations total, D3 numeric bounds, and identifier length ≤128. Add a test-support cap of 0–1,000,000 attempts/results per run. This count plus fixed per-record/identifier limits makes output finite; validate counts before allocation and map allocation failure to `AllocationFailure`. No byte budget or production D6 limit is claimed.

Golden vectors: fractional refill, cap saturation, exact-cost ALLOW, one-subunit-short LIMITED/ceil retry, LIMITED refill-time advance, equal-time order, tenant isolation, invalid selectors/no state creation, full/partial initial state, maximum B/r/c, large elapsed time, invalid balance, time regression, duplicate IDs, and malformed order. Seed mutations for reject-all, always-ALLOW, floor retry, debit-on-LIMITED, missing refill advance, over-cap refill, cross-tenant lookup, unknown-tenant insertion, wrong operation-cost resolution, and equal-time reordering. Compare arithmetic vectors with the Python arbitrary-precision oracle, but the C++ model calls neither that oracle nor production math. NDEBUG-safe fixtures have fixed expected values.

No input can claim `trusted`, `runtime_valid`, or `provenance_passed`. Runtime conformance needs a separately specified join of complete attempt, tenant/operation, policy/epoch, committed outcome/cost, and verified commit time. Existing EventV1/RunPlan is insufficient; RG-003-D, RG-005, and RG-007/008 integration remains needed before runtime evidence can be evaluated. This slice supports FR-011/012 and AT-12 only; it does not claim FR-017.

## Ordered handoff and estimate

1. Review contract and error/boundary semantics: **15–25 active minutes**.
2. Implement only `tools/replay/reference_model.h`: **40–60 minutes**.
3. Add NDEBUG-safe golden and mutation tests: **45–70 minutes**.
4. Independent Python-vector/source-import review: **20–30 minutes**.

Estimated total: **120–185 active minutes**, excluding CI queue time. Junior implements after approval; tester independently derives expected fixtures/mutations; senior reviews. Runtime history joins, interval/concurrency checking, full replay CLI, credit mode and authority changes are separate slices.

## Principal review dispositions — revision 2

- **Accepted:** Separate unexpected implementation exceptions from `ArithmeticInvariant` using `InternalFailure`. This refines the model's error reporting and changes no quota behavior.
- **Retained by explicit contract:** `MissingInitialState` denotes a nonmatching initial-state tenant set, including an extra or unknown tenant. That mapping is deliberately shared with missing records; it never creates a bucket or permits partial execution.
- **Verification additions:** Exercise every inclusive/exclusive count cap and allocation-failure atomicity. Seed all ten selected logical faults plus the targeted unchecked-u64 refill fault; successful compilation alone never counts as defect detection.
