#include "authority/bucket_math.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <variant>

using rateguard::authority::BucketDecision;
using rateguard::authority::BucketMath;
using rateguard::authority::BucketPolicy;
using rateguard::authority::BucketState;
using rateguard::authority::MathResult;
using rateguard::v1::contract::Commitment;
using rateguard::v1::contract::DecisionOutcome;
using rateguard::v1::contract::ErrorCategory;
using rateguard::v1::contract::ErrorCode;

namespace {
constexpr std::uint64_t S = 1'000'000'000ULL;
int failures = 0;
void Check(bool condition, const char* label) {
  if (!condition) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}
template <class T>
const T* Value(const MathResult<T>& result) {
  return std::get_if<T>(&result);
}
template <class T>
const rateguard::authority::ServiceError* Error(const MathResult<T>& result) {
  return std::get_if<rateguard::authority::ServiceError>(&result);
}
}  // namespace

int main() {
  // Exact threshold: available == cost*S admits, one subunit below limits.
  const BucketPolicy unit{1, 1};
  auto at_boundary = BucketMath::Decide(unit, {S - 1, 0}, 1, 1);
  Check(Value(at_boundary) != nullptr, "boundary returns decision");
  if (const auto* d = Value(at_boundary)) {
    Check(d->outcome == DecisionOutcome::Allow, "exactly cost admits");
    Check(d->next.balance_subunits == 0 && d->next.last_refill_ns == 1,
          "boundary debit and timestamp");
    Check(!d->retry_delay_ns.has_value(), "allow has no retry estimate");
  }
  auto below_boundary = BucketMath::Decide(unit, {S - 2, 0}, 1, 1);
  if (const auto* d = Value(below_boundary)) {
    Check(d->outcome == DecisionOutcome::Limited, "one subunit short limits");
    Check(d->next.balance_subunits == S - 1 && d->next.last_refill_ns == 1,
          "limited advances refill but does not debit");
    Check(d->retry_delay_ns == 1, "ceil retry estimate in ns");
  } else {
    Check(false, "one subunit short returns decision");
  }

  // A 1 ns interval at rate 3 produces exactly 3 subunits (no float rounding).
  auto fractional = BucketMath::Refill({4, 3}, {0, 100}, 101);
  if (const auto* s = Value(fractional))
    Check(s->balance_subunits == 3 && s->last_refill_ns == 101,
          "fractional 1 ns refill");
  else
    Check(false, "fractional refill succeeds");

  // Refill saturates at capacity, including with maximum legal rate/time.
  auto saturated = BucketMath::Refill({3, 2}, {2 * S, 10}, 1'000'000'010ULL);
  if (const auto* s = Value(saturated))
    Check(s->balance_subunits == 3 * S && s->last_refill_ns == 1'000'000'010ULL,
          "capacity saturation");
  else
    Check(false, "saturation succeeds");
  auto maximum = BucketMath::Refill(
      {1'000'000'000ULL, 1'000'000'000ULL},
      {0, 0}, std::numeric_limits<std::uint64_t>::max());
  if (const auto* s = Value(maximum))
    Check(s->balance_subunits == 1'000'000'000ULL * S &&
              s->last_refill_ns == std::numeric_limits<std::uint64_t>::max(),
          "maximum policy and elapsed time safely saturate");
  else
    Check(false, "maximum legal values succeed");

  // Weighted costs and full capacity debit.
  auto weighted = BucketMath::Decide({5, 7}, {5 * S, 20}, 5, 20);
  if (const auto* d = Value(weighted))
    Check(d->outcome == DecisionOutcome::Allow && d->next.balance_subunits == 0,
          "weighted full-capacity debit");
  else
    Check(false, "weighted debit succeeds");

  // Invalid inputs are rejected before state mutation with NotCommitted status.
  const auto bad_policy = BucketMath::Refill({0, 1}, {0, 0}, 0);
  const auto bad_rate = BucketMath::Refill({1, 0}, {0, 0}, 0);
  const auto bad_capacity = BucketMath::Decide({1'000'000'001ULL, 1}, {0, 0}, 1, 0);
  const auto zero_cost = BucketMath::Decide(unit, {S, 0}, 0, 0);
  const auto oversized_cost = BucketMath::Decide(unit, {S, 0}, 2, 0);
  const auto zero_retry_rate = BucketMath::RetryDelay(1, 0);
  for (const auto* e : {Error(bad_policy), Error(bad_rate), Error(bad_capacity),
                        Error(zero_cost), Error(oversized_cost),
                        Error(zero_retry_rate)}) {
    Check(e != nullptr, "invalid input returns typed error");
    if (e) {
      Check(e->category == ErrorCategory::Input &&
                e->code == ErrorCode::InvalidArgument &&
                e->commitment == Commitment::NotCommitted,
            "invalid input error classification");
    }
  }

  // Broken state and nonmonotonic time are internal integrity failures.
  const auto bad_balance = BucketMath::Refill(unit, {S + 1, 0}, 1);
  const auto backwards = BucketMath::Refill(unit, {0, 2}, 1);
  for (const auto* e : {Error(bad_balance), Error(backwards)}) {
    Check(e != nullptr, "state integrity failure returns typed error");
    if (e)
      Check(e->category == ErrorCategory::Internal &&
                e->code == ErrorCode::Internal &&
                e->commitment == Commitment::NotCommitted,
            "integrity error classification");
  }

  // Integer ceiling is exact at integral and nonintegral ratios.
  auto exact_retry = BucketMath::RetryDelay(12, 3);
  auto rounded_retry = BucketMath::RetryDelay(13, 3);
  auto max_retry = BucketMath::RetryDelay(std::numeric_limits<std::uint64_t>::max(), 1);
  Check(Value(exact_retry) && *Value(exact_retry) == 4, "exact retry division");
  Check(Value(rounded_retry) && *Value(rounded_retry) == 5, "ceil retry division");
  Check(Value(max_retry) && *Value(max_retry) == std::numeric_limits<std::uint64_t>::max(),
        "maximum retry delay without overflow");

  if (failures != 0) return EXIT_FAILURE;
  std::cout << "bucket math contract checks passed\n";
  return EXIT_SUCCESS;
}
