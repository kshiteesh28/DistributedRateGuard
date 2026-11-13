#pragma once

#include "rateguard/v1/error_contract.h"

#include <cstdint>
#include <limits>
#include <optional>
#include <variant>

namespace rateguard::authority {

using ServiceError = rateguard::v1::contract::ServiceError;
using DecisionOutcome = rateguard::v1::contract::DecisionOutcome;

template <class T>
using MathResult = std::variant<T, ServiceError>;

struct BucketPolicy {
  std::uint64_t capacity_units;
  std::uint64_t rate_units_per_second;
};

struct BucketState {
  std::uint64_t balance_subunits;
  std::uint64_t last_refill_ns;
};

struct BucketDecision {
  DecisionOutcome outcome;
  BucketState next;
  std::optional<std::uint64_t> retry_delay_ns;
};

// Pure integer arithmetic for token-bucket transitions. Time is monotonic
// nanoseconds; balances/costs are represented in 10^9 subunits per unit.
class BucketMath final {
 public:
  static constexpr std::uint64_t kSubunitsPerUnit = 1'000'000'000ULL;
  static constexpr std::uint64_t kMaxPolicyUnits = 1'000'000'000ULL;

  [[nodiscard]] static MathResult<BucketState> Refill(
      const BucketPolicy& policy, const BucketState& state,
      std::uint64_t now_ns) {
    if (!ValidPolicy(policy)) return InvalidInput();
    const std::uint64_t capacity_subunits =
        policy.capacity_units * kSubunitsPerUnit;
    if (state.balance_subunits > capacity_subunits ||
        now_ns < state.last_refill_ns)
      return InternalFailure();

    const std::uint64_t elapsed_ns = now_ns - state.last_refill_ns;
    // With S=T=10^9, r*elapsed_ns*S/T is exactly r*elapsed_ns
    // subunits. Keep the checked wide multiply even though legal input bounds
    // currently fit unsigned 128-bit.
    const uint128_t max128 = ~static_cast<uint128_t>(0);
    if (elapsed_ns != 0 &&
        static_cast<uint128_t>(policy.rate_units_per_second) >
            max128 / elapsed_ns)
      return InternalFailure();
    const uint128_t refill_subunits =
        static_cast<uint128_t>(policy.rate_units_per_second) * elapsed_ns;

    const uint128_t balance = state.balance_subunits;
    if (balance > max128 - refill_subunits) return InternalFailure();
    const uint128_t refilled = balance + refill_subunits;
    const std::uint64_t next_balance =
        refilled >= static_cast<uint128_t>(capacity_subunits)
            ? capacity_subunits
            : static_cast<std::uint64_t>(refilled);
    return BucketState{next_balance, now_ns};
  }

  [[nodiscard]] static MathResult<BucketDecision> Decide(
      const BucketPolicy& policy, const BucketState& state,
      std::uint64_t cost_units, std::uint64_t now_ns) {
    if (!ValidPolicy(policy) || cost_units == 0 ||
        cost_units > policy.capacity_units)
      return InvalidInput();

    auto refill_result = Refill(policy, state, now_ns);
    if (const auto* error = std::get_if<ServiceError>(&refill_result))
      return *error;
    const BucketState available = std::get<BucketState>(refill_result);
    const std::uint64_t cost_subunits = cost_units * kSubunitsPerUnit;
    if (available.balance_subunits >= cost_subunits) {
      return BucketDecision{DecisionOutcome::Allow,
                            {available.balance_subunits - cost_subunits,
                             available.last_refill_ns},
                            std::nullopt};
    }

    const std::uint64_t deficit = cost_subunits - available.balance_subunits;
    auto retry = RetryDelay(deficit, policy.rate_units_per_second);
    if (const auto* error = std::get_if<ServiceError>(&retry)) return *error;
    return BucketDecision{DecisionOutcome::Limited, available,
                          std::get<std::uint64_t>(retry)};
  }

  [[nodiscard]] static MathResult<std::uint64_t> RetryDelay(
      std::uint64_t deficit_subunits, std::uint64_t rate_units_per_second) {
    if (rate_units_per_second == 0 ||
        rate_units_per_second > kMaxPolicyUnits)
      return InvalidInput();
    const std::uint64_t quotient = deficit_subunits / rate_units_per_second;
    const std::uint64_t remainder = deficit_subunits % rate_units_per_second;
    if (remainder == 0) return quotient;
    if (quotient == std::numeric_limits<std::uint64_t>::max())
      return InternalFailure();
    return quotient + 1;
  }

 private:
#if defined(__SIZEOF_INT128__)
  using uint128_t = __uint128_t;
#else
#error "BucketMath requires compiler support for checked 128-bit integer arithmetic"
#endif

  [[nodiscard]] static constexpr bool ValidPolicy(
      const BucketPolicy& policy) noexcept {
    return policy.capacity_units >= 1 &&
           policy.capacity_units <= kMaxPolicyUnits &&
           policy.rate_units_per_second >= 1 &&
           policy.rate_units_per_second <= kMaxPolicyUnits;
  }

  [[nodiscard]] static constexpr ServiceError InvalidInput() noexcept {
    using namespace rateguard::v1::contract;
    return {ErrorCategory::Input, ErrorCode::InvalidArgument,
            RetryDisposition::Never, Commitment::NotCommitted};
  }

  [[nodiscard]] static constexpr ServiceError InternalFailure() noexcept {
    using namespace rateguard::v1::contract;
    return {ErrorCategory::Internal, ErrorCode::Internal,
            RetryDisposition::Never, Commitment::NotCommitted};
  }
};

}  // namespace rateguard::authority
