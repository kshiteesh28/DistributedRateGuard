#pragma once

// Independent, pure model for already ordered synthetic strict decisions.
// This is test support only; it is not a runtime conformance or safety proof.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <variant>
#include <utility>
#include <vector>

namespace rateguard::replay {

using Units = std::uint64_t;
using Subunits = std::uint64_t;
using TimeNs = std::uint64_t;

struct OperationSpec {
  std::string id;
  Units cost_units{};
};

struct TenantSpec {
  std::string id;
  Units rate_units_per_second{};
  Units capacity_units{};
  std::vector<OperationSpec> operations;
};

struct InitialBucket {
  std::string tenant_id;
  Subunits balance_subunits{};
  TimeNs last_refill_ns{};
};

struct SyntheticAttempt {
  std::uint64_t ordinal{};
  TimeNs logical_time_ns{};
  std::string tenant_id;
  std::string operation_id;
};

struct StrictScenario {
  std::vector<TenantSpec> tenants;
  std::vector<InitialBucket> initial_buckets;
  std::vector<SyntheticAttempt> attempts;
};

enum class Decision { Allow, Limited, Invalid };
enum class InvalidReason {
  MalformedTenantId,
  UnknownTenant,
  MalformedOperationId,
  UnknownOperation,
};

enum class ModelError {
  InvalidScenario,
  DuplicateIdentifier,
  MissingInitialState,
  InvalidInitialBalance,
  InvalidAttemptOrder,
  TimeRegression,
  ResourceLimit,
  ArithmeticInvariant,
  AllocationFailure,
  InternalFailure,
};

struct BucketView {
  Subunits balance_subunits{};
  TimeNs last_refill_ns{};
};

struct StepResult {
  std::uint64_t ordinal{};
  TimeNs logical_time_ns{};
  std::string tenant_id;
  std::string operation_id;
  Decision decision{Decision::Invalid};
  std::optional<InvalidReason> invalid_reason;
  std::optional<BucketView> before;
  std::optional<BucketView> after;
  std::optional<TimeNs> retry_delay_ns;
};

struct StrictSequenceResult {
  std::vector<StepResult> steps;
};

using RunResult = std::variant<StrictSequenceResult, ModelError>;

class StrictSequenceOracle final {
 public:
  [[nodiscard]] static RunResult Run(const StrictScenario& scenario) noexcept {
    try {
      if (const auto error = ValidateResourceCaps(scenario); error.has_value())
        return *error;
      if (const auto error = ValidatePolicy(scenario); error.has_value())
        return *error;

      using Index = std::map<std::string_view, std::size_t, std::less<>>;
      std::map<std::string_view, std::size_t, std::less<>> tenant_indexes;
      std::vector<Index> operation_indexes(scenario.tenants.size());
      for (std::size_t tenant_index = 0; tenant_index < scenario.tenants.size();
           ++tenant_index) {
        const auto& tenant = scenario.tenants[tenant_index];
        if (!tenant_indexes.emplace(tenant.id, tenant_index).second)
          return ModelError::DuplicateIdentifier;
        auto& operation_index = operation_indexes[tenant_index];
        for (std::size_t operation = 0; operation < tenant.operations.size();
             ++operation) {
          if (!operation_index.emplace(tenant.operations[operation].id, operation).second)
            return ModelError::DuplicateIdentifier;
        }
      }

      std::vector<BucketView> states(scenario.tenants.size());
      std::vector<bool> initial_seen(scenario.tenants.size(), false);
      for (const auto& initial : scenario.initial_buckets) {
        if (!ValidIdentifier(initial.tenant_id)) return ModelError::InvalidScenario;
        const auto found = tenant_indexes.find(initial.tenant_id);
        if (found == tenant_indexes.end()) return ModelError::MissingInitialState;
        const std::size_t index = found->second;
        if (initial_seen[index]) return ModelError::DuplicateIdentifier;
        const auto capacity = CapacitySubunits(scenario.tenants[index].capacity_units);
        if (!capacity) return ModelError::ArithmeticInvariant;
        if (initial.balance_subunits > *capacity)
          return ModelError::InvalidInitialBalance;
        initial_seen[index] = true;
        states[index] = {initial.balance_subunits, initial.last_refill_ns};
      }
      for (const bool seen : initial_seen) {
        if (!seen) return ModelError::MissingInitialState;
      }

      TimeNs previous_time = 0;
      bool has_previous_time = false;
      for (std::size_t i = 0; i < scenario.attempts.size(); ++i) {
        const auto& attempt = scenario.attempts[i];
        if (attempt.ordinal != static_cast<std::uint64_t>(i))
          return ModelError::InvalidAttemptOrder;
        if (has_previous_time && attempt.logical_time_ns < previous_time)
          return ModelError::TimeRegression;
        previous_time = attempt.logical_time_ns;
        has_previous_time = true;
      }

      StrictSequenceResult result;
      result.steps.reserve(scenario.attempts.size());
      for (const auto& attempt : scenario.attempts) {
        const auto tenant_syntax = IdentifierStatus(attempt.tenant_id);
        if (tenant_syntax == IdentifierCheck::TooLong)
          return ModelError::ResourceLimit;

        std::optional<std::size_t> tenant_index;
        if (tenant_syntax == IdentifierCheck::Valid) {
          const auto found = tenant_indexes.find(attempt.tenant_id);
          if (found != tenant_indexes.end()) {
            tenant_index = found->second;
            // Chronology is checked before selector classification or result
            // copying. Invalid operation input cannot conceal a regression.
            if (attempt.logical_time_ns < states[*tenant_index].last_refill_ns)
              return ModelError::TimeRegression;
          }
        }

        StepResult step;
        step.ordinal = attempt.ordinal;
        step.logical_time_ns = attempt.logical_time_ns;
        step.tenant_id = attempt.tenant_id;
        step.operation_id = attempt.operation_id;
        step.decision = Decision::Invalid;

        if (tenant_syntax == IdentifierCheck::Malformed) {
          step.invalid_reason = InvalidReason::MalformedTenantId;
          result.steps.push_back(std::move(step));
          continue;
        }
        if (!tenant_index.has_value()) {
          step.invalid_reason = InvalidReason::UnknownTenant;
          result.steps.push_back(std::move(step));
          continue;
        }
        const std::size_t known_tenant_index = *tenant_index;
        const auto& tenant = scenario.tenants[known_tenant_index];
        const BucketView current = states[known_tenant_index];

        const auto operation_syntax = IdentifierStatus(attempt.operation_id);
        if (operation_syntax == IdentifierCheck::TooLong)
          return ModelError::ResourceLimit;
        if (operation_syntax == IdentifierCheck::Malformed) {
          step.invalid_reason = InvalidReason::MalformedOperationId;
          step.before = current;
          step.after = current;
          result.steps.push_back(std::move(step));
          continue;
        }
        const auto operation_found = operation_indexes[known_tenant_index].find(attempt.operation_id);
        if (operation_found == operation_indexes[known_tenant_index].end()) {
          step.invalid_reason = InvalidReason::UnknownOperation;
          step.before = current;
          step.after = current;
          result.steps.push_back(std::move(step));
          continue;
        }

        const Units cost = tenant.operations[operation_found->second].cost_units;
        BucketView next{};
        std::optional<TimeNs> retry;
        const auto refill = RefillAndSaturate(
            tenant.capacity_units, tenant.rate_units_per_second, current,
            attempt.logical_time_ns);
        if (!refill.has_value()) return ModelError::ArithmeticInvariant;
        const Subunits available = *refill;
        const auto cost_subunits_value = CostSubunits(cost);
        if (!cost_subunits_value) return ModelError::ArithmeticInvariant;
        const Subunits cost_subunits = *cost_subunits_value;
        if (available >= cost_subunits) {
          step.decision = Decision::Allow;
          next = {available - cost_subunits, attempt.logical_time_ns};
        } else {
          step.decision = Decision::Limited;
          next = {available, attempt.logical_time_ns};
          const Subunits deficit = cost_subunits - available;
          const Units rate = tenant.rate_units_per_second;
          const Units quotient = deficit / rate;
          const Units remainder = deficit % rate;
          if (remainder != 0 && quotient == std::numeric_limits<TimeNs>::max())
            return ModelError::ArithmeticInvariant;
          retry = quotient + (remainder != 0 ? 1U : 0U);
        }
        step.before = current;
        step.after = next;
        step.retry_delay_ns = retry;
        states[known_tenant_index] = next;
        result.steps.push_back(std::move(step));
      }
      return result;
    } catch (const std::bad_alloc&) {
      return ModelError::AllocationFailure;
    } catch (const std::length_error&) {
      return ModelError::ResourceLimit;
    } catch (...) {
      return ModelError::InternalFailure;
    }
  }

 private:
  static constexpr Units kSubunitsPerUnit = 1'000'000'000ULL;
  static constexpr Units kMaximumPolicyUnits = 1'000'000'000ULL;
  static constexpr std::size_t kMaxTenants = 10'000;
  static constexpr std::size_t kMaxOperationsPerTenant = 64;
  static constexpr std::size_t kMaxOperationsTotal = 100'000;
  static constexpr std::size_t kMaxAttempts = 1'000'000;
  static constexpr std::size_t kMaxIdentifierBytes = 128;

  enum class IdentifierCheck { Valid, Malformed, TooLong };

  [[nodiscard]] static IdentifierCheck IdentifierStatus(std::string_view id) noexcept {
    if (id.size() > kMaxIdentifierBytes) return IdentifierCheck::TooLong;
    if (id.empty()) return IdentifierCheck::Malformed;
    for (const unsigned char ch : id) {
      const bool alpha = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
      const bool digit = ch >= '0' && ch <= '9';
      if (!alpha && !digit && ch != '_' && ch != '.' && ch != '-')
        return IdentifierCheck::Malformed;
    }
    return IdentifierCheck::Valid;
  }

  [[nodiscard]] static bool ValidIdentifier(std::string_view id) noexcept {
    return IdentifierStatus(id) == IdentifierCheck::Valid;
  }

  [[nodiscard]] static std::optional<ModelError> ValidateResourceCaps(
      const StrictScenario& scenario) noexcept {
    if (scenario.tenants.size() > kMaxTenants ||
        scenario.initial_buckets.size() > kMaxTenants ||
        scenario.attempts.size() > kMaxAttempts)
      return ModelError::ResourceLimit;
    std::size_t operation_count = 0;
    for (const auto& tenant : scenario.tenants) {
      if (tenant.id.size() > kMaxIdentifierBytes) return ModelError::ResourceLimit;
      if (tenant.operations.size() > kMaxOperationsPerTenant)
        return ModelError::ResourceLimit;
      if (tenant.operations.size() > kMaxOperationsTotal - operation_count)
        return ModelError::ResourceLimit;
      operation_count += tenant.operations.size();
      for (const auto& operation : tenant.operations) {
        if (operation.id.size() > kMaxIdentifierBytes) return ModelError::ResourceLimit;
      }
    }
    for (const auto& initial : scenario.initial_buckets) {
      if (initial.tenant_id.size() > kMaxIdentifierBytes) return ModelError::ResourceLimit;
    }
    for (const auto& attempt : scenario.attempts) {
      if (attempt.tenant_id.size() > kMaxIdentifierBytes ||
          attempt.operation_id.size() > kMaxIdentifierBytes)
        return ModelError::ResourceLimit;
    }
    return std::nullopt;
  }

  [[nodiscard]] static std::optional<ModelError> ValidatePolicy(
      const StrictScenario& scenario) noexcept {
    if (scenario.tenants.empty()) return ModelError::InvalidScenario;
    std::size_t operation_count = 0;
    for (const auto& tenant : scenario.tenants) {
      if (!ValidIdentifier(tenant.id) || tenant.capacity_units == 0 ||
          tenant.capacity_units > kMaximumPolicyUnits ||
          tenant.rate_units_per_second == 0 ||
          tenant.rate_units_per_second > kMaximumPolicyUnits ||
          tenant.operations.empty())
        return ModelError::InvalidScenario;
      operation_count += tenant.operations.size();
      for (const auto& operation : tenant.operations) {
        if (!ValidIdentifier(operation.id) || operation.cost_units == 0 ||
            operation.cost_units > tenant.capacity_units)
          return ModelError::InvalidScenario;
      }
    }
    if (operation_count > kMaxOperationsTotal) return ModelError::ResourceLimit;
    return std::nullopt;
  }

  [[nodiscard]] static std::optional<Subunits> CheckedSubunitsProduct(
      Units units) noexcept {
    using Wide = __uint128_t;
    constexpr Wide kWideMax = ~static_cast<Wide>(0);
    const Wide left = static_cast<Wide>(units);
    const Wide right = static_cast<Wide>(kSubunitsPerUnit);
    if (left != 0 && right > kWideMax / left) return std::nullopt;
    const Wide product = left * right;
    if (product > static_cast<Wide>(std::numeric_limits<Subunits>::max()))
      return std::nullopt;
    return static_cast<Subunits>(product);
  }

  [[nodiscard]] static std::optional<Subunits> CapacitySubunits(
      Units capacity_units) noexcept {
    return CheckedSubunitsProduct(capacity_units);
  }

  [[nodiscard]] static std::optional<Subunits> CostSubunits(
      Units cost_units) noexcept {
    return CheckedSubunitsProduct(cost_units);
  }

  [[nodiscard]] static std::optional<Subunits> RefillAndSaturate(
      Units capacity_units, Units rate_units_per_second, BucketView current,
      TimeNs now_ns) noexcept {
    if (capacity_units == 0 || capacity_units > kMaximumPolicyUnits ||
        rate_units_per_second == 0 || rate_units_per_second > kMaximumPolicyUnits ||
        now_ns < current.last_refill_ns)
      return std::nullopt;

    const auto capacity_value = CapacitySubunits(capacity_units);
    if (!capacity_value) return std::nullopt;
    const Subunits capacity = *capacity_value;
    if (current.balance_subunits > capacity) return std::nullopt;
    const Subunits headroom = capacity - current.balance_subunits;
    const TimeNs elapsed = now_ns - current.last_refill_ns;
    const Units quotient = headroom / rate_units_per_second;
    const Units remainder = headroom % rate_units_per_second;
    const TimeNs ns_to_full = quotient + (remainder != 0 ? 1U : 0U);
    if (elapsed >= ns_to_full) return capacity;

    using Wide = __uint128_t;
    constexpr Wide kWideMax = ~static_cast<Wide>(0);
    if (elapsed != 0 &&
        static_cast<Wide>(rate_units_per_second) > kWideMax / elapsed)
      return std::nullopt;
    const Wide refill = static_cast<Wide>(rate_units_per_second) * elapsed;
    if (refill >= static_cast<Wide>(headroom)) return std::nullopt;
    const Wide balance = static_cast<Wide>(current.balance_subunits);
    if (refill > kWideMax - balance) return std::nullopt;
    const Wide total = balance + refill;
    if (total > static_cast<Wide>(std::numeric_limits<Subunits>::max()) ||
        total > static_cast<Wide>(capacity))
      return std::nullopt;
    return static_cast<Subunits>(total);
  }
};

}  // namespace rateguard::replay
