#include "replay/reference_model.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {
using namespace rateguard::replay;
constexpr std::uint64_t S = 1'000'000'000ULL;
int failures = 0;

#define CHECK(expr) do { if (!(expr)) { \
  std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr "\n"; \
  ++failures; } } while (false)

TenantSpec Tenant(std::string id, Units capacity, Units rate,
                  std::vector<OperationSpec> operations) {
  return TenantSpec{std::move(id), rate, capacity, std::move(operations)};
}
SyntheticAttempt Attempt(std::uint64_t ordinal, TimeNs time,
                         std::string tenant, std::string operation) {
  return SyntheticAttempt{ordinal, time, std::move(tenant), std::move(operation)};
}
StrictScenario Scenario(TenantSpec tenant, InitialBucket initial,
                        std::vector<SyntheticAttempt> attempts) {
  return StrictScenario{{std::move(tenant)}, {std::move(initial)}, std::move(attempts)};
}

RunResult Run(const StrictScenario& input) {
  auto result = StrictSequenceOracle::Run(input);
  if (std::holds_alternative<ModelError>(result)) {
    std::cerr << "expected successful model result\n";
    ++failures;
  }
  return result;
}

void CheckStep(const StepResult& row, std::uint64_t ordinal, Decision decision,
               Subunits before_balance, TimeNs before_time,
               Subunits after_balance, TimeNs after_time,
               std::optional<TimeNs> retry = std::nullopt) {
  CHECK(row.ordinal == ordinal);
  CHECK(row.decision == decision);
  CHECK(!row.invalid_reason.has_value());
  CHECK(row.before.has_value());
  CHECK(row.after.has_value());
  if (row.before) {
    CHECK(row.before->balance_subunits == before_balance);
    CHECK(row.before->last_refill_ns == before_time);
  }
  if (row.after) {
    CHECK(row.after->balance_subunits == after_balance);
    CHECK(row.after->last_refill_ns == after_time);
  }
  CHECK(row.retry_delay_ns == retry);
}

void EqualTimeWeightedOrdering() {
  const auto make = [](bool heavy_first) {
    std::vector<OperationSpec> ops{{"heavy", 5}, {"light", 1}};
    std::vector<SyntheticAttempt> attempts;
    if (heavy_first) {
      attempts = {Attempt(0, 0, "tenant", "heavy"),
                  Attempt(1, 0, "tenant", "light")};
    } else {
      attempts = {Attempt(0, 0, "tenant", "light"),
                  Attempt(1, 0, "tenant", "heavy")};
    }
    return Scenario(Tenant("tenant", 5, 1, std::move(ops)),
                    InitialBucket{"tenant", 5 * S, 0}, std::move(attempts));
  };
  const auto heavy_result = Run(make(true));
  const auto* heavy = std::get_if<StrictSequenceResult>(&heavy_result);
  if (heavy != nullptr) {
    CHECK(heavy->steps.size() == 2);
    if (heavy->steps.size() == 2) {
      CheckStep(heavy->steps[0], 0, Decision::Allow, 5 * S, 0, 0, 0);
      CheckStep(heavy->steps[1], 1, Decision::Limited, 0, 0, 0, 0, S);
    }
  }
  const auto light_result = Run(make(false));
  const auto* light = std::get_if<StrictSequenceResult>(&light_result);
  if (light != nullptr) {
    CHECK(light->steps.size() == 2);
    if (light->steps.size() == 2) {
      CheckStep(light->steps[0], 0, Decision::Allow, 5 * S, 0, 4 * S, 0);
      CheckStep(light->steps[1], 1, Decision::Limited, 4 * S, 0, 4 * S, 0, S);
    }
  }
}

void LimitedRefillAdvancesTimestampAndKeepsFractions() {
  auto scenario = Scenario(
      Tenant("tenant", 5, 2, {{"heavy", 2}, {"light", 1}}),
      InitialBucket{"tenant", 0, 0},
      {Attempt(0, 499'999'999, "tenant", "heavy"),
       Attempt(1, 500'000'002, "tenant", "heavy"),
       Attempt(2, 1'000'000'000, "tenant", "light")});
  const auto run_result = Run(scenario);
  const auto* result = std::get_if<StrictSequenceResult>(&run_result);
  if (result == nullptr) return;
  CHECK(result->steps.size() == 3);
  if (result->steps.size() != 3) return;
  CheckStep(result->steps[0], 0, Decision::Limited, 0, 0,
            999'999'998, 499'999'999, 500'000'001);
  CheckStep(result->steps[1], 1, Decision::Limited, 999'999'998, 499'999'999,
            1'000'000'004, 500'000'002, 499'999'998);
  CheckStep(result->steps[2], 2, Decision::Allow, 1'000'000'004, 500'000'002,
            S, 1'000'000'000);
}

void ExactAndOneSubunitShortBoundaries() {
  auto one = Tenant("tenant", 2, 2, {{"one", 1}});
  {
    const auto run_result = Run(Scenario(one, InitialBucket{"tenant", S - 1, 0},
                                         {Attempt(0, 0, "tenant", "one")}));
    const auto* result = std::get_if<StrictSequenceResult>(&run_result);
    if (result && result->steps.size() == 1)
      CheckStep(result->steps[0], 0, Decision::Limited, S - 1, 0, S - 1, 0, 1);
    else if (result) CHECK(result->steps.size() == 1);
  }
  {
    const auto run_result = Run(Scenario(one, InitialBucket{"tenant", 0, 0},
                                         {Attempt(0, 500'000'000, "tenant", "one")}));
    const auto* result = std::get_if<StrictSequenceResult>(&run_result);
    if (result && result->steps.size() == 1)
      CheckStep(result->steps[0], 0, Decision::Allow, 0, 0, 0, 500'000'000);
    else if (result) CHECK(result->steps.size() == 1);
  }
  {
    const auto run_result = Run(Scenario(one, InitialBucket{"tenant", 0, 0},
                                         {Attempt(0, 499'999'999, "tenant", "one")}));
    const auto* result = std::get_if<StrictSequenceResult>(&run_result);
    if (result && result->steps.size() == 1)
      CheckStep(result->steps[0], 0, Decision::Limited, 0, 0,
                999'999'998, 499'999'999, 1);
    else if (result) CHECK(result->steps.size() == 1);
  }
}

void MaximumPolicyAndLargeElapsedSaturate() {
  constexpr Units kMaxPolicy = 1'000'000'000ULL;
  auto scenario = Scenario(Tenant("tenant", kMaxPolicy, kMaxPolicy,
                                  {{"max", kMaxPolicy}}),
                           InitialBucket{"tenant", 0, 0},
                           {Attempt(0, std::numeric_limits<TimeNs>::max(),
                                    "tenant", "max")});
  const auto run_result = Run(scenario);
  const auto* result = std::get_if<StrictSequenceResult>(&run_result);
  if (result && result->steps.size() == 1)
    CheckStep(result->steps[0], 0, Decision::Allow, 0, 0, 0,
              std::numeric_limits<TimeNs>::max());
  else if (result) CHECK(result->steps.size() == 1);

  // This product is just beyond uint64 max but far below UINT64_MAX elapsed.
  // A direct unchecked 64-bit product wraps to 290,448,384 subunits, so it
  // would incorrectly LIMIT instead of saturating to the 10^18-subunit cap.
  constexpr TimeNs kWrapProbeElapsedNs = 18'446'744'074ULL;
  auto wrap_probe = Scenario(Tenant("tenant", kMaxPolicy, kMaxPolicy,
                                    {{"max", kMaxPolicy}}),
                             InitialBucket{"tenant", 0, 0},
                             {Attempt(0, kWrapProbeElapsedNs, "tenant", "max")});
  const auto wrap_run = Run(wrap_probe);
  const auto* wrap_result = std::get_if<StrictSequenceResult>(&wrap_run);
  if (wrap_result && wrap_result->steps.size() == 1)
    CheckStep(wrap_result->steps[0], 0, Decision::Allow, 0, 0, 0,
              kWrapProbeElapsedNs);
  else if (wrap_result) CHECK(wrap_result->steps.size() == 1);
}

void TenantsHaveIndependentBuckets() {
  StrictScenario scenario{
      {Tenant("A", 1, 1, {{"one", 1}}), Tenant("B", 1, 1, {{"one", 1}})},
      {{"A", S, 0}, {"B", S, 0}},
      {Attempt(0, 0, "A", "one"), Attempt(1, 0, "B", "one"),
       Attempt(2, 0, "A", "one"), Attempt(3, S, "B", "one")}};
  const auto run_result = Run(scenario);
  const auto* result = std::get_if<StrictSequenceResult>(&run_result);
  if (result == nullptr) return;
  CHECK(result->steps.size() == 4);
  if (result->steps.size() != 4) return;
  CheckStep(result->steps[0], 0, Decision::Allow, S, 0, 0, 0);
  CheckStep(result->steps[1], 1, Decision::Allow, S, 0, 0, 0);
  CheckStep(result->steps[2], 2, Decision::Limited, 0, 0, 0, 0, S);
  CheckStep(result->steps[3], 3, Decision::Allow, 0, 0, 0, S);
}

void InvalidSelectorsEmitRowsWithoutMutation() {
  StrictScenario scenario{
      {Tenant("tenant", 2, 1, {{"two", 2}})},
      {{"tenant", 2 * S, 10}},
      {Attempt(0, 10, "bad/tenant", "two"),
       Attempt(1, 10, "tenant", "bad/op"),
       Attempt(2, 10, "tenant", "missing-op"),
       Attempt(3, 10, "missing-tenant", "bad/op"),
       Attempt(4, 10, "tenant", "two")}};
  const auto run_result = Run(scenario);
  const auto* result = std::get_if<StrictSequenceResult>(&run_result);
  if (result == nullptr) return;
  CHECK(result->steps.size() == 5);
  if (result->steps.size() != 5) return;
  const auto& bad_tenant = result->steps[0];
  CHECK(bad_tenant.decision == Decision::Invalid);
  CHECK(bad_tenant.invalid_reason == InvalidReason::MalformedTenantId);
  CHECK(!bad_tenant.before && !bad_tenant.after);
  const auto& bad_operation = result->steps[1];
  CHECK(bad_operation.decision == Decision::Invalid);
  CHECK(bad_operation.invalid_reason == InvalidReason::MalformedOperationId);
  CHECK(bad_operation.before && bad_operation.after);
  if (bad_operation.before && bad_operation.after) {
    CHECK(bad_operation.before->balance_subunits == 2 * S);
    CHECK(bad_operation.before->last_refill_ns == 10);
    CHECK(bad_operation.after->balance_subunits == 2 * S);
    CHECK(bad_operation.after->last_refill_ns == 10);
  }
  const auto& unknown_operation = result->steps[2];
  CHECK(unknown_operation.decision == Decision::Invalid);
  CHECK(unknown_operation.invalid_reason == InvalidReason::UnknownOperation);
  CHECK(unknown_operation.before && unknown_operation.after);
  if (unknown_operation.before && unknown_operation.after) {
    CHECK(unknown_operation.before->balance_subunits == 2 * S);
    CHECK(unknown_operation.before->last_refill_ns == 10);
    CHECK(unknown_operation.after->balance_subunits == 2 * S);
    CHECK(unknown_operation.after->last_refill_ns == 10);
  }
  const auto& missing_tenant = result->steps[3];
  CHECK(missing_tenant.decision == Decision::Invalid);
  CHECK(missing_tenant.invalid_reason == InvalidReason::UnknownTenant);
  CHECK(!missing_tenant.before && !missing_tenant.after);
  CheckStep(result->steps[4], 4, Decision::Allow, 2 * S, 10, 0, 10);
}

void InvalidSelectorDoesNotHideTenantTimeRegression() {
  StrictScenario scenario{
      {Tenant("tenant", 2, 1, {{"one", 1}})},
      {{"tenant", S, 10}},
      {Attempt(0, 9, "tenant", "missing-op")}};
  const auto result = StrictSequenceOracle::Run(scenario);
  const auto* error = std::get_if<ModelError>(&result);
  CHECK(error != nullptr);
  if (error) CHECK(*error == ModelError::TimeRegression);
}

void MalformedScenariosAreAtomicErrors() {
  const auto check_error = [](StrictScenario scenario, ModelError expected) {
    const auto result = StrictSequenceOracle::Run(scenario);
    const auto* error = std::get_if<ModelError>(&result);
    CHECK(error != nullptr);
    if (error) CHECK(*error == expected);
  };
  auto base_tenant = Tenant("tenant", 2, 1, {{"one", 1}});
  check_error(Scenario(base_tenant, InitialBucket{"tenant", 0, 0},
                       {Attempt(0, 0, "tenant", "one"),
                        Attempt(2, 0, "tenant", "one")}),
              ModelError::InvalidAttemptOrder);
  check_error(Scenario(base_tenant, InitialBucket{"tenant", 0, 0},
                       {Attempt(0, 10, "tenant", "one"),
                        Attempt(1, 9, "tenant", "one")}),
              ModelError::TimeRegression);
  check_error(Scenario(base_tenant, InitialBucket{"tenant", 2 * S + 1, 0}, {}),
              ModelError::InvalidInitialBalance);
}

void RunAll() {
  EqualTimeWeightedOrdering();
  LimitedRefillAdvancesTimestampAndKeepsFractions();
  ExactAndOneSubunitShortBoundaries();
  MaximumPolicyAndLargeElapsedSaturate();
  TenantsHaveIndependentBuckets();
  InvalidSelectorsEmitRowsWithoutMutation();
  InvalidSelectorDoesNotHideTenantTimeRegression();
  MalformedScenariosAreAtomicErrors();
}
}  // namespace

int main() {
  RunAll();
  if (failures != 0) {
    std::cerr << failures << " independent strict sequence checks failed\n";
    return 1;
  }
  std::cout << "independent strict sequence fixtures passed\n";
  return 0;
}
