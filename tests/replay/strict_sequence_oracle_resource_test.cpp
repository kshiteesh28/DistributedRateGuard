#include "replay/reference_model.h"
#include "failing_allocator.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <variant>

namespace {
using rateguard::test_support::ArmAllocationFailure;
using rateguard::test_support::DisarmAllocationFailure;
using rateguard::test_support::AllocationFailureArmedAtZero;

int failures = 0;
std::size_t injected_allocation_failure_points = 0;
void Check(bool ok, const char* label) {
  if (!ok) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}

rateguard::replay::StrictScenario SmallScenario() {
  using namespace rateguard::replay;
  StrictScenario scenario;
  const std::string tenant = "allocation_tenant_identifier";
  const std::string one = "allocation_operation_one";
  const std::string two = "allocation_operation_two";
  scenario.tenants.push_back({tenant, 2, 3, {{one, 1}, {two, 2}}});
  scenario.initial_buckets.push_back({tenant, 0, 0});
  scenario.attempts.push_back({0, 500'000'000, tenant, one});
  scenario.attempts.push_back({1, 500'000'001, tenant, two});
  return scenario;
}

std::string Numbered(std::string_view prefix, std::size_t number) {
  return std::string(prefix) + std::to_string(number);
}

rateguard::replay::StrictScenario PolicyWithTenants(std::size_t tenant_count,
                                                    std::size_t operations_each) {
  using namespace rateguard::replay;
  StrictScenario scenario;
  scenario.tenants.reserve(tenant_count);
  scenario.initial_buckets.reserve(tenant_count);
  for (std::size_t tenant = 0; tenant < tenant_count; ++tenant) {
    TenantSpec spec;
    spec.id = Numbered("t", tenant);
    spec.rate_units_per_second = 1;
    spec.capacity_units = 1;
    spec.operations.reserve(operations_each);
    for (std::size_t operation = 0; operation < operations_each; ++operation)
      spec.operations.push_back({Numbered("o", operation), 1});
    scenario.initial_buckets.push_back({spec.id, 0, 0});
    scenario.tenants.push_back(std::move(spec));
  }
  return scenario;
}

std::size_t OperationTotal(const rateguard::replay::StrictScenario& scenario) {
  std::size_t total = 0;
  for (const auto& tenant : scenario.tenants) total += tenant.operations.size();
  return total;
}

bool IsError(const rateguard::replay::RunResult& result,
             rateguard::replay::ModelError expected) {
  const auto* error = std::get_if<rateguard::replay::ModelError>(&result);
  return error != nullptr && *error == expected;
}
}  // namespace

int main() {
  using namespace rateguard::replay;

  // The exact 10,000-tenant boundary is valid; the next count is ResourceLimit
  // even though its default tenant records are otherwise malformed.
  {
    auto exact = PolicyWithTenants(10'000, 1);
    const auto result = StrictSequenceOracle::Run(exact);
    Check(std::holds_alternative<StrictSequenceResult>(result),
          "10,000 configured tenants accepted");
  }
  {
    StrictScenario too_many;
    too_many.tenants.resize(10'001);
    Check(IsError(StrictSequenceOracle::Run(too_many), ModelError::ResourceLimit),
          "10,001 tenants hit resource cap before policy validation");
  }

  // Per-tenant operation cap: 64 is accepted; 65 is rejected before invalid
  // policy numeric checks.
  {
    auto exact = PolicyWithTenants(1, 64);
    Check(OperationTotal(exact) == 64, "64-operation boundary fixture built");
    Check(std::holds_alternative<StrictSequenceResult>(StrictSequenceOracle::Run(exact)),
          "64 operations per tenant accepted");
    auto over = PolicyWithTenants(1, 65);
    over.tenants[0].capacity_units = 0;
    Check(IsError(StrictSequenceOracle::Run(over), ModelError::ResourceLimit),
          "65 operations rejected before invalid policy check");
  }

  // Exactly 100,000 total operations is valid. Above it, caps are evaluated
  // before policy validation/initial state materialization.
  {
    auto exact = PolicyWithTenants(1'562, 64);  // 99,968
    auto tail = PolicyWithTenants(1, 32);       // 32
    tail.tenants[0].id = "tail";
    tail.initial_buckets[0].tenant_id = "tail";
    exact.tenants.push_back(std::move(tail.tenants[0]));
    exact.initial_buckets.push_back(std::move(tail.initial_buckets[0]));
    Check(OperationTotal(exact) == 100'000, "100,000-operation boundary fixture built");
    Check(std::holds_alternative<StrictSequenceResult>(StrictSequenceOracle::Run(exact)),
          "100,000 total operations accepted");

    auto over = exact;
    over.tenants.back().operations.push_back({"extra", 1});
    Check(OperationTotal(over) == 100'001, "100,001-operation boundary fixture built");
    over.tenants[0].capacity_units = 0;
    Check(IsError(StrictSequenceOracle::Run(over), ModelError::ResourceLimit),
          "over 100,000 operations rejected before invalid policy check");
  }

  // Exactly 1,000,000 malformed-but-bounded selector rows are modeled; this
  // validates the cap and finite output only, not release acceptance evidence.
  {
    StrictScenario exact;
    exact.tenants.push_back({"tenant", 1, 1, {{"one", 1}}});
    exact.initial_buckets.push_back({"tenant", 0, 0});
    exact.attempts.resize(1'000'000);
    for (std::size_t i = 0; i < exact.attempts.size(); ++i)
      exact.attempts[i].ordinal = static_cast<std::uint64_t>(i);
    const auto result = StrictSequenceOracle::Run(exact);
    const auto* rows = std::get_if<StrictSequenceResult>(&result);
    Check(rows && rows->steps.size() == 1'000'000,
          "1,000,000 attempt/resource boundary accepted");
    if (rows && !rows->steps.empty())
      Check(rows->steps.front().invalid_reason == InvalidReason::MalformedTenantId &&
                rows->steps.back().ordinal == 999'999,
            "maximum-count output retains deterministic rows");

    exact.attempts.emplace_back();
    Check(IsError(StrictSequenceOracle::Run(exact), ModelError::ResourceLimit),
          "1,000,001 attempts rejected before result allocation");
  }

  // Oversized selectors are rejected before any dynamic allocation in Run.
  {
    auto oversized = SmallScenario();
    oversized.attempts[0].tenant_id.assign(129, 'x');
    ArmAllocationFailure(0);
    const auto result = StrictSequenceOracle::Run(oversized);
    const bool allocation_not_attempted =
        AllocationFailureArmedAtZero();
    DisarmAllocationFailure();
    Check(allocation_not_attempted, "resource rejection leaves allocation failpoint armed");
    Check(IsError(result, ModelError::ResourceLimit),
          "129-byte selector hits resource cap before allocation");
  }

  // Fail each allocation point in a small valid run. Every injected failure
  // must become AllocationFailure, with no partial StrictSequenceResult.
  {
    const auto scenario = SmallScenario();
    bool reached_success = false;
    for (long long fail_after = 0; fail_after < 128; ++fail_after) {
      ArmAllocationFailure(fail_after);
      const auto result = StrictSequenceOracle::Run(scenario);
      DisarmAllocationFailure();
      if (const auto* error = std::get_if<ModelError>(&result)) {
        Check(*error == ModelError::AllocationFailure,
              "injected allocation failure maps to AllocationFailure");
        ++injected_allocation_failure_points;
      } else {
        const auto& rows = std::get<StrictSequenceResult>(result).steps;
        Check(rows.size() == scenario.attempts.size(),
              "successful allocation sweep returns complete trace");
        reached_success = true;
        break;
      }
    }
    Check(injected_allocation_failure_points > 0, "allocation sweep injected failures");
    Check(reached_success, "allocation sweep eventually reaches success");
  }

  DisarmAllocationFailure();
  if (failures != 0) {
    std::cerr << failures << " check(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "strict sequence oracle resource fixtures passed; caps: "
            << "tenants=10000/10001, per-tenant-operations=64/65, "
            << "total-operations=100000/100001, attempts=1000000/1000001; "
            << "injected-allocation-failures="
            << injected_allocation_failure_points << '\n';
  return EXIT_SUCCESS;
}
