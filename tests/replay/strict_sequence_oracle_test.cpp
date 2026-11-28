#include "replay/reference_model.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace replay = rateguard::replay;
namespace {
constexpr std::uint64_t S = 1'000'000'000ULL;
int failures = 0;

void Check(bool ok, const char* label) {
  if (!ok) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}

replay::TenantSpec Tenant(std::string id, std::uint64_t rate,
                          std::uint64_t capacity,
                          std::vector<replay::OperationSpec> operations) {
  return {std::move(id), rate, capacity, std::move(operations)};
}

replay::SyntheticAttempt Attempt(std::uint64_t ordinal, std::uint64_t time,
                                 std::string tenant, std::string operation) {
  return {ordinal, time, std::move(tenant), std::move(operation)};
}

const replay::StrictSequenceResult* Result(const replay::RunResult& result) {
  return std::get_if<replay::StrictSequenceResult>(&result);
}

std::optional<replay::ModelError> Error(const replay::RunResult& result) {
  if (const auto* error = std::get_if<replay::ModelError>(&result)) return *error;
  return std::nullopt;
}

bool ViewEquals(const std::optional<replay::BucketView>& view,
                std::uint64_t balance, std::uint64_t last) {
  return view.has_value() && view->balance_subunits == balance &&
         view->last_refill_ns == last;
}

replay::StrictScenario OneTenant(std::uint64_t rate, std::uint64_t capacity,
                                 std::vector<replay::OperationSpec> operations,
                                 std::uint64_t balance, std::uint64_t last) {
  return {{Tenant("tenant", rate, capacity, std::move(operations))},
          {{"tenant", balance, last}}, {}};
}

void TestF1EqualTimeOrdinalOrder() {
  auto heavy_first = OneTenant(1, 5, {{"heavy", 5}, {"light", 1}}, 5 * S, 0);
  heavy_first.attempts = {Attempt(0, 0, "tenant", "heavy"),
                          Attempt(1, 0, "tenant", "light")};
  const auto first = replay::StrictSequenceOracle::Run(heavy_first);
  const auto* a = Result(first);
  Check(a && a->steps.size() == 2, "F1 heavy-first has two rows");
  if (a && a->steps.size() == 2) {
    Check(a->steps[0].decision == replay::Decision::Allow, "F1 heavy first ALLOW");
    Check(ViewEquals(a->steps[0].after, 0, 0), "F1 heavy first drains bucket");
    Check(a->steps[1].decision == replay::Decision::Limited, "F1 light second LIMITED");
    Check(a->steps[1].retry_delay_ns == S, "F1 light retry one second");
    Check(ViewEquals(a->steps[1].after, 0, 0), "F1 limited state remains empty");
  }

  auto light_first = OneTenant(1, 5, {{"heavy", 5}, {"light", 1}}, 5 * S, 0);
  light_first.attempts = {Attempt(0, 0, "tenant", "light"),
                          Attempt(1, 0, "tenant", "heavy")};
  const auto second = replay::StrictSequenceOracle::Run(light_first);
  const auto* b = Result(second);
  Check(b && b->steps.size() == 2, "F1 light-first has two rows");
  if (b && b->steps.size() == 2) {
    Check(b->steps[0].decision == replay::Decision::Allow, "F1 light first ALLOW");
    Check(ViewEquals(b->steps[0].after, 4 * S, 0), "F1 light first leaves four");
    Check(b->steps[1].decision == replay::Decision::Limited, "F1 heavy second LIMITED");
    Check(b->steps[1].retry_delay_ns == S, "F1 heavy retry one second");
  }
}

void TestF2LimitedAdvancesAndRetainsFractions() {
  auto scenario = OneTenant(2, 5, {{"heavy", 2}, {"light", 1}}, 0, 0);
  scenario.attempts = {Attempt(0, 499'999'999, "tenant", "heavy"),
                       Attempt(1, 500'000'002, "tenant", "heavy"),
                       Attempt(2, 1'000'000'000, "tenant", "light")};
  const auto run = replay::StrictSequenceOracle::Run(scenario);
  const auto* result = Result(run);
  Check(result && result->steps.size() == 3, "F2 has three rows");
  if (result && result->steps.size() == 3) {
    const auto& first = result->steps[0];
    Check(first.decision == replay::Decision::Limited, "F2 first limited");
    Check(ViewEquals(first.after, 999'999'998, 499'999'999), "F2 first fractional state");
    Check(first.retry_delay_ns == 500'000'001, "F2 first retry");
    const auto& second = result->steps[1];
    Check(second.decision == replay::Decision::Limited, "F2 second limited");
    Check(ViewEquals(second.before, 999'999'998, 499'999'999), "F2 second begins from advanced time");
    Check(ViewEquals(second.after, 1'000'000'004, 500'000'002), "F2 second retains fractions");
    Check(second.retry_delay_ns == 499'999'998, "F2 second retry");
    const auto& third = result->steps[2];
    Check(third.decision == replay::Decision::Allow, "F2 third allows");
    Check(ViewEquals(third.after, S, 1'000'000'000), "F2 third after state");
    Check(!third.retry_delay_ns, "F2 allow has no retry");
  }
}

void TestF3ThresholdAndOneSubunitShort() {
  auto short_by_one = OneTenant(2, 2, {{"one", 1}}, S - 1, 0);
  short_by_one.attempts = {Attempt(0, 0, "tenant", "one")};
  const auto short_run = replay::StrictSequenceOracle::Run(short_by_one);
  const auto* short_result = Result(short_run);
  Check(short_result && short_result->steps.size() == 1, "F3 short has a row");
  if (short_result && short_result->steps.size() == 1) {
    Check(short_result->steps[0].decision == replay::Decision::Limited, "F3 one below limits");
    Check(short_result->steps[0].retry_delay_ns == 1, "F3 one-subunit retry is one ns");
    Check(ViewEquals(short_result->steps[0].after, S - 1, 0), "F3 short does not debit");
  }

  auto exact = OneTenant(2, 2, {{"one", 1}}, 0, 0);
  exact.attempts = {Attempt(0, 500'000'000, "tenant", "one")};
  const auto exact_run = replay::StrictSequenceOracle::Run(exact);
  const auto* exact_result = Result(exact_run);
  Check(exact_result && exact_result->steps.size() == 1, "F3 exact has a row");
  if (exact_result && exact_result->steps.size() == 1) {
    Check(exact_result->steps[0].decision == replay::Decision::Allow, "F3 exact boundary allows");
    Check(ViewEquals(exact_result->steps[0].after, 0, 500'000'000), "F3 exact debit");
  }

  auto before_exact = OneTenant(2, 2, {{"one", 1}}, 0, 0);
  before_exact.attempts = {Attempt(0, 499'999'999, "tenant", "one")};
  const auto before_run = replay::StrictSequenceOracle::Run(before_exact);
  const auto* before_result = Result(before_run);
  Check(before_result && before_result->steps.size() == 1 &&
            before_result->steps[0].decision == replay::Decision::Limited,
        "F3 one nanosecond early limits");
  if (before_result && before_result->steps.size() == 1) {
    Check(ViewEquals(before_result->steps[0].after, 999'999'998, 499'999'999),
          "F3 one nanosecond early balance");
    Check(before_result->steps[0].retry_delay_ns == 1, "F3 early retry is one ns");
  }
}

void TestF4MaximumLegalCapacityAndTimeSaturates() {
  auto scenario = OneTenant(1'000'000'000ULL, 1'000'000'000ULL,
                            {{"max", 1'000'000'000ULL}}, 0, 0);
  scenario.attempts = {Attempt(0, std::numeric_limits<std::uint64_t>::max(),
                               "tenant", "max")};
  const auto run = replay::StrictSequenceOracle::Run(scenario);
  const auto* result = Result(run);
  Check(result && result->steps.size() == 1, "F4 maximum inputs return a row");
  if (result && result->steps.size() == 1) {
    Check(result->steps[0].decision == replay::Decision::Allow, "F4 saturated max allows");
    Check(ViewEquals(result->steps[0].after, 0, std::numeric_limits<std::uint64_t>::max()),
          "F4 max elapsed saturates and preserves time");
  }
}

void TestF5TenantIsolation() {
  replay::StrictScenario scenario{
      {Tenant("A", 1, 1, {{"one", 1}}), Tenant("B", 1, 1, {{"one", 1}})},
      {{"A", S, 0}, {"B", S, 0}},
      {Attempt(0, 0, "A", "one"), Attempt(1, 0, "B", "one"),
       Attempt(2, 0, "A", "one"), Attempt(3, S, "B", "one")}};
  const auto run = replay::StrictSequenceOracle::Run(scenario);
  const auto* result = Result(run);
  Check(result && result->steps.size() == 4, "F5 has four rows");
  if (result && result->steps.size() == 4) {
    Check(result->steps[0].decision == replay::Decision::Allow, "F5 A first allows");
    Check(result->steps[1].decision == replay::Decision::Allow, "F5 B initial state independent");
    Check(result->steps[2].decision == replay::Decision::Limited, "F5 A exhausted only A");
    Check(result->steps[3].decision == replay::Decision::Allow, "F5 B refills independently");
    Check(ViewEquals(result->steps[1].before, S, 0), "F5 B starts full");
  }
}

void TestF6InvalidSelectorsDoNotMutate() {
  auto scenario = OneTenant(1, 2, {{"two", 2}}, 2 * S, 10);
  scenario.attempts = {Attempt(0, 10, "tenant", "missing-op"),
                       Attempt(1, 10, "missing-tenant", "two"),
                       Attempt(2, 10, "tenant", "two")};
  const auto run = replay::StrictSequenceOracle::Run(scenario);
  const auto* result = Result(run);
  Check(result && result->steps.size() == 3, "F6 preserves all rows");
  if (result && result->steps.size() == 3) {
    const auto& unknown_op = result->steps[0];
    Check(unknown_op.decision == replay::Decision::Invalid &&
              unknown_op.invalid_reason == replay::InvalidReason::UnknownOperation,
          "F6 unknown operation reason");
    Check(ViewEquals(unknown_op.before, 2 * S, 10) && ViewEquals(unknown_op.after, 2 * S, 10),
          "F6 unknown operation leaves state unchanged");
    const auto& unknown_tenant = result->steps[1];
    Check(unknown_tenant.invalid_reason == replay::InvalidReason::UnknownTenant,
          "F6 unknown tenant reason");
    Check(!unknown_tenant.before && !unknown_tenant.after,
          "F6 unknown tenant has no bucket view");
    Check(result->steps[2].decision == replay::Decision::Allow,
          "F6 later valid row sees original bucket");
    Check(ViewEquals(result->steps[2].after, 0, 10), "F6 later valid row debits original state");
  }
}

void TestSelectorClassificationAndKnownTenantChronology() {
  auto scenario = OneTenant(1, 2, {{"known", 1}}, S, 10);
  scenario.attempts = {Attempt(0, 10, "bad/tenant", "bad/op"),
                       Attempt(1, 10, "tenant", "bad/op"),
                       Attempt(2, 10, "tenant", "absent"),
                       Attempt(3, 10, "absent", "bad/op")};
  const auto run = replay::StrictSequenceOracle::Run(scenario);
  const auto* result = Result(run);
  Check(result && result->steps.size() == 4, "selector classifications preserve rows");
  if (result && result->steps.size() == 4) {
    Check(result->steps[0].invalid_reason == replay::InvalidReason::MalformedTenantId,
          "tenant syntax precedes operation syntax");
    Check(!result->steps[0].before && !result->steps[0].after,
          "malformed tenant has no state view");
    Check(result->steps[1].invalid_reason == replay::InvalidReason::MalformedOperationId,
          "known tenant malformed operation");
    Check(ViewEquals(result->steps[1].before, S, 10) && ViewEquals(result->steps[1].after, S, 10),
          "known tenant malformed operation has unchanged views");
    Check(result->steps[2].invalid_reason == replay::InvalidReason::UnknownOperation,
          "known tenant unknown operation");
    Check(result->steps[3].invalid_reason == replay::InvalidReason::UnknownTenant,
          "unknown tenant precedes malformed operation");
  }

  auto regress = OneTenant(1, 2, {{"known", 1}}, S, 10);
  regress.attempts = {Attempt(0, 9, "tenant", "bad/op")};
  Check(Error(replay::StrictSequenceOracle::Run(regress)) == replay::ModelError::TimeRegression,
        "known tenant chronology regression is checked before invalid operation");

  auto oversized = OneTenant(1, 2, {{"known", 1}}, S, 10);
  oversized.attempts = {Attempt(0, 10, std::string(129, 'a'), "known")};
  Check(Error(replay::StrictSequenceOracle::Run(oversized)) == replay::ModelError::ResourceLimit,
        "selector over byte bound rejects whole scenario");
}

void TestF7WholeScenarioErrorsNeverReturnPrefix() {
  auto noncontiguous = OneTenant(1, 2, {{"one", 1}}, S, 0);
  noncontiguous.attempts = {Attempt(0, 0, "tenant", "one"), Attempt(2, 0, "tenant", "one")};
  Check(Error(replay::StrictSequenceOracle::Run(noncontiguous)) == replay::ModelError::InvalidAttemptOrder,
        "F7 noncontiguous ordinals reject whole input");

  auto global_regress = OneTenant(1, 2, {{"one", 1}}, S, 0);
  global_regress.attempts = {Attempt(0, 10, "tenant", "one"), Attempt(1, 9, "missing", "one")};
  Check(Error(replay::StrictSequenceOracle::Run(global_regress)) == replay::ModelError::TimeRegression,
        "F7 global timestamp regression rejects whole input");

  auto bad_balance = OneTenant(1, 2, {{"one", 1}}, 2 * S + 1, 0);
  Check(Error(replay::StrictSequenceOracle::Run(bad_balance)) == replay::ModelError::InvalidInitialBalance,
        "F7 above-cap initial balance rejected");

  auto missing = OneTenant(1, 2, {{"one", 1}}, 0, 0);
  missing.initial_buckets.clear();
  Check(Error(replay::StrictSequenceOracle::Run(missing)) == replay::ModelError::MissingInitialState,
        "F7 missing initial state rejected");

  auto duplicate_tenant = replay::StrictScenario{
      {Tenant("tenant", 1, 1, {{"one", 1}}), Tenant("tenant", 1, 1, {{"one", 1}})},
      {{"tenant", S, 0}}, {}};
  Check(Error(replay::StrictSequenceOracle::Run(duplicate_tenant)) == replay::ModelError::DuplicateIdentifier,
        "F7 duplicate tenant rejected");

  auto duplicate_operation = OneTenant(1, 2, {{"one", 1}, {"one", 2}}, S, 0);
  Check(Error(replay::StrictSequenceOracle::Run(duplicate_operation)) == replay::ModelError::DuplicateIdentifier,
        "F7 duplicate operation rejected");

  auto duplicate_initial = OneTenant(1, 2, {{"one", 1}}, S, 0);
  duplicate_initial.initial_buckets.push_back({"tenant", S, 0});
  Check(Error(replay::StrictSequenceOracle::Run(duplicate_initial)) == replay::ModelError::DuplicateIdentifier,
        "F7 duplicate initial state rejected");

  auto invalid_cost = OneTenant(1, 2, {{"too-large", 3}}, S, 0);
  Check(Error(replay::StrictSequenceOracle::Run(invalid_cost)) == replay::ModelError::InvalidScenario,
        "policy operation cost cannot exceed capacity");

  auto empty = OneTenant(1, 1, {{"one", 1}}, S, 0);
  const auto empty_run = replay::StrictSequenceOracle::Run(empty);
  Check(Result(empty_run) && Result(empty_run)->steps.empty(),
        "empty attempt list is a valid model input but has no evidence rows");
}

}  // namespace

int main() {
  TestF1EqualTimeOrdinalOrder();
  TestF2LimitedAdvancesAndRetainsFractions();
  TestF3ThresholdAndOneSubunitShort();
  TestF4MaximumLegalCapacityAndTimeSaturates();
  TestF5TenantIsolation();
  TestF6InvalidSelectorsDoNotMutate();
  TestSelectorClassificationAndKnownTenantChronology();
  TestF7WholeScenarioErrorsNeverReturnPrefix();
  if (failures != 0) {
    std::cerr << failures << " check(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "strict sequence oracle fixtures passed\n";
  return EXIT_SUCCESS;
}
