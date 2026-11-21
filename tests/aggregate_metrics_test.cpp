#include "src/events/event_recorder.h"
#include "src/events/aggregate_metrics.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

namespace {
using namespace rateguard::events;
using namespace rateguard::events::metrics;

void Check(bool condition, const char* name) {
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    std::exit(1);
  }
}

void TestConcurrentUpdates() {
  AggregateMetrics metrics;
  constexpr std::size_t kThreads = 8;
  constexpr std::uint64_t kPerThread = 20'000;
  std::array<std::uint64_t, kThreads> local_errors{};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (std::size_t i = 0; i < kThreads; ++i) {
    workers.emplace_back([&metrics, &local_errors, i] {
      for (std::uint64_t j = 0; j < kPerThread; ++j) {
        if (metrics.Record(ProducerOwner::Authority, Stage::StrictDecision,
                           Outcome::Allow) != RecordResult::Counted)
          ++local_errors[i];
      }
    });
  }
  for (auto& worker : workers) worker.join();

  std::uint64_t errors = 0;
  for (const auto count : local_errors) errors += count;
  Check(errors == 0, "concurrent_records_all_counted");
  const auto snapshot = metrics.Snapshot();
  constexpr std::size_t allow_index = ((2 - 1) * kStageCount + (2 - 1)) * kOutcomeCount + 1;
  Check(snapshot.counts[allow_index] == kThreads * kPerThread,
        "concurrent_counter_is_exact");
  Check(snapshot.exact(), "no_overflow_on_normal_concurrency");
}

void TestDimensionsAndRejects() {
  AggregateMetrics metrics;
  Check(metrics.Record(ProducerOwner::WorkloadGenerator, Stage::Offered,
                       Outcome::None) == RecordResult::Counted,
        "offered_none_counted");
  Check(metrics.Record(ProducerOwner::Backend, Stage::Completed,
                       Outcome::Allow) == RecordResult::Counted,
        "completed_allow_counted");
  Check(metrics.Record(static_cast<ProducerOwner>(0), Stage::Offered,
                       Outcome::None) == RecordResult::InvalidOwner,
        "unknown_owner_rejected");
  Check(metrics.Record(ProducerOwner::Authority, static_cast<Stage>(99),
                       Outcome::Allow) == RecordResult::InvalidStage,
        "unknown_stage_rejected");
  Check(metrics.Record(ProducerOwner::Authority, Stage::StrictDecision,
                       static_cast<Outcome>(99)) == RecordResult::InvalidOutcome,
        "unknown_outcome_rejected");
  Check(metrics.Record(ProducerOwner::Replica, Stage::StrictDecision,
                       Outcome::Allow) == RecordResult::InvalidOwnerStagePair,
        "wrong_owner_stage_rejected");
  const auto snapshot = metrics.Snapshot();
  Check(snapshot.counts[((1 - 1) * kStageCount + (1 - 1)) * kOutcomeCount] == 1,
        "offered_none_has_fixed_dimension");
  Check(snapshot.counts[((5 - 1) * kStageCount + (6 - 1)) * kOutcomeCount + 1] == 1,
        "completed_allow_has_fixed_dimension");
  Check(snapshot.exact(), "invalid_records_do_not_overflow_or_increment");
}

void TestSaturationHelper() {
  std::atomic<std::uint64_t> counter{UINT64_MAX - 1};
  std::atomic<bool> overflow{false};
  Check(metrics::detail::SaturatingIncrement(counter, overflow), "increment_to_max_succeeds");
  Check(counter.load() == UINT64_MAX && !overflow.load(),
        "max_value_is_reached_without_wrap");
  Check(!metrics::detail::SaturatingIncrement(counter, overflow), "increment_at_max_reports_overflow");
  Check(counter.load() == UINT64_MAX && overflow.load(),
        "saturation_is_sticky_without_wrap");
  Check(!metrics::detail::SaturatingIncrement(counter, overflow),
        "repeated_overflow_remains_explicit");
  Check(metrics::detail::NextCounterValue(UINT64_MAX).saturated,
        "pure_saturation_boundary_helper");
}

}  // namespace

int main() {
  TestConcurrentUpdates();
  TestDimensionsAndRejects();
  TestSaturationHelper();
  std::cout << "RG-005 aggregate metrics cases passed\n";
}
