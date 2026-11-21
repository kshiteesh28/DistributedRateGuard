#pragma once

// Fixed-size aggregate counters for performance runs when detailed history is
// disabled. A snapshot is intended to be taken after all writers are quiesced.

#include "src/events/event_recorder.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace rateguard::events::metrics {

inline constexpr std::uint32_t kAggregateMetricsSchemaVersion = 1;
inline constexpr std::size_t kOwnerCount = 5;
inline constexpr std::size_t kStageCount = 6;
inline constexpr std::size_t kOutcomeCount = 8;
inline constexpr std::size_t kCounterCount = kOwnerCount * kStageCount * kOutcomeCount;

enum class RecordResult : std::uint8_t {
  Counted = 0,
  CounterOverflow,
  InvalidOwner,
  InvalidStage,
  InvalidOwnerStagePair,
  InvalidOutcome,
};

struct AggregateSnapshot final {
  std::uint32_t schema_version{kAggregateMetricsSchemaVersion};
  // Fixed indexes are Owner 1..5, Stage 1..6, Outcome 0..7. There are no
  // caller-controlled labels or identifiers in this export shape.
  std::array<std::uint64_t, kCounterCount> counts{};
  bool counter_overflow{false};

  [[nodiscard]] constexpr bool exact() const noexcept {
    return schema_version == kAggregateMetricsSchemaVersion && !counter_overflow;
  }
};

namespace detail {

struct IncrementStep final {
  std::uint64_t value;
  bool saturated;
};

[[nodiscard]] constexpr IncrementStep NextCounterValue(std::uint64_t current) noexcept {
  constexpr auto max = UINT64_MAX;
  return current == max ? IncrementStep{max, true}
                        : IncrementStep{current + 1, false};
}

// Shared atomic helper; on saturation the count remains UINT64_MAX and the
// sticky overflow flag is set. Callers must treat such a run as inexact.
[[nodiscard]] inline bool SaturatingIncrement(std::atomic<std::uint64_t>& counter,
                                              std::atomic<bool>& overflow) noexcept {
  auto current = counter.load(std::memory_order_relaxed);
  for (;;) {
    const auto step = NextCounterValue(current);
    if (step.saturated) {
      overflow.store(true, std::memory_order_release);
      return false;
    }
    if (counter.compare_exchange_weak(current, step.value,
                                      std::memory_order_relaxed,
                                      std::memory_order_relaxed))
      return true;
  }
}

[[nodiscard]] constexpr bool ValidOwner(std::uint8_t owner) noexcept {
  return owner >= 1 && owner <= kOwnerCount;
}
[[nodiscard]] constexpr bool ValidStage(std::uint8_t stage) noexcept {
  return stage >= 1 && stage <= kStageCount;
}
[[nodiscard]] constexpr bool ValidOutcome(std::uint8_t outcome) noexcept {
  return outcome < kOutcomeCount;
}

[[nodiscard]] constexpr std::size_t CounterIndex(std::uint8_t owner,
                                                 std::uint8_t stage,
                                                 std::uint8_t outcome) noexcept {
  return ((static_cast<std::size_t>(owner) - 1) * kStageCount +
          (static_cast<std::size_t>(stage) - 1)) * kOutcomeCount + outcome;
}

}  // namespace detail

class AggregateMetrics final {
 public:
  AggregateMetrics() = default;
  AggregateMetrics(const AggregateMetrics&) = delete;
  AggregateMetrics& operator=(const AggregateMetrics&) = delete;

  // One call records exactly one bounded aggregate. No event ID, tenant ID,
  // grant ID, arbitrary string, or dynamically allocated label is accepted.
  [[nodiscard]] RecordResult Record(ProducerOwner owner, Stage stage,
                                    Outcome outcome) noexcept {
    const auto owner_value = static_cast<std::uint8_t>(owner);
    const auto stage_value = static_cast<std::uint8_t>(stage);
    const auto outcome_value = static_cast<std::uint8_t>(outcome);
    if (!detail::ValidOwner(owner_value)) return RecordResult::InvalidOwner;
    if (!detail::ValidStage(stage_value)) return RecordResult::InvalidStage;
    if (!detail::ValidOutcome(outcome_value)) return RecordResult::InvalidOutcome;
    if (!::rateguard::events::detail::StageOwnedBy(owner, stage))
      return RecordResult::InvalidOwnerStagePair;
    const auto index = detail::CounterIndex(owner_value, stage_value, outcome_value);
    return detail::SaturatingIncrement(counts_[index], overflow_)
        ? RecordResult::Counted
        : RecordResult::CounterOverflow;
  }

  // Counts are individually atomic, but this is not a cross-counter snapshot
  // while writers are active. Stop/join writers before exporting final totals.
  [[nodiscard]] AggregateSnapshot Snapshot() const noexcept {
    AggregateSnapshot result;
    for (std::size_t i = 0; i < counts_.size(); ++i)
      result.counts[i] = counts_[i].load(std::memory_order_relaxed);
    result.counter_overflow = overflow_.load(std::memory_order_acquire);
    return result;
  }

 private:
  std::array<std::atomic<std::uint64_t>, kCounterCount> counts_{};
  std::atomic<bool> overflow_{false};
};

}  // namespace rateguard::events::metrics
