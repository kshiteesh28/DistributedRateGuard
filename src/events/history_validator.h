#pragma once

// Independent, read-only validator for version-1 EventRecorder snapshots.
// This deliberately recomputes the
// canonical checksums instead of calling recorder/checker helpers.

#include "src/events/event_recorder.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace rateguard::events::validation {

inline constexpr std::uint64_t kMaximumRunBytes = std::uint64_t{1} << 30;

enum class Verdict : std::uint8_t { Complete = 1, Incomplete = 2, Invalid = 3 };
enum class Reason : std::uint8_t {
  None = 0,
  SnapshotIncomplete,
  ProducerMissing,
  ProducerUnexpected,
  ProducerOrderOrCapacityMismatch,
  ProducerNotSealed,
  ProducerMarkedIncomplete,
  ReservationGap,
  ReservedSlotUnpublished,
  PublishedCountMismatch,
  InvalidSlotState,
  InvalidEventEnum,
  StageOwnerMismatch,
  EventChecksumMismatch,
  ProducerChecksumMismatch,
  SnapshotChecksumMismatch,
  SchemaMismatch,
  InvalidByteAccounting,
  RunBudgetExceeded,
  InvalidExpectedPlan,
  ExpectedPlanMismatch,
  ValidatorResourceFailure,
};

struct Report final {
  Verdict verdict{Verdict::Invalid};
  Reason reason{Reason::None};
  std::uint64_t published_events{};
  std::uint64_t snapshot_bytes{};

  [[nodiscard]] constexpr bool complete() const noexcept {
    return verdict == Verdict::Complete;
  }
  // A complete artifact is not, by itself, a safety proof. The independent
  // history/model checker must still validate its semantics.
  [[nodiscard]] constexpr bool safety_pass_allowed() const noexcept {
    return false;
  }
};

namespace detail {

class Fnv1a64 final {
 public:
  void Bytes(const char* data, std::size_t size) noexcept {
    for (std::size_t i = 0; i < size; ++i) {
      value_ ^= static_cast<std::uint8_t>(data[i]);
      value_ *= 1099511628211ULL;
    }
  }
  void U8(std::uint8_t value) noexcept {
    const char byte = static_cast<char>(value);
    Bytes(&byte, 1);
  }
  void U32(std::uint32_t value) noexcept {
    U8(static_cast<std::uint8_t>(value >> 24));
    U8(static_cast<std::uint8_t>(value >> 16));
    U8(static_cast<std::uint8_t>(value >> 8));
    U8(static_cast<std::uint8_t>(value));
  }
  void U64(std::uint64_t value) noexcept {
    U8(static_cast<std::uint8_t>(value >> 56));
    U8(static_cast<std::uint8_t>(value >> 48));
    U8(static_cast<std::uint8_t>(value >> 40));
    U8(static_cast<std::uint8_t>(value >> 32));
    U8(static_cast<std::uint8_t>(value >> 24));
    U8(static_cast<std::uint8_t>(value >> 16));
    U8(static_cast<std::uint8_t>(value >> 8));
    U8(static_cast<std::uint8_t>(value));
  }
  template <std::size_t N>
  void Fixed(const std::array<std::uint8_t, N>& value) noexcept {
    for (const auto byte : value) U8(byte);
  }
  [[nodiscard]] std::uint64_t value() const noexcept { return value_; }

 private:
  std::uint64_t value_{14695981039346656037ULL};
};

template <class T>
constexpr std::uint8_t U8(T value) noexcept {
  return static_cast<std::uint8_t>(value);
}

template <class Event>
std::uint64_t EventChecksum(const Event& event) noexcept {
  Fnv1a64 hash;
  hash.Bytes("RGEV1", 5);
  hash.U8(U8(event.stage));
  hash.U8(U8(event.outcome));
  hash.Fixed(event.attempt_id);
  hash.U64(event.timestamp_ns);
  hash.U64(event.cost_units);
  return hash.value();
}

template <class Producer>
std::uint64_t ProducerChecksum(const Producer& producer) noexcept {
  Fnv1a64 hash;
  hash.Bytes("RGPS1", 5);
  hash.U8(U8(producer.owner));
  hash.U32(producer.producer_index);
  hash.U64(producer.capacity);
  hash.U64(producer.reserved_count);
  hash.U64(producer.published_count);
  hash.U8(producer.sealed ? 1 : 0);
  hash.U8(producer.incomplete ? 1 : 0);
  for (const auto& slot : producer.slots) {
    hash.U8(U8(slot.status));
    hash.U64(slot.producer_sequence);
    hash.U64(slot.checksum64);
  }
  return hash.value();
}

template <class Snapshot>
std::uint64_t SnapshotChecksum(const Snapshot& snapshot) noexcept {
  Fnv1a64 hash;
  hash.Bytes("RGRN1", 5);
  hash.U32(snapshot.schema_version);
  hash.Fixed(snapshot.epoch_id);
  hash.Fixed(snapshot.policy_digest);
  hash.U32(static_cast<std::uint32_t>(snapshot.producers.size()));
  hash.U64(snapshot.planned_bytes);
  hash.U64(snapshot.budget_bytes);
  for (const auto& producer : snapshot.producers) {
    hash.U8(U8(producer.owner));
    hash.U32(producer.producer_index);
    hash.U64(producer.capacity);
    hash.U64(producer.seal_checksum64);
  }
  hash.U8(snapshot.complete ? 1 : 0);
  return hash.value();
}

inline bool ValidStage(std::uint8_t stage) noexcept { return stage >= 1 && stage <= 6; }
inline bool ValidOutcome(std::uint8_t outcome) noexcept { return outcome <= 7; }
inline bool ValidOwner(std::uint8_t owner) noexcept { return owner >= 1 && owner <= 5; }
inline bool ValidSlotStatus(std::uint8_t status) noexcept { return status <= 3; }

inline std::uint8_t OwnerForStage(std::uint8_t stage) noexcept {
  switch (stage) {
    case 1: return 1;  // Offered -> workload generator
    case 2: return 2;  // Strict decision -> authority
    case 3: return 3;  // Responded -> replica
    case 4: return 4;  // Received -> adapter
    case 5: return 4;  // Forwarded -> adapter
    case 6: return 5;  // Completed -> backend
    default: return 0;
  }
}

inline bool AddChecked(std::uint64_t& total, std::uint64_t value) noexcept {
  if (value > std::numeric_limits<std::uint64_t>::max() - total) return false;
  total += value;
  return true;
}

inline bool MultiplyAddChecked(std::uint64_t& total, std::uint64_t count,
                               std::uint64_t extent) noexcept {
  if (count != 0 && extent > std::numeric_limits<std::uint64_t>::max() / count)
    return false;
  return AddChecked(total, count * extent);
}

inline bool ExpectedPlanBytes(std::span<const ProducerSpec> producers,
                       std::uint64_t& bytes) noexcept {
  // Independently frozen canonical extents for schema v1. Keep these literals
  // separate from recorder helpers so a changed encoder cannot self-validate.
  constexpr std::uint64_t kHeader = 80;  // RGHIST01 + fixed header fields
  constexpr std::uint64_t kProducerEnvelope = 13;
  constexpr std::uint64_t kSlot = 51;
  constexpr std::uint64_t kProducerSeal = 26;
  constexpr std::uint64_t kTerminal = 17;
  bytes = kHeader + kTerminal;
  for (const auto& producer : producers) {
    if (!AddChecked(bytes, kProducerEnvelope) ||
        !MultiplyAddChecked(bytes, producer.event_capacity, kSlot) ||
        !AddChecked(bytes, kProducerSeal)) return false;
  }
  return true;
}

inline bool ValidExpectedPlan(std::span<const ProducerSpec> producers,
                              std::uint64_t budget_bytes,
                              std::uint64_t& planned_bytes) noexcept {
  if (producers.empty() || producers.size() > std::numeric_limits<std::uint32_t>::max() ||
      budget_bytes < 97 || budget_bytes > kMaximumRunBytes)
    return false;
  for (std::size_t i = 0; i < producers.size(); ++i) {
    const auto owner = U8(producers[i].owner);
    if (!ValidOwner(owner) || producers[i].event_capacity == 0 ||
        producers[i].event_capacity >
            static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    if (i != 0 && producers[i - 1].owner == producers[i].owner &&
        producers[i - 1].producer_index == producers[i].producer_index) return false;
  }
  return ExpectedPlanBytes(producers, planned_bytes) && planned_bytes <= budget_bytes &&
         planned_bytes < kMaximumRunBytes;
}

template <class Event>
bool IsDefaultUnpublishedEvent(const Event& event) noexcept {
  if (U8(event.stage) != 1 || U8(event.outcome) != 0 ||
      event.timestamp_ns != 0 || event.cost_units != 0) return false;
  for (const auto byte : event.attempt_id) if (byte != 0) return false;
  return true;
}

}  // namespace detail

// Snapshot must be the immutable EventSnapshotV1 value type from the recorder
// contract. The caller supplies an independent run plan.
inline Report ValidateHistorySnapshot(const EventSnapshotV1& snapshot,
                                      const RunPlan& expected_plan) noexcept {
  auto invalid = [](Reason reason) { return Report{Verdict::Invalid, reason}; };
  auto incomplete = [](Reason reason) { return Report{Verdict::Incomplete, reason}; };

  try {
    // The caller's RunPlan is not assumed to have been reordered in place by
    // EventRecorder::Create. Sort a bounded copy, then compare against the
    // canonical snapshot roster. This avoids quadratic roster matching.
    if (expected_plan.budget_bytes < 97 || expected_plan.budget_bytes > kMaximumRunBytes ||
        expected_plan.producers.size() > (expected_plan.budget_bytes - 97) / 90)
      return invalid(Reason::InvalidExpectedPlan);
    std::vector<ProducerSpec> sorted_plan = expected_plan.producers;
    std::sort(sorted_plan.begin(), sorted_plan.end(), [](const auto& left, const auto& right) {
      return left.owner < right.owner ||
          (left.owner == right.owner && left.producer_index < right.producer_index);
    });
    std::uint64_t expected_planned = 0;
    if (!detail::ValidExpectedPlan(std::span<const ProducerSpec>(sorted_plan),
                                   expected_plan.budget_bytes, expected_planned))
      return invalid(Reason::InvalidExpectedPlan);
    if (snapshot.schema_version != 1) return invalid(Reason::SchemaMismatch);
    if (snapshot.epoch_id != expected_plan.epoch_id ||
        snapshot.policy_digest != expected_plan.policy_digest ||
        snapshot.budget_bytes != expected_plan.budget_bytes ||
        snapshot.planned_bytes != expected_planned)
      return invalid(Reason::ExpectedPlanMismatch);
    if (snapshot.budget_bytes == 0 || snapshot.budget_bytes > kMaximumRunBytes ||
        snapshot.planned_bytes > snapshot.budget_bytes)
      return invalid(Reason::InvalidByteAccounting);
    if (snapshot.producers.size() < sorted_plan.size())
      return incomplete(Reason::ProducerMissing);
    if (snapshot.producers.size() > sorted_plan.size())
      return invalid(Reason::ProducerUnexpected);

    Report report{Verdict::Complete, Reason::None};
    for (std::size_t index = 0; index < sorted_plan.size(); ++index) {
      const auto& expected = sorted_plan[index];
      const auto& producer = snapshot.producers[index];
      if (producer.owner != expected.owner || producer.producer_index != expected.producer_index)
        return invalid(Reason::ProducerOrderOrCapacityMismatch);
      if (producer.capacity != expected.event_capacity)
        return invalid(Reason::ProducerOrderOrCapacityMismatch);
      if (!detail::ValidOwner(detail::U8(producer.owner)) ||
          producer.capacity == 0 || producer.slots.size() != producer.capacity ||
          producer.reserved_count > producer.capacity ||
          producer.published_count > producer.reserved_count)
        return invalid(Reason::InvalidByteAccounting);

      std::uint64_t published = 0;
      for (std::size_t i = 0; i < producer.slots.size(); ++i) {
        const auto& slot = producer.slots[i];
        const auto status = detail::U8(slot.status);
        if (!detail::ValidSlotStatus(status)) return invalid(Reason::InvalidSlotState);
        if (i < producer.reserved_count) {
          if (slot.producer_sequence != static_cast<std::uint64_t>(i) + 1)
            return incomplete(Reason::ReservationGap);
          if (status != 2) {
            const auto why = status == 1 ? Reason::ReservedSlotUnpublished
                                        : Reason::ReservationGap;
            return incomplete(why);
          }
          const auto stage = detail::U8(slot.event.stage);
          const auto outcome = detail::U8(slot.event.outcome);
          if (!detail::ValidStage(stage) || !detail::ValidOutcome(outcome))
            return invalid(Reason::InvalidEventEnum);
          if (detail::OwnerForStage(stage) != detail::U8(producer.owner))
            return invalid(Reason::StageOwnerMismatch);
          const auto event_checksum = detail::EventChecksum(slot.event);
          if (slot.checksum64 != event_checksum)
            return incomplete(Reason::EventChecksumMismatch);
          ++published;
        } else {
          if (status != 0 || slot.producer_sequence != 0 || slot.checksum64 != 0 ||
              !detail::IsDefaultUnpublishedEvent(slot.event))
            return invalid(Reason::InvalidSlotState);
        }
      }
      if (published != producer.published_count)
        return incomplete(Reason::PublishedCountMismatch);
      if (!producer.sealed) return incomplete(Reason::ProducerNotSealed);
      if (producer.incomplete) return incomplete(Reason::ProducerMarkedIncomplete);
      if (producer.seal_checksum64 != detail::ProducerChecksum(producer))
        return incomplete(Reason::ProducerChecksumMismatch);
      if (!detail::AddChecked(report.published_events, published))
        return invalid(Reason::InvalidByteAccounting);
    }

    if (snapshot.checksum64 != detail::SnapshotChecksum(snapshot))
      return incomplete(Reason::SnapshotChecksumMismatch);
    if (!snapshot.complete) return incomplete(Reason::SnapshotIncomplete);
    report.snapshot_bytes = snapshot.planned_bytes;
    return report;
  } catch (...) {
    return Report{Verdict::Incomplete, Reason::ValidatorResourceFailure};
  }
}

}  // namespace rateguard::events::validation
