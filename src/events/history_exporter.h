#pragma once

#include "src/events/history_validator.h"

#include <array>
#include <cstdint>
#include <ios>
#include <ostream>

namespace rateguard::events {

// The caller supplies an unpublished binary stream. Only a successful return
// permits it to finalize the file; disk durability is the file owner's job.
enum class ExportStatus { Complete, IncompleteHistory, WriteFailed };

namespace wire {
template <typename T>
void Integer(std::ostream& stream, T value) {
  std::array<unsigned char, sizeof(T)> bytes{};
  for (std::size_t i = bytes.size(); i > 0; --i) {
    bytes[i - 1] = static_cast<unsigned char>(value & 0xffU);
    value = static_cast<T>(static_cast<std::uint64_t>(value) >> 8);
  }
  stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}
template <std::size_t N>
void Bytes(std::ostream& stream, const std::array<std::uint8_t, N>& bytes) {
  stream.write(reinterpret_cast<const char*>(bytes.data()), N);
}
}  // namespace wire

inline ExportStatus ExportStrictHistory(const RunPlan& expected,
                                        const EventSnapshotV1& snapshot,
                                        std::ostream& output) {
  if (!validation::ValidateHistorySnapshot(snapshot, expected).complete())
    return ExportStatus::IncompleteHistory;

  try {
    output.write("RGHIST01", 8);
    wire::Integer(output, snapshot.schema_version);
    wire::Bytes(output, snapshot.epoch_id);
    wire::Bytes(output, snapshot.policy_digest);
    wire::Integer(output, static_cast<std::uint32_t>(snapshot.producers.size()));
    wire::Integer(output, snapshot.planned_bytes);
    wire::Integer(output, snapshot.budget_bytes);
    for (const auto& producer : snapshot.producers) {
      wire::Integer(output, static_cast<std::uint8_t>(producer.owner));
      wire::Integer(output, producer.producer_index);
      wire::Integer(output, producer.capacity);
      for (const auto& slot : producer.slots) {
        wire::Integer(output, static_cast<std::uint8_t>(slot.status));
        wire::Integer(output, slot.producer_sequence);
        wire::Integer(output, static_cast<std::uint8_t>(slot.event.stage));
        wire::Integer(output, static_cast<std::uint8_t>(slot.event.outcome));
        wire::Bytes(output, slot.event.attempt_id);
        wire::Integer(output, slot.event.timestamp_ns);
        wire::Integer(output, slot.event.cost_units);
        wire::Integer(output, slot.checksum64);
        if (!output) return ExportStatus::WriteFailed;
      }
      wire::Integer(output, static_cast<std::uint8_t>(producer.sealed));
      wire::Integer(output, static_cast<std::uint8_t>(producer.incomplete));
      wire::Integer(output, producer.reserved_count);
      wire::Integer(output, producer.published_count);
      wire::Integer(output, producer.seal_checksum64);
    }
    wire::Integer(output, static_cast<std::uint8_t>(snapshot.complete));
    wire::Integer(output, snapshot.planned_bytes);
    wire::Integer(output, snapshot.checksum64);
    output.flush();
    return output ? ExportStatus::Complete : ExportStatus::WriteFailed;
  } catch (...) {
    return ExportStatus::WriteFailed;
  }
}

}  // namespace rateguard::events
