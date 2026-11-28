#pragma once

#include "src/events/history_validator.h"

#include <array>
#include <istream>
#include <string_view>
#include <variant>

namespace rateguard::events::history {

enum class ReadError { BadPlan, BadHeader, BadEncoding, IncompleteEvidence, ReadFailure };
using ReadResult = std::variant<EventSnapshotV1, ReadError>;

namespace input {
template <class T>
bool Number(std::istream& in, T& value) {
  std::array<unsigned char, sizeof(T)> bytes{};
  if (!in.read(reinterpret_cast<char*>(bytes.data()), bytes.size())) return false;
  value = 0;
  for (const auto byte : bytes)
    value = static_cast<T>((static_cast<std::uint64_t>(value) << 8) | byte);
  return true;
}

template <class E>
bool Enum(std::istream& in, E& value) {
  std::uint8_t octet;
  if (!Number(in, octet)) return false;
  value = static_cast<E>(octet);
  return true;
}

inline bool Flag(std::istream& in, bool& value) {
  std::uint8_t octet;
  if (!Number(in, octet) || octet > 1) return false;
  value = octet != 0;
  return true;
}

template <std::size_t N>
bool Bytes(std::istream& in, std::array<std::uint8_t, N>& field) {
  return static_cast<bool>(in.read(reinterpret_cast<char*>(field.data()), N));
}
}  // namespace input

// Offline reader for a complete binary file. The caller supplies a trusted run
// plan. File-supplied sizes never control allocations.
inline ReadResult ReadStrictHistory(std::istream& in, const RunPlan& plan) noexcept {
  try {
    if (plan.budget_bytes < 97 || plan.budget_bytes > kMaxRunBudgetBytes ||
        plan.producers.size() > (plan.budget_bytes - 97) / 90) return ReadError::BadPlan;
    auto roster = plan.producers;
    std::sort(roster.begin(), roster.end(), [](const auto& a, const auto& b) {
      return a.owner < b.owner || (a.owner == b.owner && a.producer_index < b.producer_index);
    });
    std::uint64_t extent;
    if (!validation::detail::ValidExpectedPlan(roster, plan.budget_bytes, extent))
      return ReadError::BadPlan;

    EventSnapshotV1 s;
    std::array<char, 8> magic{};
    std::uint32_t count;
    if (!in.read(magic.data(), magic.size()) || std::string_view(magic.data(), 8) != "RGHIST01" ||
        !input::Number(in, s.schema_version) || s.schema_version != 1 ||
        !input::Bytes(in, s.epoch_id) || s.epoch_id != plan.epoch_id ||
        !input::Bytes(in, s.policy_digest) || s.policy_digest != plan.policy_digest ||
        !input::Number(in, count) || count != roster.size() ||
        !input::Number(in, s.planned_bytes) || s.planned_bytes != extent ||
        !input::Number(in, s.budget_bytes) || s.budget_bytes != plan.budget_bytes)
      return ReadError::BadHeader;

    s.producers.reserve(roster.size());
    for (const auto& expected : roster) {
      auto& p = s.producers.emplace_back();
      if (!input::Enum(in, p.owner) || p.owner != expected.owner ||
          !input::Number(in, p.producer_index) || p.producer_index != expected.producer_index ||
          !input::Number(in, p.capacity) || p.capacity != expected.event_capacity)
        return ReadError::BadEncoding;
      p.slots.resize(expected.event_capacity);
      for (auto& slot : p.slots) {
        auto& e = slot.event;
        if (!input::Enum(in, slot.status) || !input::Number(in, slot.producer_sequence) ||
            !input::Enum(in, e.stage) || !input::Enum(in, e.outcome) ||
            !input::Bytes(in, e.attempt_id) || !input::Number(in, e.timestamp_ns) ||
            !input::Number(in, e.cost_units) || !input::Number(in, slot.checksum64))
          return ReadError::BadEncoding;
      }
      if (!input::Flag(in, p.sealed) || !input::Flag(in, p.incomplete) ||
          !input::Number(in, p.reserved_count) || !input::Number(in, p.published_count) ||
          !input::Number(in, p.seal_checksum64)) return ReadError::BadEncoding;
    }
    std::uint64_t terminal_extent;
    if (!input::Flag(in, s.complete) || !input::Number(in, terminal_extent) ||
        terminal_extent != extent || !input::Number(in, s.checksum64))
      return ReadError::BadEncoding;
    if (in.peek() != std::istream::traits_type::eof() || in.bad() || !in.eof())
      return ReadError::BadEncoding;
    if (!validation::ValidateHistorySnapshot(s, plan).complete())
      return ReadError::IncompleteEvidence;
    return s;
  } catch (...) {
    return ReadError::ReadFailure;
  }
}

}  // namespace rateguard::events::history
