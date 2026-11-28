#pragma once

// Pure value model for durable-before-launch epoch bootstrap. This component
// does not launch processes, persist files, or claim that a returned value is
// durable. The supervisor/store must persist each next value before acting on it.

#include "supervisor/epoch_gate.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rateguard::supervisor {

inline constexpr std::size_t kMaxBootstrapBytes = 4U * 1024U * 1024U;

struct PlannedParticipant {
  ParticipantRole role{};
  std::uint32_t slot_id{};
  std::string participant_id;
  IncarnationId incarnation{};
  std::string container_id;
  friend bool operator==(const PlannedParticipant&, const PlannedParticipant&) = default;
};

struct ObservedBootstrapIdentity {
  PlannedParticipant participant;
  std::uint64_t pid{};
  std::uint64_t pid_start_ticks{};
  platform::ClockIdentity clock_identity{};
  friend bool operator==(const ObservedBootstrapIdentity&, const ObservedBootstrapIdentity&) = default;
};

struct BootstrapRecord {
  PlannedParticipant planned;
  std::uint64_t pid{};
  std::uint64_t pid_start_ticks{};
  bool identity_recorded{};
  platform::ClockIdentity clock_identity{};
  friend bool operator==(const BootstrapRecord&, const BootstrapRecord&) = default;
};

struct BootstrapPlan {
  std::array<std::uint8_t, 16> domain_id{};
  EpochId epoch_id{};
  IncarnationId authority_incarnation{};
  PolicyDigest policy_digest{};
  platform::ClockIdentity expected_clock_identity{};
  std::vector<PlannedParticipant> participants;
};

enum class BootstrapError : std::uint8_t {
  None,
  InvalidPlan,
  TooManyParticipants,
  IdentityNotInPlan,
  IdentityMismatch,
  DuplicateProcessIdentity,
  RecoveryRequired,
  IncompleteRoster,
  InvalidEncoding,
  DuplicateKey,
  UnknownKey,
  MissingKey,
  UnsupportedSchema,
  NonCanonical,
  DigestMismatch,
  TooLarge,
  DigestFailure,
  AllocationFailure,
  RevisionExhausted,
};

class BootstrapInventory;
struct BootstrapTransition;
struct BootstrapCodecAccess;

class BootstrapInventory final {
 public:
  [[nodiscard]] static std::variant<BootstrapInventory, BootstrapError> Create(
      const BootstrapPlan& plan) noexcept;

  [[nodiscard]] const EpochId& epoch_id() const noexcept { return epoch_id_; }
  [[nodiscard]] const std::array<std::uint8_t, 16>& domain_id() const noexcept { return domain_id_; }
  [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }
  [[nodiscard]] const IncarnationId& authority_incarnation() const noexcept { return authority_incarnation_; }
  [[nodiscard]] const PolicyDigest& policy_digest() const noexcept { return policy_digest_; }
  [[nodiscard]] const platform::ClockIdentity& expected_clock_identity() const noexcept {
    return expected_clock_identity_;
  }
  [[nodiscard]] const std::vector<BootstrapRecord>& records() const noexcept { return *records_; }
  [[nodiscard]] bool recovery_required() const noexcept { return recovery_required_; }
  [[nodiscard]] BootstrapError recovery_reason() const noexcept { return recovery_reason_; }
  [[nodiscard]] std::size_t recorded_count() const noexcept;

  // Returns a new value. Exact duplicate registration is idempotent. Any
  // mismatch, unknown registration, or identity collision irreversibly latches
  // recovery_required in the returned value. The store must persist it before
  // exposing a response or taking a subsequent process action.
  [[nodiscard]] BootstrapTransition RecordIdentity(
      const ObservedBootstrapIdentity& observed) const noexcept;

  [[nodiscard]] BootstrapInventory RequireRecovery(BootstrapError reason) const noexcept;
  [[nodiscard]] std::variant<EpochCandidate, BootstrapError> ReadyCandidate() const noexcept;

 private:
  friend struct BootstrapTransition;
  friend struct BootstrapCodecAccess;
  friend std::variant<std::string, BootstrapError> EncodeBootstrapInventoryV1(
      const BootstrapInventory&) noexcept;
  friend std::variant<BootstrapInventory, BootstrapError> DecodeBootstrapInventoryV1(
      std::string_view) noexcept;
  BootstrapInventory(std::array<std::uint8_t, 16> domain, std::uint64_t revision,
                     EpochId epoch, IncarnationId authority, PolicyDigest digest,
                     platform::ClockIdentity clock,
                     std::shared_ptr<const std::vector<BootstrapRecord>> records,
                     bool recovery, BootstrapError reason) noexcept
      : domain_id_(domain), revision_(revision), epoch_id_(epoch), authority_incarnation_(authority), policy_digest_(digest),
        expected_clock_identity_(clock), records_(std::move(records)),
        recovery_required_(recovery), recovery_reason_(reason) {}

  std::array<std::uint8_t, 16> domain_id_{};
  std::uint64_t revision_{1};
  EpochId epoch_id_{};
  IncarnationId authority_incarnation_{};
  PolicyDigest policy_digest_{};
  platform::ClockIdentity expected_clock_identity_{};
  std::shared_ptr<const std::vector<BootstrapRecord>> records_;
  bool recovery_required_{};
  BootstrapError recovery_reason_{BootstrapError::None};
};

struct BootstrapTransition final {
  BootstrapInventory next;
  BootstrapError status{BootstrapError::None};
};

using BootstrapEncodeResult = std::variant<std::string, BootstrapError>;
using BootstrapDecodeResult = std::variant<BootstrapInventory, BootstrapError>;
using BootstrapDigestResult = std::variant<std::array<std::uint8_t, 32>, BootstrapError>;

[[nodiscard]] BootstrapEncodeResult EncodeBootstrapInventoryV1(
    const BootstrapInventory& inventory) noexcept;
[[nodiscard]] BootstrapDecodeResult DecodeBootstrapInventoryV1(
    std::string_view envelope) noexcept;
[[nodiscard]] BootstrapDigestResult BootstrapDigestV1(
    const BootstrapInventory& inventory) noexcept;

}  // namespace rateguard::supervisor
