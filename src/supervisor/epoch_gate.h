#pragma once

// Local, single-epoch lifecycle gate. This component is not a durable
// supervisor and cannot authorize a successor epoch by itself.

#include "platform/clock.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace rateguard::supervisor {

inline constexpr std::size_t kMaxReplicaSlots = 8;
// Proposed implementation resource cap; not a PRD/SRD participant-count
// guarantee. Inventories above this cap are rejected before internal state allocation.
inline constexpr std::size_t kMaxParticipants = 1024;

using EpochId = std::array<std::uint8_t, 16>;
using IncarnationId = std::array<std::uint8_t, 16>;
using PolicyDigest = std::array<std::uint8_t, 32>;
using OperationId = std::array<std::uint8_t, 16>;

enum class ParticipantRole : std::uint8_t { Authority, Replica, Adapter, Witness };
enum class ProcessState : std::uint8_t { Running, Exited, Unknown };
enum class EpochPhase : std::uint8_t { PreActivation, Active, Draining, Closed };
enum class DrainCause : std::uint8_t { Requested, AuthorityFailure, IntegrityFailure, ClockFailure };

struct ProcessIdentity {
  // Runtime/container identifier is a canonical lower-case 64-digit hex value.
  std::string container_id;
  // Host PID, paired with the kernel PID start-time identity below.
  std::uint64_t pid{};
  std::uint64_t pid_start_ticks{};
  friend bool operator==(const ProcessIdentity&, const ProcessIdentity&) = default;
};

struct Participant {
  ParticipantRole role{};
  // Non-replica participants use slot_id == 0. Replica IDs are fixed by policy
  // and may be any uint32 value; at most eight replica entries are accepted.
  std::uint32_t slot_id{};
  // Stable inventory key within a role; permits multiple fixed adapters.
  std::string participant_id;
  IncarnationId incarnation{};
  ProcessIdentity process;
  platform::ClockIdentity clock_identity{};
  friend bool operator==(const Participant&, const Participant&) = default;
};

struct EpochCandidate {
  EpochId epoch_id{};
  IncarnationId authority_incarnation{};
  PolicyDigest policy_digest{};
  platform::ClockIdentity clock_identity{};
  std::vector<Participant> participants;
};

enum class ControllerError : std::uint8_t { Unavailable, TimedOut, InvalidEvidence, Internal };
struct StopAck {
  OperationId operation_id{};
};
struct ProcessObservation {
  Participant participant;
  ProcessState state{ProcessState::Unknown};
};

class IProcessController {
 public:
  virtual ~IProcessController() = default;
  // Implementations must bind each response to the full expected identity.
  // Calls can block or throw; EpochGate never holds its mutex across them.
  virtual std::variant<StopAck, ControllerError> RequestStop(
      const Participant& expected, const OperationId& operation_id) = 0;
  virtual std::variant<ProcessObservation, ControllerError> Inspect(
      const Participant& expected) = 0;
};

enum class GateError : std::uint8_t {
  InvalidCandidate,
  TooManyParticipants,
  InvalidInventory,
  WrongEpoch,
  WrongPhase,
  Busy,
  ControllerFailure,
  IdentityMismatch,
  NotRunning,
  NotExited,
  WrongOperation,
  InFlightCommit,
  AllocationFailure,
};
using GateResult = std::variant<std::monostate, GateError>;
using GateCreateResult = std::variant<std::shared_ptr<class EpochGate>, GateError>;

namespace detail {
struct GateState {
  mutable std::mutex mutex;
  EpochPhase phase{EpochPhase::PreActivation};
  std::size_t active_commits{};
  bool lifecycle_io_in_progress{};
  std::optional<OperationId> drain_operation;
  DrainCause drain_cause{DrainCause::Requested};
};

inline bool AllZero(const auto& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}

inline bool CanonicalContainerId(const std::string& value) noexcept {
  if (value.size() != 64) return false;
  for (unsigned char c : value) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

inline bool ValidParticipant(const Participant& p, const EpochCandidate& c) noexcept {
  if (p.participant_id.empty() || p.participant_id.size() > 64 ||
      !std::all_of(p.participant_id.begin(), p.participant_id.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
      }) || !CanonicalContainerId(p.process.container_id) || p.process.pid == 0 ||
      p.process.pid_start_ticks == 0 || !(p.clock_identity == c.clock_identity)) return false;
  switch (p.role) {
    case ParticipantRole::Authority:
      return p.slot_id == 0 && p.incarnation == c.authority_incarnation;
    case ParticipantRole::Replica:
      return !AllZero(p.incarnation);
    case ParticipantRole::Adapter:
    case ParticipantRole::Witness:
      return p.slot_id == 0 && !AllZero(p.incarnation);
  }
  return false;
}
}  // namespace detail

// Pure bounded validation shared by lifecycle startup and durable manifest decoding.
[[nodiscard]] inline std::optional<GateError> ValidateEpochCandidate(
    const EpochCandidate& candidate) noexcept {
  if (candidate.participants.size() > kMaxParticipants) return GateError::TooManyParticipants;
  if (detail::AllZero(candidate.epoch_id) || detail::AllZero(candidate.authority_incarnation) ||
      detail::AllZero(candidate.policy_digest) || candidate.participants.empty())
    return GateError::InvalidCandidate;
  std::size_t authorities = 0, witnesses = 0, adapters = 0;
  std::size_t replicas = 0;
  for (std::size_t i = 0; i < candidate.participants.size(); ++i) {
    const auto& p = candidate.participants[i];
    if (!detail::ValidParticipant(p, candidate)) return GateError::InvalidInventory;
    if (p.role == ParticipantRole::Authority) ++authorities;
    if (p.role == ParticipantRole::Witness) ++witnesses;
    if (p.role == ParticipantRole::Adapter) ++adapters;
    if (p.role == ParticipantRole::Replica) ++replicas;
    for (std::size_t j = 0; j < i; ++j) {
      const auto& q = candidate.participants[j];
      if (p.process.container_id == q.process.container_id || p.process.pid == q.process.pid)
        return GateError::InvalidInventory;
      if (p.role == q.role && p.participant_id == q.participant_id)
        return GateError::InvalidInventory;
      if (p.role == ParticipantRole::Replica && q.role == ParticipantRole::Replica &&
          p.slot_id == q.slot_id) return GateError::InvalidInventory;
    }
  }
  if (authorities != 1 || witnesses != 1 || adapters == 0 || replicas == 0 ||
      replicas > kMaxReplicaSlots) return GateError::InvalidInventory;
  return std::nullopt;
}

class CommitLease {
 public:
  CommitLease(const CommitLease&) = delete;
  CommitLease& operator=(const CommitLease&) = delete;
  CommitLease(CommitLease&& other) noexcept : state_(std::move(other.state_)) {}
  CommitLease& operator=(CommitLease&& other) noexcept {
    if (this != &other) {
      Release();
      state_ = std::move(other.state_);
    }
    return *this;
  }
  ~CommitLease() { Release(); }

 private:
  friend class EpochGate;
  explicit CommitLease(std::shared_ptr<detail::GateState> state) : state_(std::move(state)) {}
  void Release() noexcept {
    if (!state_) return;
    auto owner = std::move(state_);
    {
      std::lock_guard lock(owner->mutex);
      if (owner->active_commits > 0) --owner->active_commits;
    }
  }
  std::shared_ptr<detail::GateState> state_;
};

class EpochGate {
 public:
  EpochGate(const EpochGate&) = delete;
  EpochGate& operator=(const EpochGate&) = delete;

  [[nodiscard]] static GateCreateResult Create(const EpochCandidate& candidate,
                                                IProcessController& controller) noexcept {
    if (const auto error = ValidateEpochCandidate(candidate)) return *error;
    try {
      auto shared_candidate = std::make_shared<const EpochCandidate>(candidate);
      auto state = std::make_shared<detail::GateState>();
      return std::shared_ptr<EpochGate>(new EpochGate(std::move(shared_candidate), controller,
                                                      std::move(state)));
    } catch (...) {
      return GateError::AllocationFailure;
    }
  }

  [[nodiscard]] EpochPhase phase() const noexcept {
    std::lock_guard lock(state_->mutex);
    return state_->phase;
  }
  [[nodiscard]] const EpochCandidate& candidate() const noexcept { return *candidate_; }

  // Readiness is local to this fixed inventory. Success is not successor-epoch
  // authorization and does not establish durable manifest or clock provenance.
  [[nodiscard]] GateResult Activate() noexcept {
    {
      std::lock_guard lock(state_->mutex);
      if (state_->phase != EpochPhase::PreActivation) return GateError::WrongPhase;
      if (state_->lifecycle_io_in_progress) return GateError::Busy;
      state_->lifecycle_io_in_progress = true;
    }
    GateError failure = GateError::ControllerFailure;
    bool ok = true;
    for (const auto& p : candidate_->participants) {
      try {
        auto result = controller_.Inspect(p);
        if (auto* err = std::get_if<ControllerError>(&result)) {
          (void)err; ok = false; break;
        }
        const auto& obs = std::get<ProcessObservation>(result);
        if (!(obs.participant == p)) { failure = GateError::IdentityMismatch; ok = false; break; }
        if (obs.state != ProcessState::Running) { failure = GateError::NotRunning; ok = false; break; }
      } catch (...) { ok = false; break; }
    }
    {
      std::lock_guard lock(state_->mutex);
      state_->lifecycle_io_in_progress = false;
      if (ok) state_->phase = EpochPhase::Active;
    }
    return ok ? GateResult{std::monostate{}} : GateResult{failure};
  }

  [[nodiscard]] std::variant<CommitLease, GateError> TryAcquireCommitPermit(
      const EpochId& expected_epoch) noexcept {
    std::lock_guard lock(state_->mutex);
    if (expected_epoch != candidate_->epoch_id) return GateError::WrongEpoch;
    if (state_->phase != EpochPhase::Active) return GateError::WrongPhase;
    if (state_->active_commits == std::numeric_limits<std::size_t>::max())
      return GateError::Busy;
    ++state_->active_commits;
    return CommitLease(state_);
  }

  [[nodiscard]] GateResult BeginDrain(const OperationId& operation_id, DrainCause cause) noexcept {
    if (detail::AllZero(operation_id)) return GateError::WrongOperation;
    std::lock_guard lock(state_->mutex);
    if (state_->lifecycle_io_in_progress) return GateError::Busy;
    if (state_->phase == EpochPhase::Closed) {
      return state_->drain_operation && *state_->drain_operation == operation_id
                 ? GateResult{std::monostate{}} : GateResult{GateError::WrongOperation};
    }
    if (state_->phase == EpochPhase::Draining) {
      return state_->drain_operation && *state_->drain_operation == operation_id
                 ? GateResult{std::monostate{}} : GateResult{GateError::WrongOperation};
    }
    if (state_->phase != EpochPhase::Active && state_->phase != EpochPhase::PreActivation)
      return GateError::WrongPhase;
    state_->phase = EpochPhase::Draining;
    state_->drain_operation = operation_id;
    state_->drain_cause = cause;
    return std::monostate{};
  }

  // Stops adapters and replicas first; authority/witness are untouched unless
  // every ingress/replica participant is positively confirmed exited.
  [[nodiscard]] GateResult FenceAndClose(const OperationId& operation_id) noexcept {
    {
      std::lock_guard lock(state_->mutex);
      if (state_->phase == EpochPhase::Closed) {
        return state_->drain_operation && *state_->drain_operation == operation_id
                   ? GateResult{std::monostate{}} : GateResult{GateError::WrongOperation};
      }
      if (state_->phase != EpochPhase::Draining) return GateError::WrongPhase;
      if (!state_->drain_operation || *state_->drain_operation != operation_id)
        return GateError::WrongOperation;
      if (state_->lifecycle_io_in_progress) return GateError::Busy;
      if (state_->active_commits != 0) return GateError::InFlightCommit;
      state_->lifecycle_io_in_progress = true;
    }

    GateError failure = GateError::ControllerFailure;
    bool ok = StopAndConfirmGroup(ParticipantRole::Adapter, ParticipantRole::Replica,
                                  operation_id, failure);
    if (ok) ok = StopAndConfirm(ParticipantRole::Authority, operation_id, failure) &&
                 StopAndConfirm(ParticipantRole::Witness, operation_id, failure);
    {
      std::lock_guard lock(state_->mutex);
      state_->lifecycle_io_in_progress = false;
      if (ok) state_->phase = EpochPhase::Closed;
    }
    return ok ? GateResult{std::monostate{}} : GateResult{failure};
  }

 private:
  EpochGate(std::shared_ptr<const EpochCandidate> candidate, IProcessController& controller,
            std::shared_ptr<detail::GateState> state)
      : candidate_(std::move(candidate)), controller_(controller), state_(std::move(state)) {}

  bool StopAndConfirm(ParticipantRole role, const OperationId& operation_id,
                      GateError& failure) noexcept {
    for (const auto& p : candidate_->participants) {
      if (p.role != role) continue;
      try {
        auto stop = controller_.RequestStop(p, operation_id);
        if (std::holds_alternative<ControllerError>(stop)) return false;
        if (!(std::get<StopAck>(stop).operation_id == operation_id)) {
          failure = GateError::WrongOperation; return false;
        }
        auto result = controller_.Inspect(p);
        if (std::holds_alternative<ControllerError>(result)) return false;
        const auto& obs = std::get<ProcessObservation>(result);
        if (!(obs.participant == p)) { failure = GateError::IdentityMismatch; return false; }
        if (obs.state != ProcessState::Exited) { failure = GateError::NotExited; return false; }
      } catch (...) {
        // Controller exceptions are evidence failures. The epoch stays draining.
        return false;
      }
    }
    return true;
  }

  bool StopAndConfirmGroup(ParticipantRole first, ParticipantRole second,
                           const OperationId& operation_id, GateError& failure) noexcept {
    bool requests_ok = true;
    for (const auto& p : candidate_->participants) {
      if (p.role != first && p.role != second) continue;
      try {
        auto stop = controller_.RequestStop(p, operation_id);
        if (std::holds_alternative<ControllerError>(stop)) {
          requests_ok = false;
        } else if (!(std::get<StopAck>(stop).operation_id == operation_id)) {
          failure = GateError::WrongOperation;
          requests_ok = false;
        }
      } catch (...) {
        requests_ok = false;
      }
    }
    bool exits_ok = true;
    for (const auto& p : candidate_->participants) {
      if (p.role != first && p.role != second) continue;
      try {
        auto result = controller_.Inspect(p);
        if (std::holds_alternative<ControllerError>(result)) {
          exits_ok = false;
          continue;
        }
        const auto& obs = std::get<ProcessObservation>(result);
        if (!(obs.participant == p)) {
          failure = GateError::IdentityMismatch;
          exits_ok = false;
        } else if (obs.state != ProcessState::Exited) {
          failure = GateError::NotExited;
          exits_ok = false;
        }
      } catch (...) {
        exits_ok = false;
      }
    }
    return requests_ok && exits_ok;
  }

  const std::shared_ptr<const EpochCandidate> candidate_;
  IProcessController& controller_;  // Must outlive this gate and its operations.
  const std::shared_ptr<detail::GateState> state_;
};

}  // namespace rateguard::supervisor
