#pragma once

// Bounded Docker Engine inspection/stop boundary. This is an observation and
// stop-request component only; it does not create/start containers, activate
// participants, close an epoch, or authorize a successor.

#include "platform/clock.h"
#include "platform/linux_process_probe.h"
#include "supervisor/epoch_gate.h"
#include "supervisor/runtime_owner.h"
#include "supervisor/unix_http_transport.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>

namespace rateguard::supervisor {

inline constexpr std::uint64_t kDockerInspectDefaultTimeoutNanos = 5'000'000'000ULL;
inline constexpr std::uint64_t kDockerStopDefaultTimeoutNanos = 15'000'000'000ULL;
inline constexpr std::uint64_t kDockerMaxOperationTimeoutNanos = 30'000'000'000ULL;
inline constexpr std::uint32_t kDockerStopGraceSeconds = 1;
inline constexpr std::size_t kDockerMaxInspectBodyBytes = kUnixHttpMaxDecodedBodyBytes;
inline constexpr std::size_t kDockerMaxJsonDepth = 16;
inline constexpr std::size_t kDockerMaxJsonFields = 256;
inline constexpr std::size_t kDockerMaxJsonNodes = 4'096;
inline constexpr std::size_t kDockerMaxJsonStringBytes = 16'384;

struct DockerTargetBinding final {
  RuntimeDomainId domain_id{};
  EpochId epoch_id{};
  IncarnationId authority_incarnation{};
  PolicyDigest policy_digest{};
  ParticipantRole role{};
  std::uint32_t slot_id{};
  std::string participant_id;
  IncarnationId incarnation{};
  // Exact canonical full 64-character lowercase container ID; never a name
  // or ID prefix.
  std::string container_id;
};

struct PendingContainerTarget final {
  DockerTargetBinding binding;
};

struct ObservedContainerTarget final {
  DockerTargetBinding binding;
  std::uint64_t host_pid{};
  std::uint64_t pid_start_ticks{};
  platform::ClockIdentity clock_identity{};
};

using RecoveryContainerTarget =
    std::variant<PendingContainerTarget, ObservedContainerTarget>;

// Bounded structural validation only. It does not authenticate or authorize a
// target; each Docker response must independently match its exact ID/labels.
[[nodiscard]] bool ValidateRecoveryContainerTarget(
    const RecoveryContainerTarget& target) noexcept;

struct ControllerDeadline final {
  // Absolute CLOCK_MONOTONIC nanoseconds from the injected platform::IClock.
  platform::MonoNanos at{};
};

enum class DockerControllerErrorCode : std::uint8_t {
  InvalidTarget,
  InvalidOperationId,
  InvalidDeadline,
  Cancelled,
  UnsupportedPlatform,
  ClockUnavailable,
  TransportUnavailable,
  TimedOut,
  HttpProtocolError,
  ResponseTooLarge,
  InvalidJson,
  IdentityMismatch,
  EngineVersionMismatch,
  AllocationFailure,
};

using DockerDeadlineResult =
    std::variant<ControllerDeadline, DockerControllerErrorCode>;
[[nodiscard]] DockerDeadlineResult MakeDockerDeadline(
    platform::IClock& clock, std::uint64_t timeout_nanos) noexcept;
[[nodiscard]] DockerDeadlineResult MakeDefaultInspectDeadline(
    platform::IClock& clock) noexcept;
[[nodiscard]] DockerDeadlineResult MakeDefaultStopDeadline(
    platform::IClock& clock) noexcept;

struct DockerControllerFailure final {
  DockerControllerErrorCode code{DockerControllerErrorCode::TransportUnavailable};
  // For RequestStop, true means a stop request byte may have reached the
  // daemon; callers must Inspect/reconcile before retrying. False is reserved
  // for failures known to occur before any stop-request byte was sent.
  bool stop_request_possibly_sent{};
};

enum class DockerContainerState : std::uint8_t {
  Created,
  Running,
  Paused,
  Restarting,
  Removing,
  Exited,
  Dead,
  Unknown,
};

enum class DockerObservationDisposition : std::uint8_t {
  MatchedRunning,
  MatchedExited,
  Unknown,
};

enum class DockerObservationReason : std::uint8_t {
  None,
  NotFound,
  TransportFailure,
  Timeout,
  MalformedResponse,
  MissingIdentity,
  LabelMismatch,
  ContainerNotTerminal,
  RestartPolicyUnexpected,
  ProcessStillPresent,
  ProcessIdentityMismatch,
  ProcessAbsenceUnverified,
  HostBootMismatch,
  PidNamespaceMismatch,
  TimeNamespaceMismatch,
};

enum class DockerExitEvidenceScope : std::uint8_t {
  None,
  RuntimeOnlyPendingTarget,
  RuntimeAndRecordedProcessAbsent,
};

struct DockerContainerObservation final {
  DockerObservationDisposition disposition{DockerObservationDisposition::Unknown};
  DockerObservationReason reason{DockerObservationReason::MalformedResponse};
  std::string exact_container_id;
  DockerContainerState state{DockerContainerState::Unknown};
  bool labels_match{};
  bool restart_policy_disabled{};
  bool running{};
  bool restarting{};
  std::uint64_t engine_pid{};
  DockerExitEvidenceScope exit_evidence_scope{DockerExitEvidenceScope::None};
  std::optional<platform::LinuxProcessObservation> process_evidence;
};

struct DockerStopAcknowledgement final {
  OperationId operation_id{};
  enum class Kind : std::uint8_t { Accepted, AlreadyStopped } kind{Kind::Accepted};
};

using DockerInspectResult =
    std::variant<DockerContainerObservation, DockerControllerFailure>;
using DockerStopResult =
    std::variant<DockerStopAcknowledgement, DockerControllerFailure>;

class IRecoveryProcessController {
 public:
  virtual ~IRecoveryProcessController() = default;

  // Inspect calls are bounded by an explicit future deadline (maximum 30s).
  // NotFound and every incomplete/mismatched observation return Unknown;
  // absence is never treated as exit. A MatchedExited result is a point-in-time
  // observation, not a fence against later external restart.
  // MatchedExited requires exact CID/labels, RestartPolicy=no, state=exited,
  // PID=0, Running=false and Restarting=false. An observed target additionally
  // requires probe RecordedProcessAbsent. MatchedZombie, any probe failure or
  // Unknown cannot satisfy that rule. A pending target has runtime-only scope.
  [[nodiscard]] virtual DockerInspectResult Inspect(
      const RecoveryContainerTarget& target, ControllerDeadline deadline,
      const std::atomic_bool& cancel_requested) noexcept = 0;

  // Before POST, inspect the exact ID and all eight immutable labels. If those
  // logical bindings match, a stop may still be requested despite bad OS PID
  // evidence or a restart-policy mismatch; those conditions prevent positive
  // exit classification but must not prevent draining the known container.
  // Uses SIGTERM with a fixed one-second grace. ACK is never exit evidence.
  // Every failure after request dispatch must preserve uncertainty for caller.
  [[nodiscard]] virtual DockerStopResult RequestStop(
      const RecoveryContainerTarget& target, const OperationId& operation_id,
      ControllerDeadline deadline,
      const std::atomic_bool& cancel_requested) noexcept = 0;
};

struct DockerProcessControllerConfig final {
  std::string unix_socket_path;
  // Explicitly selected from observed/qualified Engine API compatibility; no
  // numeric default is guessed. Factory validates the selected numeric version
  // within /version MinAPIVersion..ApiVersion (inclusive), under one fixed
  // five-second monotonic startup budget. No transparent version negotiation.
  std::string engine_api_version;
  platform::LinuxProcessProbeConfig process_probe;
};

using DockerProcessControllerCreateResult =
    std::variant<std::unique_ptr<IRecoveryProcessController>, DockerControllerFailure>;

// Dependency-injection factory for component tests. Production callers use
// CreateLinuxDockerProcessController so rootful socket UID and native procfs
// evidence cannot be silently omitted.
[[nodiscard]] DockerProcessControllerCreateResult CreateDockerProcessController(
    const DockerProcessControllerConfig& config, platform::IClock& clock,
    std::unique_ptr<IUnixHttpTransport> transport,
    std::unique_ptr<platform::IRecordedProcessProbe> process_probe) noexcept;

// Linux production factory: constructs transport with socket owner/peer UID 0,
// creates the native read-only proc probe, and requires an explicit API version.
// Host PID namespace placement and local rootful-daemon use remain qualified
// deployment preconditions; this factory does not prove either is host-global.
[[nodiscard]] DockerProcessControllerCreateResult CreateLinuxDockerProcessController(
    const DockerProcessControllerConfig& config, platform::IClock& clock) noexcept;

}  // namespace rateguard::supervisor
