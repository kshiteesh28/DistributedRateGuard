#pragma once

// Linux-only read-side evidence for a Docker-reported host PID. Results are
// point-in-time observations, never process-control or epoch-fencing tokens.

#include "platform/clock.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>

namespace rateguard::platform {

struct LinuxPidNamespaceIdentity final {
  std::uint64_t device{};
  std::uint64_t inode{};
  friend bool operator==(const LinuxPidNamespaceIdentity&,
                         const LinuxPidNamespaceIdentity&) = default;
};

// The expected observer PID namespace is supplied by trusted deployment
// qualification. The probe verifies its /proc lookup context against this
// value; it does not require a container task to be in the same PID namespace,
// and cannot itself prove that the observer namespace is the initial host one.
struct LinuxProcessProbeConfig final {
  LinuxPidNamespaceIdentity expected_observer_pid_namespace{};
  // Non-/proc roots are for internal fixtures only. Production factory fixes
  // this to /proc; an alternate path never qualifies a host placement.
  std::string proc_root{ "/proc" };
};

struct RecordedLinuxProcess final {
  std::uint64_t host_pid{};
  std::uint64_t pid_start_ticks{};
  ClockIdentity clock_identity{};
};

enum class LinuxProcessDisposition : std::uint8_t {
  LiveIdentityMatched,
  RecordedProcessAbsent,
  MatchedZombie,
  Unknown,
};

enum class LinuxProcessReason : std::uint8_t {
  None,
  InvalidRecordedIdentity,
  UnsupportedPlatform,
  DeadlineExpired,
  Cancelled,
  ProcUnavailable,
  PermissionDenied,
  MalformedStat,
  PidReused,
  BootMismatch,
  PidNamespaceMismatch,
  TimeNamespaceMismatch,
  ClockIdentityMismatch,
  ResourceLimit,
  AllocationFailure,
};

struct LinuxProcessObservation final {
  LinuxProcessDisposition disposition{LinuxProcessDisposition::Unknown};
  LinuxProcessReason reason{LinuxProcessReason::ProcUnavailable};
  std::uint64_t observed_pid_start_ticks{};
  char observed_state{};
  std::optional<ClockIdentity> observed_clock_identity;
  std::optional<LinuxPidNamespaceIdentity> observer_pid_namespace;
};

struct LinuxProcessProbeFailure final {
  LinuxProcessReason reason{LinuxProcessReason::ProcUnavailable};
};

using LinuxProcessProbeResult =
    std::variant<LinuxProcessObservation, LinuxProcessProbeFailure>;

class IRecordedProcessProbe {
 public:
  virtual ~IRecordedProcessProbe() = default;
  [[nodiscard]] virtual LinuxProcessProbeResult Check(
      const RecordedLinuxProcess& recorded, MonoNanos absolute_deadline,
      const std::atomic_bool& cancel_requested) noexcept = 0;
};

using LinuxProcessProbeCreateResult =
    std::variant<std::unique_ptr<IRecordedProcessProbe>, LinuxProcessProbeFailure>;

// Native implementation opens bounded records beneath a validated procfs
// mount without following arbitrary filesystem links. It permits only the
// kernel-controlled observer ns/pid and target ns/time magic links after validating procfs
// and the PID directory. It checks observer PID namespace, boot ID, recorded
// PID start time and target time-namespace provenance, parses stat field 22
// after the final ')' in comm, and treats permission/parse errors as Unknown.
// When the recorded PID directory is ENOENT, pidfd_open must also return ESRCH.
// A returned descriptor is closed and leaves absence uncorroborated; any other
// error is Unknown. Only that corroborated absence can be reported
// after same-boot and expected observer/proc PID-namespace checks before and
// after the lookup. A dead target's time namespace cannot be reread; do not
// present absence as a fresh target time-namespace observation. Other lookup
// errors and PID reuse remain Unknown. MatchedZombie is diagnostic only.
// It never signals, waits for, or adopts a process.
[[nodiscard]] LinuxProcessProbeCreateResult CreateLinuxRecordedProcessProbe(
    const LinuxProcessProbeConfig& config, IClock& clock) noexcept;

}  // namespace rateguard::platform
