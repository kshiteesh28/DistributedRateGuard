#pragma once

#include "platform/linux_process_probe.h"

#include <cerrno>
#include <cstdint>
#include <utility>

namespace rateguard::platform::detail {

enum class PidfdAttemptKind : std::uint8_t {
  ProcessAbsent,
  ProcessExists,
  Interrupted,
  Failed,
};

struct PidfdAttempt final {
  PidfdAttemptKind kind{PidfdAttemptKind::Failed};
  LinuxProcessReason reason{LinuxProcessReason::ProcUnavailable};
};

// Classifies one pidfd_open result. A returned descriptor is immediately
// closed; it proves only that some process currently owns this PID, not that
// it matches a recorded start time. `close_fd` is injectable only for tests.
template <class CloseFd>
PidfdAttempt ClassifyPidfdOpen(long result, int error, CloseFd&& close_fd) noexcept {
  if (result >= 0) {
    try { std::forward<CloseFd>(close_fd)(static_cast<int>(result)); }
    catch (...) { return {PidfdAttemptKind::Failed, LinuxProcessReason::ProcUnavailable}; }
    return {PidfdAttemptKind::ProcessExists, LinuxProcessReason::ProcUnavailable};
  }
  if (error == ESRCH) return {PidfdAttemptKind::ProcessAbsent, LinuxProcessReason::None};
  if (error == EINTR) return {PidfdAttemptKind::Interrupted, LinuxProcessReason::ProcUnavailable};
  if (error == EACCES || error == EPERM)
    return {PidfdAttemptKind::Failed, LinuxProcessReason::PermissionDenied};
  if (error == ENOMEM || error == EMFILE || error == ENFILE)
    return {PidfdAttemptKind::Failed, LinuxProcessReason::ResourceLimit};
  return {PidfdAttemptKind::Failed, LinuxProcessReason::ProcUnavailable};
}

}  // namespace rateguard::platform::detail
