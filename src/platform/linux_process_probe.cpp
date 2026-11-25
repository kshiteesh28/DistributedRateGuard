#include "platform/linux_process_probe.h"

#include "platform/linux_proc_stat_parser.h"
#include "platform/linux_pidfd_helper.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <climits>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace rateguard::platform {
namespace {

LinuxProcessProbeFailure Failure(LinuxProcessReason reason) noexcept {
  return LinuxProcessProbeFailure{reason};
}

#if defined(__linux__)

constexpr std::size_t kBootIdMaxBytes = 64;
constexpr std::uint64_t kProbeMaxDurationNs = 30'000'000'000ULL;
constexpr std::int32_t kClockMonotonicId = 1;

LinuxProcessObservation Unknown(LinuxProcessReason reason,
                                std::uint64_t start = 0,
                                char state = 0,
                                std::optional<ClockIdentity> clock = std::nullopt,
                                std::optional<LinuxPidNamespaceIdentity> ns = std::nullopt) {
  return {LinuxProcessDisposition::Unknown, reason, start, state,
          std::move(clock), std::move(ns)};
}

bool IsAllZero(const std::array<std::uint8_t, 16>& bytes) noexcept {
  for (auto value : bytes) if (value != 0) return false;
  return true;
}

bool ValidRecorded(const RecordedLinuxProcess& r) noexcept {
  return r.host_pid > 0 && r.host_pid <= static_cast<std::uint64_t>(INT_MAX) &&
         r.pid_start_ticks != 0 && !IsAllZero(r.clock_identity.boot_uuid) &&
         r.clock_identity.namespace_device != 0 &&
         r.clock_identity.namespace_inode != 0 &&
         r.clock_identity.clock_id == kClockMonotonicId &&
         r.clock_identity.monotonic_offset_nanoseconds < 1'000'000'000U &&
         r.clock_identity.boottime_offset_nanoseconds < 1'000'000'000U;
}

bool ParseBootUuid(std::string_view text, std::array<std::uint8_t, 16>& out) noexcept {
  if (!text.empty() && text.back() == '\n') text.remove_suffix(1);
  if (text.size() != 36) return false;
  constexpr std::array<std::size_t, 4> hyphens{8, 13, 18, 23};
  for (auto position : hyphens) if (text[position] != '-') return false;
  std::size_t nibble = 0;
  std::uint8_t byte = 0;
  std::size_t out_index = 0;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '-') continue;
    const char c = text[i];
    std::uint8_t value;
    if (c >= '0' && c <= '9') value = static_cast<std::uint8_t>(c - '0');
    else if (c >= 'a' && c <= 'f') value = static_cast<std::uint8_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') value = static_cast<std::uint8_t>(c - 'A' + 10);
    else return false;
    if ((nibble & 1U) == 0) byte = static_cast<std::uint8_t>(value << 4U);
    else out[out_index++] = static_cast<std::uint8_t>(byte | value);
    ++nibble;
  }
  return out_index == out.size() && nibble == 32;
}

#ifndef NSFS_MAGIC
#define NSFS_MAGIC 0x6e736673
#endif

class Fd final {
 public:
  explicit Fd(int value = -1) noexcept : value_(value) {}
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : value_(other.release()) {}
  Fd& operator=(Fd&& other) noexcept {
    if (this != &other) { if (value_ >= 0) ::close(value_); value_ = other.release(); }
    return *this;
  }
  ~Fd() { if (value_ >= 0) ::close(value_); }
  int get() const noexcept { return value_; }
  int release() noexcept { const int out = value_; value_ = -1; return out; }
 private:
  int value_;
};

LinuxProcessReason ErrnoReason(int e) noexcept {
  if (e == EACCES || e == EPERM) return LinuxProcessReason::PermissionDenied;
  if (e == ENOMEM || e == EMFILE || e == ENFILE) return LinuxProcessReason::ResourceLimit;
  return LinuxProcessReason::ProcUnavailable;
}

bool IsProcFs(int fd) noexcept {
  struct statfs fs {};
  return ::fstatfs(fd, &fs) == 0 &&
         static_cast<unsigned long>(fs.f_type) ==
             static_cast<unsigned long>(PROC_SUPER_MAGIC);
}

bool IsNsFs(int fd) noexcept {
  struct statfs fs {};
  return ::fstatfs(fd, &fs) == 0 &&
         static_cast<unsigned long>(fs.f_type) ==
             static_cast<unsigned long>(NSFS_MAGIC);
}

bool IsProcRegularFile(int fd) noexcept {
  struct stat st {};
  return IsProcFs(fd) && ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
}

std::variant<Fd, LinuxProcessReason> OpenProcDirectory(int parent,
                                                        const char* name,
                                                        bool allow_kernel_link = false) {
  const int flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                    (allow_kernel_link ? 0 : O_NOFOLLOW);
  Fd fd(::openat(parent, name, flags));
  if (fd.get() < 0) return ErrnoReason(errno);
  if (!IsProcFs(fd.get())) return LinuxProcessReason::ProcUnavailable;
  return fd;
}

template <class Gate>
std::variant<std::string, LinuxProcessReason> ReadProcFileAt(
    int directory, const char* name, std::size_t maximum, Gate&& gate) {
  if (const auto why = gate()) return *why;
  Fd fd(::openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (fd.get() < 0) return ErrnoReason(errno);
  if (!IsProcRegularFile(fd.get())) return LinuxProcessReason::ProcUnavailable;
  std::string data;
  data.reserve(std::min<std::size_t>(maximum, 256));
  std::array<char, 256> buffer{};
  for (;;) {
    if (const auto why = gate()) return *why;
    const auto remaining_probe = maximum - std::min(maximum, data.size());
    const auto request = std::min(buffer.size(), remaining_probe + 1);
    const ssize_t n = ::read(fd.get(), buffer.data(), request);
    if (n < 0) {
      if (errno == EINTR) continue;
      return ErrnoReason(errno);
    }
    if (n == 0) return data;
    const auto amount = static_cast<std::size_t>(n);
    if (amount > maximum - data.size()) return LinuxProcessReason::ResourceLimit;
    data.append(buffer.data(), amount);
  }
}

std::variant<LinuxPidNamespaceIdentity, LinuxProcessReason>
NamespaceIdentityAt(int namespace_dir, const char* name) {
  Fd fd(::openat(namespace_dir, name, O_RDONLY | O_CLOEXEC)); // Fixed kernel ns magic-link only.
  if (fd.get() < 0) return ErrnoReason(errno);
  if (!IsNsFs(fd.get())) return LinuxProcessReason::ProcUnavailable;
  struct stat st {};
  if (::fstat(fd.get(), &st) != 0 || st.st_ino == 0)
    return LinuxProcessReason::ProcUnavailable;
  return LinuxPidNamespaceIdentity{static_cast<std::uint64_t>(st.st_dev),
                                    static_cast<std::uint64_t>(st.st_ino)};
}

struct ObserverEvidence {
  LinuxPidNamespaceIdentity pid_namespace;
};

struct ProbeAccess {
  std::uint64_t root_device{};
  std::uint64_t root_inode{};
  LinuxPidNamespaceIdentity expected_observer_namespace;
  IClock& clock;
};

class NativeRecordedProcessProbe final : public IRecordedProcessProbe {
 public:
  NativeRecordedProcessProbe(Fd proc_root_fd, ProbeAccess access) noexcept
      : proc_root_fd_(std::move(proc_root_fd)), access_(std::move(access)) {}

  LinuxProcessProbeResult Check(const RecordedLinuxProcess& recorded,
                                MonoNanos deadline,
                                const std::atomic_bool& cancel) noexcept override {
    try {
      if (!ValidRecorded(recorded)) return Unknown(LinuxProcessReason::InvalidRecordedIdentity);
      const auto initial = SafeSample(deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(initial))
        return Failure(std::get<LinuxProcessReason>(initial));
      const auto initial_ns = std::get<MonoNanos>(initial).value;
      if (deadline.value <= initial_ns || deadline.value - initial_ns > kProbeMaxDurationNs)
        return Failure(LinuxProcessReason::DeadlineExpired);
      struct stat root_stat{};
      if (!IsProcFs(proc_root_fd_.get()) || ::fstat(proc_root_fd_.get(), &root_stat) != 0 ||
          static_cast<std::uint64_t>(root_stat.st_dev) != access_.root_device ||
          static_cast<std::uint64_t>(root_stat.st_ino) != access_.root_inode)
        return Unknown(LinuxProcessReason::ProcUnavailable);

      const auto boot_before = ReadBoot(deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(boot_before))
        return GateOrUnknown(std::get<LinuxProcessReason>(boot_before));
      const auto boot = std::get<std::array<std::uint8_t, 16>>(boot_before);
      if (boot != recorded.clock_identity.boot_uuid)
        return Unknown(LinuxProcessReason::BootMismatch);

      const auto observer_before = ObserveCurrentPidNamespace(deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(observer_before))
        return GateOrUnknown(std::get<LinuxProcessReason>(observer_before));
      const auto observer = std::get<ObserverEvidence>(observer_before);
      if (!(observer.pid_namespace == access_.expected_observer_namespace))
        return Unknown(LinuxProcessReason::PidNamespaceMismatch, 0, 0, std::nullopt,
                       observer.pid_namespace);

      const auto current_clock = SafeClockIdentity();
      if (std::holds_alternative<LinuxProcessReason>(current_clock))
        return Unknown(std::get<LinuxProcessReason>(current_clock), 0, 0, std::nullopt,
                       observer.pid_namespace);
      const auto current_identity = std::get<ClockIdentity>(current_clock);
      if (current_identity.boot_uuid != recorded.clock_identity.boot_uuid)
        return Unknown(LinuxProcessReason::BootMismatch, 0, 0, current_identity,
                       observer.pid_namespace);
      if (!(current_identity == recorded.clock_identity))
        return Unknown(LinuxProcessReason::ClockIdentityMismatch, 0, 0,
                       current_identity, observer.pid_namespace);

      std::array<char, 32> pid_text{};
      const auto [end, ec] = std::to_chars(pid_text.data(), pid_text.data() + pid_text.size(),
                                           recorded.host_pid);
      if (ec != std::errc{}) return Unknown(LinuxProcessReason::InvalidRecordedIdentity);
      const std::string_view pid_name(pid_text.data(), static_cast<std::size_t>(end - pid_text.data()));
      std::string pid_component(pid_name);
      if (const auto gate = SafeNow(deadline, cancel); gate != LinuxProcessReason::None)
        return Failure(gate);
      Fd process_fd(::openat(proc_root_fd_.get(), pid_component.c_str(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
      if (process_fd.get() < 0) {
        if (errno == ENOENT)
          return ConfirmAbsent(recorded, boot, observer.pid_namespace, deadline, cancel);
        return Unknown(ErrnoReason(errno), 0, 0, std::nullopt, observer.pid_namespace);
      }
      if (!IsProcFs(process_fd.get()))
        return Unknown(LinuxProcessReason::ProcUnavailable, 0, 0, std::nullopt,
                       observer.pid_namespace);

      const auto first_stat = ReadProcStat(process_fd.get(), deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(first_stat))
        return GateOrUnknown(std::get<LinuxProcessReason>(first_stat), 0, 0,
                             std::nullopt, observer.pid_namespace);
      auto stat = std::get<detail::ParsedProcStat>(first_stat);
      if (stat.pid != recorded.host_pid)
        return Unknown(LinuxProcessReason::PidNamespaceMismatch, stat.start_ticks,
                       stat.state, std::nullopt, observer.pid_namespace);
      if (stat.start_ticks != recorded.pid_start_ticks)
        return Unknown(LinuxProcessReason::PidReused, stat.start_ticks, stat.state,
                       std::nullopt, observer.pid_namespace);

      const auto process_ns = OpenProcDirectory(process_fd.get(), "ns");
      if (std::holds_alternative<LinuxProcessReason>(process_ns))
        return GateOrUnknown(std::get<LinuxProcessReason>(process_ns), stat.start_ticks,
                             stat.state, std::nullopt, observer.pid_namespace);
      const auto target_time_ns = NamespaceIdentityAt(
          std::get<Fd>(process_ns).get(), "time");
      if (std::holds_alternative<LinuxProcessReason>(target_time_ns))
        return GateOrUnknown(std::get<LinuxProcessReason>(target_time_ns), stat.start_ticks,
                             stat.state, std::nullopt, observer.pid_namespace);
      const auto time_ns = std::get<LinuxPidNamespaceIdentity>(target_time_ns);
      if (time_ns.device != recorded.clock_identity.namespace_device ||
          time_ns.inode != recorded.clock_identity.namespace_inode) {
        return Unknown(LinuxProcessReason::TimeNamespaceMismatch, stat.start_ticks,
                       stat.state, std::nullopt, observer.pid_namespace);
      }

      const auto second_stat = ReadProcStat(process_fd.get(), deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(second_stat))
        return GateOrUnknown(std::get<LinuxProcessReason>(second_stat), stat.start_ticks,
                             stat.state, std::nullopt, observer.pid_namespace);
      stat = std::get<detail::ParsedProcStat>(second_stat);
      if (stat.pid != recorded.host_pid)
        return Unknown(LinuxProcessReason::PidNamespaceMismatch, stat.start_ticks,
                       stat.state, std::nullopt, observer.pid_namespace);
      if (stat.start_ticks != recorded.pid_start_ticks)
        return Unknown(LinuxProcessReason::PidReused, stat.start_ticks, stat.state,
                       std::nullopt, observer.pid_namespace);

      const auto boot_after = ReadBoot(deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(boot_after))
        return GateOrUnknown(std::get<LinuxProcessReason>(boot_after), stat.start_ticks,
                             stat.state, std::nullopt, observer.pid_namespace);
      if (std::get<std::array<std::uint8_t, 16>>(boot_after) != boot)
        return Unknown(LinuxProcessReason::BootMismatch, stat.start_ticks, stat.state,
                       std::nullopt, observer.pid_namespace);
      const auto observer_after = ObserveCurrentPidNamespace(deadline, cancel);
      if (std::holds_alternative<LinuxProcessReason>(observer_after))
        return GateOrUnknown(std::get<LinuxProcessReason>(observer_after), stat.start_ticks,
                             stat.state, std::nullopt, observer.pid_namespace);
      const auto observer_final = std::get<ObserverEvidence>(observer_after).pid_namespace;
      if (!(observer_final == observer.pid_namespace) ||
          !(observer_final == access_.expected_observer_namespace))
        return Unknown(LinuxProcessReason::PidNamespaceMismatch, stat.start_ticks,
                       stat.state, std::nullopt, observer_final);
      const auto clock_after = SafeClockIdentity();
      if (std::holds_alternative<LinuxProcessReason>(clock_after))
        return Unknown(std::get<LinuxProcessReason>(clock_after), stat.start_ticks,
                       stat.state, std::nullopt, observer_final);
      const auto final_identity = std::get<ClockIdentity>(clock_after);
      if (!(final_identity == recorded.clock_identity))
        return Unknown(final_identity.boot_uuid != recorded.clock_identity.boot_uuid
                           ? LinuxProcessReason::BootMismatch
                           : LinuxProcessReason::ClockIdentityMismatch,
                       stat.start_ticks, stat.state, final_identity, observer_final);

      const auto final_gate = SafeNow(deadline, cancel);
      if (final_gate != LinuxProcessReason::None)
        return GateOrUnknown(final_gate, stat.start_ticks, stat.state, final_identity,
                             observer_final);
      const auto disposition = stat.state == 'Z' ? LinuxProcessDisposition::MatchedZombie
                                                  : LinuxProcessDisposition::LiveIdentityMatched;
      return LinuxProcessObservation{disposition, LinuxProcessReason::None,
                                     stat.start_ticks, stat.state, final_identity,
                                     observer_final};
    } catch (const std::bad_alloc&) {
      return Failure(LinuxProcessReason::AllocationFailure);
    } catch (...) {
      return Unknown(LinuxProcessReason::ProcUnavailable);
    }
  }

 private:
  LinuxProcessProbeResult GateOrUnknown(LinuxProcessReason reason,
      std::uint64_t start = 0, char state = 0,
      std::optional<ClockIdentity> clock = std::nullopt,
      std::optional<LinuxPidNamespaceIdentity> ns = std::nullopt) const noexcept {
    if (reason == LinuxProcessReason::Cancelled ||
        reason == LinuxProcessReason::DeadlineExpired)
      return Failure(reason);
    return Unknown(reason, start, state, std::move(clock), std::move(ns));
  }

  std::variant<MonoNanos, LinuxProcessReason> SafeSample(
      MonoNanos deadline, const std::atomic_bool& cancel) noexcept {
    try {
      if (cancel.load(std::memory_order_relaxed)) return LinuxProcessReason::Cancelled;
      if (!access_.clock.Healthy()) return LinuxProcessReason::ProcUnavailable;
      const auto sample = access_.clock.Now();
      if (!std::holds_alternative<MonoNanos>(sample) || !access_.clock.Healthy())
        return LinuxProcessReason::ProcUnavailable;
      const auto now = std::get<MonoNanos>(sample);
      if (now.value >= deadline.value) return LinuxProcessReason::DeadlineExpired;
      return now;
    } catch (...) {
      return LinuxProcessReason::ProcUnavailable;
    }
  }

  LinuxProcessReason SafeNow(MonoNanos deadline,
                             const std::atomic_bool& cancel) noexcept {
    const auto sample = SafeSample(deadline, cancel);
    if (std::holds_alternative<LinuxProcessReason>(sample))
      return std::get<LinuxProcessReason>(sample);
    return LinuxProcessReason::None;
  }

  std::variant<ClockIdentity, LinuxProcessReason> SafeClockIdentity() noexcept {
    try {
      if (!access_.clock.Healthy()) return LinuxProcessReason::ProcUnavailable;
      const auto identity = access_.clock.Provenance();
      if (!std::holds_alternative<ClockIdentity>(identity) || !access_.clock.Healthy())
        return LinuxProcessReason::ProcUnavailable;
      return std::get<ClockIdentity>(identity);
    } catch (...) {
      return LinuxProcessReason::ProcUnavailable;
    }
  }

  template <class Gate>
  std::variant<std::array<std::uint8_t, 16>, LinuxProcessReason> ReadBoot(
      MonoNanos deadline, const std::atomic_bool& cancel, Gate&& gate) {
    auto sys = OpenProcDirectory(proc_root_fd_.get(), "sys");
    if (std::holds_alternative<LinuxProcessReason>(sys)) return std::get<LinuxProcessReason>(sys);
    auto kernel = OpenProcDirectory(std::get<Fd>(sys).get(), "kernel");
    if (std::holds_alternative<LinuxProcessReason>(kernel)) return std::get<LinuxProcessReason>(kernel);
    auto random = OpenProcDirectory(std::get<Fd>(kernel).get(), "random");
    if (std::holds_alternative<LinuxProcessReason>(random)) return std::get<LinuxProcessReason>(random);
    auto text = ReadProcFileAt(std::get<Fd>(random).get(), "boot_id", kBootIdMaxBytes,
                               std::forward<Gate>(gate));
    if (std::holds_alternative<LinuxProcessReason>(text)) return std::get<LinuxProcessReason>(text);
    std::array<std::uint8_t, 16> result{};
    if (!ParseBootUuid(std::get<std::string>(text), result))
      return LinuxProcessReason::ProcUnavailable;
    (void)deadline;
    (void)cancel;
    return result;
  }

  std::variant<std::array<std::uint8_t, 16>, LinuxProcessReason> ReadBoot(
      MonoNanos deadline, const std::atomic_bool& cancel) {
    auto gate = [&]() -> std::optional<LinuxProcessReason> {
      const auto reason = SafeNow(deadline, cancel);
      if (reason == LinuxProcessReason::None) return std::nullopt;
      return reason;
    };
    return ReadBoot(deadline, cancel, gate);
  }

  std::variant<ObserverEvidence, LinuxProcessReason> ObserveCurrentPidNamespace(
      MonoNanos deadline, const std::atomic_bool& cancel) {
    auto self = OpenProcDirectory(proc_root_fd_.get(), "self", true);
    if (std::holds_alternative<LinuxProcessReason>(self)) return std::get<LinuxProcessReason>(self);
    auto gate = [&]() -> std::optional<LinuxProcessReason> {
      const auto reason = SafeNow(deadline, cancel);
      if (reason == LinuxProcessReason::None) return std::nullopt;
      return reason;
    };
    auto stat_text = ReadProcFileAt(std::get<Fd>(self).get(), "stat",
                                    detail::kLinuxProcStatMaxBytes, gate);
    if (std::holds_alternative<LinuxProcessReason>(stat_text)) return std::get<LinuxProcessReason>(stat_text);
    const auto parsed = detail::ParseLinuxProcStat(std::get<std::string>(stat_text));
    if (!std::holds_alternative<detail::ParsedProcStat>(parsed))
      return LinuxProcessReason::MalformedStat;
    if (std::get<detail::ParsedProcStat>(parsed).pid != static_cast<std::uint64_t>(::getpid()))
      return LinuxProcessReason::PidNamespaceMismatch;
    auto ns_dir = OpenProcDirectory(std::get<Fd>(self).get(), "ns");
    if (std::holds_alternative<LinuxProcessReason>(ns_dir)) return std::get<LinuxProcessReason>(ns_dir);
    const auto ns_identity = NamespaceIdentityAt(std::get<Fd>(ns_dir).get(), "pid");
    if (std::holds_alternative<LinuxProcessReason>(ns_identity)) return std::get<LinuxProcessReason>(ns_identity);
    return ObserverEvidence{std::get<LinuxPidNamespaceIdentity>(ns_identity)};
  }

  std::variant<detail::ParsedProcStat, LinuxProcessReason> ReadProcStat(
      int process_fd, MonoNanos deadline, const std::atomic_bool& cancel) {
    auto gate = [&]() -> std::optional<LinuxProcessReason> {
      const auto reason = SafeNow(deadline, cancel);
      if (reason == LinuxProcessReason::None) return std::nullopt;
      return reason;
    };
    auto text = ReadProcFileAt(process_fd, "stat", detail::kLinuxProcStatMaxBytes, gate);
    if (std::holds_alternative<LinuxProcessReason>(text)) return std::get<LinuxProcessReason>(text);
    const auto parsed = detail::ParseLinuxProcStat(std::get<std::string>(text));
    if (std::holds_alternative<detail::ProcStatParseError>(parsed)) {
      return std::get<detail::ProcStatParseError>(parsed) == detail::ProcStatParseError::TooLarge
                 ? LinuxProcessReason::ResourceLimit
                 : LinuxProcessReason::MalformedStat;
    }
    return std::get<detail::ParsedProcStat>(parsed);
  }

  LinuxProcessProbeResult ConfirmAbsent(const RecordedLinuxProcess& recorded,
      const std::array<std::uint8_t, 16>& boot_before,
      const LinuxPidNamespaceIdentity& observer_before,
      MonoNanos deadline, const std::atomic_bool& cancel) {
    // hidepid can make a live PID directory appear absent. Only ESRCH from
    // pidfd_open corroborates that no process currently owns this PID; a
    // returned pidfd or any other error is conservatively Unknown. This never
    // polls, signals, waits for, or adopts the process.
    for (;;) {
      const auto gate = SafeNow(deadline, cancel);
      if (gate != LinuxProcessReason::None)
        return GateOrUnknown(gate, 0, 0, std::nullopt, observer_before);
#if defined(SYS_pidfd_open)
      errno = 0;
      const long pidfd_raw = ::syscall(SYS_pidfd_open,
          static_cast<pid_t>(recorded.host_pid), 0U);
      const int pidfd_error = errno;
      const auto attempt = detail::ClassifyPidfdOpen(
          pidfd_raw, pidfd_error, [](int fd) noexcept { (void)::close(fd); });
      if (attempt.kind == detail::PidfdAttemptKind::Interrupted) continue;
      if (attempt.kind == detail::PidfdAttemptKind::ProcessExists)
        return Unknown(attempt.reason, 0, 0, std::nullopt, observer_before);
      if (attempt.kind == detail::PidfdAttemptKind::Failed)
        return Unknown(attempt.reason, 0, 0, std::nullopt, observer_before);
      break;
#else
      return Unknown(LinuxProcessReason::ProcUnavailable, 0, 0, std::nullopt,
                     observer_before);
#endif
    }

    const auto boot_after = ReadBoot(deadline, cancel);
    if (std::holds_alternative<LinuxProcessReason>(boot_after))
      return GateOrUnknown(std::get<LinuxProcessReason>(boot_after), 0, 0,
                           std::nullopt, observer_before);
    if (std::get<std::array<std::uint8_t, 16>>(boot_after) != boot_before ||
        boot_before != recorded.clock_identity.boot_uuid)
      return Unknown(LinuxProcessReason::BootMismatch, 0, 0, std::nullopt,
                     observer_before);
    const auto observer_after = ObserveCurrentPidNamespace(deadline, cancel);
    if (std::holds_alternative<LinuxProcessReason>(observer_after))
      return GateOrUnknown(std::get<LinuxProcessReason>(observer_after), 0, 0,
                           std::nullopt, observer_before);
    const auto observer = std::get<ObserverEvidence>(observer_after).pid_namespace;
    if (!(observer == observer_before) || !(observer == access_.expected_observer_namespace))
      return Unknown(LinuxProcessReason::PidNamespaceMismatch, 0, 0,
                     std::nullopt, observer);
    const auto current = SafeClockIdentity();
    if (std::holds_alternative<LinuxProcessReason>(current))
      return Unknown(std::get<LinuxProcessReason>(current), 0, 0, std::nullopt,
                     observer);
    const auto clock = std::get<ClockIdentity>(current);
    if (!(clock == recorded.clock_identity))
      return Unknown(clock.boot_uuid != recorded.clock_identity.boot_uuid
                         ? LinuxProcessReason::BootMismatch
                         : LinuxProcessReason::ClockIdentityMismatch,
                     0, 0, std::nullopt, observer);
    const auto final_gate = SafeNow(deadline, cancel);
    if (final_gate != LinuxProcessReason::None)
      return GateOrUnknown(final_gate, 0, 0, std::nullopt, observer);
    // Do not fill observed_clock_identity: the absent target's time namespace
    // can no longer be read and this result is not fresh target provenance.
    return LinuxProcessObservation{LinuxProcessDisposition::RecordedProcessAbsent,
                                   LinuxProcessReason::None, 0, 0, std::nullopt,
                                   observer};
  }

  Fd proc_root_fd_;
  ProbeAccess access_;
};

std::variant<ObserverEvidence, LinuxProcessReason> InitialObserverEvidence(int proc_fd) {
  auto self = OpenProcDirectory(proc_fd, "self", true);
  if (std::holds_alternative<LinuxProcessReason>(self)) return std::get<LinuxProcessReason>(self);
  auto stat_fd = Fd(::openat(std::get<Fd>(self).get(), "stat",
                             O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (stat_fd.get() < 0) return ErrnoReason(errno);
  if (!IsProcRegularFile(stat_fd.get())) return LinuxProcessReason::ProcUnavailable;
  std::array<char, detail::kLinuxProcStatMaxBytes + 1> buffer{};
  std::size_t used = 0;
  for (;;) {
    const auto n = ::read(stat_fd.get(), buffer.data() + used, buffer.size() - used);
    if (n < 0) { if (errno == EINTR) continue; return ErrnoReason(errno); }
    if (n == 0) break;
    used += static_cast<std::size_t>(n);
    if (used > detail::kLinuxProcStatMaxBytes)
      return LinuxProcessReason::ResourceLimit;
  }
  const auto parsed = detail::ParseLinuxProcStat(std::string_view(buffer.data(), used));
  if (!std::holds_alternative<detail::ParsedProcStat>(parsed)) return LinuxProcessReason::MalformedStat;
  if (std::get<detail::ParsedProcStat>(parsed).pid != static_cast<std::uint64_t>(::getpid()))
    return LinuxProcessReason::PidNamespaceMismatch;
  auto ns_dir = OpenProcDirectory(std::get<Fd>(self).get(), "ns");
  if (std::holds_alternative<LinuxProcessReason>(ns_dir)) return std::get<LinuxProcessReason>(ns_dir);
  const auto ns_identity = NamespaceIdentityAt(std::get<Fd>(ns_dir).get(), "pid");
  if (std::holds_alternative<LinuxProcessReason>(ns_identity)) return std::get<LinuxProcessReason>(ns_identity);
  return ObserverEvidence{std::get<LinuxPidNamespaceIdentity>(ns_identity)};
}

#endif  // __linux__
}  // namespace

LinuxProcessProbeCreateResult CreateLinuxRecordedProcessProbe(
    const LinuxProcessProbeConfig& config, IClock& clock) noexcept {
#if defined(__linux__)
  try {
    if (config.proc_root.empty() || config.proc_root.size() > 4'096 ||
        config.proc_root.find('\0') != std::string::npos ||
        config.expected_observer_pid_namespace.device == 0 ||
        config.expected_observer_pid_namespace.inode == 0)
      return Failure(LinuxProcessReason::InvalidRecordedIdentity);
    char* root_raw = ::realpath(config.proc_root.c_str(), nullptr);
    if (root_raw == nullptr) return Failure(ErrnoReason(errno));
    std::unique_ptr<char, decltype(&std::free)> root_owner(root_raw, &std::free);
    Fd root_fd(::open(root_owner.get(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root_fd.get() < 0) return Failure(ErrnoReason(errno));
    if (!IsProcFs(root_fd.get())) return Failure(LinuxProcessReason::ProcUnavailable);
    struct stat root_stat{};
    if (::fstat(root_fd.get(), &root_stat) != 0) return Failure(LinuxProcessReason::ProcUnavailable);
    const auto observer = InitialObserverEvidence(root_fd.get());
    if (std::holds_alternative<LinuxProcessReason>(observer))
      return Failure(std::get<LinuxProcessReason>(observer));
    if (!(std::get<ObserverEvidence>(observer).pid_namespace ==
          config.expected_observer_pid_namespace))
      return Failure(LinuxProcessReason::PidNamespaceMismatch);
    try {
      if (!clock.Healthy()) return Failure(LinuxProcessReason::ProcUnavailable);
      const auto identity = clock.Provenance();
      if (!std::holds_alternative<ClockIdentity>(identity) || !clock.Healthy())
        return Failure(LinuxProcessReason::ProcUnavailable);
      const auto& id = std::get<ClockIdentity>(identity);
      if (id.clock_id != kClockMonotonicId || IsAllZero(id.boot_uuid) ||
          id.namespace_device == 0 || id.namespace_inode == 0 ||
          id.monotonic_offset_nanoseconds >= 1'000'000'000U ||
          id.boottime_offset_nanoseconds >= 1'000'000'000U)
        return Failure(LinuxProcessReason::ClockIdentityMismatch);
    } catch (...) {
      return Failure(LinuxProcessReason::ProcUnavailable);
    }
    ProbeAccess access{static_cast<std::uint64_t>(root_stat.st_dev),
                       static_cast<std::uint64_t>(root_stat.st_ino),
                       config.expected_observer_pid_namespace, clock};
    auto probe = std::make_unique<NativeRecordedProcessProbe>(std::move(root_fd),
                                                              std::move(access));
    return std::unique_ptr<IRecordedProcessProbe>(std::move(probe));
  } catch (const std::bad_alloc&) {
    return Failure(LinuxProcessReason::AllocationFailure);
  } catch (...) {
    return Failure(LinuxProcessReason::ProcUnavailable);
  }
#else
  (void)config;
  (void)clock;
  return Failure(LinuxProcessReason::UnsupportedPlatform);
#endif
}

}  // namespace rateguard::platform
