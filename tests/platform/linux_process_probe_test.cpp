#include "platform/linux_process_probe.h"
#include "platform/linux_proc_stat_parser.h"
#include "platform/linux_pidfd_helper.h"

#include <array>
#include <cerrno>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <stdexcept>
#include <variant>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

namespace {
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr "\n"; ++failures; } } while (false)

std::string MakeStat(std::uint64_t pid, std::string_view comm, char state,
                     std::string_view start = "123456") {
  std::string out = std::to_string(pid) + " (" + std::string(comm) + ") " + state;
  for (int field = 4; field <= 21; ++field)
    out += " " + std::to_string(field - 3);
  out += " " + std::string(start) + " 0 0 0\n";
  return out;
}


void TestPidfdResultClassification() {
  using namespace rateguard::platform::detail;
  int closes = 0;
  const auto absent = ClassifyPidfdOpen(-1, ESRCH, [&](int) { ++closes; });
  CHECK(absent.kind == PidfdAttemptKind::ProcessAbsent);
  CHECK(absent.reason == rateguard::platform::LinuxProcessReason::None);
  CHECK(closes == 0);

  const auto present = ClassifyPidfdOpen(37, 0, [&](int fd) {
    CHECK(fd == 37);
    ++closes;
  });
  CHECK(present.kind == PidfdAttemptKind::ProcessExists);
  CHECK(present.reason == rateguard::platform::LinuxProcessReason::ProcUnavailable);
  CHECK(closes == 1);

  const auto interrupted = ClassifyPidfdOpen(-1, EINTR, [&](int) { ++closes; });
  CHECK(interrupted.kind == PidfdAttemptKind::Interrupted);
  const auto denied = ClassifyPidfdOpen(-1, EPERM, [&](int) { ++closes; });
  CHECK(denied.kind == PidfdAttemptKind::Failed);
  CHECK(denied.reason == rateguard::platform::LinuxProcessReason::PermissionDenied);
  const auto unsupported = ClassifyPidfdOpen(-1, ENOSYS, [&](int) { ++closes; });
  CHECK(unsupported.kind == PidfdAttemptKind::Failed);
  CHECK(unsupported.reason == rateguard::platform::LinuxProcessReason::ProcUnavailable);
  const auto limited = ClassifyPidfdOpen(-1, EMFILE, [&](int) { ++closes; });
  CHECK(limited.kind == PidfdAttemptKind::Failed);
  CHECK(limited.reason == rateguard::platform::LinuxProcessReason::ResourceLimit);

  const auto close_failed = ClassifyPidfdOpen(38, 0, [](int) {
    throw std::runtime_error("synthetic close failure");
  });
  CHECK(close_failed.kind == PidfdAttemptKind::Failed);
}

void TestProcStatParser() {
  using namespace rateguard::platform::detail;
  auto result = ParseLinuxProcStat(MakeStat(5678, "worker (blue) name", 'S', "987654321"));
  CHECK(std::holds_alternative<ParsedProcStat>(result));
  if (std::holds_alternative<ParsedProcStat>(result)) {
    const auto parsed = std::get<ParsedProcStat>(result);
    CHECK(parsed.pid == 5678);
    CHECK(parsed.start_ticks == 987654321);
    CHECK(parsed.state == 'S');
  }
  result = ParseLinuxProcStat(MakeStat(22, "name with spaces", 't', "900"));
  CHECK(std::holds_alternative<ParsedProcStat>(result));
  if (std::holds_alternative<ParsedProcStat>(result))
    CHECK(std::get<ParsedProcStat>(result).state == 't');

  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat("")) ==
        ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat("42 comm S 1")) ==
        ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(MakeStat(0, "zero", 'S'))) ==
        ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(MakeStat(42, "bad", '?'))) ==
        ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(MakeStat(42, "bad", 'S', "-1"))) ==
        ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(MakeStat(
            42, "bad", 'S', "18446744073709551616"))) == ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(MakeStat(42, "bad", 'S', "0"))) ==
        ProcStatParseError::Malformed);
  auto bad_middle = MakeStat(42, "bad", 'S', "10");
  const auto marker = bad_middle.find(" 7 ");
  CHECK(marker != std::string::npos);
  if (marker != std::string::npos) bad_middle.replace(marker, 3, " x ");
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(bad_middle)) ==
        ProcStatParseError::Malformed);
  auto embedded_nul = MakeStat(42, "bad", 'S');
  embedded_nul.insert(5, 1, '\0');
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(embedded_nul)) ==
        ProcStatParseError::Malformed);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(
            std::string(kLinuxProcStatMaxBytes + 1, 'x'))) == ProcStatParseError::TooLarge);
  CHECK(std::get<ProcStatParseError>(ParseLinuxProcStat(
            "42 (unfinished)")) == ProcStatParseError::Malformed);
}

#if defined(__linux__)

class TestClock final : public rateguard::platform::IClock {
 public:
  explicit TestClock(rateguard::platform::ClockIdentity identity) : identity_(identity) {}
  rateguard::platform::ClockResult<rateguard::platform::MonoNanos> Now() override {
    if (throw_now_) throw std::runtime_error("test clock throw");
    timespec ts{};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return ClockError();
    return rateguard::platform::MonoNanos{
        static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
        static_cast<std::uint64_t>(ts.tv_nsec)};
  }
  rateguard::platform::ClockResult<rateguard::platform::ClockIdentity> Provenance() override {
    if (throw_provenance_) throw std::runtime_error("test clock throw");
    return identity_;
  }
  bool Healthy() const override { return !throw_healthy_ && healthy_; }
  void set_identity(rateguard::platform::ClockIdentity value) { identity_ = value; }
  void set_healthy(bool value) { healthy_ = value; }
  void throw_now(bool value) { throw_now_ = value; }
 private:
  static rateguard::platform::ClockFailure ClockError() {
    using namespace rateguard::v1::contract;
    return {{ErrorCategory::Internal, ErrorCode::Internal, RetryDisposition::Never,
             Commitment::NotCommitted}, rateguard::platform::ClockFailureReason::ClockSyscall};
  }
  rateguard::platform::ClockIdentity identity_;
  bool healthy_{true};
  bool throw_healthy_{false};
  bool throw_now_{false};
  bool throw_provenance_{false};
};

bool ReadHexUuid(const std::string& path, std::array<std::uint8_t, 16>& out) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  char data[64]{};
  const auto n = ::read(fd, data, sizeof(data));
  ::close(fd);
  if (n < 0) return false;
  std::string_view text(data, static_cast<std::size_t>(n));
  if (!text.empty() && text.back() == '\n') text.remove_suffix(1);
  if (text.size() != 36) return false;
  std::size_t byte_index = 0;
  int high = -1;
  for (char c : text) {
    if (c == '-') continue;
    int value;
    if (c >= '0' && c <= '9') value = c - '0';
    else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
    else return false;
    if (high < 0) high = value;
    else { out[byte_index++] = static_cast<std::uint8_t>((high << 4) | value); high = -1; }
  }
  return byte_index == out.size() && high < 0;
}

std::optional<rateguard::platform::LinuxPidNamespaceIdentity> NsIdentity(
    const char* path) {
  struct stat st{};
  if (::stat(path, &st) != 0 || st.st_ino == 0) return std::nullopt;
  return rateguard::platform::LinuxPidNamespaceIdentity{
      static_cast<std::uint64_t>(st.st_dev), static_cast<std::uint64_t>(st.st_ino)};
}

std::optional<rateguard::platform::detail::ParsedProcStat> ReadStat(pid_t pid) {
  const auto path = "/proc/" + std::to_string(pid) + "/stat";
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return std::nullopt;
  std::string text;
  char buffer[1024];
  for (;;) {
    const auto n = ::read(fd, buffer, sizeof(buffer));
    if (n < 0) { if (errno == EINTR) continue; ::close(fd); return std::nullopt; }
    if (n == 0) break;
    text.append(buffer, static_cast<std::size_t>(n));
    if (text.size() > rateguard::platform::detail::kLinuxProcStatMaxBytes) {
      ::close(fd); return std::nullopt;
    }
  }
  ::close(fd);
  const auto result = rateguard::platform::detail::ParseLinuxProcStat(text);
  if (!std::holds_alternative<rateguard::platform::detail::ParsedProcStat>(result))
    return std::nullopt;
  return std::get<rateguard::platform::detail::ParsedProcStat>(result);
}

class Child final {
 public:
  Child() {
    int fds[2];
    if (::pipe(fds) != 0) return;
    const pid_t pid = ::fork();
    if (pid < 0) { ::close(fds[0]); ::close(fds[1]); return; }
    if (pid == 0) {
      ::close(fds[1]);
      char value;
      while (::read(fds[0], &value, 1) < 0 && errno == EINTR) {}
      ::close(fds[0]);
      _exit(0);
    }
    pid_ = pid;
    ::close(fds[0]);
    write_fd_ = fds[1];
  }
  ~Child() { StopAndReap(); }
  pid_t pid() const { return pid_; }
  bool valid() const { return pid_ > 0; }
  void StopAndReap() {
    if (pid_ <= 0) return;
    if (write_fd_ >= 0) {
      const char value = 'x';
      (void)::write(write_fd_, &value, 1);
      ::close(write_fd_);
      write_fd_ = -1;
    }
    int status = 0;
    while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
    pid_ = -1;
  }
 private:
  pid_t pid_{-1};
  int write_fd_{-1};
};

std::optional<rateguard::platform::ClockIdentity> CurrentIdentity() {
  using namespace rateguard::platform;
  const auto ns = NsIdentity("/proc/self/ns/time");
  if (!ns) return std::nullopt;
  ClockIdentity id{};
  if (!ReadHexUuid("/proc/sys/kernel/random/boot_id", id.boot_uuid)) return std::nullopt;
  id.namespace_device = ns->device;
  id.namespace_inode = ns->inode;
  id.clock_id = 1;
  return id;
}

rateguard::platform::MonoNanos Now(TestClock& clock) {
  const auto now = clock.Now();
  return std::get<rateguard::platform::MonoNanos>(now);
}

void TestNativeChildProbe() {
  using namespace rateguard::platform;
  const auto observer = NsIdentity("/proc/self/ns/pid");
  auto identity = CurrentIdentity();
  CHECK(observer.has_value());
  CHECK(identity.has_value());
  if (!observer || !identity) return;

  Child child;
  CHECK(child.valid());
  if (!child.valid()) return;
  const auto stat = ReadStat(child.pid());
  CHECK(stat.has_value());
  if (!stat) return;

  TestClock clock(*identity);
  LinuxProcessProbeConfig config;
  config.expected_observer_pid_namespace = *observer;
  auto wrong_observer_config = config;
  ++wrong_observer_config.expected_observer_pid_namespace.inode;
  const auto wrong_observer = CreateLinuxRecordedProcessProbe(wrong_observer_config, clock);
  CHECK(std::holds_alternative<LinuxProcessProbeFailure>(wrong_observer));
  if (std::holds_alternative<LinuxProcessProbeFailure>(wrong_observer))
    CHECK(std::get<LinuxProcessProbeFailure>(wrong_observer).reason ==
          LinuxProcessReason::PidNamespaceMismatch);
  const auto created = CreateLinuxRecordedProcessProbe(config, clock);
  CHECK(std::holds_alternative<std::unique_ptr<IRecordedProcessProbe>>(created));
  if (!std::holds_alternative<std::unique_ptr<IRecordedProcessProbe>>(created)) return;
  auto& probe = *std::get<std::unique_ptr<IRecordedProcessProbe>>(created);
  std::atomic_bool cancel{false};
  RecordedLinuxProcess record{static_cast<std::uint64_t>(child.pid()),
                              stat->start_ticks, *identity};
  const auto before = Now(clock);
  const auto live = probe.Check(record, {before.value + 5'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessObservation>(live));
  if (std::holds_alternative<LinuxProcessObservation>(live)) {
    const auto& observed = std::get<LinuxProcessObservation>(live);
    CHECK(observed.disposition == LinuxProcessDisposition::LiveIdentityMatched);
    CHECK(observed.reason == LinuxProcessReason::None);
    CHECK(observed.observed_pid_start_ticks == stat->start_ticks);
    CHECK(observed.observed_clock_identity.has_value());
    CHECK(observed.observer_pid_namespace == observer);
  }

  auto reused = record;
  ++reused.pid_start_ticks;
  const auto reuse_result = probe.Check(reused, {before.value + 5'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessObservation>(reuse_result));
  if (std::holds_alternative<LinuxProcessObservation>(reuse_result)) {
    const auto& observed = std::get<LinuxProcessObservation>(reuse_result);
    CHECK(observed.disposition == LinuxProcessDisposition::Unknown);
    CHECK(observed.reason == LinuxProcessReason::PidReused);
  }

  auto different_time_ns = record;
  ++different_time_ns.clock_identity.namespace_inode;
  clock.set_identity(different_time_ns.clock_identity);
  const auto namespace_result = probe.Check(different_time_ns,
      {before.value + 5'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessObservation>(namespace_result));
  if (std::holds_alternative<LinuxProcessObservation>(namespace_result))
    CHECK(std::get<LinuxProcessObservation>(namespace_result).reason ==
          LinuxProcessReason::TimeNamespaceMismatch);
  clock.set_identity(*identity);

  auto wrong_boot = record;
  wrong_boot.clock_identity.boot_uuid[0] ^= 0x80U;
  const auto boot_result = probe.Check(wrong_boot, {before.value + 5'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessObservation>(boot_result));
  if (std::holds_alternative<LinuxProcessObservation>(boot_result))
    CHECK(std::get<LinuxProcessObservation>(boot_result).reason ==
          LinuxProcessReason::BootMismatch);

  auto wrong_clock = record;
  ++wrong_clock.clock_identity.monotonic_offset_seconds;
  const auto clock_result = probe.Check(wrong_clock, {before.value + 5'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessObservation>(clock_result));
  if (std::holds_alternative<LinuxProcessObservation>(clock_result))
    CHECK(std::get<LinuxProcessObservation>(clock_result).reason ==
          LinuxProcessReason::ClockIdentityMismatch);

  const auto expired = probe.Check(record, {1}, cancel);
  CHECK(std::holds_alternative<LinuxProcessProbeFailure>(expired));
  if (std::holds_alternative<LinuxProcessProbeFailure>(expired))
    CHECK(std::get<LinuxProcessProbeFailure>(expired).reason ==
          LinuxProcessReason::DeadlineExpired);
  const auto too_far = probe.Check(record,
      {before.value + 31'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessProbeFailure>(too_far));
  if (std::holds_alternative<LinuxProcessProbeFailure>(too_far))
    CHECK(std::get<LinuxProcessProbeFailure>(too_far).reason ==
          LinuxProcessReason::DeadlineExpired);
  std::atomic_bool already_cancelled{true};
  const auto cancelled = probe.Check(record, {before.value + 2'000'000'000ULL},
                                     already_cancelled);
  CHECK(std::holds_alternative<LinuxProcessProbeFailure>(cancelled));
  if (std::holds_alternative<LinuxProcessProbeFailure>(cancelled))
    CHECK(std::get<LinuxProcessProbeFailure>(cancelled).reason ==
          LinuxProcessReason::Cancelled);
  clock.set_healthy(false);
  const auto unhealthy = probe.Check(record, {before.value + 2'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessProbeFailure>(unhealthy));
  if (std::holds_alternative<LinuxProcessProbeFailure>(unhealthy))
    CHECK(std::get<LinuxProcessProbeFailure>(unhealthy).reason ==
          LinuxProcessReason::ProcUnavailable);
  clock.set_healthy(true);

  child.StopAndReap();
  const auto after = Now(clock);
  const auto absent = probe.Check(record, {after.value + 5'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<LinuxProcessObservation>(absent));
  if (std::holds_alternative<LinuxProcessObservation>(absent)) {
    const auto& observed = std::get<LinuxProcessObservation>(absent);
    CHECK(observed.disposition == LinuxProcessDisposition::RecordedProcessAbsent);
    CHECK(observed.reason == LinuxProcessReason::None);
    CHECK(!observed.observed_clock_identity.has_value());
  }
}

void TestThrowingClockFailsClosed() {
  using namespace rateguard::platform;
  const auto observer = NsIdentity("/proc/self/ns/pid");
  auto identity = CurrentIdentity();
  CHECK(observer.has_value() && identity.has_value());
  if (!observer || !identity) return;
  TestClock clock(*identity);
  LinuxProcessProbeConfig config;
  config.expected_observer_pid_namespace = *observer;
  auto created = CreateLinuxRecordedProcessProbe(config, clock);
  CHECK(std::holds_alternative<std::unique_ptr<IRecordedProcessProbe>>(created));
  if (!std::holds_alternative<std::unique_ptr<IRecordedProcessProbe>>(created)) return;
  clock.throw_now(true);
  std::atomic_bool cancel{false};
  RecordedLinuxProcess record{static_cast<std::uint64_t>(::getpid()), 1, *identity};
  const auto result = std::get<std::unique_ptr<IRecordedProcessProbe>>(created)->Check(
      record, {std::numeric_limits<std::uint64_t>::max()}, cancel);
  CHECK(std::holds_alternative<LinuxProcessProbeFailure>(result));
  if (std::holds_alternative<LinuxProcessProbeFailure>(result))
    CHECK(std::get<LinuxProcessProbeFailure>(result).reason ==
          LinuxProcessReason::ProcUnavailable);
}

#endif  // __linux__

}  // namespace

int main() {
  TestProcStatParser();
  TestPidfdResultClassification();
#if defined(__linux__)
  TestNativeChildProbe();
  TestThrowingClockFailsClosed();
#endif
  if (failures != 0) {
    std::cerr << failures << " process-probe assertion(s) failed\n";
    return 1;
  }
#if defined(__linux__)
  std::cout << "Native Linux process-probe fixture and portable checks passed; no host-placement claim\n";
#else
  std::cout << "Portable parser/pidfd classification checks passed; native Linux fixture not run here\n";
#endif
  return 0;
}
