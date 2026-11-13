#include "platform/clock_linux.h"

#include "platform/clock_linux_detail.h"

#include <array>
#include <charconv>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#if defined(__linux__)
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#endif
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <time.h>
#include <unistd.h>
#include <utility>

namespace rateguard::platform {
namespace {
using rateguard::v1::contract::Commitment;
using rateguard::v1::contract::ErrorCategory;
using rateguard::v1::contract::ErrorCode;
using rateguard::v1::contract::RetryDisposition;

ClockFailure Failure(ClockFailureReason reason) {
  return {{ErrorCategory::Internal, ErrorCode::Internal, RetryDisposition::Never,
           Commitment::NotCommitted},
          reason};
}

bool ParseSigned(std::string_view text, std::int64_t& output) {
  if (text.empty() || text.front() == '+') return false;
  const auto digits = text.front() == '-' ? text.substr(1) : text;
  if (digits.empty() || (digits.size() > 1 && digits.front() == '0') ||
      (text.front() == '-' && digits == "0"))
    return false;
  for (char c : digits)
    if (c < '0' || c > '9') return false;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), output, 10);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

bool ParseUnsigned(std::string_view text, std::uint32_t& output) {
  if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;
  for (char c : text)
    if (c < '0' || c > '9') return false;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), output, 10);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

bool IsSpace(char c) {
  return c == ' ' || c == '\t';
}

ClockResult<std::array<std::string_view, 3>> ThreeFields(std::string_view line) {
  std::array<std::string_view, 3> fields{};
  std::size_t count = 0;
  std::size_t position = 0;
  while (position < line.size()) {
    while (position < line.size() && IsSpace(line[position])) ++position;
    if (position == line.size()) break;
    const std::size_t begin = position;
    while (position < line.size() && !IsSpace(line[position])) ++position;
    if (count == fields.size()) return Failure(ClockFailureReason::MalformedOffsets);
    fields[count++] = line.substr(begin, position - begin);
  }
  if (count != fields.size()) return Failure(ClockFailureReason::MalformedOffsets);
  return fields;
}

#if defined(__linux__)
class ScopedFd final {
 public:
  explicit ScopedFd(int fd) : fd_(fd) {}
  ~ScopedFd() { if (fd_ >= 0) ::close(fd_); }
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;
  [[nodiscard]] int get() const noexcept { return fd_; }

 private:
  int fd_;
};

ClockResult<std::string> ReadProcFile(const char* path, std::size_t maximum_bytes) {
  if (maximum_bytes > 512)
    return Failure(ClockFailureReason::InputTooLong);
  const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return Failure(ClockFailureReason::PlatformRead);
  ScopedFd owned(fd);
  struct statfs fs {};
  if (::fstatfs(fd, &fs) != 0 ||
      static_cast<unsigned long>(fs.f_type) !=
          static_cast<unsigned long>(PROC_SUPER_MAGIC))
    return Failure(ClockFailureReason::PlatformRead);

  std::string bytes(maximum_bytes + 1, '\0');
  std::size_t total = 0;
  while (total < bytes.size()) {
    const ssize_t count = ::read(fd, bytes.data() + total, bytes.size() - total);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) return Failure(ClockFailureReason::PlatformRead);
    if (count == 0) break;
    total += static_cast<std::size_t>(count);
  }
  if (total > maximum_bytes) return Failure(ClockFailureReason::InputTooLong);
  bytes.resize(total);
  return bytes;
}

class LinuxClockPlatform final : public IClockPlatform {
 public:
  ClockResult<bool> IsProcessLeader() override {
    const auto tid = static_cast<pid_t>(::syscall(SYS_gettid));
    if (tid < 0) return Failure(ClockFailureReason::PlatformRead);
    return tid == ::getpid();
  }

  ClockResult<std::string> ReadBootUuidFile() override {
    return ReadProcFile("/proc/sys/kernel/random/boot_id", 64);
  }

  ClockResult<detail::NamespaceFileIdentity> StatTimeNamespace(
      bool children) override {
    return StatNamespace(children ? "/proc/self/ns/time_for_children"
                                  : "/proc/self/ns/time");
  }

  ClockResult<std::string> ReadTimeOffsetsFile() override {
    return ReadProcFile("/proc/self/timens_offsets", 512);
  }

  ClockResult<std::int32_t> MonotonicClockId() override {
    return static_cast<std::int32_t>(CLOCK_MONOTONIC);
  }

  ClockResult<ClockReading> ReadMonotonic() override {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0)
      return Failure(ClockFailureReason::ClockSyscall);
    return ClockReading{static_cast<std::int64_t>(value.tv_sec),
                        static_cast<std::int64_t>(value.tv_nsec)};
  }

 private:
  static ClockResult<detail::NamespaceFileIdentity> StatNamespace(
      const char* path) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return Failure(ClockFailureReason::NamespaceStat);
    ScopedFd owned(fd);
    struct stat status {};
    struct statfs fs {};
    if (::fstat(fd, &status) != 0 || ::fstatfs(fd, &fs) != 0 ||
        static_cast<unsigned long>(fs.f_type) !=
            static_cast<unsigned long>(NSFS_MAGIC) || status.st_ino == 0)
      return Failure(ClockFailureReason::NamespaceStat);
    return detail::NamespaceFileIdentity{
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino)};
  }
};
#else
class LinuxClockPlatform final : public IClockPlatform {
 public:
  ClockResult<bool> IsProcessLeader() override {
    return Failure(ClockFailureReason::PlatformRead);
  }
  ClockResult<std::string> ReadBootUuidFile() override {
    return Failure(ClockFailureReason::PlatformRead);
  }
  ClockResult<detail::NamespaceFileIdentity> StatTimeNamespace(bool) override {
    return Failure(ClockFailureReason::PlatformRead);
  }
  ClockResult<std::string> ReadTimeOffsetsFile() override {
    return Failure(ClockFailureReason::PlatformRead);
  }
  ClockResult<std::int32_t> MonotonicClockId() override {
    return Failure(ClockFailureReason::PlatformRead);
  }
  ClockResult<ClockReading> ReadMonotonic() override {
    return Failure(ClockFailureReason::PlatformRead);
  }
};
#endif

}  // namespace

namespace {
ClockResult<ClockIdentity> ProbeIdentity(IClockPlatform& platform) {
  auto leader = platform.IsProcessLeader();
  if (auto* error = std::get_if<ClockFailure>(&leader)) return *error;
  if (!std::get<bool>(leader))
    return Failure(ClockFailureReason::NotProcessLeader);

  auto boot_file = platform.ReadBootUuidFile();
  if (auto* error = std::get_if<ClockFailure>(&boot_file)) return *error;
  auto boot = detail::ParseBootUuid(std::get<std::string>(boot_file));
  if (auto* error = std::get_if<ClockFailure>(&boot)) return *error;

  auto current_before = platform.StatTimeNamespace(false);
  if (auto* error = std::get_if<ClockFailure>(&current_before)) return *error;
  auto children_before = platform.StatTimeNamespace(true);
  if (auto* error = std::get_if<ClockFailure>(&children_before)) return *error;
  const auto current_pre = std::get<detail::NamespaceFileIdentity>(current_before);
  const auto children_pre = std::get<detail::NamespaceFileIdentity>(children_before);

  auto offsets_file = platform.ReadTimeOffsetsFile();
  if (auto* error = std::get_if<ClockFailure>(&offsets_file)) return *error;
  auto offsets = detail::ParseTimeOffsets(std::get<std::string>(offsets_file));
  if (auto* error = std::get_if<ClockFailure>(&offsets)) return *error;

  auto current_after = platform.StatTimeNamespace(false);
  if (auto* error = std::get_if<ClockFailure>(&current_after)) return *error;
  auto children_after = platform.StatTimeNamespace(true);
  if (auto* error = std::get_if<ClockFailure>(&children_after)) return *error;
  const auto current_post = std::get<detail::NamespaceFileIdentity>(current_after);
  const auto children_post = std::get<detail::NamespaceFileIdentity>(children_after);
  if (current_pre.inode == 0 || current_pre != children_pre ||
      current_pre != current_post || current_pre != children_post)
    return Failure(ClockFailureReason::NamespaceChanged);

  auto clock_id = platform.MonotonicClockId();
  if (auto* error = std::get_if<ClockFailure>(&clock_id)) return *error;

  const auto parsed_offsets = std::get<detail::TimeOffsets>(offsets);
  return ClockIdentity{std::get<std::array<std::uint8_t, 16>>(boot),
                       current_pre.device,
                       current_pre.inode,
                       parsed_offsets.monotonic_seconds,
                       parsed_offsets.monotonic_nanoseconds,
                       parsed_offsets.boottime_seconds,
                       parsed_offsets.boottime_nanoseconds,
                       std::get<std::int32_t>(clock_id)};
}
}  // namespace

namespace detail {
ClockResult<std::string> ReadBoundedFile(const char* path,
                                         std::size_t maximum_bytes) {
  if (maximum_bytes > 512)
    return Failure(ClockFailureReason::InputTooLong);
  std::ifstream input(path, std::ios::binary);
  if (!input) return Failure(ClockFailureReason::PlatformRead);
  std::string bytes(maximum_bytes + 1, '\0');
  input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  const auto count = input.gcount();
  if (count < 0) return Failure(ClockFailureReason::PlatformRead);
  if (static_cast<std::size_t>(count) > maximum_bytes)
    return Failure(ClockFailureReason::InputTooLong);
  if (input.bad()) return Failure(ClockFailureReason::PlatformRead);
  bytes.resize(static_cast<std::size_t>(count));
  return bytes;
}

ClockResult<std::array<std::uint8_t, 16>> ParseBootUuid(
    std::string_view input) {
  if (input.size() > 64) return Failure(ClockFailureReason::InputTooLong);
  if (!input.empty() && input.back() == '\n') input.remove_suffix(1);
  if (input.size() != 36) return Failure(ClockFailureReason::MalformedBootUuid);
  std::array<std::uint8_t, 16> result{};
  std::size_t output = 0;
  int high_nibble = -1;
  for (std::size_t i = 0; i < input.size(); ++i) {
    const char c = input[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return Failure(ClockFailureReason::MalformedBootUuid);
      continue;
    }
    int digit = -1;
    if (c >= '0' && c <= '9') digit = c - '0';
    else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
    if (digit < 0) return Failure(ClockFailureReason::MalformedBootUuid);
    if (high_nibble < 0) {
      high_nibble = digit;
    } else {
      if (output >= result.size())
        return Failure(ClockFailureReason::MalformedBootUuid);
      result[output++] = static_cast<std::uint8_t>((high_nibble << 4) | digit);
      high_nibble = -1;
    }
  }
  if (output != result.size() || high_nibble >= 0)
    return Failure(ClockFailureReason::MalformedBootUuid);
  return result;
}

ClockResult<TimeOffsets> ParseTimeOffsets(std::string_view input) {
  if (input.size() > 512) return Failure(ClockFailureReason::InputTooLong);
  std::optional<TimeOffsets> monotonic;
  std::optional<TimeOffsets> boottime;
  std::size_t position = 0;
  while (position < input.size()) {
    const std::size_t end = input.find('\n', position);
    const bool has_newline = end != std::string_view::npos;
    auto line = input.substr(position, has_newline ? end - position : input.size() - position);
    position = has_newline ? end + 1 : input.size();
    if (line.empty()) return Failure(ClockFailureReason::MalformedOffsets);
    auto fields_result = ThreeFields(line);
    if (auto* error = std::get_if<ClockFailure>(&fields_result)) return *error;
    const auto fields = std::get<std::array<std::string_view, 3>>(fields_result);
    std::int64_t seconds = 0;
    std::uint32_t nanoseconds = 0;
    if (!ParseSigned(fields[1], seconds) ||
        !ParseUnsigned(fields[2], nanoseconds))
      return Failure(ClockFailureReason::MalformedOffsets);
    if (nanoseconds > 999'999'999U)
      return Failure(ClockFailureReason::OffsetOutOfRange);
    if (fields[0] == "monotonic") {
      if (monotonic) return Failure(ClockFailureReason::MalformedOffsets);
      monotonic = TimeOffsets{seconds, nanoseconds, 0, 0};
    } else if (fields[0] == "boottime") {
      if (boottime) return Failure(ClockFailureReason::MalformedOffsets);
      boottime = TimeOffsets{0, 0, seconds, nanoseconds};
    } else {
      return Failure(ClockFailureReason::MalformedOffsets);
    }
  }
  if (!monotonic || !boottime)
    return Failure(ClockFailureReason::MalformedOffsets);
  return TimeOffsets{monotonic->monotonic_seconds,
                     monotonic->monotonic_nanoseconds,
                     boottime->boottime_seconds,
                     boottime->boottime_nanoseconds};
}
}  // namespace detail

ClockResult<ClockIdentity> detail::ProbeCurrentLinuxClockIdentity() {
  LinuxClockPlatform platform;
  return ProbeIdentity(platform);
}

LinuxMonotonicClock::LinuxMonotonicClock(
    ClockIdentity identity, std::unique_ptr<IClockPlatform> platform)
    : identity_(identity), platform_(std::move(platform)),
      failure_({{ErrorCategory::Internal, ErrorCode::Internal,
                 RetryDisposition::Never, Commitment::NotCommitted},
                ClockFailureReason::LatchedFailure}) {}

ClockResult<std::unique_ptr<LinuxMonotonicClock>> LinuxMonotonicClock::Create(
    const ClockIdentity& trusted_expected_identity,
    std::unique_ptr<IClockPlatform> platform) {
  if (!platform) return Failure(ClockFailureReason::PlatformRead);
  auto observed = ProbeIdentity(*platform);
  if (auto* error = std::get_if<ClockFailure>(&observed)) return *error;
  const ClockIdentity actual = std::get<ClockIdentity>(observed);
  if (actual.namespace_inode == 0 || actual.clock_id != 1 ||
      actual.monotonic_offset_nanoseconds > 999'999'999U ||
      actual.boottime_offset_nanoseconds > 999'999'999U ||
      actual != trusted_expected_identity)
    return Failure(ClockFailureReason::ExpectedIdentityMismatch);
  auto clock = std::unique_ptr<LinuxMonotonicClock>(
      new LinuxMonotonicClock(actual, std::move(platform)));
  auto initial_sample = clock->Now();
  if (auto* error = std::get_if<ClockFailure>(&initial_sample)) return *error;
  return clock;
}

ClockFailure LinuxMonotonicClock::Latch(ClockFailureReason reason) {
  if (!failed_) {
    failed_ = true;
    healthy_ = false;
    failure_ = Failure(reason);
  }
  return failure_;
}

ClockFailure LinuxMonotonicClock::CurrentFailure() const { return failure_; }

ClockResult<MonoNanos> LinuxMonotonicClock::Now() {
  std::lock_guard lock(mutex_);
  if (failed_) return CurrentFailure();
  auto reading_result = platform_->ReadMonotonic();
  if (auto* error = std::get_if<ClockFailure>(&reading_result))
    return Latch(error->reason);
  const auto reading = std::get<ClockReading>(reading_result);
  if (reading.seconds < 0 || reading.nanoseconds < 0 ||
      reading.nanoseconds > 999'999'999)
    return Latch(ClockFailureReason::InvalidTimespec);
  constexpr std::uint64_t kNanosPerSecond = 1'000'000'000ULL;
  const auto seconds = static_cast<std::uint64_t>(reading.seconds);
  if (seconds > std::numeric_limits<std::uint64_t>::max() / kNanosPerSecond)
    return Latch(ClockFailureReason::NanosecondOverflow);
  const std::uint64_t whole = seconds * kNanosPerSecond;
  const auto fraction = static_cast<std::uint64_t>(reading.nanoseconds);
  if (fraction > std::numeric_limits<std::uint64_t>::max() - whole)
    return Latch(ClockFailureReason::NanosecondOverflow);
  const MonoNanos sample{whole + fraction};
  if (last_sample_ && sample.value < last_sample_->value)
    return Latch(ClockFailureReason::BackwardsSample);
  last_sample_ = sample;
  healthy_ = true;
  return sample;
}

ClockResult<ClockIdentity> LinuxMonotonicClock::Provenance() {
  std::lock_guard lock(mutex_);
  if (failed_) return CurrentFailure();
  if (!healthy_) return Failure(ClockFailureReason::LatchedFailure);
  return identity_;
}

bool LinuxMonotonicClock::Healthy() const {
  std::lock_guard lock(mutex_);
  return healthy_ && !failed_;
}

ClockResult<std::unique_ptr<LinuxMonotonicClock>> CreateLinuxClock(
    const ClockIdentity& trusted_expected_identity) {
  return LinuxMonotonicClock::Create(
      trusted_expected_identity, std::make_unique<LinuxClockPlatform>());
}

}  // namespace rateguard::platform
