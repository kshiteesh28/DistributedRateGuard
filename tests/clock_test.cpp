#include "platform/clock_linux.h"
#include "platform/clock_linux_detail.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace rateguard::platform;
namespace detail = rateguard::platform::detail;

namespace {
int failures = 0;
void Check(bool condition, const char* label) {
  if (!condition) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}
ClockFailure Fail(ClockFailureReason reason) {
  using namespace rateguard::v1::contract;
  return {{ErrorCategory::Internal, ErrorCode::Internal, RetryDisposition::Never,
           Commitment::NotCommitted}, reason};
}

const std::string kBoot = "00112233-4455-6677-8899-aabbccddeeff\n";
const std::string kOffsets = "monotonic 0 0\nboottime -2 4\n";
const ClockIdentity kIdentity{{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                              7, 1234, 0, 0, -2, 4, 1};

class FakePlatform final : public IClockPlatform {
 public:
  bool leader{true};
  std::int32_t clock_id{1};
  std::string boot{kBoot};
  std::string offsets{kOffsets};
  std::deque<detail::NamespaceFileIdentity> namespace_sequence{
      {7, 1234}, {7, 1234}, {7, 1234}, {7, 1234}};
  std::deque<ClockResult<ClockReading>> readings;
  std::atomic<std::size_t> clock_calls{0};

  ClockResult<bool> IsProcessLeader() override { return leader; }
  ClockResult<std::string> ReadBootUuidFile() override { return boot; }
  ClockResult<detail::NamespaceFileIdentity> StatTimeNamespace(bool) override {
    if (namespace_sequence.empty()) return Fail(ClockFailureReason::NamespaceStat);
    auto value = namespace_sequence.front();
    namespace_sequence.pop_front();
    return value;
  }
  ClockResult<std::string> ReadTimeOffsetsFile() override { return offsets; }
  ClockResult<std::int32_t> MonotonicClockId() override { return clock_id; }
  ClockResult<ClockReading> ReadMonotonic() override {
    ++clock_calls;
    if (readings.empty()) return ClockReading{0, 0};
    auto result = std::move(readings.front());
    readings.pop_front();
    return result;
  }
};

ClockResult<std::unique_ptr<LinuxMonotonicClock>> MakeClock(
    std::unique_ptr<FakePlatform> platform, const ClockIdentity& expected = kIdentity) {
  std::unique_ptr<IClockPlatform> erased(std::move(platform));
  return LinuxMonotonicClock::Create(expected, std::move(erased));
}

bool HasFailure(const auto& result, ClockFailureReason reason) {
  const auto* failure = std::get_if<ClockFailure>(&result);
  return failure && failure->reason == reason &&
         failure->service_error.category == rateguard::v1::contract::ErrorCategory::Internal &&
         failure->service_error.code == rateguard::v1::contract::ErrorCode::Internal &&
         failure->service_error.commitment == rateguard::v1::contract::Commitment::NotCommitted;
}

void TestParsers() {
  const auto uuid = detail::ParseBootUuid(kBoot);
  Check(std::holds_alternative<std::array<std::uint8_t, 16>>(uuid), "valid lowercase UUID parses");
  if (const auto* bytes = std::get_if<std::array<std::uint8_t, 16>>(&uuid))
    Check(*bytes == kIdentity.boot_uuid, "UUID bytes match expected order");
  Check(HasFailure(detail::ParseBootUuid("00112233-4455-6677-8899-AABBCCDDEEFF\n"),
                   ClockFailureReason::MalformedBootUuid), "uppercase UUID rejected");
  Check(HasFailure(detail::ParseBootUuid(" 00112233-4455-6677-8899-aabbccddeeff"),
                   ClockFailureReason::MalformedBootUuid), "UUID leading space rejected");
  Check(HasFailure(detail::ParseBootUuid(kBoot + "\n"),
                   ClockFailureReason::MalformedBootUuid), "multiple UUID newlines rejected");
  Check(HasFailure(detail::ParseBootUuid(std::string(65, 'a')),
                   ClockFailureReason::InputTooLong), "UUID overlength rejected");

  const auto offsets = detail::ParseTimeOffsets(kOffsets);
  Check(std::holds_alternative<detail::TimeOffsets>(offsets), "valid offsets parse");
  if (const auto* parsed = std::get_if<detail::TimeOffsets>(&offsets))
    Check(parsed->monotonic_seconds == 0 && parsed->monotonic_nanoseconds == 0 &&
              parsed->boottime_seconds == -2 && parsed->boottime_nanoseconds == 4,
          "both offset rows map to expected fields");
  Check(std::holds_alternative<detail::TimeOffsets>(detail::ParseTimeOffsets(
            "  boottime\t-2\t4  \nmonotonic 0 0")),
        "row order and spaces/tabs accepted");
  std::string embedded_nul = "monotonic 0 0\nboottime 0 0";
  embedded_nul.push_back('\0');
  const std::array<std::string, 12> invalid_offsets{
      "monotonic +1 0\nboottime 0 0",       // plus sign
      "monotonic 01 0\nboottime 0 0",       // leading zero
      "monotonic -0 0\nboottime 0 0",       // negative zero
      "monotonic 0 00\nboottime 0 0",       // nanosecond leading zero
      "monotonic 0 1000000000\nboottime 0 0", // nsec bound
      "monotonic 0 0\r\nboottime 0 0",     // CR rejected
      "monotonic 0 0\n\nboottime 0 0",     // empty row
      "monotonic 0 0\nmonotonic 1 0",       // duplicate row
      "monotonic 0 0",                       // missing row
      "monotonic 0 0\nboottime 0 0\nother 0 0", // unknown row
      "monotonic 0 0 extra\nboottime 0 0",  // extra token
      std::move(embedded_nul)};
  for (const auto& text : invalid_offsets)
    Check(std::holds_alternative<ClockFailure>(detail::ParseTimeOffsets(text)),
          "malformed offsets rejected");
  Check(HasFailure(detail::ParseTimeOffsets(std::string(513, 'x')),
                   ClockFailureReason::InputTooLong), "offset overlength rejected");
  auto edge_offsets = detail::ParseTimeOffsets(
      "monotonic -9223372036854775808 999999999\nboottime 9223372036854775807 0\n");
  Check(std::holds_alternative<detail::TimeOffsets>(edge_offsets),
        "signed second extremes and maximum nanoseconds parse");
  if (const auto* edge = std::get_if<detail::TimeOffsets>(&edge_offsets))
    Check(edge->monotonic_seconds == std::numeric_limits<std::int64_t>::min() &&
              edge->monotonic_nanoseconds == 999'999'999U &&
              edge->boottime_seconds == std::numeric_limits<std::int64_t>::max(),
          "offset extremes preserved exactly");

  char path[] = "/tmp/rateguard-clock-bounded-XXXXXX";
  const int fd = ::mkstemp(path);
  Check(fd >= 0, "create bounded-reader temp file");
  if (fd >= 0) {
    const std::string contents(65, 'x');
    const auto written = ::write(fd, contents.data(), contents.size());
    Check(written == static_cast<ssize_t>(contents.size()),
          "write bounded-reader temp file");
    (void)::lseek(fd, 0, SEEK_SET);
    Check(HasFailure(detail::ReadBoundedFd(fd, 64),
                     ClockFailureReason::InputTooLong),
          "bounded reader detects one byte over limit");
    Check(::ftruncate(fd, 64) == 0 && ::lseek(fd, 0, SEEK_SET) == 0,
          "truncate and rewind bounded-reader file");
    const auto exact = detail::ReadBoundedFd(fd, 64);
    Check(std::get_if<std::string>(&exact) && std::get<std::string>(exact).size() == 64,
          "bounded reader accepts exact limit");
    Check(::ftruncate(fd, 0) == 0 && ::lseek(fd, 0, SEEK_SET) == 0,
          "empty bounded-reader file");
    const auto empty = detail::ReadBoundedFd(fd, 0);
    Check(std::get_if<std::string>(&empty) && std::get<std::string>(empty).empty(),
          "bounded reader accepts zero-byte file at zero limit");
    ::close(fd);
    ::unlink(path);
  }
}

void TestIdentityProbeAndMismatch() {
  auto valid = MakeClock(std::make_unique<FakePlatform>());
  Check(std::holds_alternative<std::unique_ptr<LinuxMonotonicClock>>(valid),
        "manifest-matching identity creates clock");
  if (auto* clock = std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&valid)) {
    auto provenance = (*clock)->Provenance();
    Check(std::get_if<ClockIdentity>(&provenance) &&
              std::get<ClockIdentity>(provenance) == kIdentity,
          "provenance equals captured identity");
  }

  for (int field = 0; field < 8; ++field) {
    auto expected = kIdentity;
    switch (field) {
      case 0: expected.boot_uuid[0] ^= 1; break;
      case 1: ++expected.namespace_device; break;
      case 2: ++expected.namespace_inode; break;
      case 3: ++expected.monotonic_offset_seconds; break;
      case 4: ++expected.monotonic_offset_nanoseconds; break;
      case 5: ++expected.boottime_offset_seconds; break;
      case 6: ++expected.boottime_offset_nanoseconds; break;
      case 7: expected.clock_id = 2; break;
    }
    auto result = MakeClock(std::make_unique<FakePlatform>(), expected);
    Check(HasFailure(result, ClockFailureReason::ExpectedIdentityMismatch),
          "each trusted identity field compared exactly");
  }

  auto invalid_clock_id_platform = std::make_unique<FakePlatform>();
  invalid_clock_id_platform->clock_id = 99;
  auto bad_clock = kIdentity;
  bad_clock.clock_id = 99;
  auto invalid_clock = MakeClock(std::move(invalid_clock_id_platform), bad_clock);
  Check(HasFailure(invalid_clock, ClockFailureReason::ExpectedIdentityMismatch),
        "non-CLOCK_MONOTONIC ID rejected even if expected matches");

  auto split = std::make_unique<FakePlatform>();
  split->namespace_sequence = {{7, 1234}, {7, 1235}, {7, 1234}, {7, 1235}};
  Check(HasFailure(MakeClock(std::move(split)), ClockFailureReason::NamespaceChanged),
        "current and child namespaces must match");

  auto changed = std::make_unique<FakePlatform>();
  changed->namespace_sequence = {{7, 1234}, {7, 1234}, {7, 1235}, {7, 1234}};
  Check(HasFailure(MakeClock(std::move(changed)), ClockFailureReason::NamespaceChanged),
        "all four namespace snapshots must match");

  auto nonleader = std::make_unique<FakePlatform>();
  nonleader->leader = false;
  Check(HasFailure(MakeClock(std::move(nonleader)), ClockFailureReason::NotProcessLeader),
        "nonleader probe rejected");

  auto malformed = std::make_unique<FakePlatform>();
  malformed->offsets = "monotonic 0 0\nboottime 0 0\nunknown 0 0";
  Check(HasFailure(MakeClock(std::move(malformed)), ClockFailureReason::MalformedOffsets),
        "malformed platform offsets prevent factory success");
}

void TestSamplingAndStickyFailure() {
  auto fake = std::make_unique<FakePlatform>();
  fake->readings = {ClockReading{0, 0}, ClockReading{1, 2}, ClockReading{1, 2}};
  auto created = MakeClock(std::move(fake));
  auto& clock = *std::get<std::unique_ptr<LinuxMonotonicClock>>(created);
  auto first = clock.Now();
  auto equal = clock.Now();
  Check(std::get_if<MonoNanos>(&first) && std::get<MonoNanos>(first).value == 1'000'000'002ULL,
        "seconds and nanos convert exactly");
  Check(std::get_if<MonoNanos>(&equal) && std::get<MonoNanos>(equal).value == 1'000'000'002ULL,
        "equal sample is accepted");
  Check(clock.Healthy(), "clock stays healthy after equal samples");

  auto backwards_fake = std::make_unique<FakePlatform>();
  backwards_fake->readings = {ClockReading{4, 0}, ClockReading{5, 0},
                              ClockReading{4, 999'999'999}, ClockReading{6, 0}};
  auto backwards_created = MakeClock(std::move(backwards_fake));
  auto& backwards_clock = *std::get<std::unique_ptr<LinuxMonotonicClock>>(backwards_created);
  Check(std::holds_alternative<MonoNanos>(backwards_clock.Now()), "first sample succeeds");
  auto backwards = backwards_clock.Now();
  Check(HasFailure(backwards, ClockFailureReason::BackwardsSample), "backwards sample latches");
  Check(!backwards_clock.Healthy(), "backwards failure makes clock unhealthy");
  auto sticky = backwards_clock.Now();
  Check(HasFailure(sticky, ClockFailureReason::BackwardsSample), "first failure remains sticky");
  auto provenance_after_failure = backwards_clock.Provenance();
  Check(HasFailure(provenance_after_failure, ClockFailureReason::BackwardsSample),
        "provenance fails with first sticky error");

  const std::array<ClockReading, 3> invalid_readings{{{-1, 0}, {0, -1}, {0, 1'000'000'000}}};
  const std::array<ClockFailureReason, 3> reasons{{ClockFailureReason::InvalidTimespec,
                                                  ClockFailureReason::InvalidTimespec,
                                                  ClockFailureReason::InvalidTimespec}};
  for (std::size_t i = 0; i < invalid_readings.size(); ++i) {
    auto bad = std::make_unique<FakePlatform>();
    bad->readings.push_back(ClockReading{0, 0});
    bad->readings.push_back(invalid_readings[i]);
    auto result = MakeClock(std::move(bad));
    auto& test_clock = *std::get<std::unique_ptr<LinuxMonotonicClock>>(result);
    Check(HasFailure(test_clock.Now(), reasons[i]), "invalid timespec rejected");
    Check(!test_clock.Healthy(), "invalid timespec is sticky");
  }
  auto overflow_fake = std::make_unique<FakePlatform>();
  overflow_fake->readings = {ClockReading{0, 0},
                             ClockReading{std::numeric_limits<std::int64_t>::max(), 0}};
  auto overflow_created = MakeClock(std::move(overflow_fake));
  auto& overflow_clock = *std::get<std::unique_ptr<LinuxMonotonicClock>>(overflow_created);
  Check(HasFailure(overflow_clock.Now(), ClockFailureReason::NanosecondOverflow),
        "uint64 nanosecond conversion overflow rejected");

  auto initial_bad_fake = std::make_unique<FakePlatform>();
  initial_bad_fake->readings = {ClockReading{0, 1'000'000'000}};
  Check(HasFailure(MakeClock(std::move(initial_bad_fake)),
                   ClockFailureReason::InvalidTimespec),
        "failed initial sample prevents factory from returning a usable clock");

  auto syscall_fake = std::make_unique<FakePlatform>();
  syscall_fake->readings = {Fail(ClockFailureReason::ClockSyscall)};
  Check(HasFailure(MakeClock(std::move(syscall_fake)), ClockFailureReason::ClockSyscall),
        "initial clock syscall failure prevents factory success");
}

void TestConcurrentSerializedSamples() {
  constexpr std::size_t n = 32;
  auto fake = std::make_unique<FakePlatform>();
  fake->readings.emplace_back(ClockReading{0, 0});  // successful factory sample
  for (std::size_t i = 0; i < n; ++i)
    fake->readings.emplace_back(ClockReading{static_cast<std::int64_t>(i + 1), 0});
  auto created = MakeClock(std::move(fake));
  auto& clock = *std::get<std::unique_ptr<LinuxMonotonicClock>>(created);
  std::array<std::uint64_t, n> samples{};
  std::array<bool, n> ok{};
  std::array<std::thread, n> threads;
  for (std::size_t i = 0; i < n; ++i) {
    threads[i] = std::thread([&, i] {
      auto result = clock.Now();
      if (const auto* value = std::get_if<MonoNanos>(&result)) {
        samples[i] = value->value;
        ok[i] = true;
      }
    });
  }
  for (auto& thread : threads) thread.join();
  for (bool success : ok) Check(success, "concurrent sample succeeds");
  std::sort(samples.begin(), samples.end());
  for (std::size_t i = 0; i < n; ++i)
    Check(samples[i] == (i + 1) * 1'000'000'000ULL,
          "serialized concurrent samples preserve monotonic order");
  Check(clock.Healthy(), "concurrent serialized samples remain healthy");
}
}  // namespace

int main() {
  TestParsers();
  TestIdentityProbeAndMismatch();
  TestSamplingAndStickyFailure();
  TestConcurrentSerializedSamples();
  if (failures != 0) return EXIT_FAILURE;
  std::cout << "clock contract checks passed\n";
  return EXIT_SUCCESS;
}
