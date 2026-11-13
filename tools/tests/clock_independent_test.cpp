#include "platform/clock_linux.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>

using namespace rateguard::platform;
namespace detail = rateguard::platform::detail;

namespace {
int failures = 0;
void Expect(bool value, const char* label) {
  if (!value) { std::cerr << "FAIL: " << label << '\n'; ++failures; }
}
ClockFailure Error(ClockFailureReason reason) {
  using namespace rateguard::v1::contract;
  return {{ErrorCategory::Internal, ErrorCode::Internal, RetryDisposition::Never,
           Commitment::NotCommitted}, reason};
}
const std::string boot = "01234567-89ab-cdef-0123-456789abcdef\n";
const std::string offsets = "monotonic 0 0\nboottime 0 0\n";
const ClockIdentity expected{{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                               0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
                              9, 31, 0, 0, 0, 0, 1};

class Platform final : public IClockPlatform {
 public:
  bool leader = true;
  std::string boot_bytes = boot;
  std::string offset_bytes = offsets;
  std::int32_t clock_id = 1;
  std::deque<detail::NamespaceFileIdentity> namespaces{{9,31},{9,31},{9,31},{9,31}};
  std::deque<ClockResult<ClockReading>> samples;
  unsigned reads = 0;
  ClockResult<bool> IsProcessLeader() override { return leader; }
  ClockResult<std::string> ReadBootUuidFile() override { return boot_bytes; }
  ClockResult<detail::NamespaceFileIdentity> StatTimeNamespace(bool) override {
    if (namespaces.empty()) return Error(ClockFailureReason::NamespaceStat);
    auto v = namespaces.front(); namespaces.pop_front(); return v;
  }
  ClockResult<std::string> ReadTimeOffsetsFile() override { return offset_bytes; }
  ClockResult<std::int32_t> MonotonicClockId() override { return clock_id; }
  ClockResult<ClockReading> ReadMonotonic() override {
    ++reads;
    if (samples.empty()) return ClockReading{0,0};
    auto v = std::move(samples.front()); samples.pop_front(); return v;
  }
};
auto Create(std::unique_ptr<Platform> p, ClockIdentity identity = expected) {
  return LinuxMonotonicClock::Create(identity, std::unique_ptr<IClockPlatform>(std::move(p)));
}
bool IsError(const auto& value, ClockFailureReason reason) {
  auto* f = std::get_if<ClockFailure>(&value); return f && f->reason == reason;
}

void ParserCases() {
  Expect(std::holds_alternative<std::array<std::uint8_t,16>>(detail::ParseBootUuid(boot)), "valid UUID");
  for (const std::string s : {"01234567-89AB-cdef-0123-456789abcdef", " 01234567-89ab-cdef-0123-456789abcdef", "01234567-89ab-cdef-0123-456789abcdef\n\n"})
    Expect(IsError(detail::ParseBootUuid(s), ClockFailureReason::MalformedBootUuid), "strict UUID grammar");
  Expect(IsError(detail::ParseBootUuid(std::string(65,'0')), ClockFailureReason::InputTooLong), "UUID bound");
  const auto max_off = detail::ParseTimeOffsets("monotonic -9223372036854775808 999999999\t\nboottime 9223372036854775807 0");
  Expect(std::holds_alternative<detail::TimeOffsets>(max_off), "int64 offset endpoints and whitespace");
  const std::array<std::string,13> bad{{
    "monotonic +1 0\nboottime 0 0", "monotonic -0 0\nboottime 0 0",
    "monotonic 01 0\nboottime 0 0", "monotonic 0 00\nboottime 0 0",
    "monotonic 0 1000000000\nboottime 0 0", "monotonic 0 4294967296\nboottime 0 0",
    "monotonic 9223372036854775808 0\nboottime 0 0", "monotonic 0 0\r\nboottime 0 0",
    "monotonic 0 0\n\nboottime 0 0", "monotonic 0 0\nmonotonic 1 0",
    "monotonic 0 0\nboottime 0 0 extra", "monotonic 0 0\nunknown 0 0",
    std::string("monotonic 0 0\nboottime 0 0").append(1, '\0')}};
  for (const auto& s : bad) Expect(std::holds_alternative<ClockFailure>(detail::ParseTimeOffsets(s)), "malformed offset input rejected");
  Expect(IsError(detail::ParseTimeOffsets(std::string(513,'x')), ClockFailureReason::InputTooLong), "offset bound");
  char temp_path[] = "/tmp/rateguard-clock-XXXXXX";
  const int temp_fd = ::mkstemp(temp_path);
  Expect(temp_fd >= 0, "unique temporary file created");
  if (temp_fd < 0) return;
  if (temp_fd >= 0) ::close(temp_fd);
  const std::string path(temp_path);
  { std::ofstream file(path, std::ios::binary | std::ios::trunc); file << std::string(64, 'x'); }
  const auto exact_file = detail::ReadBoundedFile(path.c_str(),64);
  Expect(std::get_if<std::string>(&exact_file) != nullptr, "bounded reader accepts exact limit");
  { std::ofstream file(path, std::ios::binary | std::ios::trunc); file << std::string(65, 'x'); }
  Expect(IsError(detail::ReadBoundedFile(path.c_str(),64),ClockFailureReason::InputTooLong),
         "bounded reader detects one byte over limit");
  ::unlink(path.c_str());
}

void IdentityCases() {
  auto p = std::make_unique<Platform>();
  auto ok = Create(std::move(p));
  Expect(std::holds_alternative<std::unique_ptr<LinuxMonotonicClock>>(ok), "matching manifest identity starts");
  for (int field=0; field<8; ++field) {
    auto e=expected;
    switch(field) {
      case 0:e.boot_uuid[15]^=1;break; case 1:e.namespace_device++;break; case 2:e.namespace_inode++;break;
      case 3:e.monotonic_offset_seconds++;break; case 4:e.monotonic_offset_nanoseconds++;break;
      case 5:e.boottime_offset_seconds++;break; case 6:e.boottime_offset_nanoseconds++;break; default:e.clock_id=2;
    }
    Expect(IsError(Create(std::make_unique<Platform>(),e), ClockFailureReason::ExpectedIdentityMismatch), "all manifest identity fields compared");
  }
  auto wrong_clock=std::make_unique<Platform>(); wrong_clock->clock_id=99;
  auto wrong_expected=expected; wrong_expected.clock_id=99;
  Expect(IsError(Create(std::move(wrong_clock),wrong_expected),ClockFailureReason::ExpectedIdentityMismatch),
         "factory rejects non-Linux CLOCK_MONOTONIC id even if manifest matches");
  auto p1=std::make_unique<Platform>(); p1->leader=false;
  Expect(IsError(Create(std::move(p1)),ClockFailureReason::NotProcessLeader),"nonleader rejected");
  auto p2=std::make_unique<Platform>(); p2->namespaces={{9,31},{9,32},{9,31},{9,31}};
  Expect(IsError(Create(std::move(p2)),ClockFailureReason::NamespaceChanged),"current and children namespace split rejected");
  auto p3=std::make_unique<Platform>(); p3->namespaces={{9,31},{9,31},{9,32},{9,31}};
  Expect(IsError(Create(std::move(p3)),ClockFailureReason::NamespaceChanged),"namespace change during offset snapshot rejected");
  auto regressed_after_start=std::make_unique<Platform>();
  regressed_after_start->samples={ClockReading{5,0},ClockReading{4,999'999'999}};
  auto started=Create(std::move(regressed_after_start));
  auto& started_clock=**std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&started);
  Expect(IsError(started_clock.Now(),ClockFailureReason::BackwardsSample),
         "successful factory sample is retained as first regression reference");
  auto failed_start=std::make_unique<Platform>();
  failed_start->samples={Error(ClockFailureReason::ClockSyscall)};
  Expect(IsError(Create(std::move(failed_start)),ClockFailureReason::ClockSyscall),
         "factory withholds readiness when initial clock sample fails");
  auto invalid_start=std::make_unique<Platform>();
  invalid_start->samples={ClockReading{-1,0}};
  Expect(IsError(Create(std::move(invalid_start)),ClockFailureReason::InvalidTimespec),
         "factory withholds readiness when initial clock sample is invalid");
}

void SampleCases() {
  constexpr std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
  constexpr std::int64_t max_seconds = static_cast<std::int64_t>(max/1'000'000'000ULL);
  constexpr std::int64_t max_nanos = static_cast<std::int64_t>(max%1'000'000'000ULL);
  auto p=std::make_unique<Platform>(); p->samples={ClockReading{0,0},ClockReading{max_seconds,max_nanos}};
  auto created=Create(std::move(p)); auto& c=**std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&created);
  auto endpoint=c.Now(); Expect(std::get_if<MonoNanos>(&endpoint)&&std::get<MonoNanos>(endpoint).value==max,"largest representable nanosecond timestamp accepted");

  auto p2=std::make_unique<Platform>(); p2->samples={ClockReading{0,0},ClockReading{max_seconds,max_nanos+1},ClockReading{8,0}};
  auto c2=Create(std::move(p2)); auto& clock=**std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&c2);
  Expect(IsError(clock.Now(),ClockFailureReason::NanosecondOverflow),"one beyond uint64 nanoseconds rejected");
  Expect(!clock.Healthy(),"overflow latches unhealthy");
  Expect(IsError(clock.Now(),ClockFailureReason::NanosecondOverflow),"failure remains sticky");

  auto p3=std::make_unique<Platform>(); p3->samples={ClockReading{9,0},ClockReading{10,0},ClockReading{9,999'999'999},ClockReading{11,0}};
  auto c3=Create(std::move(p3)); auto& clock3=**std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&c3);
  Expect(std::holds_alternative<MonoNanos>(clock3.Now()),"first sample succeeds");
  Expect(IsError(clock3.Now(),ClockFailureReason::BackwardsSample),"backward sample rejected, never clamped");
  Expect(IsError(clock3.Provenance(),ClockFailureReason::BackwardsSample),"provenance reports latched error");
  auto p4=std::make_unique<Platform>(); p4->samples={ClockReading{0,0},ClockReading{1,0},ClockReading{1,0}};
  auto c4=Create(std::move(p4)); auto& clock4=**std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&c4);
  Expect(std::holds_alternative<MonoNanos>(clock4.Now())&&std::holds_alternative<MonoNanos>(clock4.Now()),"equal readings are legal");
}
}
int main() { ParserCases(); IdentityCases(); SampleCases(); if(failures) return EXIT_FAILURE; std::cout<<"independent RG003 checks passed\n"; return EXIT_SUCCESS; }
