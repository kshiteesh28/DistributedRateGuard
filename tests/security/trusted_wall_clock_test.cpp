#include "security/trusted_wall_clock.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <variant>

using namespace rateguard::security;
namespace contract = rateguard::v1::contract;

namespace {
int failures = 0;
void Check(bool condition, const char* label) {
  if (!condition) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}
TrustedWallClockFailure Fail(TrustedWallClockFailureReason reason) {
  return {{contract::ErrorCategory::Dependency, contract::ErrorCode::Unavailable,
           contract::RetryDisposition::Never, contract::Commitment::NotCommitted},
          reason};
}

class FakePlatform final : public ITrustedWallClockPlatform {
 public:
  std::deque<TrustedWallClockResult<SynchronizationStatus>> syncs;
  std::deque<TrustedWallClockResult<RawWallTime>> times;
  std::atomic<std::size_t> sync_calls{0};
  std::atomic<std::size_t> realtime_calls{0};

  TrustedWallClockResult<SynchronizationStatus> ReadSynchronization() override {
    ++sync_calls;
    if (syncs.empty()) return SynchronizationStatus{0, 0};
    auto result = std::move(syncs.front());
    syncs.pop_front();
    return result;
  }
  TrustedWallClockResult<RawWallTime> ReadRealtime() override {
    ++realtime_calls;
    if (times.empty()) return RawWallTime{100, 0};
    auto result = std::move(times.front());
    times.pop_front();
    return result;
  }
};

TrustedWallClockResult<std::unique_ptr<TrustedWallClock>> Create(
    std::unique_ptr<FakePlatform> platform) {
  std::unique_ptr<ITrustedWallClockPlatform> erased(std::move(platform));
  return TrustedWallClock::Create(std::move(erased));
}

bool HasFailure(const auto& result, TrustedWallClockFailureReason reason) {
  const auto* failure = std::get_if<TrustedWallClockFailure>(&result);
  return failure && failure->reason == reason &&
         failure->service_error.category == contract::ErrorCategory::Dependency &&
         failure->service_error.code == contract::ErrorCode::Unavailable &&
         failure->service_error.retry == contract::RetryDisposition::Never &&
         failure->service_error.commitment == contract::Commitment::NotCommitted;
}

void TestAllowedAndRejectedStates() {
  for (std::int32_t state = 0; state <= 4; ++state) {
    auto fake = std::make_unique<FakePlatform>();
    fake->syncs = {SynchronizationStatus{state, 0}, SynchronizationStatus{state, 0}};
    fake->times = {RawWallTime{10, 50}, RawWallTime{10, 51}};
    auto created = Create(std::move(fake));
    Check(std::holds_alternative<std::unique_ptr<TrustedWallClock>>(created),
          "TIME_OK/INS/DEL/OOP/WAIT states accepted");
    if (auto* clock = std::get_if<std::unique_ptr<TrustedWallClock>>(&created)) {
      Check((*clock)->Healthy(), "healthy after initial trusted sample");
      auto now = (*clock)->Now();
      Check(std::get_if<WallTime>(&now) && std::get<WallTime>(now) == WallTime{10, 51},
            "trusted wall time sample returned exactly");
    }
  }
  auto time_error = std::make_unique<FakePlatform>();
  time_error->syncs = {SynchronizationStatus{5, 0}};
  Check(HasFailure(Create(std::move(time_error)),
                   TrustedWallClockFailureReason::TimeErrorState),
        "TIME_ERROR rejects factory");
  auto unknown = std::make_unique<FakePlatform>();
  unknown->syncs = {SynchronizationStatus{99, 0}};
  Check(HasFailure(Create(std::move(unknown)),
                   TrustedWallClockFailureReason::UnknownState),
        "unknown synchronization state rejects factory");
}

void TestStatusFlagsAndTypedErrors() {
  const std::array<std::pair<std::uint64_t, TrustedWallClockFailureReason>, 3> flags{{
      {0x0040, TrustedWallClockFailureReason::UnsynchronizedFlag},
      {0x1000, TrustedWallClockFailureReason::ClockErrorFlag},
      {0x1040, TrustedWallClockFailureReason::UnsynchronizedFlag},
  }};
  for (const auto& [bits, reason] : flags) {
    auto fake = std::make_unique<FakePlatform>();
    fake->syncs = {SynchronizationStatus{0, bits}};
    Check(HasFailure(Create(std::move(fake)), reason),
          "STA_UNSYNC/STA_CLOCKERR bits reject before realtime read");
  }

  auto sync_failure = std::make_unique<FakePlatform>();
  sync_failure->syncs = {Fail(TrustedWallClockFailureReason::SynchronizationSyscall)};
  auto sync_fail = Create(std::move(sync_failure));
  Check(HasFailure(sync_fail, TrustedWallClockFailureReason::SynchronizationSyscall),
        "synchronization syscall error is typed unavailable");

  auto realtime_failure = std::make_unique<FakePlatform>();
  realtime_failure->times = {Fail(TrustedWallClockFailureReason::RealtimeSyscall)};
  Check(HasFailure(Create(std::move(realtime_failure)),
                   TrustedWallClockFailureReason::RealtimeSyscall),
        "realtime syscall error rejects initial factory sample");
  Check(HasFailure(TrustedWallClock::Create(nullptr),
                   TrustedWallClockFailureReason::PlatformUnavailable),
        "missing platform is typed unavailable");
}

void TestRangeOrderingAndStickyFailure() {
  auto invalid_seconds = std::make_unique<FakePlatform>();
  invalid_seconds->times = {RawWallTime{-1, 0}};
  Check(HasFailure(Create(std::move(invalid_seconds)),
                   TrustedWallClockFailureReason::InvalidSeconds),
        "negative Unix seconds rejected");

  const std::array<std::int64_t, 2> invalid_nanos{-1, 1'000'000'000};
  for (std::int64_t nanos : invalid_nanos) {
    auto invalid = std::make_unique<FakePlatform>();
    invalid->times = {RawWallTime{100, nanos}};
    Check(HasFailure(Create(std::move(invalid)),
                     TrustedWallClockFailureReason::InvalidNanoseconds),
          "negative or out-of-range nanoseconds rejected");
  }

  auto extreme = std::make_unique<FakePlatform>();
  extreme->times = {RawWallTime{std::numeric_limits<std::int64_t>::max(),
                                999'999'999}};
  auto extreme_result = Create(std::move(extreme));
  Check(std::holds_alternative<std::unique_ptr<TrustedWallClock>>(extreme_result),
        "maximum int64 seconds do not overflow through nanosecond multiplication");

  auto equal = std::make_unique<FakePlatform>();
  equal->times = {RawWallTime{100, 200}, RawWallTime{100, 200}};
  auto equal_result = Create(std::move(equal));
  if (auto* clock = std::get_if<std::unique_ptr<TrustedWallClock>>(&equal_result))
    Check(std::holds_alternative<WallTime>((*clock)->Now()), "equal wall-time samples accepted");
  else
    Check(false, "equal sample clock created");

  auto backwards = std::make_unique<FakePlatform>();
  backwards->times = {RawWallTime{101, 0}, RawWallTime{100, 999'999'999},
                      RawWallTime{102, 0}};
  auto backwards_result = Create(std::move(backwards));
  auto& clock = *std::get<std::unique_ptr<TrustedWallClock>>(backwards_result);
  Check(HasFailure(clock.Now(), TrustedWallClockFailureReason::BackwardsRead),
        "lexicographically backward sample latches trust loss");
  Check(!clock.Healthy(), "backwards sample makes health false");
  Check(HasFailure(clock.Now(), TrustedWallClockFailureReason::BackwardsRead),
        "first failure remains sticky");
  Check(HasFailure(clock.Now(), TrustedWallClockFailureReason::BackwardsRead),
        "later recovery-looking data cannot restore trust");
}

void TestInitialFailureAndConcurrency() {
  auto bad_initial = std::make_unique<FakePlatform>();
  bad_initial->syncs = {SynchronizationStatus{1, 0}};
  bad_initial->times = {Fail(TrustedWallClockFailureReason::RealtimeSyscall)};
  Check(HasFailure(Create(std::move(bad_initial)),
                   TrustedWallClockFailureReason::RealtimeSyscall),
        "factory returns no usable object if initial realtime read fails");

  constexpr std::size_t count = 24;
  auto concurrent = std::make_unique<FakePlatform>();
  for (std::size_t i = 0; i <= count; ++i) {
    concurrent->syncs.emplace_back(SynchronizationStatus{0, 0});
    concurrent->times.emplace_back(RawWallTime{1000 + static_cast<std::int64_t>(i), 0});
  }
  auto result = Create(std::move(concurrent));
  auto& clock = *std::get<std::unique_ptr<TrustedWallClock>>(result);
  std::array<bool, count> successful{};
  std::array<WallTime, count> values{};
  std::array<std::thread, count> threads;
  for (std::size_t i = 0; i < count; ++i) {
    threads[i] = std::thread([&, i] {
      auto value = clock.Now();
      if (const auto* time = std::get_if<WallTime>(&value)) {
        values[i] = *time;
        successful[i] = true;
      }
    });
  }
  for (auto& thread : threads) thread.join();
  for (bool ok : successful) Check(ok, "concurrent trusted wall-time sample succeeds");
  std::sort(values.begin(), values.end(), [](WallTime lhs, WallTime rhs) { return lhs < rhs; });
  for (std::size_t i = 0; i < count; ++i)
    Check(values[i] == WallTime{1001 + static_cast<std::int64_t>(i), 0},
          "mutex serializes synchronization/read/compare sequence");
  Check(clock.Healthy(), "concurrent sequence stays trusted");
}
}  // namespace

int main() {
  TestAllowedAndRejectedStates();
  TestStatusFlagsAndTypedErrors();
  TestRangeOrderingAndStickyFailure();
  TestInitialFailureAndConcurrency();
  if (failures != 0) return EXIT_FAILURE;
  std::cout << "trusted wall clock checks passed\n";
  return EXIT_SUCCESS;
}
