#include "security/trusted_wall_clock.h"

#include <ctime>
#include <limits>
#include <utility>

#if defined(__linux__)
#include <sys/timex.h>
#endif

namespace rateguard::security {
namespace {
using rateguard::v1::contract::ErrorCategory;
using rateguard::v1::contract::ErrorCode;
using rateguard::v1::contract::RetryDisposition;

constexpr std::uint64_t kStaUnsync = 0x0040ULL;
constexpr std::uint64_t kStaClockError = 0x1000ULL;
constexpr std::int32_t kTimeOk = 0;
constexpr std::int32_t kTimeInsert = 1;
constexpr std::int32_t kTimeDelete = 2;
constexpr std::int32_t kTimeOops = 3;
constexpr std::int32_t kTimeWait = 4;
constexpr std::int32_t kTimeError = 5;
constexpr std::int64_t kMaxNanoseconds = 999'999'999;

TrustedWallClockFailure Failure(TrustedWallClockFailureReason reason) {
  return {reason};
}

std::optional<TrustedWallClockFailureReason> CheckSynchronization(
    SynchronizationStatus status) {
  switch (status.state) {
    case kTimeOk:
    case kTimeInsert:
    case kTimeDelete:
    case kTimeOops:
    case kTimeWait:
      break;
    case kTimeError:
      return TrustedWallClockFailureReason::TimeErrorState;
    default:
      return TrustedWallClockFailureReason::UnknownState;
  }
  if ((status.flags & kStaUnsync) != 0)
    return TrustedWallClockFailureReason::UnsynchronizedFlag;
  if ((status.flags & kStaClockError) != 0)
    return TrustedWallClockFailureReason::ClockErrorFlag;
  return std::nullopt;
}

}  // namespace

rateguard::v1::contract::ServiceError TrustedWallClockFailure::ToServiceError(
    rateguard::v1::contract::Commitment phase_commitment) const noexcept {
  return {ErrorCategory::Dependency, ErrorCode::Unavailable,
          RetryDisposition::Never, phase_commitment};
}

TrustedWallClock::TrustedWallClock(
    std::unique_ptr<ITrustedWallClockPlatform> platform)
    : platform_(std::move(platform)),
      failure_(Failure(TrustedWallClockFailureReason::LatchedFailure)) {}

TrustedWallClockResult<std::unique_ptr<TrustedWallClock>>
TrustedWallClock::Create(std::unique_ptr<ITrustedWallClockPlatform> platform) {
  if (!platform)
    return Failure(TrustedWallClockFailureReason::PlatformUnavailable);
  auto clock = std::unique_ptr<TrustedWallClock>(
      new TrustedWallClock(std::move(platform)));
  auto initial_sample = clock->Now();
  if (const auto* failure = std::get_if<TrustedWallClockFailure>(&initial_sample))
    return *failure;
  return clock;
}

TrustedWallClockFailure TrustedWallClock::Latch(
    TrustedWallClockFailureReason reason) {
  if (!failed_) {
    failed_ = true;
    healthy_ = false;
    failure_ = Failure(reason);
  }
  return failure_;
}

TrustedWallClockFailure TrustedWallClock::CurrentFailure() const {
  return failure_;
}

TrustedWallClockResult<WallTime> TrustedWallClock::Now() {
  std::lock_guard lock(mutex_);
  if (failed_) return CurrentFailure();

  auto synchronization = platform_->ReadSynchronization();
  if (const auto* error = std::get_if<TrustedWallClockFailure>(&synchronization))
    return Latch(error->reason);
  if (const auto problem = CheckSynchronization(
          std::get<SynchronizationStatus>(synchronization)))
    return Latch(*problem);

  auto realtime = platform_->ReadRealtime();
  if (const auto* error = std::get_if<TrustedWallClockFailure>(&realtime))
    return Latch(error->reason);
  const RawWallTime raw = std::get<RawWallTime>(realtime);
  if (raw.seconds < 0) return Latch(TrustedWallClockFailureReason::InvalidSeconds);
  if (raw.nanoseconds < 0 || raw.nanoseconds > kMaxNanoseconds)
    return Latch(TrustedWallClockFailureReason::InvalidNanoseconds);

  const WallTime sample{raw.seconds, static_cast<std::uint32_t>(raw.nanoseconds)};
  if (last_sample_ && sample < *last_sample_)
    return Latch(TrustedWallClockFailureReason::BackwardsRead);
  last_sample_ = sample;
  healthy_ = true;
  return sample;
}

bool TrustedWallClock::Healthy() const {
  std::lock_guard lock(mutex_);
  return healthy_ && !failed_;
}

TrustedWallClockResult<SynchronizationStatus>
NativeTrustedWallClockPlatform::ReadSynchronization() {
#if defined(__linux__)
  struct timex query {};
  query.modes = 0;  // Read-only query; never adjust kernel time or require CAP_SYS_TIME.
  const int state = ::adjtimex(&query);
  if (state < 0) return Failure(TrustedWallClockFailureReason::SynchronizationSyscall);
  return SynchronizationStatus{state,
                               static_cast<std::uint64_t>(
                                   static_cast<std::uint32_t>(query.status))};
#else
  return Failure(TrustedWallClockFailureReason::PlatformUnavailable);
#endif
}

TrustedWallClockResult<RawWallTime>
NativeTrustedWallClockPlatform::ReadRealtime() {
#if defined(__linux__)
  struct timespec reading {};
  if (::clock_gettime(CLOCK_REALTIME, &reading) != 0)
    return Failure(TrustedWallClockFailureReason::RealtimeSyscall);
  return RawWallTime{static_cast<std::int64_t>(reading.tv_sec),
                     static_cast<std::int64_t>(reading.tv_nsec)};
#else
  return Failure(TrustedWallClockFailureReason::PlatformUnavailable);
#endif
}

const char* FailureReasonName(TrustedWallClockFailureReason reason) noexcept {
  switch (reason) {
    case TrustedWallClockFailureReason::SynchronizationSyscall:
      return "synchronization_syscall";
    case TrustedWallClockFailureReason::RealtimeSyscall:
      return "realtime_syscall";
    case TrustedWallClockFailureReason::PlatformUnavailable:
      return "platform_unavailable";
    case TrustedWallClockFailureReason::TimeErrorState:
      return "time_error_state";
    case TrustedWallClockFailureReason::UnknownState:
      return "unknown_sync_state";
    case TrustedWallClockFailureReason::UnsynchronizedFlag:
      return "sta_unsync";
    case TrustedWallClockFailureReason::ClockErrorFlag:
      return "sta_clockerr";
    case TrustedWallClockFailureReason::InvalidSeconds:
      return "invalid_seconds";
    case TrustedWallClockFailureReason::InvalidNanoseconds:
      return "invalid_nanoseconds";
    case TrustedWallClockFailureReason::BackwardsRead:
      return "backwards_read";
    case TrustedWallClockFailureReason::LatchedFailure:
      return "latched_failure";
  }
  return "unknown_failure";
}

}  // namespace rateguard::security
