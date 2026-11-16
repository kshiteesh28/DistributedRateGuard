#pragma once

#include "rateguard/v1/error_contract.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <variant>

namespace rateguard::security {

struct WallTime {
  std::int64_t unix_seconds;
  std::uint32_t nanoseconds;
  friend constexpr bool operator==(WallTime, WallTime) = default;
  friend constexpr bool operator<(WallTime lhs, WallTime rhs) noexcept {
    return lhs.unix_seconds < rhs.unix_seconds ||
           (lhs.unix_seconds == rhs.unix_seconds &&
            lhs.nanoseconds < rhs.nanoseconds);
  }
};

struct SynchronizationStatus {
  std::int32_t state;
  std::uint64_t flags;
};

struct RawWallTime {
  std::int64_t seconds;
  std::int64_t nanoseconds;
};

enum class TrustedWallClockFailureReason : std::uint8_t {
  SynchronizationSyscall,
  RealtimeSyscall,
  PlatformUnavailable,
  TimeErrorState,
  UnknownState,
  UnsynchronizedFlag,
  ClockErrorFlag,
  InvalidSeconds,
  InvalidNanoseconds,
  BackwardsRead,
  LatchedFailure,
};

struct TrustedWallClockFailure {
  TrustedWallClockFailureReason reason;

  // The clock cannot infer whether its caller has committed quota or may
  // already have returned ALLOW. The operation layer supplies that phase.
  [[nodiscard]] rateguard::v1::contract::ServiceError ToServiceError(
      rateguard::v1::contract::Commitment phase_commitment) const noexcept;
};

template <class T>
using TrustedWallClockResult = std::variant<T, TrustedWallClockFailure>;

class ITrustedWallClock {
 public:
  virtual ~ITrustedWallClock() = default;
  [[nodiscard]] virtual TrustedWallClockResult<WallTime> Now() = 0;
  [[nodiscard]] virtual bool Healthy() const = 0;
};

class ITrustedWallClockPlatform {
 public:
  virtual ~ITrustedWallClockPlatform() = default;
  // Read-only synchronization query. Implementations must not change clock state.
  [[nodiscard]] virtual TrustedWallClockResult<SynchronizationStatus>
  ReadSynchronization() = 0;
  [[nodiscard]] virtual TrustedWallClockResult<RawWallTime> ReadRealtime() = 0;
};

class NativeTrustedWallClockPlatform final : public ITrustedWallClockPlatform {
 public:
  [[nodiscard]] TrustedWallClockResult<SynchronizationStatus>
  ReadSynchronization() override;
  [[nodiscard]] TrustedWallClockResult<RawWallTime> ReadRealtime() override;
};

class TrustedWallClock final : public ITrustedWallClock {
 public:
  [[nodiscard]] static TrustedWallClockResult<std::unique_ptr<TrustedWallClock>>
  Create(std::unique_ptr<ITrustedWallClockPlatform> platform);

  [[nodiscard]] TrustedWallClockResult<WallTime> Now() override;
  [[nodiscard]] bool Healthy() const override;

 private:
  explicit TrustedWallClock(std::unique_ptr<ITrustedWallClockPlatform> platform);
  [[nodiscard]] TrustedWallClockFailure Latch(
      TrustedWallClockFailureReason reason);
  [[nodiscard]] TrustedWallClockFailure CurrentFailure() const;

  std::unique_ptr<ITrustedWallClockPlatform> platform_;
  mutable std::mutex mutex_;
  bool healthy_{false};
  bool failed_{false};
  std::optional<WallTime> last_sample_;
  TrustedWallClockFailure failure_;
};

// Names are stable diagnostic labels for bounded probe JSON; no raw diagnostics.
[[nodiscard]] const char* FailureReasonName(
    TrustedWallClockFailureReason reason) noexcept;

}  // namespace rateguard::security
