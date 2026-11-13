#pragma once

#include "platform/clock.h"
#include "platform/clock_linux_detail.h"

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <variant>

namespace rateguard::platform {

struct ClockReading {
  std::int64_t seconds;
  std::int64_t nanoseconds;
};

// Internal platform seam. Production uses Linux syscalls/procfs; deterministic
// tests inject a fake. It is not an application service interface.
class IClockPlatform {
 public:
  virtual ~IClockPlatform() = default;
  [[nodiscard]] virtual ClockResult<bool> IsProcessLeader() = 0;
  [[nodiscard]] virtual ClockResult<std::string> ReadBootUuidFile() = 0;
  [[nodiscard]] virtual ClockResult<detail::NamespaceFileIdentity>
  StatTimeNamespace(bool children) = 0;
  [[nodiscard]] virtual ClockResult<std::string> ReadTimeOffsetsFile() = 0;
  [[nodiscard]] virtual ClockResult<std::int32_t> MonotonicClockId() = 0;
  [[nodiscard]] virtual ClockResult<ClockReading> ReadMonotonic() = 0;
};

class LinuxMonotonicClock final : public IClock {
 public:
  [[nodiscard]] static ClockResult<std::unique_ptr<LinuxMonotonicClock>> Create(
      const ClockIdentity& trusted_expected_identity,
      std::unique_ptr<IClockPlatform> platform);

  [[nodiscard]] ClockResult<MonoNanos> Now() override;
  [[nodiscard]] ClockResult<ClockIdentity> Provenance() override;
  [[nodiscard]] bool Healthy() const override;

 private:
  LinuxMonotonicClock(ClockIdentity identity,
                      std::unique_ptr<IClockPlatform> platform);
  [[nodiscard]] ClockFailure Latch(ClockFailureReason reason);
  [[nodiscard]] ClockFailure CurrentFailure() const;

  const ClockIdentity identity_;
  std::unique_ptr<IClockPlatform> platform_;
  mutable std::mutex mutex_;
  bool healthy_{false};
  bool failed_{false};
  std::optional<MonoNanos> last_sample_;
  ClockFailure failure_;
};

// Production factory helper is intentionally internal and always requires a
// trusted manifest identity; no API self-authorizes from a host probe.
[[nodiscard]] ClockResult<std::unique_ptr<LinuxMonotonicClock>> CreateLinuxClock(
    const ClockIdentity& trusted_expected_identity);

}  // namespace rateguard::platform
