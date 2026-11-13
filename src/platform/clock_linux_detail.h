#pragma once

#include "platform/clock.h"

#include <string_view>

namespace rateguard::platform::detail {

struct NamespaceFileIdentity {
  std::uint64_t device;
  std::uint64_t inode;
  friend constexpr bool operator==(NamespaceFileIdentity,
                                   NamespaceFileIdentity) = default;
};

struct TimeOffsets {
  std::int64_t monotonic_seconds;
  std::uint32_t monotonic_nanoseconds;
  std::int64_t boottime_seconds;
  std::uint32_t boottime_nanoseconds;
};

[[nodiscard]] ClockResult<std::array<std::uint8_t, 16>> ParseBootUuid(
    std::string_view input);
[[nodiscard]] ClockResult<TimeOffsets> ParseTimeOffsets(std::string_view input);
[[nodiscard]] ClockResult<std::string> ReadBoundedFile(const char* path,
                                                       std::size_t maximum_bytes);
// Internal smoke-test probe only. Production callers must use CreateLinuxClock
// with a trusted epoch-manifest identity.
[[nodiscard]] ClockResult<ClockIdentity> ProbeCurrentLinuxClockIdentity();

}  // namespace rateguard::platform::detail
