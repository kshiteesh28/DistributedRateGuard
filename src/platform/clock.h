#pragma once

#include "rateguard/v1/error_contract.h"

#include <array>
#include <cstdint>
#include <variant>

namespace rateguard::platform {

struct MonoNanos {
  std::uint64_t value;
  friend constexpr bool operator==(MonoNanos, MonoNanos) = default;
};

struct ClockIdentity {
  std::array<std::uint8_t, 16> boot_uuid;
  std::uint64_t namespace_device;
  std::uint64_t namespace_inode;
  std::int64_t monotonic_offset_seconds;
  std::uint32_t monotonic_offset_nanoseconds;
  std::int64_t boottime_offset_seconds;
  std::uint32_t boottime_offset_nanoseconds;
  std::int32_t clock_id;
  friend constexpr bool operator==(const ClockIdentity&, const ClockIdentity&) = default;
};

enum class ClockFailureReason : std::uint8_t {
  PlatformRead,
  MalformedBootUuid,
  MalformedOffsets,
  OffsetOutOfRange,
  InputTooLong,
  NotProcessLeader,
  NamespaceStat,
  NamespaceChanged,
  ExpectedIdentityMismatch,
  ClockSyscall,
  InvalidTimespec,
  NanosecondOverflow,
  BackwardsSample,
  LatchedFailure,
};

struct ClockFailure {
  rateguard::v1::contract::ServiceError service_error;
  ClockFailureReason reason;
};

template <class T>
using ClockResult = std::variant<T, ClockFailure>;

class IClock {
 public:
  virtual ~IClock() = default;
  [[nodiscard]] virtual ClockResult<MonoNanos> Now() = 0;
  [[nodiscard]] virtual ClockResult<ClockIdentity> Provenance() = 0;
  [[nodiscard]] virtual bool Healthy() const = 0;
};

}  // namespace rateguard::platform
