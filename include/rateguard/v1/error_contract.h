#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace rateguard::v1::contract {

enum class Commitment : std::uint8_t {
  NotCommitted,
  Possible,
  Committed,
};

enum class RetryDisposition : std::uint8_t {
  Never,
  NewAttempt,
  SameGrantSequence,
};

enum class ErrorCategory : std::uint8_t {
  Input,
  Authentication,
  Authorization,
  Capacity,
  Dependency,
  Deadline,
  Internal,
};

enum class ErrorCode : std::uint8_t {
  InvalidArgument,
  Unauthenticated,
  PermissionDenied,
  PayloadTooLarge,
  Unavailable,
  DeadlineExceeded,
  Cancelled,
  Internal,
};

struct ServiceError {
  ErrorCategory category;
  ErrorCode code;
  RetryDisposition retry;
  Commitment commitment;
};

enum class GrpcStatus : std::uint8_t {
  Ok,
  InvalidArgument,
  Unauthenticated,
  PermissionDenied,
  ResourceExhausted,
  Unavailable,
  DeadlineExceeded,
  Cancelled,
  Internal,
};

// This maps structured input/authentication failures to gRPC status. Quota
// outcomes and structured UNAVAILABLE/OVERLOADED are application responses
// and must use gRPC OK; they are deliberately not mapped by this function.
[[nodiscard]] constexpr GrpcStatus StatusFor(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::InvalidArgument:
      return GrpcStatus::InvalidArgument;
    case ErrorCode::Unauthenticated:
      return GrpcStatus::Unauthenticated;
    case ErrorCode::PermissionDenied:
      return GrpcStatus::PermissionDenied;
    case ErrorCode::PayloadTooLarge:
      return GrpcStatus::ResourceExhausted;
    case ErrorCode::Unavailable:
      return GrpcStatus::Unavailable;
    case ErrorCode::DeadlineExceeded:
      return GrpcStatus::DeadlineExceeded;
    case ErrorCode::Cancelled:
      return GrpcStatus::Cancelled;
    case ErrorCode::Internal:
      return GrpcStatus::Internal;
  }
  return GrpcStatus::Internal;
}

enum class DispatchPhase : std::uint8_t {
  BeforeDispatch,
  Dispatched,
};

[[nodiscard]] constexpr Commitment CommitmentForTransportFailure(
    DispatchPhase phase) noexcept {
  return phase == DispatchPhase::BeforeDispatch ? Commitment::NotCommitted
                                                : Commitment::Possible;
}

enum class DecisionOutcome : std::uint32_t {
  Unspecified = 0,
  Allow = 1,
  Limited = 2,
  Invalid = 3,
  Unauthenticated = 4,
  Unavailable = 5,
  Overloaded = 6,
};

enum class GrantOutcome : std::uint32_t {
  Unspecified = 0,
  Granted = 1,
  Limited = 2,
  Invalid = 3,
  Unavailable = 4,
  Overloaded = 5,
};

enum class AdmissionMode : std::uint32_t {
  Unspecified = 0,
  Strict = 1,
  Credit = 2,
};

[[nodiscard]] constexpr bool IsKnownDecisionOutcome(std::uint32_t raw) noexcept {
  return raw >= static_cast<std::uint32_t>(DecisionOutcome::Allow) &&
         raw <= static_cast<std::uint32_t>(DecisionOutcome::Overloaded);
}

[[nodiscard]] constexpr bool IsKnownGrantOutcome(std::uint32_t raw) noexcept {
  return raw >= static_cast<std::uint32_t>(GrantOutcome::Granted) &&
         raw <= static_cast<std::uint32_t>(GrantOutcome::Overloaded);
}

[[nodiscard]] constexpr bool IsKnownAdmissionMode(std::uint32_t raw) noexcept {
  return raw >= static_cast<std::uint32_t>(AdmissionMode::Strict) &&
         raw <= static_cast<std::uint32_t>(AdmissionMode::Credit);
}

// A transport success alone is insufficient; only a timely, epoch-validated
// ALLOW is a forwarding permit. This helper intentionally checks only outcome.
[[nodiscard]] constexpr bool IsAllowOutcome(DecisionOutcome outcome) noexcept {
  return outcome == DecisionOutcome::Allow;
}

[[nodiscard]] inline bool IsValidIdentifier(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128) return false;
  for (const unsigned char c : value) {
    const bool alpha_num = (c >= 'A' && c <= 'Z') ||
                           (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9');
    if (!alpha_num && c != '_' && c != '.' && c != '-') return false;
  }
  return true;
}

[[nodiscard]] inline bool HasExactWidth(std::string_view bytes,
                                        std::size_t expected) noexcept {
  return bytes.size() == expected;
}

}  // namespace rateguard::v1::contract
