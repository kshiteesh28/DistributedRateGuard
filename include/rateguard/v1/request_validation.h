#pragma once

#include "proto/rateguard/v1/admission.pb.h"
#include "proto/rateguard/v1/authority.pb.h"
#include "rateguard/v1/error_contract.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace rateguard::v1::validation {

inline constexpr std::size_t kMaxRequestBytes = 16 * 1024;
inline constexpr std::size_t kMaxRegisteredReplicaSlots = 8;
inline constexpr std::uint64_t kMaxPolicyUnits = 1000000000ULL;

struct RegisteredReplicaSlot {
  std::uint32_t slot;
  std::string_view incarnation_id;
};

[[nodiscard]] inline std::optional<contract::ServiceError>
InvalidInput() noexcept {
  return contract::ServiceError{
      contract::ErrorCategory::Input,
      contract::ErrorCode::InvalidArgument,
      contract::RetryDisposition::Never,
      contract::Commitment::NotCommitted};
}

[[nodiscard]] inline std::optional<contract::ServiceError>
ValidateCheckAdmissionRequest(const CheckAdmissionRequest& request,
                              std::string_view configured_tenant,
                              std::string_view configured_operation,
                              std::string_view active_epoch_id,
                              std::string_view active_policy_digest) noexcept {
  if (!contract::IsValidIdentifier(request.tenant_id()) ||
      !contract::IsValidIdentifier(request.operation_id()) ||
      !contract::HasExactWidth(request.attempt_id(), 16) ||
      !contract::HasExactWidth(request.epoch_id(), 16) ||
      !contract::HasExactWidth(request.policy_digest(), 32) ||
      request.tenant_id() != configured_tenant ||
      request.operation_id() != configured_operation ||
      request.epoch_id() != active_epoch_id ||
      request.policy_digest() != active_policy_digest ||
      request.ByteSizeLong() > kMaxRequestBytes)
    return InvalidInput();
  return std::nullopt;
}

// Tenant, slot registry, active epoch/digest, and operation/cost values come
// from the immutable authenticated epoch policy. Authenticate the caller and
// enforce the transport message-size cap before parsing; this post-decode
// ByteSizeLong check is defense in depth. Do not mutate state on failure.
[[nodiscard]] inline std::optional<contract::ServiceError>
ValidateAcquireCreditRequest(
    const AcquireCreditRequest& request,
    std::span<const RegisteredReplicaSlot> registered_slots,
    std::string_view configured_tenant,
    std::string_view configured_operation,
    std::string_view active_epoch_id,
    std::string_view active_policy_digest,
    std::uint64_t configured_cost_units,
    std::uint64_t tenant_capacity_units) noexcept {
  const auto registered = std::find_if(
      registered_slots.begin(), registered_slots.end(),
      [&](const RegisteredReplicaSlot& slot) { return slot.slot == request.slot(); });
  if (registered_slots.size() > kMaxRegisteredReplicaSlots ||
      !contract::IsValidIdentifier(request.tenant_id()) ||
      !contract::IsValidIdentifier(request.trigger_operation_id()) ||
      request.tenant_id() != configured_tenant ||
      request.trigger_operation_id() != configured_operation ||
      registered == registered_slots.end() ||
      !contract::HasExactWidth(registered->incarnation_id, 16) ||
      !contract::HasExactWidth(request.incarnation_id(), 16) ||
      request.incarnation_id() != registered->incarnation_id ||
      !contract::HasExactWidth(request.epoch_id(), 16) ||
      !contract::HasExactWidth(request.policy_digest(), 32) ||
      request.epoch_id() != active_epoch_id ||
      request.policy_digest() != active_policy_digest ||
      request.sequence() == 0 ||
      tenant_capacity_units == 0 || tenant_capacity_units > kMaxPolicyUnits ||
      configured_cost_units == 0 || configured_cost_units > tenant_capacity_units ||
      request.trigger_cost_units() != configured_cost_units ||
      request.ByteSizeLong() > kMaxRequestBytes)
    return InvalidInput();
  return std::nullopt;
}

[[nodiscard]] constexpr bool IsKnownDecisionOutcome(std::uint32_t raw) noexcept {
  return contract::IsKnownDecisionOutcome(raw);
}
[[nodiscard]] constexpr bool IsKnownGrantOutcome(std::uint32_t raw) noexcept {
  return contract::IsKnownGrantOutcome(raw);
}
[[nodiscard]] constexpr bool IsKnownAdmissionMode(std::uint32_t raw) noexcept {
  return contract::IsKnownAdmissionMode(raw);
}

}  // namespace rateguard::v1::validation
