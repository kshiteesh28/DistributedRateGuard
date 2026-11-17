#include "rateguard/security/authorization_resolver.h"

#include "policy/canonical_codec.h"
#include "rateguard/v1/error_contract.h"
#include "rateguard/v1/request_validation.h"

#include <algorithm>
#include <string_view>
#include <utility>

namespace rateguard::security {
namespace {

using Reason = AuthorizationFailureReason;
using Disposition = AuthorizationDisposition;
using Failure = AuthorizationFailure;

Failure Invalid(Reason reason = Reason::InvalidRequest) noexcept {
  return {reason, Disposition::InvalidArgument};
}
Failure Denied(Reason reason) noexcept {
  return {reason, Disposition::PermissionDenied};
}
Failure Unauthenticated(Reason reason) noexcept {
  return {reason, Disposition::Unauthenticated};
}
Failure Unavailable(Reason reason) noexcept {
  return {reason, Disposition::ApplicationUnavailable};
}

bool BytesEqual(std::string_view bytes, const policy::Id16& expected) noexcept {
  return bytes.size() == expected.size() &&
         std::equal(bytes.begin(), bytes.end(), expected.begin(),
                    [](char actual, std::uint8_t value) {
                      return static_cast<unsigned char>(actual) == value;
                    });
}
bool BytesEqual(std::string_view bytes, const policy::Digest32& expected) noexcept {
  return bytes.size() == expected.size() &&
         std::equal(bytes.begin(), bytes.end(), expected.begin(),
                    [](char actual, std::uint8_t value) {
                      return static_cast<unsigned char>(actual) == value;
                    });
}

bool IsValidWallTime(WallTime value) noexcept {
  return value.unix_seconds >= 0 && value.nanoseconds < 1'000'000'000U;
}

PeerRole ToPeerRole(policy::PrincipalRole role) noexcept {
  switch (role) {
    case policy::PrincipalRole::Adapter: return PeerRole::kAdapter;
    case policy::PrincipalRole::Replica: return PeerRole::kReplica;
    case policy::PrincipalRole::Authority: return PeerRole::kAuthority;
  }
  return static_cast<PeerRole>(0);
}

bool IsPolicyBindingValid(const CertificateRegistry& registry) {
  const auto& snapshot = registry.policy();
  if (registry.epoch_id() != snapshot.epoch_id() ||
      registry.authority_incarnation() != snapshot.authority_incarnation() ||
      registry.root_der_sha256() != snapshot.trust_root_sha256()) return false;
  const auto digest = policy::CanonicalPolicyCodec::Digest(snapshot);
  const auto* value = std::get_if<policy::Digest32>(&digest);
  return value != nullptr && *value == registry.policy_digest();
}

}  // namespace

std::variant<AuthorizationResolver, AuthorizationFailure>
AuthorizationResolver::Create(std::shared_ptr<const CertificateRegistry> registry,
                              ITrustedWallClock& trusted_clock) {
  if (!registry) return Unavailable(Reason::NullRegistry);
  try {
    if (!IsPolicyBindingValid(*registry)) return Unavailable(Reason::PolicyBindingMismatch);
    return AuthorizationResolver(std::move(registry), trusted_clock);
  } catch (...) {
    return Unavailable(Reason::PolicyBindingMismatch);
  }
}

std::optional<AuthorizationFailure> AuthorizationResolver::CheckPeerAndClock(
    const AuthenticatedPeer& peer) const {
  if (!registry_) return Unavailable(Reason::NullRegistry);
  if (peer.registry().get() != registry_.get())
    return Unauthenticated(Reason::MixedRegistry);
  const auto* registered = registry_->Find(peer.uri());
  if (registered == nullptr || registered != peer.certificate() ||
      registered->peer.role != peer.role())
    return Unauthenticated(Reason::MixedRegistry);

  if (!trusted_clock_.Healthy()) return Unavailable(Reason::ClockUntrusted);
  auto time_result = trusted_clock_.Now();
  const auto* now = std::get_if<WallTime>(&time_result);
  if (now == nullptr || !trusted_clock_.Healthy() || !IsValidWallTime(*now))
    return Unavailable(Reason::ClockUntrusted);
  if (!registry_->root_validity().Contains(*now))
    return Unauthenticated(*now < registry_->root_validity().not_before
                               ? Reason::CertificateNotYetValid
                               : Reason::CertificateExpired);
  if (!registered->validity.Contains(*now))
    return Unauthenticated(*now < registered->validity.not_before
                               ? Reason::CertificateNotYetValid
                               : Reason::CertificateExpired);
  return std::nullopt;
}

std::variant<AuthorizedOperation, AuthorizationFailure>
AuthorizationResolver::Resolve(
    const AuthenticatedPeer& peer, RpcMethod method,
    const rateguard::v1::CheckAdmissionRequest& request) const noexcept {
  try {
    if (const auto failure = CheckPeerAndClock(peer)) return *failure;
    const auto& snapshot = registry_->policy();
    if (method == RpcMethod::AdapterCheckAdmission) {
      if (peer.role() != PeerRole::kAdapter)
        return Denied(Reason::MethodRoleMismatch);
    } else if (method == RpcMethod::ReplicaStrictCheck) {
      if (peer.role() != PeerRole::kReplica)
        return Denied(Reason::MethodRoleMismatch);
    } else {
      return Invalid(Reason::InvalidRequest);
    }
    const auto& epoch = snapshot.epoch_id();
    const auto& digest = registry_->policy_digest();
    if (request.ByteSizeLong() > rateguard::v1::validation::kMaxRequestBytes ||
        !rateguard::v1::contract::IsValidIdentifier(request.tenant_id()) ||
        !rateguard::v1::contract::IsValidIdentifier(request.operation_id()) ||
        request.attempt_id().size() != 16 || request.epoch_id().size() != 16 ||
        request.policy_digest().size() != 32)
      return Invalid();
    if (!BytesEqual(request.epoch_id(), epoch) ||
        !BytesEqual(request.policy_digest(), digest))
      return Invalid(Reason::PolicyBindingMismatch);
    if (method == RpcMethod::ReplicaStrictCheck &&
        snapshot.mode() != policy::Mode::Strict)
      return Invalid(Reason::ModeMismatch);

    const auto* tenant = snapshot.FindTenant(request.tenant_id());
    if (tenant == nullptr) return Invalid(Reason::UnknownTenant);
    const auto* operation = tenant->FindOperation(request.operation_id());
    if (operation == nullptr) return Invalid(Reason::UnknownOperation);

    const auto* principal = snapshot.FindPrincipal(peer.uri());
    if (principal == nullptr || ToPeerRole(principal->role) != peer.role())
      return Denied(Reason::MethodRoleMismatch);
    if (!snapshot.IsAuthorized(peer.uri(), principal->role,
                               request.tenant_id(), request.operation_id()))
      return Denied(Reason::UnauthorizedPair);

    const std::optional<std::uint32_t> replica_slot = principal->slot_id;
    std::optional<policy::Id16> replica_incarnation;
    if (method == RpcMethod::ReplicaStrictCheck &&
        (!principal->slot_id || principal->role != policy::PrincipalRole::Replica))
      return Unavailable(Reason::PolicyBindingMismatch);
    if (principal->role == policy::PrincipalRole::Replica) {
      if (!principal->slot_id)
        return Unavailable(Reason::PolicyBindingMismatch);
      const auto slot = std::find_if(snapshot.replica_slots().begin(),
          snapshot.replica_slots().end(), [&](const policy::ReplicaSlot& value) {
            return value.slot_id == *principal->slot_id;
          });
      if (slot == snapshot.replica_slots().end())
        return Unavailable(Reason::PolicyBindingMismatch);
      replica_incarnation = slot->incarnation_id;
    }
    auto payload = std::make_shared<const AuthorizedOperation::Payload>(
        peer, method, request.tenant_id(), request.operation_id(),
        operation->cost_units, snapshot.mode(), request.attempt_id(),
        snapshot.epoch_id(), digest, replica_slot, replica_incarnation);
    const AuthorizedOperation authorized(std::move(payload));
    return std::variant<AuthorizedOperation, AuthorizationFailure>(
        std::in_place_index<0>, authorized);
  } catch (...) {
    return Unavailable(Reason::PolicyBindingMismatch);
  }
}

std::variant<AuthorizedGrant, AuthorizationFailure>
AuthorizationResolver::Resolve(
    const AuthenticatedPeer& peer, RpcMethod method,
    const rateguard::v1::AcquireCreditRequest& request) const noexcept {
  try {
    if (const auto failure = CheckPeerAndClock(peer)) return *failure;
    const auto& snapshot = registry_->policy();
    if (method != RpcMethod::ReplicaAcquireCredit)
      return Invalid(Reason::InvalidRequest);
    if (peer.role() != PeerRole::kReplica)
      return Denied(Reason::MethodRoleMismatch);
    const auto& digest = registry_->policy_digest();
    if (request.ByteSizeLong() > rateguard::v1::validation::kMaxRequestBytes ||
        !rateguard::v1::contract::IsValidIdentifier(request.tenant_id()) ||
        !rateguard::v1::contract::IsValidIdentifier(request.trigger_operation_id()) ||
        request.incarnation_id().size() != 16 || request.epoch_id().size() != 16 ||
        request.policy_digest().size() != 32 || request.sequence() == 0)
      return Invalid();
    if (!BytesEqual(request.epoch_id(), snapshot.epoch_id()) ||
        !BytesEqual(request.policy_digest(), digest))
      return Invalid(Reason::PolicyBindingMismatch);
    if (snapshot.mode() != policy::Mode::Credit)
      return Invalid(Reason::ModeMismatch);

    const auto* principal = snapshot.FindPrincipal(peer.uri());
    if (principal == nullptr || principal->role != policy::PrincipalRole::Replica ||
        !principal->slot_id)
      return Denied(Reason::MethodRoleMismatch);
    if (*principal->slot_id != request.slot())
      return Invalid(Reason::ReplicaSlotMismatch);
    const auto slot = std::find_if(snapshot.replica_slots().begin(),
        snapshot.replica_slots().end(), [&](const policy::ReplicaSlot& value) {
          return value.slot_id == request.slot();
        });
    if (slot == snapshot.replica_slots().end())
      return Invalid(Reason::ReplicaSlotMismatch);
    if (!BytesEqual(request.incarnation_id(), slot->incarnation_id))
      return Invalid(Reason::ReplicaIncarnationMismatch);

    const auto* tenant = snapshot.FindTenant(request.tenant_id());
    if (tenant == nullptr) return Invalid(Reason::UnknownTenant);
    const auto* operation = tenant->FindOperation(request.trigger_operation_id());
    if (operation == nullptr) return Invalid(Reason::UnknownOperation);
    if (!snapshot.IsAuthorized(peer.uri(), principal->role,
                               request.tenant_id(), request.trigger_operation_id()))
      return Denied(Reason::UnauthorizedPair);
    if (request.trigger_cost_units() != operation->cost_units)
      return Invalid(Reason::TriggerCostMismatch);

    auto payload = std::make_shared<const AuthorizedGrant::Payload>(
        peer, method, request.tenant_id(), request.trigger_operation_id(),
        operation->cost_units, request.slot(), slot->incarnation_id,
        request.sequence(), snapshot.epoch_id(), digest);
    const AuthorizedGrant authorized(std::move(payload));
    return std::variant<AuthorizedGrant, AuthorizationFailure>(
        std::in_place_index<0>, authorized);
  } catch (...) {
    return Unavailable(Reason::PolicyBindingMismatch);
  }
}

}  // namespace rateguard::security
