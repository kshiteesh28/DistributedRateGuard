#include "rateguard/security/client_call_guard.h"

#include "policy/canonical_codec.h"

#include <algorithm>
#include <utility>

namespace rateguard::security {
namespace {

using Reason = ClientGuardFailureReason;
using Disposition = ClientGuardDisposition;
using Failure = ClientCallGuardFailure;

Failure CredentialFailure(Reason reason) noexcept {
  return {reason, Disposition::CredentialInvalid};
}
Failure DependencyFailure(Reason reason) noexcept {
  return {reason, Disposition::ApplicationUnavailable};
}

bool IsValidWallTime(WallTime value) noexcept {
  return value.unix_seconds >= 0 && value.nanoseconds < 1'000'000'000U;
}

bool IsConfiguredUri(std::string_view uri) noexcept {
  if (uri.empty() || uri.size() > 256 ||
      uri.find('\0') != std::string_view::npos) return false;
  return std::all_of(uri.begin(), uri.end(), [](unsigned char byte) {
    return byte <= 0x7f;
  });
}

bool PolicyBindingMatches(const CertificateRegistry& registry) {
  const auto& policy = registry.policy();
  if (registry.epoch_id() != policy.epoch_id() ||
      registry.authority_incarnation() != policy.authority_incarnation() ||
      registry.root_der_sha256() != policy.trust_root_sha256()) return false;
  const auto digest = policy::CanonicalPolicyCodec::Digest(policy);
  const auto* value = std::get_if<policy::Digest32>(&digest);
  return value != nullptr && *value == registry.policy_digest();
}

bool HasRole(const CertificateRegistry& registry, std::string_view uri,
             PeerRole expected) noexcept {
  const auto* certificate = registry.Find(uri);
  const auto* principal = registry.policy().FindPrincipal(uri);
  if (certificate == nullptr || principal == nullptr) return false;
  if (certificate->peer.role != expected) return false;
  switch (expected) {
    case PeerRole::kAdapter:
      return principal->role == policy::PrincipalRole::Adapter &&
             !principal->slot_id.has_value();
    case PeerRole::kReplica: {
      if (principal->role != policy::PrincipalRole::Replica || !principal->slot_id)
        return false;
      return std::any_of(registry.policy().replica_slots().begin(),
                         registry.policy().replica_slots().end(),
                         [&](const policy::ReplicaSlot& slot) {
                           return slot.slot_id == *principal->slot_id;
                         });
    }
    case PeerRole::kAuthority:
      return principal->role == policy::PrincipalRole::Authority &&
             !principal->slot_id.has_value();
  }
  return false;
}

std::pair<PeerRole, PeerRole> ExpectedRoles(ClientCallPurpose purpose) noexcept {
  switch (purpose) {
    case ClientCallPurpose::AdapterToReplicaAdmission:
      return {PeerRole::kAdapter, PeerRole::kReplica};
    case ClientCallPurpose::ReplicaToAuthority:
      return {PeerRole::kReplica, PeerRole::kAuthority};
  }
  return {static_cast<PeerRole>(0), static_cast<PeerRole>(0)};
}

Reason ExpiryReason(const CertificateValidityWindow& window, WallTime now,
                    Reason before, Reason after) noexcept {
  return now < window.not_before ? before : after;
}

}  // namespace

std::variant<ClientCallGuard, ClientCallGuardFailure> ClientCallGuard::Create(
    std::shared_ptr<const CertificateRegistry> registry,
    ITrustedWallClock& trusted_clock, ClientCallPurpose purpose,
    std::string local_uri, std::string expected_server_uri) {
  if (!registry) return DependencyFailure(Reason::NullRegistry);
  if (!IsConfiguredUri(local_uri)) return CredentialFailure(Reason::InvalidClientIdentity);
  if (!IsConfiguredUri(expected_server_uri))
    return CredentialFailure(Reason::InvalidServerIdentity);
  try {
    if (!PolicyBindingMatches(*registry))
      return DependencyFailure(Reason::PolicyBindingMismatch);
    const auto roles = ExpectedRoles(purpose);
    if (roles.first == static_cast<PeerRole>(0))
      return CredentialFailure(Reason::InvalidClientIdentity);
    if (!registry->Find(local_uri))
      return CredentialFailure(Reason::MissingClientCertificate);
    if (!registry->Find(expected_server_uri))
      return CredentialFailure(Reason::MissingServerCertificate);
    if (!HasRole(*registry, local_uri, roles.first))
      return CredentialFailure(Reason::ClientRoleMismatch);
    if (!HasRole(*registry, expected_server_uri, roles.second))
      return CredentialFailure(Reason::ServerRoleMismatch);

    auto binding = std::make_shared<const detail::ClientCallBinding>(
        detail::ClientCallBinding{registry, registry->epoch_id(),
                                  registry->policy_digest(), purpose,
                                  std::move(local_uri),
                                  std::move(expected_server_uri)});
    const ClientCallGuard guard(std::move(binding), trusted_clock);
    return std::variant<ClientCallGuard, ClientCallGuardFailure>(
        std::in_place_index<0>, guard);
  } catch (...) {
    return DependencyFailure(Reason::DependencyFailure);
  }
}

std::variant<WallTime, ClientCallGuardFailure>
ClientCallGuard::ValidateCurrentTime() const {
  if (!binding_ || !binding_->registry)
    return DependencyFailure(Reason::PolicyBindingMismatch);
  if (!trusted_clock_.Healthy()) return DependencyFailure(Reason::ClockUntrusted);
  const auto time_result = trusted_clock_.Now();
  const auto* now = std::get_if<WallTime>(&time_result);
  if (now == nullptr || !trusted_clock_.Healthy())
    return DependencyFailure(Reason::ClockUntrusted);
  if (!IsValidWallTime(*now)) return DependencyFailure(Reason::InvalidWallTime);

  const auto& registry = *binding_->registry;
  if (!registry.root_validity().Contains(*now))
    return CredentialFailure(ExpiryReason(registry.root_validity(), *now,
        Reason::RootNotYetValid, Reason::RootExpired));
  const auto* local = registry.Find(binding_->local_uri);
  if (local == nullptr) return CredentialFailure(Reason::MissingClientCertificate);
  if (!local->validity.Contains(*now))
    return CredentialFailure(ExpiryReason(local->validity, *now,
        Reason::ClientNotYetValid, Reason::ClientExpired));
  const auto* server = registry.Find(binding_->expected_server_uri);
  if (server == nullptr) return CredentialFailure(Reason::MissingServerCertificate);
  if (!server->validity.Contains(*now))
    return CredentialFailure(ExpiryReason(server->validity, *now,
        Reason::ServerNotYetValid, Reason::ServerExpired));
  return *now;
}

std::variant<PreparedClientCall, ClientCallGuardFailure>
ClientCallGuard::ValidateBeforeCall() const {
  try {
    const auto time_result = ValidateCurrentTime();
    const auto* now = std::get_if<WallTime>(&time_result);
    if (now == nullptr)
      return std::get<ClientCallGuardFailure>(time_result);
    auto payload = std::make_shared<const detail::ClientCallProofPayload>(
        detail::ClientCallProofPayload{binding_, *now});
    const PreparedClientCall prepared(std::move(payload));
    return std::variant<PreparedClientCall, ClientCallGuardFailure>(
        std::in_place_index<0>, prepared);
  } catch (...) {
    return DependencyFailure(Reason::DependencyFailure);
  }
}

std::variant<ClientCallGuardPassed, ClientCallGuardFailure>
ClientCallGuard::ValidateBeforeForward(const PreparedClientCall& prepared) const {
  try {
    if (!binding_ || !prepared.payload_ ||
        prepared.payload_->binding.get() != binding_.get() ||
        !prepared.payload_->binding ||
        prepared.payload_->binding->registry.get() != binding_->registry.get() ||
        prepared.payload_->binding->epoch_id != binding_->epoch_id ||
        prepared.payload_->binding->policy_digest != binding_->policy_digest ||
        prepared.payload_->binding->purpose != binding_->purpose ||
        prepared.payload_->binding->local_uri != binding_->local_uri ||
        prepared.payload_->binding->expected_server_uri != binding_->expected_server_uri ||
        !IsValidWallTime(prepared.payload_->checked_at))
      return CredentialFailure(Reason::ForeignPreparedCall);

    const auto time_result = ValidateCurrentTime();
    const auto* now = std::get_if<WallTime>(&time_result);
    if (now == nullptr)
      return std::get<ClientCallGuardFailure>(time_result);
    if (*now < prepared.payload_->checked_at)
      return DependencyFailure(Reason::ClockUntrusted);
    auto payload = std::make_shared<const detail::ClientCallProofPayload>(
        detail::ClientCallProofPayload{binding_, *now});
    const ClientCallGuardPassed passed(std::move(payload));
    return std::variant<ClientCallGuardPassed, ClientCallGuardFailure>(
        std::in_place_index<0>, passed);
  } catch (...) {
    return DependencyFailure(Reason::DependencyFailure);
  }
}

}  // namespace rateguard::security
