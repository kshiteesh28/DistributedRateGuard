#pragma once

#include "proto/rateguard/v1/admission.pb.h"
#include "proto/rateguard/v1/authority.pb.h"
#include "rateguard/security/peer_authenticator.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace rateguard::security {

enum class AuthorizationFailureReason : std::uint8_t {
  NullRegistry,
  PolicyBindingMismatch,
  MixedRegistry,
  ClockUntrusted,
  CertificateNotYetValid,
  CertificateExpired,
  InvalidRequest,
  UnknownTenant,
  UnknownOperation,
  MethodRoleMismatch,
  ModeMismatch,
  UnauthorizedPair,
  ReplicaSlotMismatch,
  ReplicaIncarnationMismatch,
  TriggerCostMismatch,
};

enum class AuthorizationDisposition : std::uint8_t {
  Unauthenticated,
  InvalidArgument,
  PermissionDenied,
  ApplicationUnavailable,
};

// Bounded reason only. The RPC handler maps disposition and supplies the
// operation's actual commitment phase when constructing a ServiceError.
struct AuthorizationFailure final {
  AuthorizationFailureReason reason;
  AuthorizationDisposition disposition;
};

class AuthorizationResolver;

class AuthorizedOperation final {
 public:
  AuthorizedOperation(const AuthorizedOperation&) = default;
  AuthorizedOperation& operator=(const AuthorizedOperation&) = default;
  [[nodiscard]] const std::string& tenant_id() const noexcept { return data_->tenant_id; }
  [[nodiscard]] const std::string& operation_id() const noexcept { return data_->operation_id; }
  [[nodiscard]] std::uint64_t cost_units() const noexcept { return data_->cost_units; }
  [[nodiscard]] policy::Mode mode() const noexcept { return data_->mode; }
  [[nodiscard]] const std::string& attempt_id() const noexcept { return data_->attempt_id; }
  [[nodiscard]] const policy::Id16& epoch_id() const noexcept { return data_->epoch_id; }
  [[nodiscard]] const policy::Digest32& policy_digest() const noexcept { return data_->policy_digest; }
  [[nodiscard]] const AuthenticatedPeer& peer() const noexcept { return data_->peer; }
  [[nodiscard]] RpcMethod method() const noexcept { return data_->method; }
  [[nodiscard]] const std::optional<std::uint32_t>& replica_slot() const noexcept {
    return data_->replica_slot;
  }
  [[nodiscard]] const std::optional<policy::Id16>& replica_incarnation() const noexcept {
    return data_->replica_incarnation;
  }
  [[nodiscard]] const std::shared_ptr<const CertificateRegistry>& registry() const noexcept {
    return data_->peer.registry();
  }

 private:
  friend class AuthorizationResolver;
  struct Payload final {
    Payload(const AuthenticatedPeer& peer_arg, RpcMethod method_arg,
            std::string tenant_arg, std::string operation_arg,
            std::uint64_t cost_arg, policy::Mode mode_arg,
            std::string attempt_arg, policy::Id16 epoch_arg,
            policy::Digest32 digest_arg,
            std::optional<std::uint32_t> slot_arg,
            std::optional<policy::Id16> incarnation_arg)
        : peer(peer_arg), method(method_arg), tenant_id(std::move(tenant_arg)),
          operation_id(std::move(operation_arg)), cost_units(cost_arg), mode(mode_arg),
          attempt_id(std::move(attempt_arg)), epoch_id(epoch_arg),
          policy_digest(digest_arg), replica_slot(slot_arg),
          replica_incarnation(incarnation_arg) {}
    AuthenticatedPeer peer;
    RpcMethod method;
    std::string tenant_id;
    std::string operation_id;
    std::uint64_t cost_units;
    policy::Mode mode;
    std::string attempt_id;
    policy::Id16 epoch_id;
    policy::Digest32 policy_digest;
    std::optional<std::uint32_t> replica_slot;
    std::optional<policy::Id16> replica_incarnation;
  };
  explicit AuthorizedOperation(std::shared_ptr<const Payload> data) noexcept
      : data_(std::move(data)) {}
  std::shared_ptr<const Payload> data_;
};

class AuthorizedGrant final {
 public:
  AuthorizedGrant(const AuthorizedGrant&) = default;
  AuthorizedGrant& operator=(const AuthorizedGrant&) = default;
  // Authorizes the request only; it does not mean a debit or grant committed.
  [[nodiscard]] const std::string& tenant_id() const noexcept { return data_->tenant_id; }
  [[nodiscard]] const std::string& operation_id() const noexcept { return data_->operation_id; }
  [[nodiscard]] std::uint64_t cost_units() const noexcept { return data_->cost_units; }
  [[nodiscard]] std::uint32_t slot() const noexcept { return data_->slot; }
  [[nodiscard]] const policy::Id16& incarnation_id() const noexcept { return data_->incarnation_id; }
  [[nodiscard]] std::uint64_t sequence() const noexcept { return data_->sequence; }
  [[nodiscard]] const policy::Id16& epoch_id() const noexcept { return data_->epoch_id; }
  [[nodiscard]] const policy::Digest32& policy_digest() const noexcept { return data_->policy_digest; }
  [[nodiscard]] const AuthenticatedPeer& peer() const noexcept { return data_->peer; }
  [[nodiscard]] RpcMethod method() const noexcept { return data_->method; }
  [[nodiscard]] const std::shared_ptr<const CertificateRegistry>& registry() const noexcept {
    return data_->peer.registry();
  }

 private:
  friend class AuthorizationResolver;
  struct Payload final {
    Payload(const AuthenticatedPeer& peer_arg, RpcMethod method_arg,
            std::string tenant_arg, std::string operation_arg,
            std::uint64_t cost_arg, std::uint32_t slot_arg,
            policy::Id16 incarnation_arg, std::uint64_t sequence_arg,
            policy::Id16 epoch_arg, policy::Digest32 digest_arg)
        : peer(peer_arg), method(method_arg), tenant_id(std::move(tenant_arg)),
          operation_id(std::move(operation_arg)), cost_units(cost_arg),
          slot(slot_arg), incarnation_id(incarnation_arg), sequence(sequence_arg),
          epoch_id(epoch_arg), policy_digest(digest_arg) {}
    AuthenticatedPeer peer;
    RpcMethod method;
    std::string tenant_id;
    std::string operation_id;
    std::uint64_t cost_units;
    std::uint32_t slot;
    policy::Id16 incarnation_id;
    std::uint64_t sequence;
    policy::Id16 epoch_id;
    policy::Digest32 policy_digest;
  };
  explicit AuthorizedGrant(std::shared_ptr<const Payload> data) noexcept
      : data_(std::move(data)) {}
  std::shared_ptr<const Payload> data_;
};

class AuthorizationResolver final {
 public:
  [[nodiscard]] static std::variant<AuthorizationResolver, AuthorizationFailure> Create(
      std::shared_ptr<const CertificateRegistry> registry,
      ITrustedWallClock& trusted_clock);

  [[nodiscard]] std::variant<AuthorizedOperation, AuthorizationFailure> Resolve(
      const AuthenticatedPeer& peer, RpcMethod method,
      const rateguard::v1::CheckAdmissionRequest& request) const noexcept;

  [[nodiscard]] std::variant<AuthorizedGrant, AuthorizationFailure> Resolve(
      const AuthenticatedPeer& peer, RpcMethod method,
      const rateguard::v1::AcquireCreditRequest& request) const noexcept;

 private:
  AuthorizationResolver(std::shared_ptr<const CertificateRegistry> registry,
                        ITrustedWallClock& trusted_clock) noexcept
      : registry_(std::move(registry)), trusted_clock_(trusted_clock) {}

  [[nodiscard]] std::optional<AuthorizationFailure> CheckPeerAndClock(
      const AuthenticatedPeer& peer) const;

  std::shared_ptr<const CertificateRegistry> registry_;
  ITrustedWallClock& trusted_clock_;
};

}  // namespace rateguard::security
