#pragma once

#include "rateguard/security/certificate_registry.h"
#include "security/trusted_wall_clock.h"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace rateguard::security {

enum class ClientCallPurpose : std::uint8_t {
  AdapterToReplicaAdmission,
  ReplicaToAuthority,
};

enum class ClientGuardFailureReason : std::uint8_t {
  NullRegistry,
  PolicyBindingMismatch,
  InvalidClientIdentity,
  InvalidServerIdentity,
  ClientRoleMismatch,
  ServerRoleMismatch,
  MissingClientCertificate,
  MissingServerCertificate,
  ClockUntrusted,
  DependencyFailure,
  InvalidWallTime,
  RootNotYetValid,
  RootExpired,
  ClientNotYetValid,
  ClientExpired,
  ServerNotYetValid,
  ServerExpired,
  ForeignPreparedCall,
};

enum class ClientGuardDisposition : std::uint8_t {
  // Local trust classification only; this is not a downstream RPC status.
  CredentialInvalid,
  ApplicationUnavailable,
};

struct ClientCallGuardFailure final {
  ClientGuardFailureReason reason;
  ClientGuardDisposition disposition;
};

namespace detail {
struct ClientCallBinding final {
  std::shared_ptr<const CertificateRegistry> registry;
  policy::Id16 epoch_id{};
  policy::Digest32 policy_digest{};
  ClientCallPurpose purpose{};
  std::string local_uri;
  std::string expected_server_uri;
};

struct ClientCallProofPayload final {
  std::shared_ptr<const ClientCallBinding> binding;
  WallTime checked_at{};
};
}  // namespace detail

class ClientCallGuard;

class PreparedClientCall final {
 public:
  PreparedClientCall(const PreparedClientCall&) = default;
  PreparedClientCall& operator=(const PreparedClientCall&) = default;

 private:
  friend class ClientCallGuard;
  explicit PreparedClientCall(
      std::shared_ptr<const detail::ClientCallProofPayload> payload) noexcept
      : payload_(std::move(payload)) {}
  std::shared_ptr<const detail::ClientCallProofPayload> payload_;
};

// A fresh time-validation proof only. It is not a downstream ALLOW, deadline
// result, epoch-active check, or forwarding permit.
class ClientCallGuardPassed final {
 public:
  ClientCallGuardPassed(const ClientCallGuardPassed&) = default;
  ClientCallGuardPassed& operator=(const ClientCallGuardPassed&) = default;

 private:
  friend class ClientCallGuard;
  explicit ClientCallGuardPassed(
      std::shared_ptr<const detail::ClientCallProofPayload> payload) noexcept
      : payload_(std::move(payload)) {}
  std::shared_ptr<const detail::ClientCallProofPayload> payload_;
};

class ClientCallGuard final {
 public:
  [[nodiscard]] static std::variant<ClientCallGuard, ClientCallGuardFailure> Create(
      std::shared_ptr<const CertificateRegistry> registry,
      ITrustedWallClock& trusted_clock, ClientCallPurpose purpose,
      std::string local_uri, std::string expected_server_uri);

  [[nodiscard]] std::variant<PreparedClientCall, ClientCallGuardFailure>
  ValidateBeforeCall() const;

  [[nodiscard]] std::variant<ClientCallGuardPassed, ClientCallGuardFailure>
  ValidateBeforeForward(const PreparedClientCall& prepared) const;

 private:
  // The injected clock is non-owning and must outlive this guard and calls.
  ClientCallGuard(std::shared_ptr<const detail::ClientCallBinding> binding,
                  ITrustedWallClock& trusted_clock) noexcept
      : binding_(std::move(binding)), trusted_clock_(trusted_clock) {}

  [[nodiscard]] std::variant<WallTime, ClientCallGuardFailure>
  ValidateCurrentTime() const;

  std::shared_ptr<const detail::ClientCallBinding> binding_;
  ITrustedWallClock& trusted_clock_;
};

}  // namespace rateguard::security
