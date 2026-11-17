#pragma once

#include "rateguard/security/certificate_registry.h"
#include "security/trusted_wall_clock.h"

#include <grpc/grpc_security_constants.h>
#include <grpcpp/security/auth_context.h>

#include <memory>
#include <string>
#include <cstdint>
#include <utility>
#include <variant>

namespace rateguard::security {

enum class PeerAuthFailureReason : std::uint8_t {
  NullRegistry,
  UnauthenticatedContext,
  MissingOrAmbiguousTransport,
  UnsupportedTransport,
  MissingOrAmbiguousUri,
  InvalidUri,
  MissingOrAmbiguousLeaf,
  OversizedLeaf,
  InvalidLeafPem,
  UnregisteredUri,
  LeafPinMismatch,
  ClockUntrusted,
  CertificateNotYetValid,
  CertificateExpired,
  CryptoFailure,
};

enum class PeerAuthDisposition : std::uint8_t {
  Unauthenticated,
  ApplicationUnavailable,
};

enum class RpcMethod : std::uint8_t {
  AdapterCheckAdmission,
  ReplicaStrictCheck,
  ReplicaAcquireCredit,
};

// Bounded reason/disposition only. The RPC handler supplies commitment phase
// when translating failures; this type never guesses it.
struct PeerAuthFailure final {
  PeerAuthFailureReason reason;
  PeerAuthDisposition disposition;
};

class PeerAuthenticator;

// An opaque, copyable identity proof. Its private constructor prevents callers
// from manufacturing a trusted principal; holding the registry pins its record
// and lifetime to the exact validated epoch snapshot.
class AuthenticatedPeer final {
 public:
  AuthenticatedPeer(const AuthenticatedPeer&) = default;
  AuthenticatedPeer& operator=(const AuthenticatedPeer&) = default;
  // Explicit copy operations suppress implicit move operations. Even an
  // rvalue therefore copies the registry owner and remains a live proof.
  [[nodiscard]] const std::string& uri() const noexcept { return payload_->uri; }
  [[nodiscard]] PeerRole role() const noexcept { return payload_->role; }
  [[nodiscard]] const RegisteredCertificate* certificate() const noexcept {
    return payload_->registry->Find(payload_->uri);
  }
  [[nodiscard]] const std::shared_ptr<const CertificateRegistry>& registry() const noexcept {
    return payload_->registry;
  }

 private:
  struct Payload final {
    std::shared_ptr<const CertificateRegistry> registry;
    std::string uri;
    PeerRole role;
  };

  friend class PeerAuthenticator;
  AuthenticatedPeer(std::shared_ptr<const CertificateRegistry> registry,
                    const RegisteredCertificate* certificate)
      : payload_(std::make_shared<const Payload>(Payload{
            std::move(registry), certificate == nullptr ? std::string{} : certificate->peer.uri,
            certificate == nullptr ? PeerRole::kAdapter : certificate->peer.role})) {}

  // One immutable allocation makes copy assignment atomic with respect to all
  // capability fields: allocation can fail only while constructing a new proof.
  std::shared_ptr<const Payload> payload_;
};

class PeerAuthenticator final {
 public:
  PeerAuthenticator(std::shared_ptr<const CertificateRegistry> registry,
                    ITrustedWallClock& trusted_clock) noexcept
      : registry_(std::move(registry)), trusted_clock_(trusted_clock) {}

  [[nodiscard]] std::variant<AuthenticatedPeer, PeerAuthFailure> Authenticate(
      const grpc::AuthContext& auth_context) const noexcept;

 private:
  std::shared_ptr<const CertificateRegistry> registry_;
  ITrustedWallClock& trusted_clock_;
};

}  // namespace rateguard::security
