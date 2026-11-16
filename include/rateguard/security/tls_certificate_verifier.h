#pragma once

#include <functional>
#include <memory>
#include <optional>

#include <grpcpp/security/tls_certificate_verifier.h>

#include "rateguard/security/peer_identity.h"

namespace rateguard::security {

// Verifies the peer leaf identity after gRPC's normal TLS chain validation.
// With expected set, this is a channel-specific pin. Without it, the peer must
// match a registered epoch leaf (server-side client authentication).
class PinnedPeerVerifier final : public grpc::experimental::ExternalCertificateVerifier {
 public:
  PinnedPeerVerifier(std::shared_ptr<const PeerRegistry> registry,
                     std::optional<ExpectedPeer> expected = std::nullopt);
  bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)> callback,
              grpc::Status* sync_status) override;
  void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest*) override {}

 private:
  std::shared_ptr<const PeerRegistry> registry_;
  std::optional<ExpectedPeer> expected_;
};

}  // namespace rateguard::security
