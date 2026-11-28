#pragma once

#include "proto/rateguard/v1/admission.grpc.pb.h"
#include "proto/rateguard/v1/authority.grpc.pb.h"
#include "rateguard/security/client_call_guard.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <grpcpp/support/status.h>

namespace rateguard::security {

// Secrets are accepted only as bounded in-memory inputs. The factory never
// reports their contents or OpenSSL parser diagnostics.
struct PinnedPeerClientConfig final {
  ClientCallPurpose purpose{ClientCallPurpose::AdapterToReplicaAdmission};
  std::string target;
  std::string local_uri;
  std::string expected_server_uri;
  std::string root_certificate_pem;
  std::string local_certificate_pem;
  std::string local_private_key_pem;
};

enum class PinnedClientFactoryFailureReason : std::uint8_t {
  NullRegistry,
  InvalidTarget,
  OversizedCredential,
  InvalidRootPem,
  RootPinMismatch,
  InvalidClientCertificatePem,
  ClientPinMismatch,
  InvalidPrivateKeyPem,
  PrivateKeyMismatch,
  InvalidEndpointBinding,
  CredentialConstructionFailed,
  ChannelConstructionFailed,
  StubConstructionFailed,
  DependencyFailure,
};

struct PinnedClientFactoryFailure final {
  PinnedClientFactoryFailureReason reason;
  ClientGuardDisposition disposition;
};

enum class PinnedClientCallFailureReason : std::uint8_t {
  PurposeMethodMismatch,
  PolicyModeMismatch,
  InvalidDeadline,
  OversizedRequest,
  GuardRejected,
  LocalAllocationFailure,
};

struct PinnedClientCallFailure final {
  PinnedClientCallFailureReason reason;
  std::optional<ClientCallGuardFailure> guard_failure;
};

// This result means the generated stub was never invoked for this attempt.
// It carries no gRPC status and no application response.
struct NotSent final {
  PinnedClientCallFailure failure;
};

// The stub was invoked exactly once. Status and response are raw transport
// data; they are not a trusted ALLOW, grant, or commitment proof.
template <class Response>
class Invoked final {
 public:
  Invoked(const Invoked&) = default;
  Invoked& operator=(const Invoked&) = default;

  [[nodiscard]] bool has_transport_status() const noexcept {
    return payload_->transport_status.has_value();
  }
  [[nodiscard]] const std::optional<grpc::Status>& transport_status() const noexcept {
    return payload_->transport_status;
  }
  [[nodiscard]] const Response& raw_response() const noexcept { return payload_->response; }

 private:
  friend class PinnedPeerRpcClient;
  struct Payload final {
    explicit Payload(const PreparedClientCall& prepared) : proof(prepared) {}
    std::optional<grpc::Status> transport_status;
    Response response;
    PreparedClientCall proof;
  };
  explicit Invoked(std::shared_ptr<const Payload> payload) noexcept
      : payload_(std::move(payload)) {}

  std::shared_ptr<const Payload> payload_;
};

template <class Response>
using PinnedClientCallResult = std::variant<NotSent, Invoked<Response>>;

// Owns its credentials, channel, generated stub and immutable endpoint binding.
// No channel, credentials, or stub accessor is provided.
class PinnedPeerRpcClient final {
 public:
  PinnedPeerRpcClient(const PinnedPeerRpcClient&) = delete;
  PinnedPeerRpcClient& operator=(const PinnedPeerRpcClient&) = delete;
  PinnedPeerRpcClient(PinnedPeerRpcClient&&) noexcept;
  PinnedPeerRpcClient& operator=(PinnedPeerRpcClient&&) noexcept;
  ~PinnedPeerRpcClient();

  [[nodiscard]] static std::variant<PinnedPeerRpcClient, PinnedClientFactoryFailure>
  Create(PinnedPeerClientConfig config,
         std::shared_ptr<const CertificateRegistry> registry,
         ITrustedWallClock& trusted_clock) noexcept;

  [[nodiscard]] PinnedClientCallResult<rateguard::v1::AdmissionDecision>
  CheckAdmission(const rateguard::v1::CheckAdmissionRequest& request,
                 std::chrono::system_clock::time_point deadline) noexcept;

  [[nodiscard]] PinnedClientCallResult<rateguard::v1::AdmissionDecision>
  StrictCheck(const rateguard::v1::CheckAdmissionRequest& request,
              std::chrono::system_clock::time_point deadline) noexcept;

  [[nodiscard]] PinnedClientCallResult<rateguard::v1::AcquireCreditResponse>
  AcquireCredit(const rateguard::v1::AcquireCreditRequest& request,
                std::chrono::system_clock::time_point deadline) noexcept;

  // Revalidates only the certificate/time guard for an adapter response.
  // The caller must separately require a timely application ALLOW and an
  // active epoch before forwarding. This method never forwards or commits.
  [[nodiscard]] std::variant<ClientCallGuardPassed, ClientCallGuardFailure>
  ValidateBeforeForward(
      const Invoked<rateguard::v1::AdmissionDecision>& invocation) const noexcept;

 private:
  struct Impl;
  explicit PinnedPeerRpcClient(std::unique_ptr<Impl> impl) noexcept;
  template <class Response, class RpcCall>
  PinnedClientCallResult<Response> InvokeOnce(
      std::chrono::system_clock::time_point deadline, RpcCall&& rpc_call) noexcept;
  std::unique_ptr<Impl> impl_;
};

}  // namespace rateguard::security
