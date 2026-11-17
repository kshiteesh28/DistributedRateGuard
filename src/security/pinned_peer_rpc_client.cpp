#include "rateguard/security/pinned_peer_rpc_client.h"

#include "rateguard/security/tls_certificate_verifier.h"

#include <grpc/grpc_security.h>
#include <grpc/impl/codegen/grpc_types.h>
#include <grpcpp/channel.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace rateguard::security {
namespace {

constexpr std::size_t kMaxCredentialBytes = 64U * 1024U;
constexpr int kRpcMessageLimitBytes = 16 * 1024;

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

enum class PemReadFailure : std::uint8_t { Invalid, Crypto };

bool IsAsciiWhitespace(unsigned char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v';
}

bool OnlyWhitespaceRemainder(BIO* bio) noexcept {
  std::array<char, 256> bytes{};
  int count = 0;
  while ((count = BIO_read(bio, bytes.data(), static_cast<int>(bytes.size()))) > 0) {
    for (int i = 0; i < count; ++i) {
      if (!IsAsciiWhitespace(static_cast<unsigned char>(bytes[static_cast<std::size_t>(i)])))
        return false;
    }
  }
  return count == 0;
}

std::variant<X509Ptr, PemReadFailure> ReadSingleCertificate(std::string_view pem) {
  constexpr std::string_view marker = "-----BEGIN CERTIFICATE-----";
  if (pem.empty() || pem.size() > kMaxCredentialBytes ||
      pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      pem.find('\0') != std::string_view::npos) return PemReadFailure::Invalid;
  std::size_t first = 0;
  while (first < pem.size() && IsAsciiWhitespace(static_cast<unsigned char>(pem[first]))) ++first;
  if (pem.substr(first, marker.size()) != marker) return PemReadFailure::Invalid;
  BioPtr bio(BIO_new_mem_buf(pem.data() + first, static_cast<int>(pem.size() - first)), &BIO_free);
  if (!bio) return PemReadFailure::Crypto;
  X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (raw == nullptr) return PemReadFailure::Invalid;
  X509Ptr certificate(raw, &X509_free);
  if (!OnlyWhitespaceRemainder(bio.get())) return PemReadFailure::Invalid;
  return std::variant<X509Ptr, PemReadFailure>(std::in_place_index<0>,
                                                std::move(certificate));
}

std::variant<PkeyPtr, PemReadFailure> ReadSinglePrivateKey(std::string_view pem) {
  if (pem.empty() || pem.size() > kMaxCredentialBytes ||
      pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      pem.find('\0') != std::string_view::npos) return PemReadFailure::Invalid;
  std::size_t first = 0;
  while (first < pem.size() && IsAsciiWhitespace(static_cast<unsigned char>(pem[first]))) ++first;
  constexpr std::string_view private_key_marker = "-----BEGIN PRIVATE KEY-----";
  constexpr std::string_view ec_private_key_marker = "-----BEGIN EC PRIVATE KEY-----";
  if (pem.substr(first, private_key_marker.size()) != private_key_marker &&
      pem.substr(first, ec_private_key_marker.size()) != ec_private_key_marker)
    return PemReadFailure::Invalid;
  BioPtr bio(BIO_new_mem_buf(pem.data() + first, static_cast<int>(pem.size() - first)), &BIO_free);
  if (!bio) return PemReadFailure::Crypto;
  // Returning zero rejects encrypted PEM without invoking an interactive
  // password prompt. No parser detail or key bytes are exposed to callers.
  const auto reject_password = [](char*, int, int, void*) -> int { return 0; };
  EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, reject_password, nullptr);
  if (raw == nullptr) return PemReadFailure::Invalid;
  PkeyPtr key(raw, &EVP_PKEY_free);
  if (!OnlyWhitespaceRemainder(bio.get())) return PemReadFailure::Invalid;
  return std::variant<PkeyPtr, PemReadFailure>(std::in_place_index<0>,
                                               std::move(key));
}

std::variant<Sha256Digest, PemReadFailure> CertificateDigest(std::string_view pem) {
  auto parsed = ReadSingleCertificate(pem);
  auto* cert = std::get_if<X509Ptr>(&parsed);
  if (cert == nullptr) return std::get<PemReadFailure>(parsed);
  const int size = i2d_X509(cert->get(), nullptr);
  if (size <= 0) return PemReadFailure::Crypto;
  if (static_cast<std::size_t>(size) > kMaxCredentialBytes) return PemReadFailure::Invalid;
  std::vector<unsigned char> der(static_cast<std::size_t>(size));
  unsigned char* cursor = der.data();
  if (i2d_X509(cert->get(), &cursor) != size) return PemReadFailure::Crypto;
  Sha256Digest digest{};
  unsigned int actual_size = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &actual_size,
                 EVP_sha256(), nullptr) != 1 || actual_size != digest.size())
    return PemReadFailure::Crypto;
  return digest;
}

bool ValidTarget(std::string_view target) noexcept {
  if (target.empty() || target.size() > 256 || target.find('\0') != std::string_view::npos)
    return false;
  for (unsigned char ch : target) {
    if (ch < 0x21 || ch > 0x7e) return false;
  }
  return true;
}

bool AtMostCredentialBound(const PinnedPeerClientConfig& config) noexcept {
  return config.root_certificate_pem.size() <= kMaxCredentialBytes &&
         config.local_certificate_pem.size() <= kMaxCredentialBytes &&
         config.local_private_key_pem.size() <= kMaxCredentialBytes;
}

PinnedClientFactoryFailure FactoryFailure(PinnedClientFactoryFailureReason reason,
                                           ClientGuardDisposition disposition =
                                               ClientGuardDisposition::CredentialInvalid) noexcept {
  return {reason, disposition};
}

PinnedClientCallFailure CallFailure(PinnedClientCallFailureReason reason) noexcept {
  return {reason, std::nullopt};
}

PinnedClientCallFailure CallFailure(ClientCallGuardFailure failure) noexcept {
  return {PinnedClientCallFailureReason::GuardRejected, failure};
}

std::optional<std::chrono::system_clock::time_point> BoundedAuthorityDeadline(
    std::chrono::system_clock::time_point requested) noexcept {
  const auto now = std::chrono::system_clock::now();
  if (requested == std::chrono::system_clock::time_point::max() || requested <= now)
    return std::nullopt;
  const auto authority_cap = now + std::chrono::milliseconds(20);
  return std::min(requested, authority_cap);
}

}  // namespace

struct PinnedPeerRpcClient::Impl final {
  ClientCallPurpose purpose;
  policy::Mode mode;
  std::shared_ptr<const CertificateRegistry> registry;
  std::shared_ptr<grpc::experimental::CertificateProviderInterface> provider;
  std::shared_ptr<grpc::ChannelCredentials> credentials;
  std::shared_ptr<grpc::Channel> channel;
  std::unique_ptr<rateguard::v1::AdmissionService::Stub> admission_stub;
  std::unique_ptr<rateguard::v1::AuthorityService::Stub> authority_stub;
  ClientCallGuard guard;

  Impl(ClientCallPurpose purpose_arg, policy::Mode mode_arg,
       std::shared_ptr<const CertificateRegistry> registry_arg,
       std::shared_ptr<grpc::experimental::CertificateProviderInterface> provider_arg,
       std::shared_ptr<grpc::ChannelCredentials> credentials_arg,
       std::shared_ptr<grpc::Channel> channel_arg, ClientCallGuard guard_arg)
      : purpose(purpose_arg), mode(mode_arg), registry(std::move(registry_arg)),
        provider(std::move(provider_arg)), credentials(std::move(credentials_arg)),
        channel(std::move(channel_arg)), guard(std::move(guard_arg)) {}
};

PinnedPeerRpcClient::PinnedPeerRpcClient(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
PinnedPeerRpcClient::PinnedPeerRpcClient(PinnedPeerRpcClient&&) noexcept = default;
PinnedPeerRpcClient& PinnedPeerRpcClient::operator=(PinnedPeerRpcClient&&) noexcept = default;
PinnedPeerRpcClient::~PinnedPeerRpcClient() = default;

std::variant<PinnedPeerRpcClient, PinnedClientFactoryFailure>
PinnedPeerRpcClient::Create(PinnedPeerClientConfig config,
                            std::shared_ptr<const CertificateRegistry> registry,
                            ITrustedWallClock& trusted_clock) noexcept {
  if (!registry) return FactoryFailure(PinnedClientFactoryFailureReason::NullRegistry,
                                       ClientGuardDisposition::ApplicationUnavailable);
  if (!ValidTarget(config.target)) return FactoryFailure(PinnedClientFactoryFailureReason::InvalidTarget);
  if (!AtMostCredentialBound(config))
    return FactoryFailure(PinnedClientFactoryFailureReason::OversizedCredential);

  try {
    auto guard_result = ClientCallGuard::Create(registry, trusted_clock, config.purpose,
                                                 config.local_uri,
                                                 config.expected_server_uri);
    auto* guard_value = std::get_if<ClientCallGuard>(&guard_result);
    if (guard_value == nullptr) {
      const auto& failure = std::get<ClientCallGuardFailure>(guard_result);
      return FactoryFailure(PinnedClientFactoryFailureReason::InvalidEndpointBinding,
                            failure.disposition);
    }

    auto root_digest = CertificateDigest(config.root_certificate_pem);
    const auto* root_hash = std::get_if<Sha256Digest>(&root_digest);
    if (root_hash == nullptr) {
      const auto reason = std::get<PemReadFailure>(root_digest) == PemReadFailure::Invalid
                              ? PinnedClientFactoryFailureReason::InvalidRootPem
                              : PinnedClientFactoryFailureReason::DependencyFailure;
      return FactoryFailure(reason, reason == PinnedClientFactoryFailureReason::DependencyFailure
                                       ? ClientGuardDisposition::ApplicationUnavailable
                                       : ClientGuardDisposition::CredentialInvalid);
    }
    if (*root_hash != registry->root_der_sha256())
      return FactoryFailure(PinnedClientFactoryFailureReason::RootPinMismatch);

    auto local_digest = CertificateDigest(config.local_certificate_pem);
    const auto* local_hash = std::get_if<Sha256Digest>(&local_digest);
    if (local_hash == nullptr) {
      const auto reason = std::get<PemReadFailure>(local_digest) == PemReadFailure::Invalid
                              ? PinnedClientFactoryFailureReason::InvalidClientCertificatePem
                              : PinnedClientFactoryFailureReason::DependencyFailure;
      return FactoryFailure(reason, reason == PinnedClientFactoryFailureReason::DependencyFailure
                                       ? ClientGuardDisposition::ApplicationUnavailable
                                       : ClientGuardDisposition::CredentialInvalid);
    }
    const auto* local_record = registry->Find(config.local_uri);
    if (local_record == nullptr || *local_hash != local_record->peer.leaf_der_sha256)
      return FactoryFailure(PinnedClientFactoryFailureReason::ClientPinMismatch);

    auto certificate = ReadSingleCertificate(config.local_certificate_pem);
    auto* certificate_value = std::get_if<X509Ptr>(&certificate);
    if (certificate_value == nullptr)
      return FactoryFailure(PinnedClientFactoryFailureReason::InvalidClientCertificatePem);
    auto key = ReadSinglePrivateKey(config.local_private_key_pem);
    auto* key_value = std::get_if<PkeyPtr>(&key);
    if (key_value == nullptr) {
      const auto reason = std::get<PemReadFailure>(key) == PemReadFailure::Invalid
                              ? PinnedClientFactoryFailureReason::InvalidPrivateKeyPem
                              : PinnedClientFactoryFailureReason::DependencyFailure;
      return FactoryFailure(reason, reason == PinnedClientFactoryFailureReason::DependencyFailure
                                       ? ClientGuardDisposition::ApplicationUnavailable
                                       : ClientGuardDisposition::CredentialInvalid);
    }
    if (X509_check_private_key(certificate_value->get(), key_value->get()) != 1)
      return FactoryFailure(PinnedClientFactoryFailureReason::PrivateKeyMismatch);

    const auto* server_record = registry->Find(config.expected_server_uri);
    if (server_record == nullptr)
      return FactoryFailure(PinnedClientFactoryFailureReason::InvalidEndpointBinding);

    using grpc::experimental::IdentityKeyCertPair;
    using grpc::experimental::StaticDataCertificateProvider;
    std::vector<IdentityKeyCertPair> pairs;
    pairs.push_back({config.local_private_key_pem, config.local_certificate_pem});
    auto provider = std::make_shared<StaticDataCertificateProvider>(
        config.root_certificate_pem, pairs);

    grpc::experimental::TlsChannelCredentialsOptions options;
    options.set_certificate_provider(provider);
    options.watch_root_certs();
    options.watch_identity_key_cert_pairs();
    options.set_verify_server_certs(true);
    options.set_check_call_host(false);
    auto verifier =
        grpc::experimental::ExternalCertificateVerifier::Create<PinnedPeerVerifier>(
            registry->peer_pins(), ExpectedPeer{server_record->peer.uri,
                                                 server_record->peer.leaf_der_sha256,
                                                 server_record->peer.role});
    if (!verifier || verifier->c_verifier() == nullptr)
      return FactoryFailure(PinnedClientFactoryFailureReason::CredentialConstructionFailed,
                            ClientGuardDisposition::ApplicationUnavailable);
    options.set_certificate_verifier(std::move(verifier));
    auto credentials = grpc::experimental::TlsCredentials(options);
    if (!credentials)
      return FactoryFailure(PinnedClientFactoryFailureReason::CredentialConstructionFailed,
                            ClientGuardDisposition::ApplicationUnavailable);

    grpc::ChannelArguments arguments;
    // Per-client pool prevents accidental cross-guard channel reuse.
    arguments.SetInt("grpc.use_local_subchannel_pool", 1);
    // Disable transparent/configured retries and experimental hedging.
    arguments.SetInt("grpc.enable_retries", 0);
    arguments.SetInt("grpc.experimental.enable_hedging", 0);
    arguments.SetInt("grpc.max_metadata_size", kRpcMessageLimitBytes);
    arguments.SetMaxSendMessageSize(kRpcMessageLimitBytes);
    arguments.SetMaxReceiveMessageSize(kRpcMessageLimitBytes);
    // Deliberately do not attach grpc_ssl_session_cache: this factory does not
    // opt in to gRPC's client session-cache resumption path. Reconnect behavior
    // remains a separate SEC-11 qualification; no resumption pass is claimed.
    auto channel = grpc::CreateCustomChannel(config.target, credentials, arguments);
    if (!channel)
      return FactoryFailure(PinnedClientFactoryFailureReason::ChannelConstructionFailed,
                            ClientGuardDisposition::ApplicationUnavailable);

    const auto mode = registry->policy().mode();
    auto impl = std::make_unique<Impl>(config.purpose, mode,
        std::move(registry), std::move(provider), std::move(credentials),
        channel, *guard_value);
    if (config.purpose == ClientCallPurpose::AdapterToReplicaAdmission)
      impl->admission_stub = rateguard::v1::AdmissionService::NewStub(channel);
    else
      impl->authority_stub = rateguard::v1::AuthorityService::NewStub(channel);
    if ((!impl->admission_stub && config.purpose == ClientCallPurpose::AdapterToReplicaAdmission) ||
        (!impl->authority_stub && config.purpose == ClientCallPurpose::ReplicaToAuthority))
      return FactoryFailure(PinnedClientFactoryFailureReason::StubConstructionFailed,
                            ClientGuardDisposition::ApplicationUnavailable);
    return PinnedPeerRpcClient(std::move(impl));
  } catch (...) {
    return FactoryFailure(PinnedClientFactoryFailureReason::DependencyFailure,
                          ClientGuardDisposition::ApplicationUnavailable);
  }
}

template <class Response, class RpcCall>
PinnedClientCallResult<Response> PinnedPeerRpcClient::InvokeOnce(
    std::chrono::system_clock::time_point deadline, RpcCall&& rpc_call) noexcept {
  if (!impl_) return NotSent{CallFailure(PinnedClientCallFailureReason::LocalAllocationFailure)};
  if (deadline == std::chrono::system_clock::time_point::max() ||
      deadline <= std::chrono::system_clock::now())
    return NotSent{CallFailure(PinnedClientCallFailureReason::InvalidDeadline)};
  auto guarded = impl_->guard.ValidateBeforeCall();
  auto* proof = std::get_if<PreparedClientCall>(&guarded);
  if (proof == nullptr) return NotSent{CallFailure(std::get<ClientCallGuardFailure>(guarded))};

  // Allocate the response/proof bundle before the call. Once the stub is
  // entered, returning an Invoked value cannot allocate or lose its proof.
  std::shared_ptr<typename Invoked<Response>::Payload> payload;
  try {
    payload = std::make_shared<typename Invoked<Response>::Payload>(*proof);
  } catch (...) {
    return NotSent{CallFailure(PinnedClientCallFailureReason::LocalAllocationFailure)};
  }

  bool invoked = false;
  try {
    grpc::ClientContext context;
    context.set_deadline(deadline);
    invoked = true;
    auto status = rpc_call(&context, &payload->response);
    payload->transport_status.emplace(std::move(status));
  } catch (...) {
    if (!invoked)
      return NotSent{CallFailure(PinnedClientCallFailureReason::LocalAllocationFailure)};
    // The stub has been entered. A local exception cannot establish whether
    // the remote operation committed; retain Invoked with no raw status.
  }
  std::shared_ptr<const typename Invoked<Response>::Payload> immutable_payload =
      std::move(payload);
  return Invoked<Response>(std::move(immutable_payload));
}

PinnedClientCallResult<rateguard::v1::AdmissionDecision>
PinnedPeerRpcClient::CheckAdmission(
    const rateguard::v1::CheckAdmissionRequest& request,
    std::chrono::system_clock::time_point deadline) noexcept {
  if (!impl_ || impl_->purpose != ClientCallPurpose::AdapterToReplicaAdmission)
    return NotSent{CallFailure(PinnedClientCallFailureReason::PurposeMethodMismatch)};
  if (request.ByteSizeLong() > static_cast<std::size_t>(kRpcMessageLimitBytes))
    return NotSent{CallFailure(PinnedClientCallFailureReason::OversizedRequest)};
  if (!impl_->admission_stub)
    return NotSent{CallFailure(PinnedClientCallFailureReason::LocalAllocationFailure)};
  return InvokeOnce<rateguard::v1::AdmissionDecision>(deadline,
      [&](grpc::ClientContext* context, rateguard::v1::AdmissionDecision* response) {
        return impl_->admission_stub->CheckAdmission(context, request, response);
      });
}

PinnedClientCallResult<rateguard::v1::AdmissionDecision>
PinnedPeerRpcClient::StrictCheck(
    const rateguard::v1::CheckAdmissionRequest& request,
    std::chrono::system_clock::time_point deadline) noexcept {
  if (!impl_ || impl_->purpose != ClientCallPurpose::ReplicaToAuthority)
    return NotSent{CallFailure(PinnedClientCallFailureReason::PurposeMethodMismatch)};
  if (impl_->mode != policy::Mode::Strict)
    return NotSent{CallFailure(PinnedClientCallFailureReason::PolicyModeMismatch)};
  if (request.ByteSizeLong() > static_cast<std::size_t>(kRpcMessageLimitBytes))
    return NotSent{CallFailure(PinnedClientCallFailureReason::OversizedRequest)};
  if (!impl_->authority_stub)
    return NotSent{CallFailure(PinnedClientCallFailureReason::LocalAllocationFailure)};
  const auto bounded_deadline = BoundedAuthorityDeadline(deadline);
  if (!bounded_deadline)
    return NotSent{CallFailure(PinnedClientCallFailureReason::InvalidDeadline)};
  return InvokeOnce<rateguard::v1::AdmissionDecision>(*bounded_deadline,
      [&](grpc::ClientContext* context, rateguard::v1::AdmissionDecision* response) {
        return impl_->authority_stub->StrictCheck(context, request, response);
      });
}

PinnedClientCallResult<rateguard::v1::AcquireCreditResponse>
PinnedPeerRpcClient::AcquireCredit(
    const rateguard::v1::AcquireCreditRequest& request,
    std::chrono::system_clock::time_point deadline) noexcept {
  if (!impl_ || impl_->purpose != ClientCallPurpose::ReplicaToAuthority)
    return NotSent{CallFailure(PinnedClientCallFailureReason::PurposeMethodMismatch)};
  if (impl_->mode != policy::Mode::Credit)
    return NotSent{CallFailure(PinnedClientCallFailureReason::PolicyModeMismatch)};
  if (request.ByteSizeLong() > static_cast<std::size_t>(kRpcMessageLimitBytes))
    return NotSent{CallFailure(PinnedClientCallFailureReason::OversizedRequest)};
  if (!impl_->authority_stub)
    return NotSent{CallFailure(PinnedClientCallFailureReason::LocalAllocationFailure)};
  const auto bounded_deadline = BoundedAuthorityDeadline(deadline);
  if (!bounded_deadline)
    return NotSent{CallFailure(PinnedClientCallFailureReason::InvalidDeadline)};
  return InvokeOnce<rateguard::v1::AcquireCreditResponse>(*bounded_deadline,
      [&](grpc::ClientContext* context, rateguard::v1::AcquireCreditResponse* response) {
        return impl_->authority_stub->AcquireCredit(context, request, response);
      });
}

std::variant<ClientCallGuardPassed, ClientCallGuardFailure>
PinnedPeerRpcClient::ValidateBeforeForward(
    const Invoked<rateguard::v1::AdmissionDecision>& invocation) const noexcept {
  if (!impl_ || impl_->purpose != ClientCallPurpose::AdapterToReplicaAdmission) {
    return ClientCallGuardFailure{ClientCallGuardFailureReason::ForeignPreparedCall,
                                  ClientGuardDisposition::CredentialInvalid};
  }
  return impl_->guard.ValidateBeforeForward(invocation.payload_->proof);
}

}  // namespace rateguard::security
