#include "ephemeral_pki.h"

#include "policy/canonical_codec.h"
#include "policy/policy_loader.h"
#include "proto/rateguard/v1/admission.grpc.pb.h"
#include "rateguard/security/pinned_peer_rpc_client.h"
#include "rateguard/security/tls_certificate_verifier.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpc/grpc_security.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <nlohmann/json.hpp>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
namespace rg = rateguard::v1;
using grpc::experimental::IdentityKeyCertPair;
using grpc::experimental::StaticDataCertificateProvider;

namespace {

[[noreturn]] void Fail(std::string_view label) {
  std::cerr << "FAIL " << label << '\n';
  std::exit(1);
}
void Check(bool condition, std::string_view label) {
  if (!condition) Fail(label);
}

class MutableClock final : public sec::ITrustedWallClock {
 public:
  explicit MutableClock(sec::WallTime value) : value_(value) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override {
    std::lock_guard lock(mutex_);
    if (!healthy_) return sec::TrustedWallClockFailure{
        sec::TrustedWallClockFailureReason::PlatformUnavailable};
    return value_;
  }
  bool Healthy() const override {
    std::lock_guard lock(mutex_);
    return healthy_;
  }
  // This mutable clock separates test subcases. It is not the production
  // clock's sticky-loss/recovery behavior and says nothing about fencing.
  void Set(sec::WallTime value) {
    std::lock_guard lock(mutex_);
    value_ = value;
  }
  void SetHealthy(bool value) {
    std::lock_guard lock(mutex_);
    healthy_ = value;
  }
 private:
  mutable std::mutex mutex_;
  sec::WallTime value_;
  bool healthy_{true};
};

std::string ReadFile(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return {};
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void RemoveCreditBatchFields(nlohmann::json& value) {
  if (value.is_object()) {
    value.erase("credit_batch_units");
    for (auto& [key, child] : value.items()) {
      (void)key;
      RemoveCreditBatchFields(child);
    }
  } else if (value.is_array()) {
    for (auto& child : value) RemoveCreditBatchFields(child);
  }
}
std::string Hex(std::span<const std::uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 15]);
  }
  return out;
}
pol::Digest32 RootDigest(std::string_view pem) {
  BIO* raw = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw) Fail("fixture_root_bio");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw, BIO_free);
  X509* cert_raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!cert_raw) Fail("fixture_root_cert");
  std::unique_ptr<X509, decltype(&X509_free)> cert(cert_raw, X509_free);
  const int length = i2d_X509(cert.get(), nullptr);
  if (length <= 0 || length > 64 * 1024) Fail("fixture_root_der");
  std::vector<std::uint8_t> der(static_cast<std::size_t>(length));
  auto* cursor = der.data();
  if (i2d_X509(cert.get(), &cursor) != length) Fail("fixture_root_der");
  pol::Digest32 digest{};
  unsigned int written = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &written,
                 EVP_sha256(), nullptr) != 1 || written != digest.size())
    Fail("fixture_root_digest");
  return digest;
}

struct Fixture final {
  sec::test::EphemeralPki pki;
  std::shared_ptr<const pol::PolicySnapshot> policy;
  std::shared_ptr<const sec::CertificateRegistry> registry;
  std::vector<const sec::test::EphemeralIdentity*> identities;
  const sec::test::EphemeralIdentity* adapter{};
  const sec::test::EphemeralIdentity* replica{};
  const sec::test::EphemeralIdentity* authority{};
  pol::Digest32 digest{};
  sec::WallTime now{};

  Fixture(const std::string& policy_path, long adapter_expiry_delta,
          long replica_expiry_delta, long others_expiry_delta = 48 * 60 * 60,
          bool strict_policy = false) {
    auto document = nlohmann::json::parse(ReadFile(policy_path));
    document["trust_root_sha256"] = Hex(RootDigest(pki.root_certificate_pem()));
    if (strict_policy) {
      document["mode"] = "strict";
      RemoveCreditBatchFields(document);
    }
    auto loaded = pol::PolicyLoader::Load(document.dump());
    const auto* policy_value = std::get_if<std::shared_ptr<const pol::PolicySnapshot>>(&loaded);
    if (policy_value == nullptr) {
      // Fixed numeric error category only; never print policy/credential input.
      const auto* error = std::get_if<pol::PolicyError>(&loaded);
      Fail(error ? "fixture_policy_load_code_" +
          std::to_string(static_cast<unsigned>(error->code)) :
          "fixture_policy_load_unknown");
    }
    policy = *policy_value;
    const auto digest_result = pol::CanonicalPolicyCodec::Digest(*policy);
    const auto* digest_value = std::get_if<pol::Digest32>(&digest_result);
    Check(digest_value != nullptr, "fixture_policy_digest");
    digest = *digest_value;

    std::vector<std::string_view> leaves;
    identities.reserve(policy->principals().size());
    leaves.reserve(policy->principals().size());
    for (const auto& principal : policy->principals()) {
      sec::PeerRole role = sec::PeerRole::kAdapter;
      if (principal.role == pol::PrincipalRole::Replica) role = sec::PeerRole::kReplica;
      if (principal.role == pol::PrincipalRole::Authority) role = sec::PeerRole::kAuthority;
      long expiry = others_expiry_delta;
      if (principal.role == pol::PrincipalRole::Adapter) expiry = adapter_expiry_delta;
      if (principal.role == pol::PrincipalRole::Replica && principal.slot_id == 7U)
        expiry = replica_expiry_delta;
      const auto& identity = pki.IssueWithValidity(role, principal.uri, -60, expiry);
      identities.push_back(&identity);
      leaves.push_back(identity.certificate_pem);
      if (principal.role == pol::PrincipalRole::Adapter && adapter == nullptr)
        adapter = &identity;
      if (principal.role == pol::PrincipalRole::Replica && principal.slot_id == 7U)
        replica = &identity;
      if (principal.role == pol::PrincipalRole::Authority && authority == nullptr)
        authority = &identity;
    }
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    now = {seconds, 0};
    MutableClock initial(now);
    const auto built = sec::CertificateRegistryLoader::Load(
        policy, pki.root_certificate_pem(), leaves, initial);
    const auto* registry_value = std::get_if<
        std::shared_ptr<const sec::CertificateRegistry>>(&built);
    Check(registry_value != nullptr, "fixture_registry_load");
    registry = *registry_value;
    Check(adapter != nullptr && replica != nullptr && authority != nullptr,
          "fixture_has_required_roles");
  }

  sec::PinnedPeerClientConfig ClientConfig(int port) const {
    return {sec::ClientCallPurpose::AdapterToReplicaAdmission,
            "127.0.0.1:" + std::to_string(port), adapter->registered.uri,
            replica->registered.uri, pki.root_certificate_pem(),
            adapter->certificate_pem, adapter->private_key_pem};
  }
  sec::PinnedPeerClientConfig AuthorityClientConfig(int port) const {
    return {sec::ClientCallPurpose::ReplicaToAuthority,
            "127.0.0.1:" + std::to_string(port), replica->registered.uri,
            authority->registered.uri, pki.root_certificate_pem(),
            replica->certificate_pem, replica->private_key_pem};
  }
};

std::shared_ptr<grpc::experimental::CertificateProviderInterface> Provider(
    const std::string& root, const sec::test::EphemeralIdentity& identity) {
  std::vector<IdentityKeyCertPair> pairs{{identity.private_key_pem,
                                           identity.certificate_pem}};
  return std::make_shared<StaticDataCertificateProvider>(root, pairs);
}

class CountingClientVerifier final
    : public grpc::experimental::ExternalCertificateVerifier {
 public:
  CountingClientVerifier(std::shared_ptr<const sec::PeerRegistry> registry,
                         sec::ExpectedPeer expected,
                         std::shared_ptr<std::atomic<unsigned>> count)
      : delegate_(std::move(registry), std::move(expected)), count_(std::move(count)) {}
  bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)> callback,
              grpc::Status* status) override {
    count_->fetch_add(1, std::memory_order_relaxed);
    return delegate_.Verify(request, std::move(callback), status);
  }
  void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest* request) override {
    delegate_.Cancel(request);
  }
 private:
  sec::PinnedPeerVerifier delegate_;
  std::shared_ptr<std::atomic<unsigned>> count_;
};

std::shared_ptr<grpc::ServerCredentials> ServerCredentials(
    const Fixture& fixture, const sec::test::EphemeralIdentity& server,
    std::shared_ptr<std::atomic<unsigned>> verify_count = {}) {
  grpc::experimental::TlsServerCredentialsOptions options(
      Provider(fixture.pki.root_certificate_pem(), server));
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  options.set_cert_request_type(
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  if (verify_count) {
    class CountingVerifier final : public grpc::experimental::ExternalCertificateVerifier {
     public:
      CountingVerifier(std::shared_ptr<const sec::PeerRegistry> registry,
                       std::shared_ptr<std::atomic<unsigned>> count)
          : delegate_(std::move(registry)), count_(std::move(count)) {}
      bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
                  std::function<void(grpc::Status)> callback,
                  grpc::Status* status) override {
        count_->fetch_add(1, std::memory_order_relaxed);
        return delegate_.Verify(request, std::move(callback), status);
      }
      void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest* request) override {
        delegate_.Cancel(request);
      }
     private:
      sec::PinnedPeerVerifier delegate_;
      std::shared_ptr<std::atomic<unsigned>> count_;
    };
    options.set_certificate_verifier(
        grpc::experimental::ExternalCertificateVerifier::Create<CountingVerifier>(
            fixture.registry->peer_pins(), std::move(verify_count)));
  } else {
    options.set_certificate_verifier(
        grpc::experimental::ExternalCertificateVerifier::Create<sec::PinnedPeerVerifier>(
            fixture.registry->peer_pins()));
  }
  return grpc::experimental::TlsServerCredentials(options);
}

class AdmissionSink final : public rg::AdmissionService::Service {
 public:
  grpc::Status CheckAdmission(grpc::ServerContext* context,
                              const rg::CheckAdmissionRequest* request,
                              rg::AdmissionDecision* response) override {
    if (context->auth_context()) {
      const auto transports = context->auth_context()->FindPropertyValues(
          GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME);
      const auto uris = context->auth_context()->FindPropertyValues(
          GRPC_PEER_URI_PROPERTY_NAME);
      const auto leafs = context->auth_context()->FindPropertyValues(
          GRPC_X509_PEM_CERT_PROPERTY_NAME);
      const bool leaf_matches = leafs.size() == 1 && leafs.front().data() != nullptr &&
          std::string_view(leafs.front().data(), leafs.front().size()) == expected_leaf_pem;
      last_properties_ok.store(transports.size() == 1 && uris.size() == 1 &&
          leafs.size() == 1 && transports.front().data() != nullptr &&
          uris.front().data() != nullptr && leafs.front().data() != nullptr &&
          std::string_view(transports.front().data(), transports.front().size()) ==
              GRPC_TLS_TRANSPORT_SECURITY_TYPE &&
          std::string_view(uris.front().data(), uris.front().size()) == expected_uri &&
          leaf_matches,
          std::memory_order_release);
      const auto resumed = context->auth_context()->FindPropertyValues(
          GRPC_SSL_SESSION_REUSED_PROPERTY);
      const bool session_property_present = resumed.size() == 1 && resumed.front().data() != nullptr;
      const bool session_reused = session_property_present &&
          std::string_view(resumed.front().data(), resumed.front().size()) == "true";
      std::lock_guard lock(observation_mutex);
      observed.push_back({context->peer(), session_property_present, session_reused, leaf_matches});
    }
    calls.fetch_add(1, std::memory_order_release);
    if (request->operation_id() == "transport_unavailable")
      return {grpc::StatusCode::UNAVAILABLE, "synthetic transport failure"};
    response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
    response->set_attempt_id(request->attempt_id());
    return grpc::Status::OK;
  }
  std::string expected_uri;
  std::string expected_leaf_pem;
  std::atomic<unsigned> calls{0};
  std::atomic<bool> last_properties_ok{false};
  std::mutex observation_mutex;
  struct Observation final {
    std::string peer;
    bool session_property_present;
    bool resumed;
    bool leaf_matches;
  };
  std::vector<Observation> observed;
};

struct ServerNode final {
  AdmissionSink service;
  std::unique_ptr<grpc::Server> server;
  int port{};
  ServerNode(const Fixture& fixture, const sec::test::EphemeralIdentity& server_identity,
             std::shared_ptr<std::atomic<unsigned>> verify_count = {})
      : service{} {
    service.expected_uri = fixture.adapter->registered.uri;
    service.expected_leaf_pem = fixture.adapter->certificate_pem;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0",
        ServerCredentials(fixture, server_identity, std::move(verify_count)), &port);
    builder.RegisterService(&service);
    server = builder.BuildAndStart();
    Check(server != nullptr && port > 0, "probe_tls_server_started");
  }
  ~ServerNode() {
    if (server) {
      server->Shutdown();
      server->Wait();
    }
  }
};

class AuthoritySink final : public rg::AuthorityService::Service {
 public:
  grpc::Status StrictCheck(grpc::ServerContext*, const rg::CheckAdmissionRequest* request,
                           rg::AdmissionDecision* response) override {
    calls.fetch_add(1, std::memory_order_release);
    if (request->operation_id() == "slow")
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
    return grpc::Status::OK;
  }
  grpc::Status AcquireCredit(grpc::ServerContext*, const rg::AcquireCreditRequest* request,
                             rg::AcquireCreditResponse* response) override {
    calls.fetch_add(1, std::memory_order_release);
    if (request->trigger_operation_id() == "slow")
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    response->set_grant_outcome(rg::GRANT_OUTCOME_UNAVAILABLE);
    return grpc::Status::OK;
  }
  std::atomic<unsigned> calls{0};
};

struct AuthorityNode final {
  AuthoritySink service;
  std::unique_ptr<grpc::Server> server;
  int port{};
  explicit AuthorityNode(const Fixture& fixture) {
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0",
        ServerCredentials(fixture, *fixture.authority), &port);
    builder.RegisterService(&service);
    server = builder.BuildAndStart();
    Check(server != nullptr && port > 0, "authority_tls_server_started");
  }
  ~AuthorityNode() {
    if (server) { server->Shutdown(); server->Wait(); }
  }
};

rg::CheckAdmissionRequest Request(const Fixture& fixture,
                                  std::string operation = "list") {
  rg::CheckAdmissionRequest request;
  request.set_tenant_id("zeta");
  request.set_operation_id(std::move(operation));
  request.set_attempt_id(std::string(16, 'a'));
  request.set_epoch_id(reinterpret_cast<const char*>(fixture.policy->epoch_id().data()), 16);
  request.set_policy_digest(reinterpret_cast<const char*>(fixture.digest.data()), 32);
  return request;
}
auto Deadline() {
  return std::chrono::system_clock::now() + std::chrono::seconds(5);
}

std::variant<sec::PinnedPeerRpcClient, sec::PinnedClientFactoryFailure>
CreateClient(const Fixture& fixture, int port, MutableClock& clock) {
  return sec::PinnedPeerRpcClient::Create(fixture.ClientConfig(port), fixture.registry, clock);
}

sec::PinnedPeerRpcClient& RequireClient(
    std::variant<sec::PinnedPeerRpcClient, sec::PinnedClientFactoryFailure>& storage) {
  auto* client = std::get_if<sec::PinnedPeerRpcClient>(&storage);
  Check(client != nullptr, "typed_pinned_client_factory_succeeds");
  return *client;
}

sec::WallTime OneNanosecondBefore(sec::WallTime value) {
  if (value.nanoseconds != 0) return {value.unix_seconds, value.nanoseconds - 1};
  return {value.unix_seconds - 1, 999'999'999U};
}

void AssertNotSent(const auto& result, sec::ClientGuardFailureReason reason,
                   sec::ClientGuardDisposition disposition, std::string_view label) {
  const auto* not_sent = std::get_if<sec::NotSent>(&result);
  Check(not_sent != nullptr, label);
  Check(not_sent->failure.guard_failure.has_value(), label);
  Check(not_sent->failure.guard_failure->reason == reason &&
        not_sent->failure.guard_failure->disposition == disposition, label);
}

void AssertFactoryFailure(const Fixture& fixture, sec::PinnedPeerClientConfig config,
                          MutableClock& clock,
                          sec::PinnedClientFactoryFailureReason expected,
                          std::string_view label) {
  const auto result = sec::PinnedPeerRpcClient::Create(
      std::move(config), fixture.registry, clock);
  const auto* failure = std::get_if<sec::PinnedClientFactoryFailure>(&result);
  Check(failure != nullptr && failure->reason == expected, label);
}

void RunClientFactoryValidationCases(const std::string& policy_path) {
  Fixture fixture(policy_path, 48 * 60 * 60, 48 * 60 * 60);
  MutableClock clock(fixture.now);
  const auto base = fixture.ClientConfig(1);
  auto bad_root = base;
  bad_root.root_certificate_pem = "not a certificate";
  AssertFactoryFailure(fixture, std::move(bad_root), clock,
      sec::PinnedClientFactoryFailureReason::InvalidRootPem, "invalid_root_pem_rejected");
  sec::test::EphemeralPki other_pki;
  auto wrong_root = base;
  wrong_root.root_certificate_pem = other_pki.root_certificate_pem();
  AssertFactoryFailure(fixture, std::move(wrong_root), clock,
      sec::PinnedClientFactoryFailureReason::RootPinMismatch, "wrong_root_pin_rejected");
  auto prefix_cert = base;
  prefix_cert.local_certificate_pem = "junk\n" + prefix_cert.local_certificate_pem;
  AssertFactoryFailure(fixture, std::move(prefix_cert), clock,
      sec::PinnedClientFactoryFailureReason::InvalidClientCertificatePem,
      "junk_before_client_certificate_rejected");
  const auto& alternate = fixture.pki.IssueWithValidity(
      sec::PeerRole::kAdapter, fixture.adapter->registered.uri, -60, 48 * 60 * 60);
  auto wrong_pin = base;
  wrong_pin.local_certificate_pem = alternate.certificate_pem;
  AssertFactoryFailure(fixture, std::move(wrong_pin), clock,
      sec::PinnedClientFactoryFailureReason::ClientPinMismatch,
      "same_uri_alternate_local_leaf_pin_rejected");
  auto wrong_key = base;
  wrong_key.local_private_key_pem = fixture.authority->private_key_pem;
  AssertFactoryFailure(fixture, std::move(wrong_key), clock,
      sec::PinnedClientFactoryFailureReason::PrivateKeyMismatch,
      "mismatched_private_key_rejected");
  auto prefix_key = base;
  prefix_key.local_private_key_pem = "junk\n" + prefix_key.local_private_key_pem;
  AssertFactoryFailure(fixture, std::move(prefix_key), clock,
      sec::PinnedClientFactoryFailureReason::InvalidPrivateKeyPem,
      "junk_before_private_key_rejected");
  auto multiple_keys = base;
  multiple_keys.local_private_key_pem += multiple_keys.local_private_key_pem;
  AssertFactoryFailure(fixture, std::move(multiple_keys), clock,
      sec::PinnedClientFactoryFailureReason::InvalidPrivateKeyPem,
      "multiple_private_keys_rejected");
  auto encrypted_key = base;
  encrypted_key.local_private_key_pem =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZQ==\n-----END ENCRYPTED PRIVATE KEY-----\n";
  AssertFactoryFailure(fixture, std::move(encrypted_key), clock,
      sec::PinnedClientFactoryFailureReason::InvalidPrivateKeyPem,
      "encrypted_private_key_rejected_without_prompt");
  auto oversized = base;
  oversized.root_certificate_pem.assign(64U * 1024U + 1U, ' ');
  AssertFactoryFailure(fixture, std::move(oversized), clock,
      sec::PinnedClientFactoryFailureReason::OversizedCredential,
      "oversized_credential_rejected_before_parse");
}

void RunExpiryCase(const std::string& policy_path, long adapter_delta,
                   long server_delta, bool expire_root, bool expire_adapter,
                   bool expire_server) {
  Check((expire_root ? 1 : 0) + (expire_adapter ? 1 : 0) + (expire_server ? 1 : 0) == 1,
        "exactly_one_expiry_case_selected");
  Fixture fixture(policy_path, adapter_delta, server_delta,
                  expire_root ? 48 * 60 * 60 : 48 * 60 * 60);
  MutableClock clock(fixture.now);
  ServerNode server(fixture, *fixture.replica);
  auto client_storage = CreateClient(fixture, server.port, clock);
  auto& client = RequireClient(client_storage);
  const auto request = Request(fixture);

  const auto infinite_deadline = client.CheckAdmission(
      request, std::chrono::system_clock::time_point::max());
  const auto* infinite_not_sent = std::get_if<sec::NotSent>(&infinite_deadline);
  Check(infinite_not_sent &&
        infinite_not_sent->failure.reason == sec::PinnedClientCallFailureReason::InvalidDeadline,
        "infinite_deadline_rejected_before_stub");
  const auto elapsed_deadline = client.CheckAdmission(
      request, std::chrono::system_clock::now() - std::chrono::seconds(1));
  const auto* elapsed_not_sent = std::get_if<sec::NotSent>(&elapsed_deadline);
  Check(elapsed_not_sent &&
        elapsed_not_sent->failure.reason == sec::PinnedClientCallFailureReason::InvalidDeadline,
        "expired_deadline_rejected_before_stub");
  const auto wrong_method = client.StrictCheck(request, Deadline());
  const auto* wrong_method_not_sent = std::get_if<sec::NotSent>(&wrong_method);
  Check(wrong_method_not_sent && wrong_method_not_sent->failure.reason ==
        sec::PinnedClientCallFailureReason::PurposeMethodMismatch,
        "adapter_client_cannot_invoke_authority_method");
  const auto wrong_credit_method = client.AcquireCredit(rg::AcquireCreditRequest{}, Deadline());
  const auto* wrong_credit_not_sent = std::get_if<sec::NotSent>(&wrong_credit_method);
  Check(wrong_credit_not_sent && wrong_credit_not_sent->failure.reason ==
        sec::PinnedClientCallFailureReason::PurposeMethodMismatch,
        "adapter_client_cannot_invoke_credit_authority_method");
  Check(server.service.calls.load(std::memory_order_acquire) == 0,
        "preflight_validation_rejections_do_not_dispatch");

  auto first = client.CheckAdmission(request, Deadline());
  const auto* invocation = std::get_if<sec::Invoked<rg::AdmissionDecision>>(&first);
  Check(invocation != nullptr && invocation->has_transport_status() &&
        invocation->transport_status()->ok() &&
        invocation->raw_response().outcome() == rg::DECISION_OUTCOME_UNAVAILABLE,
        "warm_tls_rpc_returns_untrusted_probe_sentinel");
  Check(server.service.calls.load(std::memory_order_acquire) == 1 &&
        server.service.last_properties_ok.load(std::memory_order_acquire),
        "actual_mtls_handler_observed_registered_adapter_properties_once");
  if (!invocation) return;

  const auto forward_valid = client.ValidateBeforeForward(*invocation);
  Check(std::holds_alternative<sec::ClientCallGuardPassed>(forward_valid),
        "forward_guard_rechecks_time_while_currently_valid_without_forwarding");

  sec::WallTime boundary{};
  sec::ClientGuardFailureReason expected_reason{};
  if (expire_root) {
    boundary = fixture.registry->root_validity().not_after;
    expected_reason = sec::ClientGuardFailureReason::RootExpired;
    Check(boundary < fixture.registry->Find(fixture.adapter->registered.uri)->validity.not_after &&
          boundary < fixture.registry->Find(fixture.replica->registered.uri)->validity.not_after,
          "root_expiry_isolated_from_leaf_expiry");
  } else if (expire_adapter) {
    boundary = fixture.registry->Find(fixture.adapter->registered.uri)->validity.not_after;
    expected_reason = sec::ClientGuardFailureReason::ClientExpired;
    Check(fixture.registry->root_validity().Contains(boundary) &&
          fixture.registry->Find(fixture.replica->registered.uri)->validity.Contains(
              OneNanosecondBefore(boundary)),
          "client_leaf_expiry_isolated_from_root_and_server_leaf");
  } else {
    boundary = fixture.registry->Find(fixture.replica->registered.uri)->validity.not_after;
    expected_reason = sec::ClientGuardFailureReason::ServerExpired;
    Check(fixture.registry->root_validity().Contains(boundary) &&
          fixture.registry->Find(fixture.adapter->registered.uri)->validity.Contains(
              OneNanosecondBefore(boundary)),
          "server_leaf_expiry_isolated_from_root_and_client_leaf");
  }

  clock.Set(boundary);
  const auto forward_expired = client.ValidateBeforeForward(*invocation);
  const auto* forward_failure = std::get_if<sec::ClientCallGuardFailure>(&forward_expired);
  Check(forward_failure != nullptr && forward_failure->reason == expected_reason &&
        forward_failure->disposition == sec::ClientGuardDisposition::CredentialInvalid,
        "pre_forward_guard_rechecks_expired_certificate_without_backend_call");
  auto expired_call = client.CheckAdmission(request, Deadline());
  AssertNotSent(expired_call, expected_reason,
                sec::ClientGuardDisposition::CredentialInvalid,
                "fresh_per_call_guard_blocks_expired_pinned_identity_before_dispatch");
  Check(server.service.calls.load(std::memory_order_acquire) == 1,
        "expired_warm_channel_attempt_not_dispatched");

  clock.Set(fixture.now);
  clock.SetHealthy(false);
  auto clock_failure = client.CheckAdmission(request, Deadline());
  AssertNotSent(clock_failure, sec::ClientGuardFailureReason::ClockUntrusted,
                sec::ClientGuardDisposition::ApplicationUnavailable,
                "clock_loss_is_local_unavailable_before_dispatch");
  Check(server.service.calls.load(std::memory_order_acquire) == 1,
        "untrusted_clock_attempt_not_dispatched");
}

void RunRetryAndReconnectCases(const std::string& policy_path) {
  Fixture fixture(policy_path, 48 * 60 * 60, 48 * 60 * 60);
  MutableClock clock(fixture.now);
  ServerNode server(fixture, *fixture.replica);
  auto storage = CreateClient(fixture, server.port, clock);
  auto& client = RequireClient(storage);
  const auto request = Request(fixture, "transport_unavailable");
  const auto result = client.CheckAdmission(request, Deadline());
  const auto* invoked = std::get_if<sec::Invoked<rg::AdmissionDecision>>(&result);
  Check(invoked && invoked->has_transport_status() &&
        invoked->transport_status()->error_code() == grpc::StatusCode::UNAVAILABLE,
        "invoked_transport_failure_retained_as_raw_status");
  Check(server.service.calls.load(std::memory_order_acquire) == 1,
        "enforcement_wrapper_does_not_retry_an_invoked_rpc");
}

void RunChangedServerPinCase(const std::string& policy_path) {
  Fixture fixture(policy_path, 48 * 60 * 60, 48 * 60 * 60);
  // The alternate certificate has the registered server URI but a different
  // DER leaf. It is intentionally not added to the registry.
  const auto& replacement = fixture.pki.IssueWithValidity(
      sec::PeerRole::kReplica, fixture.replica->registered.uri, -60, 48 * 60 * 60);
  MutableClock clock(fixture.now);
  ServerNode replacement_server(fixture, replacement);
  auto storage = CreateClient(fixture, replacement_server.port, clock);
  auto& client = RequireClient(storage);
  const auto result = client.CheckAdmission(Request(fixture), Deadline());
  const auto* invoked = std::get_if<sec::Invoked<rg::AdmissionDecision>>(&result);
  Check(invoked != nullptr && invoked->has_transport_status() &&
        !invoked->transport_status()->ok(),
        "new_endpoint_same_uri_replacement_leaf_fails_tls_pin");
  Check(replacement_server.service.calls.load(std::memory_order_acquire) == 0,
        "replacement_server_leaf_rejected_before_handler");
}

void RunAuthorityWrapperCase(const std::string& policy_path, bool strict_policy) {
  Fixture fixture(policy_path, 48 * 60 * 60, 48 * 60 * 60,
                  48 * 60 * 60, strict_policy);
  Check(fixture.policy->mode() ==
        (strict_policy ? pol::Mode::Strict : pol::Mode::Credit),
        "authority_fixture_has_requested_policy_mode");
  MutableClock clock(fixture.now);
  AuthorityNode server(fixture);
  auto result = sec::PinnedPeerRpcClient::Create(
      fixture.AuthorityClientConfig(server.port), fixture.registry, clock);
  auto* client = std::get_if<sec::PinnedPeerRpcClient>(&result);
  Check(client != nullptr, "replica_to_authority_wrapper_factory_succeeds");
  if (client == nullptr) return;

  const auto forbidden_adapter_method = client->CheckAdmission(Request(fixture), Deadline());
  const auto* forbidden_not_sent = std::get_if<sec::NotSent>(&forbidden_adapter_method);
  Check(forbidden_not_sent && forbidden_not_sent->failure.reason ==
        sec::PinnedClientCallFailureReason::PurposeMethodMismatch,
        "replica_authority_client_cannot_call_adapter_admission");

  rg::CheckAdmissionRequest strict_request = Request(fixture);
  auto strict_result = client->StrictCheck(strict_request, Deadline());
  if (fixture.policy->mode() == pol::Mode::Strict) {
    const auto* strict_invoked =
        std::get_if<sec::Invoked<rg::AdmissionDecision>>(&strict_result);
    Check(strict_invoked && strict_invoked->has_transport_status() &&
          strict_invoked->transport_status()->ok() &&
          strict_invoked->raw_response().outcome() == rg::DECISION_OUTCOME_UNAVAILABLE,
          "replica_to_authority_strict_rpc_invoked_once_and_raw_response_retained");
  } else {
    const auto* strict_not_sent = std::get_if<sec::NotSent>(&strict_result);
    Check(strict_not_sent && strict_not_sent->failure.reason ==
          sec::PinnedClientCallFailureReason::PolicyModeMismatch,
          "strict_rpc_rejected_for_credit_policy_before_stub");
  }

  rg::AcquireCreditRequest grant_request;
  grant_request.set_tenant_id("zeta");
  grant_request.set_slot(7);
  const auto slot = std::find_if(fixture.policy->replica_slots().begin(),
      fixture.policy->replica_slots().end(), [](const auto& value) { return value.slot_id == 7; });
  Check(slot != fixture.policy->replica_slots().end(), "fixture_replica_slot_found");
  if (slot == fixture.policy->replica_slots().end()) return;
  grant_request.set_incarnation_id(
      reinterpret_cast<const char*>(slot->incarnation_id.data()), slot->incarnation_id.size());
  grant_request.set_epoch_id(reinterpret_cast<const char*>(fixture.policy->epoch_id().data()), 16);
  grant_request.set_policy_digest(reinterpret_cast<const char*>(fixture.digest.data()), 32);
  grant_request.set_sequence(1);
  grant_request.set_trigger_cost_units(2);
  grant_request.set_trigger_operation_id("list");
  auto grant_result = client->AcquireCredit(grant_request, Deadline());
  if (fixture.policy->mode() == pol::Mode::Credit) {
    const auto* grant_invoked =
        std::get_if<sec::Invoked<rg::AcquireCreditResponse>>(&grant_result);
    Check(grant_invoked && grant_invoked->has_transport_status() &&
          grant_invoked->transport_status()->ok() &&
          grant_invoked->raw_response().grant_outcome() == rg::GRANT_OUTCOME_UNAVAILABLE,
          "replica_to_authority_credit_rpc_invoked_once_and_raw_response_retained");
  } else {
    const auto* grant_not_sent = std::get_if<sec::NotSent>(&grant_result);
    Check(grant_not_sent && grant_not_sent->failure.reason ==
          sec::PinnedClientCallFailureReason::PolicyModeMismatch,
          "credit_rpc_rejected_for_strict_policy_before_stub");
  }
  Check(server.service.calls.load(std::memory_order_acquire) == 1U,
        "only_policy_mode_supported_authority_method_dispatched_once");

  const unsigned calls_before_timeout = server.service.calls.load(std::memory_order_acquire);
  if (fixture.policy->mode() == pol::Mode::Strict) {
    strict_request.set_operation_id("slow");
    const auto timeout_result = client->StrictCheck(strict_request, Deadline());
    const auto* invoked = std::get_if<sec::Invoked<rg::AdmissionDecision>>(&timeout_result);
    Check(invoked && invoked->has_transport_status() &&
          invoked->transport_status()->error_code() == grpc::StatusCode::DEADLINE_EXCEEDED,
          "authority_deadline_is_bounded_and_invoked_status_preserved");
  } else {
    grant_request.set_trigger_operation_id("slow");
    const auto timeout_result = client->AcquireCredit(grant_request, Deadline());
    const auto* invoked = std::get_if<sec::Invoked<rg::AcquireCreditResponse>>(&timeout_result);
    Check(invoked && invoked->has_transport_status() &&
          invoked->transport_status()->error_code() == grpc::StatusCode::DEADLINE_EXCEEDED,
          "authority_deadline_is_bounded_and_invoked_status_preserved");
  }
  Check(server.service.calls.load(std::memory_order_acquire) == calls_before_timeout + 1,
        "bounded_authority_timeout_has_single_server_dispatch");
}

void RunSessionCacheQualification(const std::string& policy_path) {
  Fixture fixture(policy_path, 48 * 60 * 60, 48 * 60 * 60);
  auto server_verifier_calls = std::make_shared<std::atomic<unsigned>>(0);
  auto client_verifier_calls = std::make_shared<std::atomic<unsigned>>(0);
  ServerNode server(fixture, *fixture.replica, server_verifier_calls);

  grpc::experimental::TlsChannelCredentialsOptions client_options;
  client_options.set_certificate_provider(
      Provider(fixture.pki.root_certificate_pem(), *fixture.adapter));
  client_options.watch_root_certs();
  client_options.watch_identity_key_cert_pairs();
  client_options.set_verify_server_certs(true);
  client_options.set_check_call_host(false);
  client_options.set_certificate_verifier(
      grpc::experimental::ExternalCertificateVerifier::Create<
          CountingClientVerifier>(fixture.registry->peer_pins(),
              sec::ExpectedPeer{fixture.replica->registered.uri,
                  fixture.replica->registered.leaf_der_sha256,
                  fixture.replica->registered.role}, client_verifier_calls));
  auto credentials = grpc::experimental::TlsCredentials(client_options);
  Check(credentials != nullptr, "session_probe_tls_credentials_created");

  std::string first_fresh_peer;
  for (unsigned attempt = 0; attempt < 2; ++attempt) {
    grpc::ChannelArguments fresh_args;
    fresh_args.SetInt("grpc.use_local_subchannel_pool", 1);
    fresh_args.SetInt("grpc.enable_retries", 0);
    fresh_args.SetInt("grpc.experimental.enable_hedging", 0);
    auto fresh_channel = grpc::CreateCustomChannel(
        "127.0.0.1:" + std::to_string(server.port), credentials, fresh_args);
    Check(fresh_channel != nullptr, "fresh_reconnect_channel_created");
    auto fresh_stub = rg::AdmissionService::NewStub(fresh_channel);
    grpc::ClientContext fresh_context;
    fresh_context.set_deadline(Deadline());
    rg::AdmissionDecision fresh_response;
    const auto fresh_status = fresh_stub->CheckAdmission(
        &fresh_context, Request(fixture), &fresh_response);
    Check(fresh_status.ok() &&
          fresh_response.outcome() == rg::DECISION_OUTCOME_UNAVAILABLE,
          "fresh_reconnect_rpc_sentinel");
    const auto fresh_auth = fresh_context.auth_context();
    Check(fresh_auth != nullptr, "fresh_reconnect_auth_context");
    if (fresh_auth == nullptr) continue;
    const auto reused_values = fresh_auth->FindPropertyValues(
        GRPC_SSL_SESSION_REUSED_PROPERTY);
    const auto server_uri = fresh_auth->FindPropertyValues(GRPC_PEER_URI_PROPERTY_NAME);
    const auto server_leaf = fresh_auth->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    const bool client_says_fresh = reused_values.size() == 1 &&
        reused_values.front().data() != nullptr &&
        std::string_view(reused_values.front().data(), reused_values.front().size()) == "false";
    Check(client_says_fresh && server_uri.size() == 1 && server_leaf.size() == 1 &&
          server_uri.front().data() != nullptr && server_leaf.front().data() != nullptr &&
          std::string_view(server_uri.front().data(), server_uri.front().size()) ==
              fixture.replica->registered.uri &&
          std::string_view(server_leaf.front().data(), server_leaf.front().size()) ==
              fixture.replica->certificate_pem,
          "uncached_new_transport_has_exact_server_identity_and_no_resume");
    std::string peer;
    {
      std::lock_guard lock(server.service.observation_mutex);
      Check(server.service.observed.size() > attempt,
            "fresh_reconnect_server_observed_transport");
      if (server.service.observed.size() > attempt) {
        const auto& observation = server.service.observed[attempt];
        peer = observation.peer;
        Check(observation.session_property_present && !observation.resumed &&
              observation.leaf_matches,
              "uncached_server_auth_context_is_fresh_and_pinned");
      }
    }
    if (attempt == 0) first_fresh_peer = std::move(peer);
    else Check(!peer.empty() && peer != first_fresh_peer,
               "uncached_reconnect_uses_distinct_tcp_endpoint");
  }
  const std::size_t cache_observation_base = 2;
  Check(client_verifier_calls->load() > 0 && server_verifier_calls->load() > 0,
        "uncached_handshakes_invoked_both_real_pin_verifiers");

  grpc_ssl_session_cache* cache = grpc_ssl_session_cache_create_lru(1);
  Check(cache != nullptr, "bounded_one_entry_session_cache_created");
  grpc_arg cache_arg = grpc_ssl_session_cache_create_channel_arg(cache);

  std::vector<std::string> peers;
  bool saw_resume_with_leaf_proof = false;
  bool saw_resume_without_leaf_proof = false;
  bool client_leaf_exact_on_resume = false;
  unsigned client_delta_on_resume = 0;
  unsigned server_delta_on_resume = 0;
  bool new_transport = false;
  unsigned cache_handler_calls = 0;
  unsigned cache_attempts = 0;
  for (unsigned attempt = 0; attempt < 8; ++attempt) {
    cache_attempts = attempt + 1;
    grpc::ChannelArguments args;
    args.SetInt("grpc.use_local_subchannel_pool", 1);
    args.SetInt("grpc.enable_retries", 0);
    args.SetInt("grpc.experimental.enable_hedging", 0);
    args.SetPointerWithVtable(cache_arg.key, cache_arg.value.pointer.p,
                              cache_arg.value.pointer.vtable);
    auto channel = grpc::CreateCustomChannel("127.0.0.1:" + std::to_string(server.port),
                                       credentials, args);
    Check(channel != nullptr, "session_probe_channel_created");
    auto stub = rg::AdmissionService::NewStub(channel);
    const unsigned handler_calls_before = server.service.calls.load(std::memory_order_acquire);
    const unsigned client_verifier_calls_before = client_verifier_calls->load();
    const unsigned server_verifier_calls_before = server_verifier_calls->load();
    grpc::ClientContext context;
    context.set_deadline(Deadline());
    rg::AdmissionDecision response;
    const auto status = stub->CheckAdmission(&context, Request(fixture), &response);
    const auto auth = context.auth_context();
    if (auth == nullptr) {
      if (attempt == 0) Fail("initial_session_probe_auth_context_missing");
      break;
    }
    const auto reused = auth->FindPropertyValues(GRPC_SSL_SESSION_REUSED_PROPERTY);
    const auto uri = auth->FindPropertyValues(GRPC_PEER_URI_PROPERTY_NAME);
    const auto leaf = auth->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    const bool is_reused = reused.size() == 1 && reused.front().data() != nullptr &&
        std::string_view(reused.front().data(), reused.front().size()) == "true";
    const bool client_leaf_exact = uri.size() == 1 && leaf.size() == 1 &&
        uri.front().data() != nullptr && leaf.front().data() != nullptr &&
        std::string_view(uri.front().data(), uri.front().size()) ==
            fixture.replica->registered.uri &&
        std::string_view(leaf.front().data(), leaf.front().size()) ==
            fixture.replica->certificate_pem;
    std::string peer;
    bool server_reused = false;
    bool server_session_property_present = false;
    bool server_leaf_exact = false;
    {
      std::lock_guard lock(server.service.observation_mutex);
      if (server.service.observed.size() > cache_observation_base + attempt) {
        const auto& observation = server.service.observed.back();
        peer = observation.peer;
        server_session_property_present = observation.session_property_present;
        server_reused = observation.resumed;
        server_leaf_exact = observation.leaf_matches;
      }
    }
    if (is_reused) {
      client_leaf_exact_on_resume = client_leaf_exact;
      new_transport = !peers.empty() && !peer.empty() && peer != peers.front();
      if (!status.ok()) {
        const unsigned handler_calls_after = server.service.calls.load(std::memory_order_acquire);
        saw_resume_without_leaf_proof = handler_calls_after == handler_calls_before;
        if (!saw_resume_without_leaf_proof) {
          std::cout << nlohmann::json{{"status", "unsafe_resumed_failure_after_dispatch"},
              {"actual_resumed", true}, {"dispatch_unchanged", false}}.dump() << '\n';
          grpc_ssl_session_cache_destroy(cache);
          std::exit(2);
        }
        break;
      }
      Check(response.outcome() == rg::DECISION_OUTCOME_UNAVAILABLE,
            "resumed_probe_sentinel_response");
      client_delta_on_resume = client_verifier_calls->load() - client_verifier_calls_before;
      server_delta_on_resume = server_verifier_calls->load() - server_verifier_calls_before;
      const bool verifiers_ran = client_delta_on_resume > 0 && server_delta_on_resume > 0;
      saw_resume_with_leaf_proof = client_leaf_exact && server_session_property_present &&
          server_reused && server_leaf_exact && verifiers_ran;
      cache_handler_calls = server.service.calls.load(std::memory_order_acquire);
      if (!saw_resume_with_leaf_proof || !new_transport ||
          cache_handler_calls != handler_calls_before + 1) {
        std::cout << nlohmann::json{{"status", "unsafe_resumed_path_without_complete_proof"},
            {"actual_resumed", true}, {"new_transport", new_transport},
            {"client_leaf_pin", client_leaf_exact}, {"server_leaf_pin", server_leaf_exact},
            {"server_reused_property", server_session_property_present && server_reused},
            {"verifiers_ran", client_verifier_calls->load() > client_verifier_calls_before &&
                server_verifier_calls->load() > server_verifier_calls_before},
            {"handler_dispatched", cache_handler_calls == handler_calls_before + 1}}.dump()
                  << '\n';
        grpc_ssl_session_cache_destroy(cache);
        std::exit(2);
      }
      break;
    }
    if (!status.ok()) {
      if (attempt == 0) Fail("initial_session_probe_rpc_failed");
      break;
    }
    Check(response.outcome() == rg::DECISION_OUTCOME_UNAVAILABLE,
          "session_probe_rpc_sentinel_response");
    peers.push_back(std::move(peer));
    // Scope exit destroys the channel/stub before the next forced transport.
  }
  if (saw_resume_with_leaf_proof && new_transport && client_leaf_exact_on_resume) {
    std::cout << nlohmann::json{{"status", "qualified"}, {"actual_resumed", true},
        {"client_verifier_delta", client_delta_on_resume},
        {"server_verifier_delta", server_delta_on_resume},
        {"new_transport", true}, {"client_leaf_pin", true}, {"server_leaf_pin", true},
        {"uncached_reconnects_passed", true}, {"cache_attempts", cache_attempts},
        {"cache_capacity", 1},
        {"client_verifier_calls", client_verifier_calls->load()},
        {"server_verifier_calls", server_verifier_calls->load()}}.dump() << '\n';
  } else if (saw_resume_without_leaf_proof) {
    std::cout << nlohmann::json{{"status", "not_qualified_no_dispatch_observed"},
        {"actual_resumed", true}, {"dispatch_unchanged", true},
        {"new_transport", new_transport}, {"uncached_reconnects_passed", true},
        {"cache_attempts", cache_attempts}, {"cache_capacity", 1},
        {"client_verifier_calls", client_verifier_calls->load()},
        {"server_verifier_calls", server_verifier_calls->load()}}.dump() << '\n';
  } else {
    std::cout << nlohmann::json{{"status", "not_demonstrated"},
        {"actual_resumed", false}, {"max_attempts", 8},
        {"cache_attempts", cache_attempts}, {"uncached_reconnects_passed", true},
        {"cache_capacity", 1},
        {"client_verifier_calls", client_verifier_calls->load()},
        {"server_verifier_calls", server_verifier_calls->load()}}.dump() << '\n';
  }
  grpc_ssl_session_cache_destroy(cache);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2 && argc != 3) Fail("usage");
  if (argc == 3 && std::string_view(argv[2]) != "--qualify-session") Fail("usage");
  try {
    if (argc == 3 && std::string_view(argv[2]) == "--qualify-session") {
      RunSessionCacheQualification(argv[1]);
      return 0;
    }
    RunExpiryCase(argv[1], 48 * 60 * 60, 48 * 60 * 60,
                  true, false, false);
    RunExpiryCase(argv[1], 60 * 60, 48 * 60 * 60,
                  false, true, false);
    RunExpiryCase(argv[1], 48 * 60 * 60, 60 * 60,
                  false, false, true);
    RunRetryAndReconnectCases(argv[1]);
    RunChangedServerPinCase(argv[1]);
    RunClientFactoryValidationCases(argv[1]);
    RunAuthorityWrapperCase(argv[1], false);
    RunAuthorityWrapperCase(argv[1], true);
  } catch (const std::exception&) {
    Fail("fixture_or_rpc_exception");
  }
  std::cout << "PASS pinned_peer_rpc_client_fresh_guard" << '\n';
  return 0;
}
