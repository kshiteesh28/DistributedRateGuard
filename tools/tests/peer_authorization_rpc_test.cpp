#include "ephemeral_pki.h"
#include "rateguard/v1/channel_policy.h"

#include "policy/canonical_codec.h"
#include "policy/policy_loader.h"
#include "proto/rateguard/v1/admission.grpc.pb.h"
#include "proto/rateguard/v1/authority.grpc.pb.h"
#include "rateguard/security/authorization_resolver.h"
#include "rateguard/security/peer_authenticator.h"
#include "rateguard/security/tls_certificate_verifier.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
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
    ++samples_;
    if (!healthy_) return sec::TrustedWallClockFailure{
        sec::TrustedWallClockFailureReason::PlatformUnavailable};
    return value_;
  }
  bool Healthy() const override {
    std::lock_guard lock(mutex_);
    return healthy_;
  }
  // This mutable fake permits independent test subcases. It is not the
  // production clock's sticky-failure/reset contract and proves no epoch
  // recovery, rollback, readiness, or fencing behavior.
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
  std::uint64_t samples_{};
};

class CountingPinnedVerifier final
    : public grpc::experimental::ExternalCertificateVerifier {
 public:
  CountingPinnedVerifier(std::shared_ptr<const sec::PeerRegistry> registry,
                         std::optional<sec::ExpectedPeer> expected,
                         std::shared_ptr<std::atomic<unsigned>> count)
      : delegate_(std::move(registry), std::move(expected)), count_(std::move(count)) {}
  bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)> callback,
              grpc::Status* sync_status) override {
    count_->fetch_add(1, std::memory_order_relaxed);
    return delegate_.Verify(request, std::move(callback), sync_status);
  }
  void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest* request) override {
    delegate_.Cancel(request);
  }
 private:
  sec::PinnedPeerVerifier delegate_;
  std::shared_ptr<std::atomic<unsigned>> count_;
};

std::string ReadFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
std::string Hex(std::span<const std::uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}
pol::Digest32 RootDigest(std::string_view pem) {
  BIO* raw_bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw_bio) Fail("fixture_root_parse");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!raw_cert) Fail("fixture_root_parse");
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
  const int length = i2d_X509(cert.get(), nullptr);
  if (length <= 0 || length > 64 * 1024) Fail("fixture_root_der");
  std::vector<std::uint8_t> der(static_cast<std::size_t>(length));
  auto* cursor = der.data();
  if (i2d_X509(cert.get(), &cursor) != length) Fail("fixture_root_der");
  pol::Digest32 digest{};
  unsigned int written = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &written,
                 EVP_sha256(), nullptr) != 1 || written != digest.size())
    Fail("fixture_root_hash");
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

  explicit Fixture(const std::string& fixture_path) {
    auto document = nlohmann::json::parse(ReadFile(fixture_path));
    document["trust_root_sha256"] = Hex(RootDigest(pki.root_certificate_pem()));
    for (auto& principal : document["principals"]) {
      if (principal["role"] == "replica" && principal.value("slot_id", 0U) == 7U) {
        principal["permissions"].push_back({{"tenant_id", "zeta"},
                                             {"operation_id", "list"}});
      }
    }
    auto loaded = pol::PolicyLoader::Load(document.dump());
    const auto* parsed = std::get_if<std::shared_ptr<const pol::PolicySnapshot>>(&loaded);
    Check(parsed != nullptr, "policy_fixture_loads");
    policy = *parsed;
    auto digest_result = pol::CanonicalPolicyCodec::Digest(*policy);
    const auto* digest_value = std::get_if<pol::Digest32>(&digest_result);
    Check(digest_value != nullptr, "policy_digest_available");
    digest = *digest_value;

    std::vector<std::string_view> leaf_pems;
    identities.reserve(policy->principals().size());
    leaf_pems.reserve(policy->principals().size());
    for (const auto& principal : policy->principals()) {
      sec::PeerRole role = sec::PeerRole::kAdapter;
      if (principal.role == pol::PrincipalRole::Replica) role = sec::PeerRole::kReplica;
      if (principal.role == pol::PrincipalRole::Authority) role = sec::PeerRole::kAuthority;
      const auto& identity = pki.IssueWithValidity(role, principal.uri, -60, 3600);
      identities.push_back(&identity);
      leaf_pems.push_back(identity.certificate_pem);
      if (principal.role == pol::PrincipalRole::Adapter && adapter == nullptr) adapter = &identity;
      if (principal.role == pol::PrincipalRole::Replica && principal.slot_id == 7U) replica = &identity;
      if (principal.role == pol::PrincipalRole::Authority && authority == nullptr) authority = &identity;
    }
    const auto wall_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    now = {wall_seconds, 0};
    MutableClock initial_clock(now);
    auto built = sec::CertificateRegistryLoader::Load(
        policy, pki.root_certificate_pem(), leaf_pems, initial_clock);
    const auto* value = std::get_if<std::shared_ptr<const sec::CertificateRegistry>>(&built);
    Check(value != nullptr, "registry_fixture_loads");
    registry = *value;
    Check(adapter != nullptr && replica != nullptr && authority != nullptr,
          "fixture_has_all_endpoint_roles");
  }
};

std::shared_ptr<grpc::experimental::CertificateProviderInterface> Provider(
    const std::string& root, const sec::test::EphemeralIdentity& identity) {
  std::vector<IdentityKeyCertPair> pairs{{identity.private_key_pem,
                                           identity.certificate_pem}};
  return std::make_shared<StaticDataCertificateProvider>(root, pairs);
}

std::shared_ptr<grpc::ChannelCredentials> ClientCredentials(
    const Fixture& fixture, const sec::test::EphemeralIdentity& client,
    const sec::test::EphemeralIdentity& server) {
  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(Provider(fixture.pki.root_certificate_pem(), client));
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  options.set_verify_server_certs(true);
  options.set_check_call_host(false);
  options.set_certificate_verifier(
      grpc::experimental::ExternalCertificateVerifier::Create<sec::PinnedPeerVerifier>(
          fixture.registry->peer_pins(), sec::ExpectedPeer{
              server.registered.uri, server.registered.leaf_der_sha256,
              server.registered.role}));
  return grpc::experimental::TlsCredentials(options);
}

struct StateSpy final {
  void Call(std::uint64_t cost) {
    last_cost.store(cost, std::memory_order_relaxed);
    calls.fetch_add(1, std::memory_order_release);
  }
  std::atomic<unsigned> calls{0};
  std::atomic<std::uint64_t> last_cost{0};
};

grpc::Status Reject(sec::PeerAuthDisposition disposition) {
  switch (disposition) {
    case sec::PeerAuthDisposition::Unauthenticated:
      return {grpc::StatusCode::UNAUTHENTICATED, "peer rejected"};
    case sec::PeerAuthDisposition::InvalidArgument:
      return {grpc::StatusCode::INVALID_ARGUMENT, "request rejected"};
    case sec::PeerAuthDisposition::PermissionDenied:
      return {grpc::StatusCode::PERMISSION_DENIED, "operation denied"};
    case sec::PeerAuthDisposition::ApplicationUnavailable:
      return grpc::Status::OK;
  }
  return {grpc::StatusCode::INTERNAL, "internal rejection"};
}
grpc::Status Reject(sec::AuthorizationDisposition disposition) {
  switch (disposition) {
    case sec::AuthorizationDisposition::Unauthenticated:
      return {grpc::StatusCode::UNAUTHENTICATED, "peer rejected"};
    case sec::AuthorizationDisposition::InvalidArgument:
      return {grpc::StatusCode::INVALID_ARGUMENT, "request rejected"};
    case sec::AuthorizationDisposition::PermissionDenied:
      return {grpc::StatusCode::PERMISSION_DENIED, "operation denied"};
    case sec::AuthorizationDisposition::ApplicationUnavailable:
      return grpc::Status::OK;
  }
  return {grpc::StatusCode::INTERNAL, "internal rejection"};
}

class AdmissionProbe final : public rg::AdmissionService::Service {
 public:
  struct Observation final {
    unsigned calls{};
    std::string peer;
    std::shared_ptr<const grpc::AuthContext> auth_context;
    bool properties_ok{};
  };
  AdmissionProbe(std::shared_ptr<const sec::CertificateRegistry> registry,
                 sec::ITrustedWallClock& clock, StateSpy& spy,
                 std::string expected_uri, std::string expected_leaf_pem)
      : authenticator_(registry, clock), spy_(spy),
        expected_uri_(std::move(expected_uri)), expected_leaf_pem_(std::move(expected_leaf_pem)) {
    auto result = sec::AuthorizationResolver::Create(std::move(registry), clock);
    const auto* value = std::get_if<sec::AuthorizationResolver>(&result);
    Check(value != nullptr, "admission_resolver_factory_succeeds");
    resolver_.emplace(*value);
  }

  grpc::Status CheckAdmission(grpc::ServerContext* context,
                              const rg::CheckAdmissionRequest* request,
                              rg::AdmissionDecision* response) override {
    const unsigned call_number = handler_calls.fetch_add(1, std::memory_order_relaxed) + 1;
    auto current_auth_context = context->auth_context();
    if (!current_auth_context) return {grpc::StatusCode::UNAUTHENTICATED, "peer rejected"};
    const auto transports = current_auth_context->FindPropertyValues(
        GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME);
    const auto uris = current_auth_context->FindPropertyValues(GRPC_PEER_URI_PROPERTY_NAME);
    const auto leafs = current_auth_context->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    const bool properties_ok = transports.size() == 1 && uris.size() == 1 && leafs.size() == 1 &&
        transports.front().data() != nullptr && uris.front().data() != nullptr &&
        leafs.front().data() != nullptr &&
        std::string_view(transports.front().data(), transports.front().size()) ==
            GRPC_TLS_TRANSPORT_SECURITY_TYPE &&
        std::string_view(uris.front().data(), uris.front().size()) == expected_uri_ &&
        std::string_view(leafs.front().data(), leafs.front().size()) == expected_leaf_pem_;
    {
      std::lock_guard lock(observation_mutex_);
      observation_ = Observation{call_number, context->peer(), current_auth_context, properties_ok};
    }
    const auto authenticated = authenticator_.Authenticate(*current_auth_context);
    const auto* peer = std::get_if<sec::AuthenticatedPeer>(&authenticated);
    if (!peer) {
      const auto& failure = std::get<sec::PeerAuthFailure>(authenticated);
      if (failure.disposition == sec::PeerAuthDisposition::ApplicationUnavailable) {
        response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
        return grpc::Status::OK;
      }
      return Reject(failure.disposition);
    }
    const auto authorized = resolver_->Resolve(*peer, sec::RpcMethod::AdapterCheckAdmission,
                                                *request);
    const auto* operation = std::get_if<sec::AuthorizedOperation>(&authorized);
    if (!operation) {
      const auto& failure = std::get<sec::AuthorizationFailure>(authorized);
      if (failure.disposition == sec::AuthorizationDisposition::ApplicationUnavailable) {
        response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
        return grpc::Status::OK;
      }
      return Reject(failure.disposition);
    }
    spy_.Call(operation->cost_units());
    // This is a test sink, not a quota implementation. Avoid returning ALLOW.
    response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
    response->set_attempt_id(request->attempt_id());
    response->set_epoch_id(reinterpret_cast<const char*>(operation->epoch_id().data()),
                           operation->epoch_id().size());
    response->set_policy_digest(reinterpret_cast<const char*>(operation->policy_digest().data()),
                                 operation->policy_digest().size());
    response->set_mode(operation->mode() == pol::Mode::Credit
                           ? rg::ADMISSION_MODE_CREDIT
                           : rg::ADMISSION_MODE_STRICT);
    return grpc::Status::OK;
  }

  [[nodiscard]] Observation Snapshot() const {
    std::lock_guard lock(observation_mutex_);
    return observation_;
  }
 private:
  std::atomic<unsigned> handler_calls{0};
  mutable std::mutex observation_mutex_;
  Observation observation_;
  sec::PeerAuthenticator authenticator_;
  StateSpy& spy_;
  std::string expected_uri_;
  std::string expected_leaf_pem_;
  std::optional<sec::AuthorizationResolver> resolver_;
};

class AuthorityProbe final : public rg::AuthorityService::Service {
 public:
  AuthorityProbe(std::shared_ptr<const sec::CertificateRegistry> registry,
                 sec::ITrustedWallClock& clock, StateSpy& spy,
                 std::string expected_uri, std::string expected_leaf_pem)
      : authenticator_(registry, clock), spy_(spy),
        expected_uri_(std::move(expected_uri)), expected_leaf_pem_(std::move(expected_leaf_pem)) {
    auto result = sec::AuthorizationResolver::Create(std::move(registry), clock);
    const auto* value = std::get_if<sec::AuthorizationResolver>(&result);
    Check(value != nullptr, "authority_resolver_factory_succeeds");
    resolver_.emplace(*value);
  }

  grpc::Status StrictCheck(grpc::ServerContext* context,
                           const rg::CheckAdmissionRequest* request,
                           rg::AdmissionDecision* response) override {
    return Check(context, request, response, sec::RpcMethod::ReplicaStrictCheck);
  }
  grpc::Status AcquireCredit(grpc::ServerContext* context,
                             const rg::AcquireCreditRequest* request,
                             rg::AcquireCreditResponse* response) override {
    handler_calls.fetch_add(1, std::memory_order_relaxed);
    auto auth_context = context->auth_context();
    if (!auth_context) return {grpc::StatusCode::UNAUTHENTICATED, "peer rejected"};
    last_properties_ok.store(HasExpectedProperties(*auth_context), std::memory_order_relaxed);
    const auto authenticated = authenticator_.Authenticate(*auth_context);
    const auto* peer = std::get_if<sec::AuthenticatedPeer>(&authenticated);
    if (!peer) {
      const auto disposition = std::get<sec::PeerAuthFailure>(authenticated).disposition;
      if (disposition == sec::PeerAuthDisposition::ApplicationUnavailable) {
        response->set_grant_outcome(rg::GRANT_OUTCOME_UNAVAILABLE);
        return grpc::Status::OK;
      }
      return Reject(disposition);
    }
    const auto authorized = resolver_->Resolve(*peer, sec::RpcMethod::ReplicaAcquireCredit,
                                                *request);
    const auto* grant = std::get_if<sec::AuthorizedGrant>(&authorized);
    if (!grant) {
      const auto disposition = std::get<sec::AuthorizationFailure>(authorized).disposition;
      if (disposition == sec::AuthorizationDisposition::ApplicationUnavailable) {
        response->set_grant_outcome(rg::GRANT_OUTCOME_UNAVAILABLE);
        return grpc::Status::OK;
      }
      return Reject(disposition);
    }
    spy_.Call(grant->cost_units());
    // Authorization is not a committed grant; response is a probe sentinel.
    response->set_grant_outcome(rg::GRANT_OUTCOME_UNAVAILABLE);
    response->set_sequence(grant->sequence());
    response->set_epoch_id(request->epoch_id());
    response->set_policy_digest(request->policy_digest());
    return grpc::Status::OK;
  }

  std::atomic<unsigned> handler_calls{0};
  std::atomic<bool> last_properties_ok{false};
 private:
  bool HasExpectedProperties(const grpc::AuthContext& context) const {
    const auto transports = context.FindPropertyValues(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME);
    const auto uris = context.FindPropertyValues(GRPC_PEER_URI_PROPERTY_NAME);
    const auto leaves = context.FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    return transports.size() == 1 && uris.size() == 1 && leaves.size() == 1 &&
        transports.front().data() != nullptr && uris.front().data() != nullptr &&
        leaves.front().data() != nullptr &&
        std::string_view(transports.front().data(), transports.front().size()) ==
            GRPC_TLS_TRANSPORT_SECURITY_TYPE &&
        std::string_view(uris.front().data(), uris.front().size()) == expected_uri_ &&
        std::string_view(leaves.front().data(), leaves.front().size()) == expected_leaf_pem_;
  }
  grpc::Status Check(grpc::ServerContext* context,
                     const rg::CheckAdmissionRequest* request,
                     rg::AdmissionDecision* response, sec::RpcMethod method) {
    handler_calls.fetch_add(1, std::memory_order_relaxed);
    const auto auth_context = context->auth_context();
    if (!auth_context) return {grpc::StatusCode::UNAUTHENTICATED, "peer rejected"};
    last_properties_ok.store(HasExpectedProperties(*auth_context), std::memory_order_relaxed);
    const auto authenticated = authenticator_.Authenticate(*auth_context);
    const auto* peer = std::get_if<sec::AuthenticatedPeer>(&authenticated);
    if (!peer) {
      const auto disposition = std::get<sec::PeerAuthFailure>(authenticated).disposition;
      if (disposition == sec::PeerAuthDisposition::ApplicationUnavailable) {
        response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
        return grpc::Status::OK;
      }
      return Reject(disposition);
    }
    const auto authorized = resolver_->Resolve(*peer, method, *request);
    const auto* operation = std::get_if<sec::AuthorizedOperation>(&authorized);
    if (!operation) {
      const auto disposition = std::get<sec::AuthorizationFailure>(authorized).disposition;
      if (disposition == sec::AuthorizationDisposition::ApplicationUnavailable) {
        response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
        return grpc::Status::OK;
      }
      return Reject(disposition);
    }
    spy_.Call(operation->cost_units());
    response->set_outcome(rg::DECISION_OUTCOME_UNAVAILABLE);
    return grpc::Status::OK;
  }
  sec::PeerAuthenticator authenticator_;
  StateSpy& spy_;
  std::string expected_uri_;
  std::string expected_leaf_pem_;
  std::optional<sec::AuthorizationResolver> resolver_;
};

std::shared_ptr<grpc::ServerCredentials> ServerCredentials(
    const Fixture& fixture, const sec::test::EphemeralIdentity& server,
    std::shared_ptr<std::atomic<unsigned>> verify_count) {
  grpc::experimental::TlsServerCredentialsOptions options(
      Provider(fixture.pki.root_certificate_pem(), server));
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  options.set_cert_request_type(
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  options.set_certificate_verifier(
      grpc::experimental::ExternalCertificateVerifier::Create<CountingPinnedVerifier>(
          fixture.registry->peer_pins(), std::nullopt, std::move(verify_count)));
  return grpc::experimental::TlsServerCredentials(options);
}

struct AdmissionNode final {
  AdmissionProbe service;
  std::unique_ptr<grpc::Server> server;
  int port{};
  AdmissionNode(const Fixture& fixture, sec::ITrustedWallClock& clock,
                StateSpy& spy, std::shared_ptr<std::atomic<unsigned>> verify_count)
      : service(fixture.registry, clock, spy, fixture.adapter->registered.uri,
                fixture.adapter->certificate_pem) {
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0",
        ServerCredentials(fixture, *fixture.replica, std::move(verify_count)), &port);
    builder.RegisterService(&service);
    server = builder.BuildAndStart();
    Check(server != nullptr && port > 0, "admission_tls_server_starts");
  }
  ~AdmissionNode() { if (server) server->Shutdown(); }
};
struct AuthorityNode final {
  AuthorityProbe service;
  std::unique_ptr<grpc::Server> server;
  int port{};
  AuthorityNode(const Fixture& fixture, sec::ITrustedWallClock& clock,
                StateSpy& spy, std::shared_ptr<std::atomic<unsigned>> verify_count)
      : service(fixture.registry, clock, spy, fixture.replica->registered.uri,
                fixture.replica->certificate_pem) {
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0",
        ServerCredentials(fixture, *fixture.authority, std::move(verify_count)), &port);
    builder.RegisterService(&service);
    server = builder.BuildAndStart();
    Check(server != nullptr && port > 0, "authority_tls_server_starts");
  }
  ~AuthorityNode() { if (server) server->Shutdown(); }
};

rg::CheckAdmissionRequest AdmissionRequest(const Fixture& fixture) {
  rg::CheckAdmissionRequest request;
  request.set_tenant_id("zeta");
  request.set_operation_id("list");
  request.set_attempt_id(std::string(16, 'a'));
  request.set_epoch_id(reinterpret_cast<const char*>(fixture.policy->epoch_id().data()), 16);
  request.set_policy_digest(reinterpret_cast<const char*>(fixture.digest.data()), 32);
  return request;
}
rg::AcquireCreditRequest CreditRequest(const Fixture& fixture) {
  rg::AcquireCreditRequest request;
  request.set_tenant_id("zeta");
  request.set_slot(7);
  const auto& slot = *std::find_if(fixture.policy->replica_slots().begin(),
      fixture.policy->replica_slots().end(), [](const auto& value) { return value.slot_id == 7; });
  request.set_incarnation_id(reinterpret_cast<const char*>(slot.incarnation_id.data()), 16);
  request.set_epoch_id(reinterpret_cast<const char*>(fixture.policy->epoch_id().data()), 16);
  request.set_policy_digest(reinterpret_cast<const char*>(fixture.digest.data()), 32);
  request.set_sequence(1);
  request.set_trigger_cost_units(2);
  request.set_trigger_operation_id("list");
  return request;
}
void SetDeadline(grpc::ClientContext& context) {
  context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
}

void Run(const std::string& policy_path) {
  Fixture fixture(policy_path);
  MutableClock clock(fixture.now);
  StateSpy admission_spy;
  StateSpy authority_spy;
  auto admission_verifications = std::make_shared<std::atomic<unsigned>>(0);
  auto authority_verifications = std::make_shared<std::atomic<unsigned>>(0);
  AdmissionNode admission(fixture, clock, admission_spy, admission_verifications);
  AuthorityNode authority(fixture, clock, authority_spy, authority_verifications);

  auto admission_channel = rg::transport::CreateEnforcementChannel(
      "127.0.0.1:" + std::to_string(admission.port),
      ClientCredentials(fixture, *fixture.adapter, *fixture.replica));
  auto admission_stub = rg::AdmissionService::NewStub(admission_channel);
  auto request = AdmissionRequest(fixture);
  rg::AdmissionDecision response;
  grpc::ClientContext first_context;
  SetDeadline(first_context);
  const auto first_status = admission_stub->CheckAdmission(&first_context, request, &response);
  Check(first_status.ok() && response.outcome() == rg::DECISION_OUTCOME_UNAVAILABLE,
        "adapter_tls_rpc_authenticates_and_resolves_without_claiming_allow");
  Check(admission_spy.calls.load() == 1 && admission_spy.last_cost.load() == 2,
        "policy_cost_reaches_only_authorized_state_spy");
  const auto first_observation = admission.service.Snapshot();
  Check(first_observation.auth_context != nullptr && !first_observation.peer.empty(),
        "real_server_context_auth_and_peer_observed_without_logging_identity");
  Check(first_observation.properties_ok,
        "real_tls_auth_context_exposes_exact_single_uri_and_leaf_properties");
  // Keep the first context alive for the full same-channel comparison so an
  // allocator cannot recycle its address and create a false pointer match.
  const auto retained_first_auth_context = first_observation.auth_context;
  const auto peer_endpoint = first_observation.peer;
  const auto handshake_count = admission_verifications->load();
  Check(handshake_count == 1, "server_leaf_verifier_runs_once_for_first_channel_rpc");

  // Unknown protobuf field 6 is deliberately not a cost input. The resolver
  // must use the immutable policy cost even when a client sends that unknown tag.
  auto forged_cost = AdmissionRequest(fixture);
  forged_cost.GetReflection()->MutableUnknownFields(&forged_cost)->AddVarint(6, 999);
  rg::AdmissionDecision forged_response;
  grpc::ClientContext forged_context;
  SetDeadline(forged_context);
  const auto forged_status = admission_stub->CheckAdmission(
      &forged_context, forged_cost, &forged_response);
  Check(forged_status.ok() && forged_response.outcome() == rg::DECISION_OUTCOME_UNAVAILABLE &&
        admission_spy.calls.load() == 2 && admission_spy.last_cost.load() == 2,
        "unknown_wire_cost_cannot_change_authorized_policy_cost");

  auto unknown = AdmissionRequest(fixture);
  unknown.set_operation_id("unknown");
  rg::AdmissionDecision ignored;
  grpc::ClientContext unknown_context;
  SetDeadline(unknown_context);
  const auto unknown_status = admission_stub->CheckAdmission(&unknown_context, unknown, &ignored);
  Check(unknown_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        admission_spy.calls.load() == 2,
        "unknown_operation_maps_invalid_argument_before_state_spy");

  auto forbidden = AdmissionRequest(fixture);
  forbidden.set_operation_id("delete");
  grpc::ClientContext forbidden_context;
  SetDeadline(forbidden_context);
  const auto forbidden_status = admission_stub->CheckAdmission(
      &forbidden_context, forbidden, &ignored);
  Check(forbidden_status.error_code() == grpc::StatusCode::PERMISSION_DENIED &&
        admission_spy.calls.load() == 2,
        "known_unauthorized_pair_maps_permission_denied_before_state_spy");

  auto stale = AdmissionRequest(fixture);
  stale.set_policy_digest(std::string(32, 'x'));
  grpc::ClientContext stale_context;
  SetDeadline(stale_context);
  const auto stale_status = admission_stub->CheckAdmission(&stale_context, stale, &ignored);
  Check(stale_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        admission_spy.calls.load() == 2,
        "stale_digest_maps_invalid_argument_before_state_spy");

  auto short_id = AdmissionRequest(fixture);
  short_id.set_attempt_id(std::string(15, 'a'));
  grpc::ClientContext short_id_context;
  SetDeadline(short_id_context);
  const auto short_id_status = admission_stub->CheckAdmission(
      &short_id_context, short_id, &ignored);
  Check(short_id_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        admission_spy.calls.load() == 2,
        "malformed_attempt_width_maps_invalid_argument_before_state_spy");

  auto oversized = AdmissionRequest(fixture);
  oversized.GetReflection()->MutableUnknownFields(&oversized)->AddLengthDelimited(
      100, std::string(16 * 1024, 'x'));
  grpc::ClientContext oversized_context;
  SetDeadline(oversized_context);
  const auto oversized_status = admission_stub->CheckAdmission(
      &oversized_context, oversized, &ignored);
  Check(oversized_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        admission_spy.calls.load() == 2,
        "decoded_oversize_maps_invalid_argument_before_state_spy");

  // Advance only the injected trusted clock; OS/TLS wall time and channel do
  // not change. The existing connection must be rejected by the per-call
  // application guard, not by a reconnect or a second TLS verification.
  const auto* adapter_record = fixture.registry->Find(fixture.adapter->registered.uri);
  Check(adapter_record != nullptr, "registered_adapter_record");
  if (adapter_record) {
    Check(fixture.registry->root_validity().Contains(adapter_record->validity.not_after),
          "root_remains_valid_at_leaf_expiration_boundary");
    clock.Set(adapter_record->validity.not_after);
  }
  rg::AdmissionDecision expired_response;
  grpc::ClientContext expired_context;
  SetDeadline(expired_context);
  const auto expired_status = admission_stub->CheckAdmission(
      &expired_context, request, &expired_response);
  Check(expired_status.error_code() == grpc::StatusCode::UNAUTHENTICATED &&
        admission_spy.calls.load() == 2,
        "same_channel_expiry_fails_auth_before_state_spy");
  const auto expired_observation = admission.service.Snapshot();
  Check(retained_first_auth_context != nullptr && expired_observation.auth_context != nullptr &&
        expired_observation.properties_ok && expired_observation.peer == peer_endpoint &&
        admission_verifications->load() == handshake_count,
        "expiry_call_reused_peer_identity_endpoint_and_tls_handshake");

  clock.Set(fixture.now);
  clock.SetHealthy(false);
  rg::AdmissionDecision clock_response;
  grpc::ClientContext clock_context;
  SetDeadline(clock_context);
  const auto clock_status = admission_stub->CheckAdmission(
      &clock_context, request, &clock_response);
  Check(clock_status.ok() && clock_response.outcome() == rg::DECISION_OUTCOME_UNAVAILABLE &&
        admission_spy.calls.load() == 2,
        "clock_failure_is_application_unavailable_with_no_state_call");

  // Restore time and verify the separate authority endpoint uses its own
  // server role (authority) and accepts only the registered replica identity.
  clock.SetHealthy(true);

  const auto pre_tls_negative = admission.service.Snapshot();
  const auto& unregistered_client = fixture.pki.Issue(
      sec::PeerRole::kAdapter, "spiffe://rateguard.local/adapter/not-registered");
  const auto& same_uri_alternate_leaf = fixture.pki.Issue(
      sec::PeerRole::kAdapter, fixture.adapter->registered.uri);
  for (const auto* rejected_client : {&unregistered_client, &same_uri_alternate_leaf}) {
    auto rejected_channel = rg::transport::CreateEnforcementChannel(
        "127.0.0.1:" + std::to_string(admission.port),
        ClientCredentials(fixture, *rejected_client, *fixture.replica));
    auto rejected_stub = rg::AdmissionService::NewStub(rejected_channel);
    rg::AdmissionDecision rejected_response;
    grpc::ClientContext rejected_context;
    SetDeadline(rejected_context);
    const auto rejected_status = rejected_stub->CheckAdmission(
        &rejected_context, request, &rejected_response);
    Check(!rejected_status.ok() && admission.service.Snapshot().calls == pre_tls_negative.calls &&
          admission_spy.calls.load() == 2,
          rejected_client == &unregistered_client
              ? "unregistered_valid_ca_client_rejected_before_handler"
              : "same_uri_alternate_leaf_rejected_before_handler");
    rejected_channel.reset();
  }

  auto authority_channel = rg::transport::CreateEnforcementChannel(
      "127.0.0.1:" + std::to_string(authority.port),
      ClientCredentials(fixture, *fixture.replica, *fixture.authority));
  auto authority_stub = rg::AuthorityService::NewStub(authority_channel);
  auto grant = CreditRequest(fixture);
  rg::AcquireCreditResponse grant_response;
  grpc::ClientContext grant_context;
  SetDeadline(grant_context);
  const auto grant_status = authority_stub->AcquireCredit(
      &grant_context, grant, &grant_response);
  Check(grant_status.ok() && grant_response.grant_outcome() == rg::GRANT_OUTCOME_UNAVAILABLE &&
        authority_spy.calls.load() == 1 && authority_spy.last_cost.load() == 2,
        "replica_tls_rpc_resolves_credit_without_claiming_a_grant");
  Check(authority.service.last_properties_ok.load(std::memory_order_relaxed),
        "authority_service_auth_context_exposes_registered_replica_properties");
  clock.SetHealthy(false);
  rg::AcquireCreditResponse unavailable_grant;
  grpc::ClientContext unavailable_grant_context;
  SetDeadline(unavailable_grant_context);
  const auto unavailable_grant_status = authority_stub->AcquireCredit(
      &unavailable_grant_context, grant, &unavailable_grant);
  Check(unavailable_grant_status.ok() &&
        unavailable_grant.grant_outcome() == rg::GRANT_OUTCOME_UNAVAILABLE &&
        authority_spy.calls.load() == 1,
        "authority_clock_failure_returns_application_unavailable_without_state_call");
  clock.SetHealthy(true);

  auto grant_bad = CreditRequest(fixture);
  grant_bad.set_sequence(0);
  grpc::ClientContext zero_sequence_context;
  SetDeadline(zero_sequence_context);
  const auto zero_sequence_status = authority_stub->AcquireCredit(
      &zero_sequence_context, grant_bad, &grant_response);
  Check(zero_sequence_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        authority_spy.calls.load() == 1,
        "zero_grant_sequence_maps_invalid_argument_before_state_spy");
  grant_bad = CreditRequest(fixture);
  grant_bad.set_slot(2);
  grpc::ClientContext slot_context;
  SetDeadline(slot_context);
  const auto slot_status = authority_stub->AcquireCredit(&slot_context, grant_bad, &grant_response);
  Check(slot_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        authority_spy.calls.load() == 1,
        "wrong_replica_slot_maps_invalid_argument_before_state_spy");
  grant_bad = CreditRequest(fixture);
  grant_bad.set_incarnation_id(std::string(16, 'x'));
  grpc::ClientContext incarnation_context;
  SetDeadline(incarnation_context);
  const auto incarnation_status = authority_stub->AcquireCredit(
      &incarnation_context, grant_bad, &grant_response);
  Check(incarnation_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        authority_spy.calls.load() == 1,
        "wrong_replica_incarnation_maps_invalid_argument_before_state_spy");
  grant_bad = CreditRequest(fixture);
  grant_bad.set_trigger_cost_units(999);
  grpc::ClientContext cost_context;
  SetDeadline(cost_context);
  const auto trigger_cost_status = authority_stub->AcquireCredit(
      &cost_context, grant_bad, &grant_response);
  Check(trigger_cost_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        authority_spy.calls.load() == 1,
        "wrong_trigger_cost_maps_invalid_argument_before_state_spy");

  auto strict_request = AdmissionRequest(fixture);
  rg::AdmissionDecision strict_response;
  grpc::ClientContext strict_context;
  SetDeadline(strict_context);
  const auto strict_status = authority_stub->StrictCheck(
      &strict_context, strict_request, &strict_response);
  Check(strict_status.error_code() == grpc::StatusCode::INVALID_ARGUMENT &&
        authority_spy.calls.load() == 1,
        "strict_method_rejected_in_credit_mode_before_state_spy");

  // A registered adapter cannot invoke the internal authority method even if
  // its selectors happen to name a valid operation.
  auto adapter_to_authority = rg::transport::CreateEnforcementChannel(
      "127.0.0.1:" + std::to_string(authority.port),
      ClientCredentials(fixture, *fixture.adapter, *fixture.authority));
  auto adapter_authority_stub = rg::AuthorityService::NewStub(adapter_to_authority);
  auto adapter_grant = CreditRequest(fixture);
  grpc::ClientContext wrong_role_context;
  SetDeadline(wrong_role_context);
  const auto wrong_role_status = adapter_authority_stub->AcquireCredit(
      &wrong_role_context, adapter_grant, &grant_response);
  Check(wrong_role_status.error_code() == grpc::StatusCode::PERMISSION_DENIED &&
        authority_spy.calls.load() == 1,
        "adapter_cannot_call_replica_authority_method");

  admission_channel.reset();
  authority_channel.reset();
  adapter_to_authority.reset();
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) Fail("usage");
  try {
    Run(argv[1]);
  } catch (const std::exception&) {
    // Do not echo exception text: it may contain peer-controlled or credential data.
    Fail("fixture_or_rpc_exception");
  }
  std::cout << "PASS peer_authorization_real_tls_rpc" << '\n';
  return 0;
}
