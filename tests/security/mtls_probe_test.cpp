#include "ephemeral_pki.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>

#include "proto/rateguard/v1/admission.grpc.pb.h"
#include "rateguard/security/tls_certificate_verifier.h"

namespace sec = rateguard::security;
namespace rg = rateguard::v1;
using grpc::experimental::IdentityKeyCertPair;
using grpc::experimental::StaticDataCertificateProvider;

namespace {
class ProbeService final : public rg::AdmissionService::Service {
 public:
  grpc::Status CheckAdmission(grpc::ServerContext*, const rg::CheckAdmissionRequest*,
                              rg::AdmissionDecision* response) override {
    ++calls;
    response->set_outcome(rg::DECISION_OUTCOME_ALLOW);
    return grpc::Status::OK;
  }
  std::atomic<unsigned> calls{0};
};

struct RunResult { grpc::Status status; unsigned calls; };

std::shared_ptr<grpc::experimental::CertificateProviderInterface> Provider(
    const std::string& root, const sec::test::EphemeralIdentity* identity) {
  std::vector<IdentityKeyCertPair> pairs;
  if (identity) pairs.push_back({identity->private_key_pem, identity->certificate_pem});
  return std::make_shared<StaticDataCertificateProvider>(root, pairs);
}

std::shared_ptr<grpc::ChannelCredentials> ClientCredentials(
    const std::string& trusted_root,
    const sec::test::EphemeralIdentity* client_identity,
    std::shared_ptr<const sec::PeerRegistry> registry,
    sec::ExpectedPeer expected) {
  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(Provider(trusted_root, client_identity));
  options.watch_root_certs();
  if (client_identity) {
    options.watch_identity_key_cert_pairs();
  }
  options.set_verify_server_certs(true);
  options.set_check_call_host(false);
  options.set_certificate_verifier(
      grpc::experimental::ExternalCertificateVerifier::Create<sec::PinnedPeerVerifier>(
          std::move(registry), std::move(expected)));
  return grpc::experimental::TlsCredentials(options);
}

RunResult Invoke(const std::string& server_root,
                 const sec::test::EphemeralIdentity& server_identity,
                 const std::vector<sec::RegisteredPeer>& server_registry_records,
                 std::shared_ptr<grpc::ChannelCredentials> client_credentials,
                 unsigned rpc_count = 1) {
  ProbeService service;
  grpc::experimental::TlsServerCredentialsOptions server_options(
      Provider(server_root, &server_identity));
  server_options.watch_root_certs();
  server_options.watch_identity_key_cert_pairs();
  server_options.set_cert_request_type(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  server_options.set_certificate_verifier(
      grpc::experimental::ExternalCertificateVerifier::Create<sec::PinnedPeerVerifier>(
          std::make_shared<const sec::PeerRegistry>(server_registry_records)));
  auto server_credentials = grpc::experimental::TlsServerCredentials(server_options);
  int port = 0;
  grpc::ServerBuilder builder;
  builder.AddListeningPort("127.0.0.1:0", server_credentials, &port);
  builder.RegisterService(&service);
  auto server = builder.BuildAndStart();
  if (!server || port <= 0) return {grpc::Status(grpc::StatusCode::UNAVAILABLE, "probe server failed"), service.calls.load()};

  auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port), client_credentials);
  auto stub = rg::AdmissionService::NewStub(channel);
  rg::CheckAdmissionRequest request;
  request.set_tenant_id("probe");
  request.set_operation_id("read");
  request.set_attempt_id(std::string(16, '\x01'));
  request.set_epoch_id(std::string(16, '\x02'));
  request.set_policy_digest(std::string(32, '\x03'));
  grpc::Status status;
  for (unsigned i = 0; i < rpc_count; ++i) {
    rg::AdmissionDecision response;
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(3));
    status = stub->CheckAdmission(&context, request, &response);
    if (!status.ok()) break;
  }
  const unsigned calls = service.calls.load();
  channel.reset();
  server->Shutdown();
  return {status, calls};
}

bool Scenario(const char* name, bool expected_ok, const RunResult& result,
              unsigned expected_calls = 1) {
  const bool ok = result.status.ok() == expected_ok &&
                  result.calls == (expected_ok ? expected_calls : 0);
  std::cout << name << ": " << (ok ? "PASS" : "FAIL") << " rpc="
            << (result.status.ok() ? "OK" : "REJECTED") << " handler_calls=" << result.calls << '\n';
  return ok;
}
}  // namespace

int main() {
  try {
    sec::test::EphemeralPki pki;
    const auto& server = pki.Issue(sec::PeerRole::kReplica,
        "spiffe://rateguard.local/replica/1/0102030405060708090a0b0c0d0e0f10");
    const auto& client = pki.Issue(sec::PeerRole::kAdapter, "spiffe://rateguard.local/adapter/probe");
    const auto& bad_uri = pki.Issue(sec::PeerRole::kAdapter, "spiffe://rateguard.local/adapter/unregistered");
    const auto& second_client = pki.Issue(sec::PeerRole::kAdapter, client.registered.uri);
    const auto& wrong_eku = pki.Issue(sec::PeerRole::kAuthority,
        "spiffe://rateguard.local/authority/030405060708090a0b0c0d0e0f101112");
    const auto& expired_client = pki.IssueWithValidity(sec::PeerRole::kAdapter,
        "spiffe://rateguard.local/adapter/expired", -7200, -3600);
    const auto& future_client = pki.IssueWithValidity(sec::PeerRole::kAdapter,
        "spiffe://rateguard.local/adapter/future", 3600, 7200);
    const auto& multi_uri_client = pki.IssueWithUriSans(sec::PeerRole::kAdapter,
        {"spiffe://rateguard.local/adapter/probe", "spiffe://rateguard.local/adapter/other"});
    const auto& wrong_server_uri = pki.Issue(sec::PeerRole::kReplica,
        "spiffe://rateguard.local/replica/9/0909090a0b0c0d0e0f10111213141516");
    const auto& second_server = pki.Issue(sec::PeerRole::kReplica, server.registered.uri);
    sec::test::EphemeralPki foreign_pki;
    const auto& unknown_ca_client = foreign_pki.Issue(sec::PeerRole::kAdapter, "spiffe://rateguard.local/adapter/probe");
    const auto& unknown_ca_server = foreign_pki.Issue(sec::PeerRole::kReplica,
        "spiffe://rateguard.local/replica/1/0102030405060708090a0b0c0d0e0f10");

    auto client_registry = std::make_shared<const sec::PeerRegistry>(
        std::vector<sec::RegisteredPeer>{server.registered});
    const sec::ExpectedPeer expected_server{server.registered.uri, server.registered.leaf_der_sha256,
                                             server.registered.role};
    auto server_registry_for = [](const sec::test::EphemeralIdentity& peer) {
      return std::vector<sec::RegisteredPeer>{peer.registered};
    };
    int fails = 0;
    auto run = [&](const char* name, const sec::test::EphemeralIdentity* presented,
                   std::vector<sec::RegisteredPeer> allowlist, bool expect_ok,
                   const std::string& trusted_root = std::string{}) {
      const auto& root = trusted_root.empty() ? pki.root_certificate_pem() : trusted_root;
      auto creds = ClientCredentials(root, presented, client_registry, expected_server);
      if (!Scenario(name, expect_ok, Invoke(pki.root_certificate_pem(), server,
                                             allowlist, std::move(creds)))) ++fails;
    };
    run("valid", &client, server_registry_for(client), true);
    run("wrong_uri", &bad_uri, server_registry_for(client), false);
    // The server allowlist has the expected URI and expected digest, while the
    // presented leaf has the same URI but a different DER digest.
    run("same_uri_wrong_leaf_pin", &second_client, server_registry_for(client), false);
    run("wrong_eku", &wrong_eku, server_registry_for(wrong_eku), false);
    run("unknown_ca", &unknown_ca_client, server_registry_for(client), false);
    run("missing_client_certificate", nullptr, server_registry_for(client), false);
    run("expired_client_leaf", &expired_client, server_registry_for(expired_client), false);
    run("not_yet_valid_client_leaf", &future_client, server_registry_for(future_client), false);
    run("multiple_uri_sans", &multi_uri_client, server_registry_for(multi_uri_client), false);

    auto expected_client_creds = [&](sec::ExpectedPeer expected) {
      return ClientCredentials(pki.root_certificate_pem(), &client, client_registry,
                               std::move(expected));
    };
    auto server_pin_case = [&](const char* name, const sec::test::EphemeralIdentity& presented_server,
                               bool expect_ok) {
      const auto result = Invoke(pki.root_certificate_pem(), presented_server,
          server_registry_for(client), expected_client_creds(expected_server));
      if (!Scenario(name, expect_ok, result)) ++fails;
    };
    server_pin_case("wrong_server_uri", wrong_server_uri, false);
    server_pin_case("same_uri_wrong_server_leaf_pin", second_server, false);
    server_pin_case("unknown_server_ca", unknown_ca_server, false);
    const auto reused = Invoke(pki.root_certificate_pem(), server,
        server_registry_for(client), expected_client_creds(expected_server), 2);
    if (!Scenario("reused_channel_two_rpcs", true, reused, 2)) ++fails;
    return fails == 0 ? 0 : 1;
  } catch (const std::exception&) {
    // Do not print OpenSSL errors or credential material; they can contain
    // peer-controlled strings in future implementations.
    std::cerr << "mTLS probe setup failed\n";
    return 2;
  }
}
