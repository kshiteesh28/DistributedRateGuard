#include "ephemeral_pki.h"
#include "rateguard/security/pinned_peer_rpc_client.h"

#include "policy/policy_loader.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
namespace rg = rateguard::v1;

static_assert(!std::is_copy_constructible_v<sec::PinnedPeerRpcClient>);
static_assert(std::is_move_constructible_v<sec::PinnedPeerRpcClient>);
static_assert(std::is_copy_constructible_v<sec::PreparedClientCall>);
static_assert(std::is_copy_constructible_v<sec::ClientCallGuardPassed>);
static_assert(std::is_same_v<
    sec::PinnedClientCallResult<rg::AdmissionDecision>,
    std::variant<sec::NotSent, sec::Invoked<rg::AdmissionDecision>>>);

namespace {

int failures = 0;
void Check(bool ok, std::string_view label) {
  if (!ok) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}

std::string ReadFile(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return {};
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
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
  if (raw_bio == nullptr) return {};
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
  X509* raw_certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (raw_certificate == nullptr) return {};
  std::unique_ptr<X509, decltype(&X509_free)> certificate(raw_certificate, &X509_free);
  const int size = i2d_X509(certificate.get(), nullptr);
  if (size <= 0 || size > 64 * 1024) return {};
  std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
  unsigned char* cursor = der.data();
  if (i2d_X509(certificate.get(), &cursor) != size) return {};
  pol::Digest32 digest{};
  unsigned int digest_size = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &digest_size,
                 EVP_sha256(), nullptr) != 1 || digest_size != digest.size()) return {};
  return digest;
}

class MutableClock final : public sec::ITrustedWallClock {
 public:
  explicit MutableClock(sec::WallTime now) : now_(now) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override { return now_; }
  bool Healthy() const override { return healthy_; }
  void Set(sec::WallTime now) { now_ = now; }
  void SetHealthy(bool healthy) { healthy_ = healthy; }
 private:
  sec::WallTime now_;
  bool healthy_{true};
};

struct Fixture final {
  sec::test::EphemeralPki pki;
  std::shared_ptr<const pol::PolicySnapshot> policy;
  std::shared_ptr<const sec::CertificateRegistry> registry;
  const sec::test::EphemeralIdentity* adapter{};
  const sec::test::EphemeralIdentity* replica{};
  const sec::test::EphemeralIdentity* authority{};
  sec::WallTime now{};

  explicit Fixture(const std::string& policy_path) {
    auto document = nlohmann::json::parse(ReadFile(policy_path));
    document["trust_root_sha256"] = Hex(RootDigest(pki.root_certificate_pem()));
    auto loaded = pol::PolicyLoader::Load(document.dump());
    auto* policy_value = std::get_if<std::shared_ptr<const pol::PolicySnapshot>>(&loaded);
    Check(policy_value != nullptr, "policy_fixture_loads");
    if (policy_value == nullptr) return;
    policy = *policy_value;

    const auto unix_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    now = {unix_seconds, 0};
    MutableClock initial_clock(now);
    std::vector<std::string_view> leaf_pems;
    leaf_pems.reserve(policy->principals().size());
    for (const auto& principal : policy->principals()) {
      sec::PeerRole role = sec::PeerRole::kAdapter;
      if (principal.role == pol::PrincipalRole::Replica) role = sec::PeerRole::kReplica;
      if (principal.role == pol::PrincipalRole::Authority) role = sec::PeerRole::kAuthority;
      const auto& identity = pki.IssueWithValidity(role, principal.uri, -60, 3600);
      leaf_pems.push_back(identity.certificate_pem);
      if (principal.role == pol::PrincipalRole::Adapter && adapter == nullptr)
        adapter = &identity;
      if (principal.role == pol::PrincipalRole::Replica && replica == nullptr)
        replica = &identity;
      if (principal.role == pol::PrincipalRole::Authority && authority == nullptr)
        authority = &identity;
    }
    auto loaded_registry = sec::CertificateRegistryLoader::Load(
        policy, pki.root_certificate_pem(), leaf_pems, initial_clock);
    auto* registry_value = std::get_if<std::shared_ptr<const sec::CertificateRegistry>>(
        &loaded_registry);
    Check(registry_value != nullptr, "certificate_registry_loads");
    if (registry_value != nullptr) registry = *registry_value;
  }

  sec::PinnedPeerClientConfig Config() const {
    sec::PinnedPeerClientConfig config;
    config.purpose = sec::ClientCallPurpose::AdapterToReplicaAdmission;
    config.target = "127.0.0.1:1";  // Deliberately no service is listening.
    config.local_uri = adapter->registered.uri;
    config.expected_server_uri = replica->registered.uri;
    config.root_certificate_pem = pki.root_certificate_pem();
    config.local_certificate_pem = adapter->certificate_pem;
    config.local_private_key_pem = adapter->private_key_pem;
    return config;
  }
};

bool IsFactoryFailure(const std::variant<sec::PinnedPeerRpcClient,
                                         sec::PinnedClientFactoryFailure>& result,
                      sec::PinnedClientFactoryFailureReason reason) {
  const auto* failure = std::get_if<sec::PinnedClientFactoryFailure>(&result);
  return failure != nullptr && failure->reason == reason;
}

void Run(const std::string& policy_path) {
  Fixture fixture(policy_path);
  Check(fixture.registry != nullptr && fixture.adapter != nullptr &&
        fixture.replica != nullptr && fixture.authority != nullptr,
        "fixture_has_registered_roles");
  if (!fixture.registry || fixture.adapter == nullptr || fixture.replica == nullptr) return;

  MutableClock clock(fixture.now);
  auto valid = sec::PinnedPeerRpcClient::Create(fixture.Config(), fixture.registry, clock);
  Check(std::holds_alternative<sec::PinnedPeerRpcClient>(valid),
        "valid_pinned_client_factory_succeeds");
  if (auto* client = std::get_if<sec::PinnedPeerRpcClient>(&valid)) {
    rg::CheckAdmissionRequest request;
    request.set_tenant_id("alpha");
    request.set_operation_id("read");
    request.set_attempt_id(std::string(16, '\x01'));
    request.set_epoch_id(std::string(16, '\x02'));
    request.set_policy_digest(std::string(32, '\x03'));

    clock.Set({fixture.now.unix_seconds + 3700, 0});
    auto expired = client->CheckAdmission(
        request, std::chrono::system_clock::now() + std::chrono::seconds(2));
    Check(std::holds_alternative<sec::NotSent>(expired),
          "expired_guard_is_not_sent");

    clock.Set(fixture.now);
    auto invoked = client->CheckAdmission(
        request, std::chrono::system_clock::now() + std::chrono::milliseconds(100));
    auto* result = std::get_if<sec::Invoked<rg::AdmissionDecision>>(&invoked);
    Check(result != nullptr, "stub_invocation_is_reported_as_invoked");
    if (result != nullptr) {
      Check(result->has_transport_status(), "invoked_result_preserves_transport_status");
      clock.Set({fixture.now.unix_seconds + 3700, 0});
      auto forward_check = client->ValidateBeforeForward(*result);
      Check(std::holds_alternative<sec::ClientCallGuardFailure>(forward_check),
            "post_response_expiry_blocks_forward_check");
      Check(result->raw_response().outcome() == rg::DECISION_OUTCOME_UNSPECIFIED,
            "post_response_guard_does_not_rewrite_raw_response");
    }
  }

  auto prefixed_key = fixture.Config();
  prefixed_key.local_private_key_pem =
      fixture.pki.root_certificate_pem() + prefixed_key.local_private_key_pem;
  Check(IsFactoryFailure(sec::PinnedPeerRpcClient::Create(
            std::move(prefixed_key), fixture.registry, clock),
            sec::PinnedClientFactoryFailureReason::InvalidPrivateKeyPem),
        "key_prefix_is_rejected");

  auto multiple_keys = fixture.Config();
  multiple_keys.local_private_key_pem += "\n" + multiple_keys.local_private_key_pem;
  Check(IsFactoryFailure(sec::PinnedPeerRpcClient::Create(
            std::move(multiple_keys), fixture.registry, clock),
            sec::PinnedClientFactoryFailureReason::InvalidPrivateKeyPem),
        "multiple_key_blocks_are_rejected");

  auto wrong_key = fixture.Config();
  wrong_key.local_private_key_pem = fixture.authority->private_key_pem;
  Check(IsFactoryFailure(sec::PinnedPeerRpcClient::Create(
            std::move(wrong_key), fixture.registry, clock),
            sec::PinnedClientFactoryFailureReason::PrivateKeyMismatch),
        "private_key_must_match_pinned_leaf");

  auto oversized_key = fixture.Config();
  oversized_key.local_private_key_pem.assign(64U * 1024U + 1U, 'x');
  Check(IsFactoryFailure(sec::PinnedPeerRpcClient::Create(
            std::move(oversized_key), fixture.registry, clock),
            sec::PinnedClientFactoryFailureReason::OversizedCredential),
        "private_key_input_cap_is_enforced");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: pinned_peer_rpc_client_contract_test <policy-json>\n";
    return 2;
  }
  try {
    Run(argv[1]);
  } catch (...) {
    std::cerr << "FAIL: unexpected bounded test exception\n";
    ++failures;
  }
  std::cout << (failures == 0 ? "PASS" : "FAIL")
            << ": pinned outbound client contract checks\n";
  return failures == 0 ? 0 : 1;
}
