#include "rateguard/security/client_call_guard.h"

#include "ephemeral_pki.h"
#include "policy/canonical_codec.h"
#include "policy/policy_loader.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
using rateguard::security::test::EphemeralPki;

namespace {

[[noreturn]] void Fail(std::string_view label) {
  std::cerr << "FAIL " << label << '\n';
  std::exit(1);
}
void Check(bool condition, std::string_view label) {
  if (!condition) Fail(label);
}

sec::WallTime JustBefore(sec::WallTime value) {
  if (value.unix_seconds <= 0 || value.nanoseconds != 0)
    Fail("fixture_whole_second_boundary");
  return {value.unix_seconds - 1, 999'999'999U};
}

class FixedClock final : public sec::ITrustedWallClock {
 public:
  explicit FixedClock(sec::WallTime value) : value_(value) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override {
    ++calls;
    if (fail_after_sample_) {
      healthy_ = false;
      return value_;
    }
    if (!healthy_ && !return_value_when_unhealthy_)
      return sec::TrustedWallClockFailure{
          sec::TrustedWallClockFailureReason::PlatformUnavailable};
    return value_;
  }
  bool Healthy() const override { ++health_checks; return healthy_; }
  void Set(sec::WallTime value) { value_ = value; }
  void SetUnhealthyValue() { healthy_ = false; return_value_when_unhealthy_ = true; }
  void FailAfterSample() { fail_after_sample_ = true; }
  mutable unsigned health_checks{};
  unsigned calls{};
 private:
  sec::WallTime value_;
  bool healthy_{true};
  bool return_value_when_unhealthy_{false};
  bool fail_after_sample_{false};
};

std::string ReadFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string Hex(std::span<const std::uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 15]);
  }
  return out;
}

pol::Digest32 RootDigest(std::string_view pem) {
  BIO* raw_bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw_bio) Fail("fixture_root_parse");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!raw_cert) Fail("fixture_root_parse");
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
  const int size = i2d_X509(cert.get(), nullptr);
  if (size <= 0 || size > 64 * 1024) Fail("fixture_root_der");
  std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
  auto* cursor = der.data();
  if (i2d_X509(cert.get(), &cursor) != size) Fail("fixture_root_der");
  pol::Digest32 digest{};
  unsigned int written = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &written,
                 EVP_sha256(), nullptr) != 1 || written != digest.size())
    Fail("fixture_root_digest");
  return digest;
}

sec::PeerRole ToPeerRole(pol::PrincipalRole role) {
  switch (role) {
    case pol::PrincipalRole::Adapter: return sec::PeerRole::kAdapter;
    case pol::PrincipalRole::Replica: return sec::PeerRole::kReplica;
    case pol::PrincipalRole::Authority: return sec::PeerRole::kAuthority;
  }
  Fail("fixture_role");
}

struct Fixture final {
  EphemeralPki pki;
  std::shared_ptr<const pol::PolicySnapshot> policy;
  std::shared_ptr<const sec::CertificateRegistry> registry;
  std::string root_pem;
  std::vector<std::string> leaf_pems;
  std::map<sec::PeerRole, std::string> uri_by_role;
  std::map<sec::PeerRole, sec::WallTime> not_before_by_role;
  std::map<sec::PeerRole, sec::WallTime> not_after_by_role;
  sec::WallTime now{};

  Fixture(const std::string& policy_path,
          const std::map<sec::PeerRole, std::pair<long, long>>& validity = {}) {
    root_pem = pki.root_certificate_pem();
    auto json = nlohmann::json::parse(ReadFile(policy_path));
    json["trust_root_sha256"] = Hex(RootDigest(root_pem));
    auto loaded = pol::PolicyLoader::Load(json.dump());
    const auto* snapshot = std::get_if<std::shared_ptr<const pol::PolicySnapshot>>(&loaded);
    if (snapshot == nullptr) Fail("fixture_policy");
    policy = *snapshot;

    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    now = {seconds, 0};
    leaf_pems.reserve(policy->principals().size());
    for (const auto& principal : policy->principals()) {
      const auto role = ToPeerRole(principal.role);
      uri_by_role.try_emplace(role, principal.uri);
      const auto interval = validity.find(role);
      const auto& identity = interval == validity.end()
          ? pki.Issue(role, principal.uri)
          : pki.IssueWithValidity(role, principal.uri,
                                  interval->second.first, interval->second.second);
      leaf_pems.push_back(identity.certificate_pem);
    }
    std::vector<std::string_view> leaf_views;
    leaf_views.reserve(leaf_pems.size());
    for (const auto& pem : leaf_pems) leaf_views.emplace_back(pem);
    FixedClock clock(now);
    auto registry_result = sec::CertificateRegistryLoader::Load(
        policy, root_pem, leaf_views, clock);
    const auto* value = std::get_if<std::shared_ptr<const sec::CertificateRegistry>>(
        &registry_result);
    if (value == nullptr) Fail("fixture_registry");
    registry = *value;
    for (const auto& [role, uri] : uri_by_role) {
      const auto* cert = registry->Find(uri);
      if (cert == nullptr) Fail("fixture_registry_lookup");
      not_before_by_role[role] = cert->validity.not_before;
      not_after_by_role[role] = cert->validity.not_after;
    }
  }
};

template <typename T>
void CheckFailure(const T& result, sec::ClientGuardDisposition disposition,
                  sec::ClientGuardFailureReason reason,
                  std::string_view label) {
  const auto* failure = std::get_if<sec::ClientCallGuardFailure>(&result);
  Check(failure != nullptr, label);
  Check(failure->disposition == disposition && failure->reason == reason, label);
}

auto CreateGuard(const std::shared_ptr<const sec::CertificateRegistry>& registry,
                 sec::ITrustedWallClock& clock, sec::ClientCallPurpose purpose,
                 const std::map<sec::PeerRole, std::string>& uris) {
  sec::PeerRole local_role = purpose == sec::ClientCallPurpose::AdapterToReplicaAdmission
                                 ? sec::PeerRole::kAdapter : sec::PeerRole::kReplica;
  sec::PeerRole server_role = purpose == sec::ClientCallPurpose::AdapterToReplicaAdmission
                                  ? sec::PeerRole::kReplica : sec::PeerRole::kAuthority;
  return sec::ClientCallGuard::Create(registry, clock, purpose,
      uris.at(local_role), uris.at(server_role));
}

void TestHappyPathAndBindings(const std::string& policy_path) {
  Fixture fixture(policy_path);
  FixedClock clock(fixture.now);
  auto guard_result = CreateGuard(fixture.registry, clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission, fixture.uri_by_role);
  auto* guard = std::get_if<sec::ClientCallGuard>(&guard_result);
  Check(guard != nullptr, "adapter_replica_guard_create");
  if (guard == nullptr) return;
  auto prepared_result = guard->ValidateBeforeCall();
  auto* prepared = std::get_if<sec::PreparedClientCall>(&prepared_result);
  Check(prepared != nullptr, "pre_call_valid");
  if (prepared == nullptr) return;
  auto passed = guard->ValidateBeforeForward(*prepared);
  Check(std::holds_alternative<sec::ClientCallGuardPassed>(passed),
        "pre_forward_fresh_validation");

  auto replica_authority = CreateGuard(fixture.registry, clock,
      sec::ClientCallPurpose::ReplicaToAuthority, fixture.uri_by_role);
  auto* internal_guard = std::get_if<sec::ClientCallGuard>(&replica_authority);
  Check(internal_guard != nullptr, "replica_authority_guard_create");
  if (internal_guard != nullptr) {
    auto internal_prepared = internal_guard->ValidateBeforeCall();
    auto* token = std::get_if<sec::PreparedClientCall>(&internal_prepared);
    Check(token != nullptr, "replica_authority_prepared");
    if (token != nullptr) {
      CheckFailure(guard->ValidateBeforeForward(*token),
          sec::ClientGuardDisposition::CredentialInvalid,
          sec::ClientGuardFailureReason::ForeignPreparedCall,
          "cross_guard_prepared_proof_rejected");
    }
  }

  // Equal IDs, purpose, and endpoints do not make independently loaded
  // registry objects interchangeable; proof binding uses object identity.
  std::vector<std::string_view> leaf_views;
  for (const auto& pem : fixture.leaf_pems) leaf_views.emplace_back(pem);
  auto second_registry_result = sec::CertificateRegistryLoader::Load(
      fixture.policy, fixture.root_pem, leaf_views, clock);
  const auto* second_registry = std::get_if<
      std::shared_ptr<const sec::CertificateRegistry>>(&second_registry_result);
  Check(second_registry != nullptr, "same_policy_second_registry_loads");
  if (second_registry != nullptr) {
    auto second_guard_result = CreateGuard(*second_registry, clock,
        sec::ClientCallPurpose::AdapterToReplicaAdmission, fixture.uri_by_role);
    auto* second_guard = std::get_if<sec::ClientCallGuard>(&second_guard_result);
    Check(second_guard != nullptr, "same_config_second_guard");
    if (second_guard != nullptr) {
      auto second_prepared_result = second_guard->ValidateBeforeCall();
      const auto* second_prepared = std::get_if<sec::PreparedClientCall>(
          &second_prepared_result);
      Check(second_prepared != nullptr, "same_config_second_proof");
      if (second_prepared != nullptr) {
        CheckFailure(guard->ValidateBeforeForward(*second_prepared),
            sec::ClientGuardDisposition::CredentialInvalid,
            sec::ClientGuardFailureReason::ForeignPreparedCall,
            "different_registry_same_config_proof_rejected");
      }
    }
  }

  auto wrong_server = sec::ClientCallGuard::Create(fixture.registry, clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission,
      fixture.uri_by_role.at(sec::PeerRole::kAdapter),
      fixture.uri_by_role.at(sec::PeerRole::kAuthority));
  CheckFailure(wrong_server, sec::ClientGuardDisposition::CredentialInvalid,
      sec::ClientGuardFailureReason::ServerRoleMismatch,
      "wrong_endpoint_role_rejected");
  auto unknown_local = sec::ClientCallGuard::Create(fixture.registry, clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission,
      "spiffe://rateguard.invalid/adapter/missing",
      fixture.uri_by_role.at(sec::PeerRole::kReplica));
  CheckFailure(unknown_local, sec::ClientGuardDisposition::CredentialInvalid,
      sec::ClientGuardFailureReason::MissingClientCertificate,
      "unknown_local_identity_rejected");

}

void TestProofOwnsRegistry(const std::string& policy_path) {
  Fixture fixture(policy_path);
  FixedClock clock(fixture.now);
  auto owned_registry = fixture.registry;
  std::weak_ptr<const sec::CertificateRegistry> weak_registry = owned_registry;
  std::optional<sec::PreparedClientCall> retained;
  {
    auto lifetime_guard = CreateGuard(owned_registry, clock,
        sec::ClientCallPurpose::AdapterToReplicaAdmission, fixture.uri_by_role);
    auto* lifetime_guard_ptr = std::get_if<sec::ClientCallGuard>(&lifetime_guard);
    Check(lifetime_guard_ptr != nullptr, "lifetime_guard_create");
    if (lifetime_guard_ptr != nullptr) {
      auto result = lifetime_guard_ptr->ValidateBeforeCall();
      const auto* value = std::get_if<sec::PreparedClientCall>(&result);
      Check(value != nullptr, "lifetime_token_create");
      if (value != nullptr) retained.emplace(*value);
    }
  }
  owned_registry.reset();
  fixture.registry.reset();
  Check(retained.has_value() && !weak_registry.expired(),
        "prepared_token_owns_immutable_registry");
  retained.reset();
  Check(weak_registry.expired(), "registry_released_after_proof_release");
}

void TestClockFailuresAndFreshness(const std::string& policy_path) {
  Fixture fixture(policy_path);
  FixedClock clock(fixture.now);
  auto guard_result = CreateGuard(fixture.registry, clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission, fixture.uri_by_role);
  auto* guard = std::get_if<sec::ClientCallGuard>(&guard_result);
  Check(guard != nullptr, "clock_guard_create");
  if (guard == nullptr) return;
  auto prepared_result = guard->ValidateBeforeCall();
  const auto* prepared = std::get_if<sec::PreparedClientCall>(&prepared_result);
  Check(prepared != nullptr, "clock_prepared");
  if (prepared == nullptr) return;

  clock.Set({fixture.now.unix_seconds - 1, 999'999'999U});
  CheckFailure(guard->ValidateBeforeForward(*prepared),
      sec::ClientGuardDisposition::ApplicationUnavailable,
      sec::ClientGuardFailureReason::ClockUntrusted,
      "pre_forward_rejects_time_before_pre_call_sample");
  clock.Set(fixture.now);

  clock.SetUnhealthyValue();
  const auto calls_before = clock.calls;
  CheckFailure(guard->ValidateBeforeForward(*prepared),
      sec::ClientGuardDisposition::ApplicationUnavailable,
      sec::ClientGuardFailureReason::ClockUntrusted,
      "pre_unhealthy_clock_rejected");
  Check(clock.calls == calls_before, "unhealthy_clock_checked_before_now");

  FixedClock post_failure_clock(fixture.now);
  auto post_guard_result = CreateGuard(fixture.registry, post_failure_clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission, fixture.uri_by_role);
  auto* post_guard = std::get_if<sec::ClientCallGuard>(&post_guard_result);
  if (post_guard == nullptr) Fail("post_failure_guard_create");
  const auto initial_post_result = post_guard->ValidateBeforeCall();
  Check(std::holds_alternative<sec::PreparedClientCall>(initial_post_result),
        "pre_failure_sample_valid");
  post_failure_clock.FailAfterSample();
  CheckFailure(post_guard->ValidateBeforeCall(),
      sec::ClientGuardDisposition::ApplicationUnavailable,
      sec::ClientGuardFailureReason::ClockUntrusted,
      "post_sample_unhealthy_clock_rejected");
}

void TestExpiryBoundaries(const std::string& policy_path) {
  // The local leaf has a later notBefore than the server leaf and an earlier
  // notAfter, allowing both sides of its half-open interval to be isolated.
  Fixture local_fixture(policy_path, {
      {sec::PeerRole::kAdapter, {-30, 3600}},
      {sec::PeerRole::kReplica, {-60, 7200}}});
  FixedClock local_clock(local_fixture.now);
  auto local_guard_result = CreateGuard(local_fixture.registry, local_clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission, local_fixture.uri_by_role);
  auto* local_guard = std::get_if<sec::ClientCallGuard>(&local_guard_result);
  Check(local_guard != nullptr, "local_boundary_guard");
  if (local_guard != nullptr) {
    auto local_prepared_result = local_guard->ValidateBeforeCall();
    const auto* local_prepared_value = std::get_if<sec::PreparedClientCall>(
        &local_prepared_result);
    Check(local_prepared_value != nullptr, "local_prepared_before_expiry");
    std::optional<sec::PreparedClientCall> local_prepared;
    if (local_prepared_value != nullptr) local_prepared.emplace(*local_prepared_value);
    const auto local_before = local_fixture.not_before_by_role.at(sec::PeerRole::kAdapter);
    local_clock.Set(JustBefore(local_before));
    CheckFailure(local_guard->ValidateBeforeCall(),
        sec::ClientGuardDisposition::CredentialInvalid,
        sec::ClientGuardFailureReason::ClientNotYetValid,
        "local_before_not_before_rejected");
    local_clock.Set(local_before);
    Check(std::holds_alternative<sec::PreparedClientCall>(
        local_guard->ValidateBeforeCall()), "local_exact_not_before_allowed");

    const auto local_after = local_fixture.not_after_by_role.at(sec::PeerRole::kAdapter);
    local_clock.Set(JustBefore(local_after));
    Check(std::holds_alternative<sec::PreparedClientCall>(
        local_guard->ValidateBeforeCall()), "local_before_not_after_allowed");
    local_clock.Set(local_after);
    CheckFailure(local_guard->ValidateBeforeCall(),
        sec::ClientGuardDisposition::CredentialInvalid,
        sec::ClientGuardFailureReason::ClientExpired,
        "local_exact_not_after_rejected");
    if (local_prepared) {
      CheckFailure(local_guard->ValidateBeforeForward(*local_prepared),
          sec::ClientGuardDisposition::CredentialInvalid,
          sec::ClientGuardFailureReason::ClientExpired,
          "pre_forward_rechecks_local_expiry");
    }
  }

  // Reverse notBefore ordering to isolate the expected server certificate.
  Fixture server_fixture(policy_path, {
      {sec::PeerRole::kAdapter, {-60, 7200}},
      {sec::PeerRole::kReplica, {-30, 3600}}});
  FixedClock server_clock(server_fixture.now);
  auto server_guard_result = CreateGuard(server_fixture.registry, server_clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission, server_fixture.uri_by_role);
  auto* server_guard = std::get_if<sec::ClientCallGuard>(&server_guard_result);
  Check(server_guard != nullptr, "server_boundary_guard");
  if (server_guard != nullptr) {
    const auto server_before = server_fixture.not_before_by_role.at(sec::PeerRole::kReplica);
    server_clock.Set(JustBefore(server_before));
    CheckFailure(server_guard->ValidateBeforeCall(),
        sec::ClientGuardDisposition::CredentialInvalid,
        sec::ClientGuardFailureReason::ServerNotYetValid,
        "server_before_not_before_rejected");
    server_clock.Set(server_before);
    Check(std::holds_alternative<sec::PreparedClientCall>(
        server_guard->ValidateBeforeCall()), "server_exact_not_before_allowed");

    const auto server_after = server_fixture.not_after_by_role.at(sec::PeerRole::kReplica);
    server_clock.Set(JustBefore(server_after));
    Check(std::holds_alternative<sec::PreparedClientCall>(
        server_guard->ValidateBeforeCall()), "server_before_not_after_allowed");
    server_clock.Set(server_after);
    CheckFailure(server_guard->ValidateBeforeCall(),
        sec::ClientGuardDisposition::CredentialInvalid,
        sec::ClientGuardFailureReason::ServerExpired,
        "server_exact_not_after_rejected");
  }

  Fixture root_fixture(policy_path);
  FixedClock root_clock(root_fixture.now);
  auto root_guard_result = CreateGuard(root_fixture.registry, root_clock,
      sec::ClientCallPurpose::AdapterToReplicaAdmission, root_fixture.uri_by_role);
  auto* root_guard = std::get_if<sec::ClientCallGuard>(&root_guard_result);
  Check(root_guard != nullptr, "root_boundary_guard");
  if (root_guard != nullptr) {
    const auto root_after = root_fixture.registry->root_validity().not_after;
    root_clock.Set(JustBefore(root_after));
    Check(std::holds_alternative<sec::PreparedClientCall>(
        root_guard->ValidateBeforeCall()), "root_before_not_after_allowed");
    root_clock.Set(root_after);
    CheckFailure(root_guard->ValidateBeforeCall(),
        sec::ClientGuardDisposition::CredentialInvalid,
        sec::ClientGuardFailureReason::RootExpired,
        "root_exact_not_after_rejected");
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) Fail("usage: client_call_guard_test policy_fixture.json");
  TestHappyPathAndBindings(argv[1]);
  TestClockFailuresAndFreshness(argv[1]);
  TestProofOwnsRegistry(argv[1]);
  TestExpiryBoundaries(argv[1]);
  std::cout << "PASS client_call_guard_registry_time" << '\n';
  return 0;
}
