#include "rateguard/security/authorization_resolver.h"

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
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>
#include <google/protobuf/unknown_field_set.h>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
namespace contract = rateguard::v1::contract;
using rateguard::security::test::EphemeralPki;

namespace {

[[noreturn]] void Fail(std::string_view label) {
  std::cerr << "FAIL " << label << '\n';
  std::exit(1);
}
void Check(bool condition, std::string_view label) {
  if (!condition) Fail(label);
}

class FixedClock final : public sec::ITrustedWallClock {
 public:
  explicit FixedClock(sec::WallTime value) : value_(value) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override {
    ++calls;
    if (!healthy_ && !return_value_when_unhealthy_) return sec::TrustedWallClockFailure{
        sec::TrustedWallClockFailureReason::PlatformUnavailable};
    return value_;
  }
  bool Healthy() const override { return healthy_; }
  void Set(sec::WallTime value) { value_ = value; }
  void SetUnhealthyButReturnValue() { healthy_ = false; return_value_when_unhealthy_ = true; }
  unsigned calls{};
 private:
  sec::WallTime value_;
  bool healthy_{true};
  bool return_value_when_unhealthy_{false};
};

class EmptyAuthIterator final : public grpc::AuthPropertyIterator {
 public:
  EmptyAuthIterator() : grpc::AuthPropertyIterator() {}
};

class FakeAuthContext final : public grpc::AuthContext {
 public:
  bool IsPeerAuthenticated() const override { return authenticated_; }
  std::vector<grpc::string_ref> GetPeerIdentity() const override {
    std::vector<grpc::string_ref> result;
    const auto found = properties_.find(identity_name_);
    if (found != properties_.end())
      for (const auto& value : found->second) result.emplace_back(value);
    return result;
  }
  std::string GetPeerIdentityPropertyName() const override { return identity_name_; }
  std::vector<grpc::string_ref> FindPropertyValues(
      const std::string& name) const override {
    std::vector<grpc::string_ref> result;
    const auto found = properties_.find(name);
    if (found != properties_.end())
      for (const auto& value : found->second) result.emplace_back(value);
    return result;
  }
  grpc::AuthPropertyIterator begin() const override { return EmptyAuthIterator{}; }
  grpc::AuthPropertyIterator end() const override { return EmptyAuthIterator{}; }
  void AddProperty(const std::string& key, const grpc::string_ref& value) override {
    properties_[key].emplace_back(value.data(), value.size());
  }
  bool SetPeerIdentityPropertyName(const std::string& name) override {
    identity_name_ = name;
    return true;
  }
  void Add(std::string key, std::string value) {
    properties_[std::move(key)].push_back(std::move(value));
  }
  void SetAuthenticated(bool value) { authenticated_ = value; }
 private:
  bool authenticated_{true};
  std::string identity_name_{GRPC_PEER_URI_PROPERTY_NAME};
  std::map<std::string, std::vector<std::string>, std::less<>> properties_;
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

struct Fixture {
  EphemeralPki pki;
  std::shared_ptr<const pol::PolicySnapshot> policy;
  std::shared_ptr<const sec::CertificateRegistry> registry;
  std::vector<std::pair<std::string, std::string>> identity_pems;
  pol::Digest32 digest{};
  sec::WallTime now{};

  explicit Fixture(const std::string& policy_path) {
    auto root = RootDigest(pki.root_certificate_pem());
    auto json = nlohmann::json::parse(ReadFile(policy_path));
    json["trust_root_sha256"] = Hex(root);
    for (auto& principal : json["principals"]) {
      if (principal["role"] == "replica" && principal.value("slot_id", 0U) == 7U) {
        principal["permissions"].push_back({{"tenant_id", "zeta"},
                                             {"operation_id", "list"}});
      }
    }
    auto loaded = pol::PolicyLoader::Load(json.dump());
    const auto* snapshot = std::get_if<std::shared_ptr<const pol::PolicySnapshot>>(&loaded);
    if (snapshot == nullptr) Fail("fixture_policy");
    policy = *snapshot;
    auto digest_result = pol::CanonicalPolicyCodec::Digest(*policy);
    const auto* digest_ptr = std::get_if<pol::Digest32>(&digest_result);
    if (digest_ptr == nullptr) Fail("fixture_policy_digest");
    digest = *digest_ptr;

    std::vector<std::string_view> leaf_views;
    std::vector<std::string> owned_pems;
    for (const auto& principal : policy->principals()) {
      sec::PeerRole role = sec::PeerRole::kAdapter;
      if (principal.role == pol::PrincipalRole::Replica) role = sec::PeerRole::kReplica;
      if (principal.role == pol::PrincipalRole::Authority) role = sec::PeerRole::kAuthority;
      const auto& identity = pki.Issue(role, principal.uri);
      identity_pems.emplace_back(principal.uri, identity.certificate_pem);
      owned_pems.push_back(identity.certificate_pem);
    }
    for (const auto& pem : owned_pems) leaf_views.emplace_back(pem);
    const auto system_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    now = {system_seconds, 0};
    FixedClock clock(now);
    auto registry_result = sec::CertificateRegistryLoader::Load(
        policy, pki.root_certificate_pem(), leaf_views, clock);
    const auto* value = std::get_if<std::shared_ptr<const sec::CertificateRegistry>>(
        &registry_result);
    if (value == nullptr) Fail("fixture_registry");
    registry = *value;
  }

  FakeAuthContext Context(std::string_view uri) const {
    FakeAuthContext context;
    const auto found = std::find_if(identity_pems.begin(), identity_pems.end(),
        [&](const auto& entry) { return entry.first == uri; });
    if (found == identity_pems.end()) Fail("fixture_identity");
    context.Add(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
                GRPC_TLS_TRANSPORT_SECURITY_TYPE);
    context.Add(GRPC_PEER_URI_PROPERTY_NAME, found->first);
    context.Add(GRPC_X509_PEM_CERT_PROPERTY_NAME, found->second);
    return context;
  }
};

std::string Bytes(const auto& array) {
  return {reinterpret_cast<const char*>(array.data()), array.size()};
}

void CheckFailure(const auto& result, sec::AuthorizationDisposition expected,
                  sec::AuthorizationFailureReason reason, std::string_view label) {
  const auto* failure = std::get_if<sec::AuthorizationFailure>(&result);
  Check(failure != nullptr, label);
  Check(failure->disposition == expected && failure->reason == reason, label);
}

void Run(const std::string& policy_path) {
  Fixture fixture(policy_path);
  FixedClock clock(fixture.now);
  auto resolver_result = sec::AuthorizationResolver::Create(fixture.registry, clock);
  auto* resolver = std::get_if<sec::AuthorizationResolver>(&resolver_result);
  Check(resolver != nullptr, "resolver_create_valid_binding");
  if (resolver == nullptr) return;

  sec::PeerAuthenticator authenticator(fixture.registry, clock);
  const auto adapter_it = std::find_if(fixture.policy->principals().begin(),
      fixture.policy->principals().end(), [](const auto& p) {
        return p.role == pol::PrincipalRole::Adapter;
      });
  const auto replica_it = std::find_if(fixture.policy->principals().begin(),
      fixture.policy->principals().end(), [](const auto& p) {
        return p.role == pol::PrincipalRole::Replica && p.slot_id == 7U;
      });
  Check(adapter_it != fixture.policy->principals().end() &&
        replica_it != fixture.policy->principals().end(), "fixture_has_adapter_replica");
  if (adapter_it == fixture.policy->principals().end() ||
      replica_it == fixture.policy->principals().end()) return;

  const auto adapter_result = authenticator.Authenticate(fixture.Context(adapter_it->uri));
  auto* adapter = std::get_if<sec::AuthenticatedPeer>(&adapter_result);
  Check(adapter != nullptr, "adapter_authenticated");
  const auto replica_result = authenticator.Authenticate(fixture.Context(replica_it->uri));
  auto* replica = std::get_if<sec::AuthenticatedPeer>(&replica_result);
  Check(replica != nullptr, "replica_authenticated");
  if (adapter == nullptr || replica == nullptr) return;

  rateguard::v1::CheckAdmissionRequest check;
  check.set_tenant_id("zeta");
  check.set_operation_id("list");
  check.set_attempt_id(std::string(16, 'a'));
  check.set_epoch_id(Bytes(fixture.policy->epoch_id()));
  check.set_policy_digest(Bytes(fixture.digest));

  auto allowed = resolver->Resolve(*adapter, sec::RpcMethod::AdapterCheckAdmission, check);
  const auto* authorized = std::get_if<sec::AuthorizedOperation>(&allowed);
  Check(authorized && authorized->cost_units() == 2 &&
        authorized->mode() == pol::Mode::Credit &&
        authorized->tenant_id() == "zeta" && authorized->operation_id() == "list" &&
        authorized->attempt_id() == std::string(16, 'a') &&
        authorized->peer().uri() == adapter_it->uri &&
        authorized->method() == sec::RpcMethod::AdapterCheckAdmission,
        "adapter_allowed_policy_cost_and_identity");
  if (authorized) {
    const sec::AuthorizedOperation copied = *authorized;
    Check(copied.peer().uri() == adapter_it->uri &&
          authorized->registry().get() == fixture.registry.get(),
          "authorization_proof_copy_retains_registry");
  }

  auto forbidden = check;
  forbidden.set_operation_id("delete");
  auto denied = resolver->Resolve(*adapter, sec::RpcMethod::AdapterCheckAdmission, forbidden);
  CheckFailure(denied, sec::AuthorizationDisposition::PermissionDenied,
              sec::AuthorizationFailureReason::UnauthorizedPair,
              "configured_but_forbidden_pair_denied");

  auto unknown = check;
  unknown.set_tenant_id("unknown");
  auto unknown_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, unknown);
  CheckFailure(unknown_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::UnknownTenant,
              "unknown_tenant_invalid_argument");
  auto unknown_operation = check;
  unknown_operation.set_operation_id("missing");
  auto unknown_operation_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, unknown_operation);
  CheckFailure(unknown_operation_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::UnknownOperation,
              "unknown_operation_invalid_argument");

  auto short_attempt = check;
  short_attempt.set_attempt_id(std::string(15, 'a'));
  auto short_id_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, short_attempt);
  CheckFailure(short_id_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::InvalidRequest,
              "attempt_id_width_rejected");
  auto stale_digest = check;
  stale_digest.set_policy_digest(std::string(32, 'x'));
  auto stale_digest_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, stale_digest);
  CheckFailure(stale_digest_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::PolicyBindingMismatch,
              "stale_policy_digest_rejected");

  // Unknown wire field 6 is not a trusted cost input; configured policy cost
  // remains the only cost returned by the resolver.
  auto cost_extension = check;
  cost_extension.GetReflection()->MutableUnknownFields(&cost_extension)->AddVarint(6, 999);
  auto extension_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, cost_extension);
  const auto* extension_auth = std::get_if<sec::AuthorizedOperation>(&extension_result);
  Check(extension_auth && extension_auth->cost_units() == 2,
        "unknown_cost_wire_field_cannot_change_policy_cost");
  auto oversized = check;
  oversized.GetReflection()->MutableUnknownFields(&oversized)->AddLengthDelimited(
      100, std::string(16 * 1024, 'x'));
  auto oversized_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, oversized);
  CheckFailure(oversized_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::InvalidRequest,
              "decoded_payload_size_rejected");

  auto malformed = check;
  malformed.set_attempt_id("short");
  auto wrong_role_malformed = resolver->Resolve(*adapter,
      sec::RpcMethod::ReplicaStrictCheck, malformed);
  CheckFailure(wrong_role_malformed, sec::AuthorizationDisposition::PermissionDenied,
              sec::AuthorizationFailureReason::MethodRoleMismatch,
              "wrong_role_precedes_malformed_fields");
  auto bad_overload = resolver->Resolve(*adapter,
      sec::RpcMethod::ReplicaAcquireCredit, check);
  CheckFailure(bad_overload, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::InvalidRequest,
              "wrong_method_overload_invalid_argument");
  auto unknown_method = resolver->Resolve(*adapter,
      static_cast<sec::RpcMethod>(255), check);
  CheckFailure(unknown_method, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::InvalidRequest,
              "unknown_method_invalid_argument");

  auto strict_mismatch = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaStrictCheck, check);
  CheckFailure(strict_mismatch, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::ModeMismatch,
              "strict_method_rejected_under_credit_policy");

  rateguard::v1::AcquireCreditRequest grant;
  grant.set_tenant_id("zeta");
  grant.set_slot(7);
  const auto slot = std::find_if(fixture.policy->replica_slots().begin(),
      fixture.policy->replica_slots().end(), [](const auto& entry) {
        return entry.slot_id == 7;
      });
  Check(slot != fixture.policy->replica_slots().end(), "fixture_slot_7");
  if (slot == fixture.policy->replica_slots().end()) return;
  grant.set_incarnation_id(Bytes(slot->incarnation_id));
  grant.set_epoch_id(Bytes(fixture.policy->epoch_id()));
  grant.set_policy_digest(Bytes(fixture.digest));
  grant.set_sequence(1);
  grant.set_trigger_cost_units(2);
  grant.set_trigger_operation_id("list");
  auto grant_result = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaAcquireCredit, grant);
  const auto* grant_auth = std::get_if<sec::AuthorizedGrant>(&grant_result);
  Check(grant_auth && grant_auth->cost_units() == 2 && grant_auth->slot() == 7 &&
        grant_auth->sequence() == 1 && grant_auth->peer().uri() == replica_it->uri &&
        grant_auth->method() == sec::RpcMethod::ReplicaAcquireCredit &&
        grant_auth->incarnation_id() == slot->incarnation_id,
        "replica_credit_authorized_without_claiming_grant");

  auto bad_cost = grant;
  bad_cost.set_trigger_cost_units(3);
  auto cost_result = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaAcquireCredit, bad_cost);
  CheckFailure(cost_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::TriggerCostMismatch,
              "trigger_cost_mismatch_rejected");
  auto zero_sequence = grant;
  zero_sequence.set_sequence(0);
  auto sequence_result = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaAcquireCredit, zero_sequence);
  CheckFailure(sequence_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::InvalidRequest,
              "zero_sequence_rejected");
  auto wrong_slot = grant;
  wrong_slot.set_slot(2);
  auto slot_result = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaAcquireCredit, wrong_slot);
  CheckFailure(slot_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::ReplicaSlotMismatch,
              "wrong_registered_slot_rejected");
  auto wrong_incarnation = grant;
  wrong_incarnation.set_incarnation_id(std::string(16, 'x'));
  auto incarnation_result = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaAcquireCredit, wrong_incarnation);
  CheckFailure(incarnation_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::ReplicaIncarnationMismatch,
              "wrong_incarnation_rejected");
  auto forbidden_cost = grant;
  forbidden_cost.set_trigger_operation_id("delete");
  forbidden_cost.set_trigger_cost_units(999);
  auto forbidden_cost_result = resolver->Resolve(*replica,
      sec::RpcMethod::ReplicaAcquireCredit, forbidden_cost);
  CheckFailure(forbidden_cost_result, sec::AuthorizationDisposition::PermissionDenied,
              sec::AuthorizationFailureReason::UnauthorizedPair,
              "unauthorized_pair_precedes_cost_binding");

  auto stale = check;
  stale.set_epoch_id(std::string(16, 'x'));
  auto stale_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, stale);
  CheckFailure(stale_result, sec::AuthorizationDisposition::InvalidArgument,
              sec::AuthorizationFailureReason::PolicyBindingMismatch,
              "stale_epoch_rejected");

  // Same URI and certificate under a separately loaded snapshot is still a
  // mixed proof; the resolver requires exact registry object identity.
  std::vector<std::string_view> leaf_views;
  for (const auto& identity : fixture.identity_pems) leaf_views.emplace_back(identity.second);
  auto duplicate_registry_result = sec::CertificateRegistryLoader::Load(
      fixture.policy, fixture.pki.root_certificate_pem(), leaf_views, clock);
  const auto* duplicate_registry = std::get_if<
      std::shared_ptr<const sec::CertificateRegistry>>(&duplicate_registry_result);
  Check(duplicate_registry != nullptr, "duplicate_snapshot_loads");
  if (duplicate_registry != nullptr) {
    sec::PeerAuthenticator duplicate_auth(*duplicate_registry, clock);
    const auto duplicate_peer_result = duplicate_auth.Authenticate(
        fixture.Context(adapter_it->uri));
    const auto* duplicate_peer = std::get_if<sec::AuthenticatedPeer>(
        &duplicate_peer_result);
    Check(duplicate_peer != nullptr, "duplicate_snapshot_peer_authenticates");
    if (duplicate_peer != nullptr) {
      auto mixed = resolver->Resolve(*duplicate_peer,
          sec::RpcMethod::AdapterCheckAdmission, check);
      CheckFailure(mixed, sec::AuthorizationDisposition::Unauthenticated,
                  sec::AuthorizationFailureReason::MixedRegistry,
                  "mixed_registry_token_rejected");
    }
  }

  // The same authenticated token is revalidated against current UTC at every
  // Resolve call; expiration cannot be bypassed by holding the token.
  const auto* adapter_cert = fixture.registry->Find(adapter_it->uri);
  Check(adapter_cert != nullptr, "adapter_registry_record");
  if (adapter_cert != nullptr) {
    clock.Set(adapter_cert->validity.not_after);
    auto expired_result = resolver->Resolve(*adapter,
        sec::RpcMethod::AdapterCheckAdmission, check);
    CheckFailure(expired_result, sec::AuthorizationDisposition::Unauthenticated,
                sec::AuthorizationFailureReason::CertificateExpired,
                "fresh_expiry_checked_per_resolve");
  }
  clock.Set(fixture.now);
  clock.SetUnhealthyButReturnValue();
  const unsigned clock_calls = clock.calls;
  auto clock_result = resolver->Resolve(*adapter,
      sec::RpcMethod::AdapterCheckAdmission, check);
  CheckFailure(clock_result, sec::AuthorizationDisposition::ApplicationUnavailable,
              sec::AuthorizationFailureReason::ClockUntrusted,
              "untrusted_clock_fails_closed");
  Check(clock.calls == clock_calls,
        "unhealthy_clock_rejected_before_sampling_value");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) Fail("usage: authorization_resolver_test policy_fixture.json");
  Run(argv[1]);
  std::cout << "PASS authorization_resolver_policy_identity_clock" << '\n';
  return 0;
}
