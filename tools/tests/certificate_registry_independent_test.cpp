#include "rateguard/security/certificate_registry.h"
#include "policy/canonical_codec.h"
#include "policy/policy_loader.h"
#include "ephemeral_pki.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
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

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
using rateguard::security::test::EphemeralPki;

namespace {
class FixedClock final : public sec::ITrustedWallClock {
 public:
  explicit FixedClock(sec::WallTime value) : value_(value) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override {
    if (failure_) return sec::TrustedWallClockFailure{*failure_};
    return value_;
  }
  bool Healthy() const override { return !failure_.has_value(); }
  void Set(sec::WallTime value) { value_ = value; }
  void Fail() { failure_ = sec::TrustedWallClockFailureReason::UnsynchronizedFlag; }
 private:
  sec::WallTime value_;
  std::optional<sec::TrustedWallClockFailureReason> failure_;
};

[[noreturn]] void Fail(std::string_view label) {
  std::cerr << "FAIL " << label << '\n';
  std::exit(1);
}
void Check(bool condition, std::string_view label) {
  if (!condition) Fail(label);
}

std::string ReadFile(const char* path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) Fail("fixture_open");
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
sec::Sha256Digest DerDigest(std::string_view pem) {
  BIO* raw_bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw_bio) Fail("fixture_parse");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!raw_cert) Fail("fixture_parse");
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
  const int size = i2d_X509(cert.get(), nullptr);
  if (size <= 0) Fail("fixture_der");
  std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
  auto* cursor = der.data();
  if (i2d_X509(cert.get(), &cursor) != size) Fail("fixture_der");
  sec::Sha256Digest digest{};
  unsigned int output_size = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &output_size,
                 EVP_sha256(), nullptr) != 1 || output_size != digest.size()) {
    Fail("fixture_sha256");
  }
  return digest;
}
sec::WallTime CertTime(std::string_view pem, bool not_after) {
  BIO* raw_bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw_bio) Fail("fixture_time_parse");
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!raw_cert) Fail("fixture_time_parse");
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
  std::tm fields{};
  const ASN1_TIME* value = not_after ? X509_get0_notAfter(cert.get())
                                     : X509_get0_notBefore(cert.get());
  if (ASN1_TIME_to_tm(value, &fields) != 1) Fail("fixture_time_convert");
  const std::time_t seconds = timegm(&fields);
  if (seconds == static_cast<std::time_t>(-1)) Fail("fixture_time_convert");
  return {static_cast<std::int64_t>(seconds), 0};
}
std::string BindPolicyRoot(std::string json, const sec::Sha256Digest& digest) {
  constexpr std::string_view key = "\"trust_root_sha256\": \"";
  const auto begin = json.find(key);
  if (begin == std::string::npos) Fail("fixture_policy_shape");
  const auto value_begin = begin + key.size();
  const auto value_end = json.find('"', value_begin);
  if (value_end == std::string::npos) Fail("fixture_policy_shape");
  json.replace(value_begin, value_end - value_begin, Hex(digest));
  return json;
}
std::shared_ptr<const pol::PolicySnapshot> LoadPolicy(
    const std::string& fixture_json, const sec::Sha256Digest& root_digest) {
  auto parsed = pol::PolicyLoader::Load(BindPolicyRoot(fixture_json, root_digest));
  if (!std::holds_alternative<std::shared_ptr<const pol::PolicySnapshot>>(parsed))
    Fail("fixture_policy_invalid");
  return std::get<std::shared_ptr<const pol::PolicySnapshot>>(std::move(parsed));
}
sec::PeerRole ToPeerRole(pol::PrincipalRole role) {
  switch (role) {
    case pol::PrincipalRole::Adapter: return sec::PeerRole::kAdapter;
    case pol::PrincipalRole::Replica: return sec::PeerRole::kReplica;
    case pol::PrincipalRole::Authority: return sec::PeerRole::kAuthority;
  }
  Fail("fixture_role");
}
std::vector<std::string> IssueAll(EphemeralPki& pki,
                                  const pol::PolicySnapshot& policy) {
  std::vector<std::string> pems;
  for (const auto& principal : policy.principals())
    pems.push_back(pki.Issue(ToPeerRole(principal.role), principal.uri).certificate_pem);
  return pems;
}
std::vector<std::string_view> Views(const std::vector<std::string>& pems) {
  std::vector<std::string_view> result;
  result.reserve(pems.size());
  for (const auto& pem : pems) result.emplace_back(pem);
  return result;
}
using LoadResult = sec::CertificateRegistryResult<std::shared_ptr<const sec::CertificateRegistry>>;
LoadResult Load(std::shared_ptr<const pol::PolicySnapshot> policy,
                const std::string& root, const std::vector<std::string>& leafs,
                FixedClock& clock) {
  const auto views = Views(leafs);
  return sec::CertificateRegistryLoader::Load(std::move(policy), root, views, clock);
}
void ExpectError(const LoadResult& result, sec::CertificateRegistryErrorCode code,
                 std::string_view label) {
  Check(std::holds_alternative<sec::CertificateRegistryError>(result), label);
  Check(std::get<sec::CertificateRegistryError>(result).code == code, label);
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) Fail("usage_registry_fixture_json");
  const std::string policy_json = ReadFile(argv[1]);
  const auto now_sec = static_cast<std::int64_t>(std::chrono::duration_cast<
      std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  FixedClock clock({now_sec, 0});
  EphemeralPki pki;
  const auto root_digest = DerDigest(pki.root_certificate_pem());
  auto policy = LoadPolicy(policy_json, root_digest);
  auto leaves = IssueAll(pki, *policy);
  std::map<std::string, sec::Sha256Digest, std::less<>> expected_leaf_digests;
  Check(leaves.size() == policy->principals().size(), "fixture_leaf_count");
  for (std::size_t i = 0; i < leaves.size(); ++i)
    expected_leaf_digests.emplace(policy->principals()[i].uri, DerDigest(leaves[i]));

  // Positive oracle: exact principal set, URI, role and independently computed
  // SHA-256(DER) pins; reversed input order must not change lookup results.
  std::reverse(leaves.begin(), leaves.end());
  auto loaded = Load(policy, pki.root_certificate_pem(), leaves, clock);
  Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(loaded), "valid_registry");
  const auto registry = std::get<std::shared_ptr<const sec::CertificateRegistry>>(loaded);
  Check(registry->peers().size() == policy->principals().size(), "principal_count");
  Check(registry->epoch_id() == policy->epoch_id(), "epoch_binding");
  Check(registry->authority_incarnation() == policy->authority_incarnation(), "authority_binding");
  Check(registry->policy_digest() == std::get<pol::Digest32>(pol::CanonicalPolicyCodec::Digest(*policy)), "policy_digest_binding");
  Check(registry->root_der_sha256() == root_digest, "root_der_digest");
  Check(registry->validated_at() == sec::WallTime{now_sec, 0}, "trusted_validation_time");
  Check(registry->AllValidAt({now_sec, 0}), "validity_inclusive_start");
  for (const auto& principal : policy->principals()) {
    const auto* registered = registry->Find(principal.uri);
    Check(registered != nullptr, "principal_lookup");
    Check(registered->peer.role == ToPeerRole(principal.role), "principal_role");
    Check(registered->peer.leaf_der_sha256 == expected_leaf_digests.at(principal.uri),
          "leaf_der_pin");
  }
  auto pins = registry->peer_pins();
  Check(pins && pins->valid(), "peer_pin_registry_valid");
  for (const auto& principal : policy->principals()) {
    const auto* pin = pins->Find(principal.uri);
    Check(pin && pin->role == ToPeerRole(principal.role), "peer_pin_identity");
    Check(pin->leaf_der_sha256 == registry->Find(principal.uri)->peer.leaf_der_sha256,
          "peer_pin_digest");
  }
  Check(registry->Find("spiffe://rateguard.local/adapter/not-registered") == nullptr,
        "unknown_lookup_is_read_only");
  Check(registry->peers().size() == policy->principals().size(),
        "unknown_lookup_did_not_insert");
  Check(std::is_sorted(registry->peers().begin(), registry->peers().end(),
      [](const auto& a, const auto& b) { return a.peer.uri < b.peer.uri; }),
      "registry_metadata_sorted");

  // The snapshot must own only immutable metadata; it must remain usable after
  // the caller drops all policy/PEM/PKI owners used for construction.
  std::shared_ptr<const sec::CertificateRegistry> retained;
  {
    EphemeralPki short_lived_pki;
    const auto short_lived_root_digest = DerDigest(short_lived_pki.root_certificate_pem());
    auto short_lived_policy = LoadPolicy(policy_json, short_lived_root_digest);
    auto short_lived_leaves = IssueAll(short_lived_pki, *short_lived_policy);
    FixedClock short_lived_clock({now_sec, 0});
    auto short_lived_result = Load(short_lived_policy,
        short_lived_pki.root_certificate_pem(), short_lived_leaves, short_lived_clock);
    Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(
              short_lived_result), "owned_snapshot_setup");
    retained = std::get<std::shared_ptr<const sec::CertificateRegistry>>(
        std::move(short_lived_result));
    short_lived_policy.reset();
  }
  Check(retained->epoch_id() == policy->epoch_id(), "snapshot_survives_input_lifetimes");
  Check(retained->Find("spiffe://rateguard.local/adapter/ingress1") != nullptr,
        "retained_snapshot_lookup");
  Check(retained->peer_pins() && retained->peer_pins()->valid(),
        "retained_snapshot_peer_pins");

  // Root digest binds the actual DER root to the immutable policy.
  auto wrong_root_hash_json = policy_json;
  const auto marker = wrong_root_hash_json.find("\"trust_root_sha256\": \"");
  Check(marker != std::string::npos, "fixture_root_key");
  const auto hash_begin = marker + std::string_view("\"trust_root_sha256\": \"").size();
  wrong_root_hash_json.replace(hash_begin, 64, 64, '0');
  auto wrong_hash_policy_result = pol::PolicyLoader::Load(wrong_root_hash_json);
  Check(std::holds_alternative<std::shared_ptr<const pol::PolicySnapshot>>(wrong_hash_policy_result),
        "wrong_hash_policy_parses");
  const auto wrong_hash_policy = std::get<std::shared_ptr<const pol::PolicySnapshot>>(wrong_hash_policy_result);
  auto wrong_root_hash = Load(wrong_hash_policy, pki.root_certificate_pem(), leaves, clock);
  ExpectError(wrong_root_hash, sec::CertificateRegistryErrorCode::RootFingerprintMismatch,
              "wrong_root_digest_rejected");

  // Exact set semantics and principal-to-certificate binding.
  auto missing = leaves;
  missing.pop_back();
  ExpectError(Load(policy, pki.root_certificate_pem(), missing, clock),
              sec::CertificateRegistryErrorCode::LeafCountMismatch, "missing_leaf_rejected");
  auto duplicated = leaves;
  duplicated.back() = duplicated.front();
  ExpectError(Load(policy, pki.root_certificate_pem(), duplicated, clock),
              sec::CertificateRegistryErrorCode::DuplicateLeaf, "duplicate_leaf_rejected");
  auto unknown_pki = pki.Issue(sec::PeerRole::kAdapter,
      "spiffe://rateguard.local/adapter/unknown");
  auto unknown = leaves;
  unknown.back() = unknown_pki.certificate_pem;
  ExpectError(Load(policy, pki.root_certificate_pem(), unknown, clock),
              sec::CertificateRegistryErrorCode::UnknownPrincipal, "unknown_principal_rejected");
  auto key_material = pki.Issue(sec::PeerRole::kAdapter,
      "spiffe://rateguard.local/adapter/private-material-control");
  auto certificate_plus_key = leaves;
  certificate_plus_key.back() = key_material.certificate_pem + key_material.private_key_pem;
  ExpectError(Load(policy, pki.root_certificate_pem(), certificate_plus_key, clock),
              sec::CertificateRegistryErrorCode::InvalidPem,
              "private_key_material_rejected_from_leaf_input");
  auto two_cert_root = pki.root_certificate_pem() + pki.root_certificate_pem();
  ExpectError(Load(policy, two_cert_root, leaves, clock),
              sec::CertificateRegistryErrorCode::InvalidPem,
              "multiple_root_certificates_rejected");
  auto two_cert_leafs = leaves;
  two_cert_leafs.front() += pki.root_certificate_pem();
  ExpectError(Load(policy, pki.root_certificate_pem(), two_cert_leafs, clock),
              sec::CertificateRegistryErrorCode::InvalidPem,
              "multiple_leaf_certificates_rejected");

  const auto adapter = std::find_if(policy->principals().begin(), policy->principals().end(),
      [](const pol::Principal& p) { return p.role == pol::PrincipalRole::Adapter; });
  Check(adapter != policy->principals().end(), "fixture_adapter");
  const auto adapter_index = static_cast<std::size_t>(std::distance(policy->principals().begin(), adapter));

  EphemeralPki foreign_pki;
  const auto foreign_adapter = foreign_pki.Issue(sec::PeerRole::kAdapter, adapter->uri);
  auto wrong_chain_leafs = leaves;
  wrong_chain_leafs[leaves.size() - 1 - adapter_index] =
      foreign_adapter.certificate_pem;
  ExpectError(Load(policy, pki.root_certificate_pem(), wrong_chain_leafs, clock),
              sec::CertificateRegistryErrorCode::InvalidChain,
              "foreign_direct_issuer_rejected");

  // Create role/SAN/validity variants for this exact registered principal.
  auto wrong_role = pki.Issue(sec::PeerRole::kAuthority, adapter->uri);
  auto role_leafs = leaves;
  // Locate the correct adapter PEM by SAN binding via the helper's registry metadata.
  for (std::size_t i = 0; i < leaves.size(); ++i) {
    // We know the helper initially issued leaves in policy order, then reversed them.
    const auto original_index = leaves.size() - 1 - i;
    if (original_index == adapter_index) role_leafs[i] = wrong_role.certificate_pem;
  }
  ExpectError(Load(policy, pki.root_certificate_pem(), role_leafs, clock),
              sec::CertificateRegistryErrorCode::InvalidLeafProfile, "wrong_role_eku_rejected");
  auto multi_uri = pki.IssueWithUriSans(sec::PeerRole::kAdapter,
      {adapter->uri, "spiffe://rateguard.local/adapter/extra"});
  auto multi_leafs = leaves;
  const auto reversed_adapter_index = leaves.size() - 1 - adapter_index;
  multi_leafs[reversed_adapter_index] = multi_uri.certificate_pem;
  ExpectError(Load(policy, pki.root_certificate_pem(), multi_leafs, clock),
              sec::CertificateRegistryErrorCode::IdentityMismatch, "multiple_uri_sans_rejected");

  auto expired = pki.IssueWithValidity(sec::PeerRole::kAdapter, adapter->uri, -7200, -3600);
  auto expired_leafs = leaves;
  expired_leafs[reversed_adapter_index] = expired.certificate_pem;
  ExpectError(Load(policy, pki.root_certificate_pem(), expired_leafs, clock),
              sec::CertificateRegistryErrorCode::CertificateExpired, "expired_leaf_rejected");
  auto future = pki.IssueWithValidity(sec::PeerRole::kAdapter, adapter->uri, 3600, 7200);
  auto future_leafs = leaves;
  future_leafs[reversed_adapter_index] = future.certificate_pem;
  ExpectError(Load(policy, pki.root_certificate_pem(), future_leafs, clock),
              sec::CertificateRegistryErrorCode::CertificateNotYetValid, "future_leaf_rejected");

  // Fractional trusted-now comparisons are tested on both half-open edges.
  // The ASN.1 validity fields are second precision; the injected trusted clock
  // carries nanoseconds and is independently positioned around those fields.
  auto start_edge = pki.IssueWithValidity(sec::PeerRole::kAdapter, adapter->uri, -1, 3600);
  auto start_edge_leafs = leaves;
  start_edge_leafs[reversed_adapter_index] = start_edge.certificate_pem;
  const auto not_before = CertTime(start_edge.certificate_pem, false);
  clock.Set({not_before.unix_seconds, 0});
  Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(
            Load(policy, pki.root_certificate_pem(), start_edge_leafs, clock)),
        "not_before_exact_accepted");
  clock.Set({not_before.unix_seconds - 1, 999'999'999U});
  ExpectError(Load(policy, pki.root_certificate_pem(), start_edge_leafs, clock),
              sec::CertificateRegistryErrorCode::CertificateNotYetValid,
              "not_before_minus_one_ns_rejected");
  clock.Set({not_before.unix_seconds, 1});
  Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(
            Load(policy, pki.root_certificate_pem(), start_edge_leafs, clock)),
        "not_before_plus_one_ns_accepted");

  auto end_edge = pki.IssueWithValidity(sec::PeerRole::kAdapter, adapter->uri, -7200, -1);
  auto end_edge_leafs = leaves;
  end_edge_leafs[reversed_adapter_index] = end_edge.certificate_pem;
  const auto not_after = CertTime(end_edge.certificate_pem, true);
  clock.Set({not_after.unix_seconds - 1, 999'999'999U});
  Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(
            Load(policy, pki.root_certificate_pem(), end_edge_leafs, clock)),
        "not_after_minus_one_ns_accepted");
  clock.Set({not_after.unix_seconds, 0});
  ExpectError(Load(policy, pki.root_certificate_pem(), end_edge_leafs, clock),
              sec::CertificateRegistryErrorCode::CertificateExpired,
              "not_after_exact_rejected");
  clock.Set({not_after.unix_seconds, 1});
  ExpectError(Load(policy, pki.root_certificate_pem(), end_edge_leafs, clock),
              sec::CertificateRegistryErrorCode::CertificateExpired,
              "not_after_plus_one_ns_rejected");

  clock.Fail();
  ExpectError(Load(policy, pki.root_certificate_pem(), leaves, clock),
              sec::CertificateRegistryErrorCode::ClockUntrusted, "untrusted_clock_rejected");

  // Enforce byte caps before unbounded parsing and avoid emitting input data.
  clock = FixedClock({now_sec, 0});
  auto oversized = leaves;
  oversized.front().append(sec::CertificateRegistry::kMaxCertificatePemBytes + 1,
                           ' ');
  ExpectError(Load(policy, pki.root_certificate_pem(), oversized, clock),
              sec::CertificateRegistryErrorCode::ResourceLimit, "per_certificate_limit");

  // The byte bound is inclusive. Surrounding ASCII whitespace is part of the
  // input byte count but is permitted by the PEM grammar.
  auto exact_leaf_cap = leaves;
  exact_leaf_cap.front().append(
      sec::CertificateRegistry::kMaxCertificatePemBytes - exact_leaf_cap.front().size(), ' ');
  auto exact_leaf_result = Load(policy, pki.root_certificate_pem(), exact_leaf_cap, clock);
  Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(
            exact_leaf_result), "exact_per_certificate_cap_accepted");
  std::string exact_root_cap = pki.root_certificate_pem();
  exact_root_cap.append(sec::CertificateRegistry::kMaxCertificatePemBytes -
                            exact_root_cap.size(), ' ');
  auto exact_root_result = Load(policy, exact_root_cap, leaves, clock);
  Check(std::holds_alternative<std::shared_ptr<const sec::CertificateRegistry>>(
            exact_root_result), "exact_root_certificate_cap_accepted");
  auto oversized_root = exact_root_cap;
  oversized_root.push_back(' ');
  ExpectError(Load(policy, oversized_root, leaves, clock),
              sec::CertificateRegistryErrorCode::ResourceLimit,
              "root_certificate_limit_plus_one");

  // Exercise aggregate-byte arithmetic before parsing/count validation using
  // repeated views into one bounded valid PEM buffer. Exactly 64 MiB proceeds
  // to the independently expected count error; one additional byte is capped.
  const std::size_t aggregate_cap = sec::CertificateRegistry::kMaxAggregatePemBytes;
  const std::size_t repeated_count = 1023;
  std::string repeated_pem = leaves.front();
  repeated_pem.append(sec::CertificateRegistry::kMaxCertificatePemBytes -
                          repeated_pem.size(), ' ');
  std::vector<std::string_view> aggregate_views(repeated_count, repeated_pem);
  const std::size_t root_size = pki.root_certificate_pem().size();
  const std::size_t last_size = aggregate_cap - root_size -
      repeated_count * sec::CertificateRegistry::kMaxCertificatePemBytes;
  Check(last_size <= sec::CertificateRegistry::kMaxCertificatePemBytes,
        "aggregate_fixture_arithmetic");
  aggregate_views.emplace_back(repeated_pem.data(), last_size);
  auto exact_aggregate = sec::CertificateRegistryLoader::Load(
      policy, pki.root_certificate_pem(), aggregate_views, clock);
  ExpectError(exact_aggregate, sec::CertificateRegistryErrorCode::LeafCountMismatch,
              "exact_aggregate_cap_not_resource_limited");
  aggregate_views.back() = std::string_view(repeated_pem.data(), last_size + 1);
  auto over_aggregate = sec::CertificateRegistryLoader::Load(
      policy, pki.root_certificate_pem(), aggregate_views, clock);
  ExpectError(over_aggregate, sec::CertificateRegistryErrorCode::ResourceLimit,
              "aggregate_cap_plus_one_rejected");

  std::vector<std::string_view> principal_overflow(
      sec::CertificateRegistry::kMaxPrincipalCount + 1, "x");
  ExpectError(sec::CertificateRegistryLoader::Load(
                  policy, pki.root_certificate_pem(), principal_overflow, clock),
              sec::CertificateRegistryErrorCode::ResourceLimit,
              "principal_count_cap_plus_one_rejected");

  std::cout << "PASS registry_valid_binding_negative_identity_eku_time_caps" << '\n';
  return 0;
}
