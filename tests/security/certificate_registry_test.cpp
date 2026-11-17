#include "ephemeral_pki.h"

#include "policy/canonical_codec.h"
#include "policy/policy_loader.h"
#include "rateguard/security/certificate_registry.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
namespace {

int failures = 0;
void Check(bool condition, std::string_view label) {
  if (!condition) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}

class TestClock final : public sec::ITrustedWallClock {
 public:
  explicit TestClock(sec::WallTime time, bool healthy = true)
      : time_(time), healthy_(healthy) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override {
    ++calls;
    if (!healthy_) return sec::TrustedWallClockFailure{
        sec::TrustedWallClockFailureReason::PlatformUnavailable};
    return time_;
  }
  bool Healthy() const override { return healthy_; }
  void Set(sec::WallTime time) { time_ = time; }
  unsigned calls{};
 private:
  sec::WallTime time_;
  bool healthy_;
};

std::string ReadFile(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return {};
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string Hex(const std::uint8_t* data, std::size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(size * 2, '0');
  for (std::size_t i = 0; i < size; ++i) {
    result[i * 2] = digits[data[i] >> 4];
    result[i * 2 + 1] = digits[data[i] & 0x0f];
  }
  return result;
}

bool RootDigest(std::string_view pem, pol::Digest32* digest) {
  BIO* raw_bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!raw_bio) return false;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!raw_cert) return false;
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
  const int length = i2d_X509(cert.get(), nullptr);
  if (length <= 0 || length > 64 * 1024) return false;
  std::vector<std::uint8_t> der(static_cast<std::size_t>(length));
  unsigned char* cursor = der.data();
  if (i2d_X509(cert.get(), &cursor) != length) return false;
  unsigned int written = 0;
  return EVP_Digest(der.data(), der.size(), digest->data(), &written,
                    EVP_sha256(), nullptr) == 1 && written == digest->size();
}

struct Fixture {
  sec::test::EphemeralPki pki;
  std::shared_ptr<const pol::PolicySnapshot> snapshot;
  std::vector<const sec::test::EphemeralIdentity*> identities;
  std::vector<std::string_view> leaf_pems;
  std::string policy_error;

  explicit Fixture(const std::string& policy_fixture_path) {
    const std::string base = ReadFile(policy_fixture_path);
    if (base.empty()) { policy_error = "fixture unavailable"; return; }
    pol::Digest32 root_hash{};
    if (!RootDigest(pki.root_certificate_pem(), &root_hash)) {
      policy_error = "root digest failed";
      return;
    }
    try {
      auto json = nlohmann::json::parse(base);
      json["trust_root_sha256"] = Hex(root_hash.data(), root_hash.size());
      const std::string bound_policy = json.dump();
      auto loaded = pol::PolicyLoader::Load(bound_policy);
      if (const auto* error = std::get_if<pol::PolicyError>(&loaded)) {
        policy_error = error->message;
        return;
      }
      snapshot = std::get<std::shared_ptr<const pol::PolicySnapshot>>(std::move(loaded));
      identities.reserve(snapshot->principals().size());
      leaf_pems.reserve(snapshot->principals().size());
      for (const auto& principal : snapshot->principals()) {
        sec::PeerRole role = sec::PeerRole::kAdapter;
        switch (principal.role) {
          case pol::PrincipalRole::Adapter: role = sec::PeerRole::kAdapter; break;
          case pol::PrincipalRole::Replica: role = sec::PeerRole::kReplica; break;
          case pol::PrincipalRole::Authority: role = sec::PeerRole::kAuthority; break;
        }
        const auto& identity = pki.IssueWithValidity(role, principal.uri, -60, 3600);
        identities.push_back(&identity);
        leaf_pems.push_back(identity.certificate_pem);
      }
    } catch (const std::exception&) {
      policy_error = "fixture setup failed";
    }
  }
};

using LoadResult = sec::CertificateRegistryResult<
    std::shared_ptr<const sec::CertificateRegistry>>;

const sec::CertificateRegistry* Loaded(const LoadResult& result) {
  const auto* value = std::get_if<std::shared_ptr<const sec::CertificateRegistry>>(&result);
  return value ? value->get() : nullptr;
}

std::optional<sec::CertificateRegistryErrorCode> ErrorOf(const LoadResult& result) {
  const auto* error = std::get_if<sec::CertificateRegistryError>(&result);
  return error ? std::optional(error->code) : std::nullopt;
}

void TestValidSnapshotAndOrder(const std::string& policy_path) {
  Fixture fixture(policy_path);
  Check(fixture.snapshot != nullptr, "policy fixture loads with ephemeral root fingerprint");
  if (!fixture.snapshot) return;
  TestClock clock({1'800'000'000, 0});
  // The certificate fixture is generated relative to system time. Select that
  // time for successful construction; boundary tests use copied bounds below.
  const auto system_seconds = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  clock.Set({system_seconds, 0});
  const auto result = sec::CertificateRegistryLoader::Load(
      fixture.snapshot, fixture.pki.root_certificate_pem(), fixture.leaf_pems, clock);
  const auto* registry = Loaded(result);
  Check(registry != nullptr, "valid direct root and every leaf create snapshot");
  Check(clock.calls == 1, "load samples trusted wall clock exactly once");
  if (!registry) return;
  Check(registry->validated_at() == sec::WallTime{system_seconds, 0},
        "snapshot records validation sample without retaining input PEM");
  Check(registry->epoch_id() == fixture.snapshot->epoch_id() &&
        registry->authority_incarnation() == fixture.snapshot->authority_incarnation(),
        "registry is bound to immutable policy epoch and authority");
  const auto digest = pol::CanonicalPolicyCodec::Digest(*fixture.snapshot);
  Check(std::get_if<pol::Digest32>(&digest) != nullptr &&
        registry->policy_digest() == std::get<pol::Digest32>(digest),
        "registry carries canonical policy digest");
  Check(registry->peers().size() == fixture.snapshot->principals().size(),
        "registry includes exactly the policy principal set");
  Check(registry->peer_pins() && registry->peer_pins()->valid() &&
        registry->AllValidAt({system_seconds, 0}), "registry exposes immutable verifier pins and validity");

  auto reversed = fixture.leaf_pems;
  std::reverse(reversed.begin(), reversed.end());
  TestClock second_clock({system_seconds, 0});
  const auto reordered = sec::CertificateRegistryLoader::Load(
      fixture.snapshot, fixture.pki.root_certificate_pem(), reversed, second_clock);
  const auto* reordered_registry = Loaded(reordered);
  Check(reordered_registry && reordered_registry->peers().size() == registry->peers().size(),
        "leaf input order does not affect sorted immutable registry");
  if (reordered_registry) {
    for (std::size_t i = 0; i < registry->peers().size(); ++i) {
      Check(registry->peers()[i].peer.uri == reordered_registry->peers()[i].peer.uri &&
            registry->peers()[i].peer.leaf_der_sha256 == reordered_registry->peers()[i].peer.leaf_der_sha256,
            "canonical registry order and pins are stable");
    }
  }
}

void TestHalfOpenTimeBoundaries(const std::string& policy_path) {
  Fixture fixture(policy_path);
  if (!fixture.snapshot) { Check(false, "time fixture policy loads"); return; }
  const auto system_seconds = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  TestClock initial_clock({system_seconds, 0});
  const auto initial = sec::CertificateRegistryLoader::Load(
      fixture.snapshot, fixture.pki.root_certificate_pem(), fixture.leaf_pems, initial_clock);
  const auto* registry = Loaded(initial);
  Check(registry != nullptr, "time boundary fixture validates initially");
  if (!registry) return;

  sec::WallTime latest_start = registry->root_validity().not_before;
  sec::WallTime earliest_end = registry->root_validity().not_after;
  for (const auto& peer : registry->peers()) {
    if (latest_start < peer.validity.not_before) latest_start = peer.validity.not_before;
    if (peer.validity.not_after < earliest_end) earliest_end = peer.validity.not_after;
  }
  Check(latest_start < earliest_end, "all fixture certificates have a common valid interval");
  if (!(latest_start < earliest_end)) return;

  auto LoadAt = [&](sec::WallTime time) {
    TestClock clock(time);
    return sec::CertificateRegistryLoader::Load(
        fixture.snapshot, fixture.pki.root_certificate_pem(), fixture.leaf_pems, clock);
  };
  Check(ErrorOf(LoadAt({latest_start.unix_seconds - 1, 999'999'999U})) ==
            sec::CertificateRegistryErrorCode::CertificateNotYetValid,
        "notBefore minus one nanosecond is rejected");
  Check(Loaded(LoadAt(latest_start)) != nullptr, "notBefore is inclusive");
  Check(Loaded(LoadAt({latest_start.unix_seconds, 1U})) != nullptr,
        "notBefore plus one nanosecond is valid");
  Check(Loaded(LoadAt({earliest_end.unix_seconds - 1, 999'999'999U})) != nullptr,
        "notAfter minus one nanosecond is valid");
  Check(ErrorOf(LoadAt(earliest_end)) == sec::CertificateRegistryErrorCode::CertificateExpired,
        "notAfter is exclusive");
  Check(ErrorOf(LoadAt({earliest_end.unix_seconds, 1U})) ==
            sec::CertificateRegistryErrorCode::CertificateExpired,
        "notAfter plus one nanosecond is expired");
}

void TestInputAndBindingFailures(const std::string& policy_path) {
  Fixture fixture(policy_path);
  if (!fixture.snapshot) { Check(false, "negative fixture policy loads"); return; }
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  auto load = [&](std::string_view root, std::span<const std::string_view> leaves,
                  TestClock& clock) {
    return sec::CertificateRegistryLoader::Load(fixture.snapshot, root, leaves, clock);
  };
  TestClock clock({now, 0});
  std::string prefix = "untrusted-prefix\n" + fixture.pki.root_certificate_pem();
  Check(ErrorOf(load(prefix, fixture.leaf_pems, clock)) ==
            sec::CertificateRegistryErrorCode::InvalidPem,
        "non-whitespace prefix is rejected");
  std::string trailing = fixture.pki.root_certificate_pem() + "extra";
  Check(ErrorOf(load(trailing, fixture.leaf_pems, clock)) ==
            sec::CertificateRegistryErrorCode::InvalidPem,
        "non-whitespace trailing data is rejected");
  Check(ErrorOf(load(fixture.pki.root_certificate_pem(),
                     std::span<const std::string_view>(fixture.leaf_pems).first(fixture.leaf_pems.size() - 1),
                     clock)) == sec::CertificateRegistryErrorCode::LeafCountMismatch,
        "missing leaf is rejected");
  auto duplicate = fixture.leaf_pems;
  duplicate.back() = duplicate.front();
  Check(ErrorOf(load(fixture.pki.root_certificate_pem(), duplicate, clock)) ==
            sec::CertificateRegistryErrorCode::DuplicateLeaf,
        "duplicate principal leaf is rejected");
  auto extra = fixture.leaf_pems;
  extra.push_back(extra.front());
  Check(ErrorOf(load(fixture.pki.root_certificate_pem(), extra, clock)) ==
            sec::CertificateRegistryErrorCode::LeafCountMismatch,
        "extra leaf is rejected");

  sec::test::EphemeralPki foreign;
  const auto& foreign_root_peer = foreign.Issue(sec::PeerRole::kAdapter,
      fixture.snapshot->principals().front().uri);
  (void)foreign_root_peer;
  Check(ErrorOf(load(foreign.root_certificate_pem(), fixture.leaf_pems, clock)) ==
            sec::CertificateRegistryErrorCode::RootFingerprintMismatch,
        "different root fingerprint cannot bind to policy snapshot");

  std::string oversized(sec::CertificateRegistry::kMaxCertificatePemBytes + 1, ' ');
  Check(ErrorOf(load(oversized, fixture.leaf_pems, clock)) ==
            sec::CertificateRegistryErrorCode::ResourceLimit,
        "per-certificate PEM bound is enforced before parsing");
  std::string cap_filler(sec::CertificateRegistry::kMaxCertificatePemBytes, ' ');
  std::vector<std::string_view> over_aggregate(1024, cap_filler);
  Check(ErrorOf(load(fixture.pki.root_certificate_pem(), over_aggregate, clock)) ==
            sec::CertificateRegistryErrorCode::ResourceLimit,
        "aggregate public PEM cap includes all supplied leaf entries");
  std::vector<std::string_view> too_many(sec::CertificateRegistry::kMaxPrincipalCount + 1,
                                         std::string_view{});
  Check(ErrorOf(load(fixture.pki.root_certificate_pem(), too_many, clock)) ==
            sec::CertificateRegistryErrorCode::ResourceLimit,
        "principal count cap is enforced");

  TestClock untrusted({now, 0}, false);
  Check(ErrorOf(load(fixture.pki.root_certificate_pem(), fixture.leaf_pems, untrusted)) ==
            sec::CertificateRegistryErrorCode::ClockUntrusted,
        "untrusted current time fails closed");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: certificate_registry_test <policy-fixture-path>\n";
    return 2;
  }
  TestValidSnapshotAndOrder(argv[1]);
  TestHalfOpenTimeBoundaries(argv[1]);
  TestInputAndBindingFailures(argv[1]);
  if (failures != 0) return 1;
  std::cout << "certificate registry checks passed\n";
  return 0;
}
