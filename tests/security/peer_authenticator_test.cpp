#include "ephemeral_pki.h"
#include "rateguard/security/peer_authenticator.h"

#include "policy/canonical_codec.h"
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
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;

namespace {

static_assert(std::is_copy_constructible_v<sec::AuthenticatedPeer>);
static_assert(std::is_nothrow_copy_assignable_v<sec::AuthenticatedPeer>);
// Rvalue construction remains possible through the copy constructor; no
// implicit move operation may transfer the registry owner away.
static_assert(std::is_move_constructible_v<sec::AuthenticatedPeer>);

int failures = 0;

void Check(bool condition, std::string_view label) {
  if (!condition) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}

class EmptyAuthPropertyIterator final : public grpc::AuthPropertyIterator {
 public:
  EmptyAuthPropertyIterator() : grpc::AuthPropertyIterator() {}
};

class TestAuthContext final : public grpc::AuthContext {
 public:
  explicit TestAuthContext(bool authenticated = true) : authenticated_(authenticated) {}

  void Add(std::string name, std::string value) {
    properties_.emplace_back(std::move(name), std::move(value));
  }
  bool IsPeerAuthenticated() const override { return authenticated_; }
  std::vector<grpc::string_ref> GetPeerIdentity() const override {
    return FindPropertyValues(GRPC_PEER_URI_PROPERTY_NAME);
  }
  std::string GetPeerIdentityPropertyName() const override {
    return GRPC_PEER_URI_PROPERTY_NAME;
  }
  std::vector<grpc::string_ref> FindPropertyValues(
      const std::string& name) const override {
    std::vector<grpc::string_ref> values;
    for (const auto& property : properties_) {
      if (property.first == name) values.emplace_back(property.second.data(), property.second.size());
    }
    return values;
  }
  grpc::AuthPropertyIterator begin() const override {
    return EmptyAuthPropertyIterator{};
  }
  grpc::AuthPropertyIterator end() const override {
    return EmptyAuthPropertyIterator{};
  }
  void AddProperty(const std::string&, const grpc::string_ref&) override {}
  bool SetPeerIdentityPropertyName(const std::string&) override { return false; }

 private:
  bool authenticated_;
  std::vector<std::pair<std::string, std::string>> properties_;
};

class TestClock final : public sec::ITrustedWallClock {
 public:
  explicit TestClock(sec::WallTime time, bool healthy = true)
      : time_(time), healthy_(healthy) {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override {
    ++calls;
    if (!healthy_) {
      return sec::TrustedWallClockFailure{
          sec::TrustedWallClockFailureReason::PlatformUnavailable};
    }
    return time_;
  }
  bool Healthy() const override { return healthy_; }
  void Set(sec::WallTime time) { time_ = time; }
  void SetHealthy(bool healthy) { healthy_ = healthy; }
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
  if (raw_bio == nullptr) return false;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (raw_cert == nullptr) return false;
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

struct Fixture final {
  sec::test::EphemeralPki pki;
  std::shared_ptr<const pol::PolicySnapshot> policy;
  std::shared_ptr<const sec::CertificateRegistry> registry;
  const sec::test::EphemeralIdentity* adapter{};
  std::string error;

  explicit Fixture(const std::string& path) {
    const std::string source = ReadFile(path);
    if (source.empty()) {
      error = "policy fixture unavailable";
      return;
    }
    pol::Digest32 root_hash{};
    if (!RootDigest(pki.root_certificate_pem(), &root_hash)) {
      error = "root digest unavailable";
      return;
    }
    try {
      auto json = nlohmann::json::parse(source);
      json["trust_root_sha256"] = Hex(root_hash.data(), root_hash.size());
      auto loaded = pol::PolicyLoader::Load(json.dump());
      if (const auto* issue = std::get_if<pol::PolicyError>(&loaded)) {
        error = issue->message;
        return;
      }
      policy = std::get<std::shared_ptr<const pol::PolicySnapshot>>(std::move(loaded));

      std::vector<const sec::test::EphemeralIdentity*> identities;
      std::vector<std::string_view> leaves;
      identities.reserve(policy->principals().size());
      leaves.reserve(policy->principals().size());
      for (const auto& principal : policy->principals()) {
        sec::PeerRole role = sec::PeerRole::kAdapter;
        switch (principal.role) {
          case pol::PrincipalRole::Adapter: role = sec::PeerRole::kAdapter; break;
          case pol::PrincipalRole::Replica: role = sec::PeerRole::kReplica; break;
          case pol::PrincipalRole::Authority: role = sec::PeerRole::kAuthority; break;
        }
        const auto& identity = pki.IssueWithValidity(role, principal.uri, -60, 3600);
        identities.push_back(&identity);
        leaves.push_back(identity.certificate_pem);
        if (principal.role == pol::PrincipalRole::Adapter && adapter == nullptr) {
          adapter = &identity;
        }
      }
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
      TestClock initial_clock({now, 0});
      auto built = sec::CertificateRegistryLoader::Load(
          policy, pki.root_certificate_pem(), leaves, initial_clock);
      if (const auto* issue = std::get_if<sec::CertificateRegistryError>(&built)) {
        error = "certificate registry fixture rejected";
        (void)issue;
        return;
      }
      registry = std::get<std::shared_ptr<const sec::CertificateRegistry>>(std::move(built));
    } catch (const std::exception&) {
      error = "fixture setup failed";
    }
  }
};

TestAuthContext Context(std::string_view uri, std::string_view cert,
                        std::string_view transport = GRPC_TLS_TRANSPORT_SECURITY_TYPE) {
  TestAuthContext context;
  context.Add(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME, std::string(transport));
  context.Add(GRPC_PEER_URI_PROPERTY_NAME, std::string(uri));
  context.Add(GRPC_X509_PEM_CERT_PROPERTY_NAME, std::string(cert));
  return context;
}

void TestAuthenticatedPrincipalAndLifetime(const std::string& path) {
  Fixture fixture(path);
  Check(fixture.registry != nullptr && fixture.adapter != nullptr,
        "validated policy and adapter certificate fixture available");
  if (!fixture.registry || fixture.adapter == nullptr) return;
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  TestClock clock({now, 0});
  auto context = Context(fixture.adapter->registered.uri,
                         fixture.adapter->certificate_pem);
  std::optional<sec::AuthenticatedPeer> rvalue_constructed;
  {
    sec::PeerAuthenticator authenticator(fixture.registry, clock);
    auto result = authenticator.Authenticate(context);
    auto* proof = std::get_if<sec::AuthenticatedPeer>(&result);
    Check(proof != nullptr, "registered TLS URI and exact DER leaf pin authenticate");
    Check(clock.calls == 1, "each authentication obtains a fresh trusted clock sample");
    if (proof == nullptr) return;
    Check(proof->uri() == fixture.adapter->registered.uri &&
          proof->role() == sec::PeerRole::kAdapter &&
          proof->registry().get() == fixture.registry.get(),
          "opaque proof owns exact registry and resolved principal identity");
    rvalue_constructed.emplace(std::move(*proof));
  }
  fixture.registry.reset();
  Check(rvalue_constructed && rvalue_constructed->registry() != nullptr &&
        rvalue_constructed->certificate() != nullptr &&
        rvalue_constructed->certificate()->peer.uri == rvalue_constructed->uri(),
        "rvalue construction retains the proof after original variant and registry owners die");
}

void TestRejectedTransportIdentityAndPem(const std::string& path) {
  Fixture fixture(path);
  Check(fixture.registry != nullptr && fixture.adapter != nullptr,
        "negative identity fixture available");
  if (!fixture.registry || fixture.adapter == nullptr) return;
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  TestClock clock({now, 0});
  sec::PeerAuthenticator authenticator(fixture.registry, clock);
  const auto& id = *fixture.adapter;

  auto expect = [&](const TestAuthContext& context, sec::PeerAuthFailureReason reason,
                    sec::PeerAuthDisposition disposition, std::string_view label) {
    auto result = authenticator.Authenticate(context);
    const auto* failure = std::get_if<sec::PeerAuthFailure>(&result);
    Check(failure && failure->reason == reason && failure->disposition == disposition, label);
  };

  TestAuthContext no_identity(false);
  no_identity.Add(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME, GRPC_TLS_TRANSPORT_SECURITY_TYPE);
  no_identity.Add(GRPC_PEER_URI_PROPERTY_NAME, id.registered.uri);
  no_identity.Add(GRPC_X509_PEM_CERT_PROPERTY_NAME, id.certificate_pem);
  expect(no_identity, sec::PeerAuthFailureReason::UnauthenticatedContext,
         sec::PeerAuthDisposition::Unauthenticated, "unauthenticated auth context fails closed");

  auto bad_transport = Context(id.registered.uri, id.certificate_pem, "ssl");
  expect(bad_transport, sec::PeerAuthFailureReason::UnsupportedTransport,
         sec::PeerAuthDisposition::Unauthenticated, "wrong transport security type fails closed");

  auto ambiguous_transport = Context(id.registered.uri, id.certificate_pem);
  ambiguous_transport.Add(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
                          GRPC_TLS_TRANSPORT_SECURITY_TYPE);
  expect(ambiguous_transport, sec::PeerAuthFailureReason::MissingOrAmbiguousTransport,
         sec::PeerAuthDisposition::Unauthenticated, "multiple transport properties fail closed");

  auto ambiguous_uri = Context(id.registered.uri, id.certificate_pem);
  ambiguous_uri.Add(GRPC_PEER_URI_PROPERTY_NAME, id.registered.uri);
  expect(ambiguous_uri, sec::PeerAuthFailureReason::MissingOrAmbiguousUri,
         sec::PeerAuthDisposition::Unauthenticated, "multiple URI properties fail closed");

  auto missing_cert = TestAuthContext{};
  missing_cert.Add(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME, GRPC_TLS_TRANSPORT_SECURITY_TYPE);
  missing_cert.Add(GRPC_PEER_URI_PROPERTY_NAME, id.registered.uri);
  expect(missing_cert, sec::PeerAuthFailureReason::MissingOrAmbiguousLeaf,
         sec::PeerAuthDisposition::Unauthenticated, "missing leaf property fails closed");

  auto ambiguous_leaf = Context(id.registered.uri, id.certificate_pem);
  ambiguous_leaf.Add(GRPC_X509_PEM_CERT_PROPERTY_NAME, id.certificate_pem);
  expect(ambiguous_leaf, sec::PeerAuthFailureReason::MissingOrAmbiguousLeaf,
         sec::PeerAuthDisposition::Unauthenticated, "multiple leaf properties fail closed");

  const auto& changed_pin = fixture.pki.Issue(sec::PeerRole::kAdapter,
                                               id.registered.uri);
  auto pin_mismatch = Context(id.registered.uri, changed_pin.certificate_pem);
  expect(pin_mismatch, sec::PeerAuthFailureReason::LeafPinMismatch,
         sec::PeerAuthDisposition::Unauthenticated, "same URI with different leaf DER fails pin check");

  auto unknown_uri = Context("spiffe://rateguard.local/adapter/unknown", id.certificate_pem);
  expect(unknown_uri, sec::PeerAuthFailureReason::UnregisteredUri,
         sec::PeerAuthDisposition::Unauthenticated, "unregistered URI fails closed");

  std::string prefixed = "prefix" + id.certificate_pem;
  auto prefix_ctx = Context(id.registered.uri, prefixed);
  expect(prefix_ctx, sec::PeerAuthFailureReason::InvalidLeafPem,
         sec::PeerAuthDisposition::Unauthenticated, "nonwhitespace PEM prefix rejected");

  std::string multiple_certs = id.certificate_pem + id.certificate_pem;
  auto multi_ctx = Context(id.registered.uri, multiple_certs);
  expect(multi_ctx, sec::PeerAuthFailureReason::InvalidLeafPem,
         sec::PeerAuthDisposition::Unauthenticated, "additional PEM certificate rejected");

  std::string nul_uri = id.registered.uri;
  nul_uri.push_back('\0');
  auto nul_ctx = Context(nul_uri, id.certificate_pem);
  expect(nul_ctx, sec::PeerAuthFailureReason::InvalidUri,
         sec::PeerAuthDisposition::Unauthenticated, "embedded NUL in URI rejected");

  std::string non_ascii_uri = id.registered.uri;
  non_ascii_uri.append("\xc3\xa9", 2);
  auto non_ascii_ctx = Context(non_ascii_uri, id.certificate_pem);
  expect(non_ascii_ctx, sec::PeerAuthFailureReason::InvalidUri,
         sec::PeerAuthDisposition::Unauthenticated, "non-ASCII URI bytes rejected");

  std::string nul_pem = id.certificate_pem;
  nul_pem.push_back('\0');
  auto nul_pem_ctx = Context(id.registered.uri, nul_pem);
  expect(nul_pem_ctx, sec::PeerAuthFailureReason::InvalidLeafPem,
         sec::PeerAuthDisposition::Unauthenticated, "embedded NUL in PEM rejected");

  auto oversized_ctx = Context(id.registered.uri,
      std::string(sec::CertificateRegistry::kMaxCertificatePemBytes + 1, 'x'));
  expect(oversized_ctx, sec::PeerAuthFailureReason::OversizedLeaf,
         sec::PeerAuthDisposition::Unauthenticated, "oversized leaf metadata fails closed");
}

void TestFreshValidityAndClockFailures(const std::string& path) {
  Fixture fixture(path);
  Check(fixture.registry != nullptr && fixture.adapter != nullptr,
        "validity fixture available");
  if (!fixture.registry || fixture.adapter == nullptr) return;
  auto context = Context(fixture.adapter->registered.uri,
                         fixture.adapter->certificate_pem);
  const auto* record = fixture.registry->Find(fixture.adapter->registered.uri);
  Check(record != nullptr, "adapter record in immutable registry");
  if (record == nullptr) return;

  TestClock expired_clock(record->validity.not_after);
  sec::PeerAuthenticator expired_auth(fixture.registry, expired_clock);
  auto expired = expired_auth.Authenticate(context);
  const auto* expired_error = std::get_if<sec::PeerAuthFailure>(&expired);
  Check(expired_error && expired_error->reason == sec::PeerAuthFailureReason::CertificateExpired &&
        expired_error->disposition == sec::PeerAuthDisposition::Unauthenticated,
        "leaf notAfter is exclusive on a fresh authentication");

  TestClock unhealthy(record->validity.not_before, false);
  sec::PeerAuthenticator unhealthy_auth(fixture.registry, unhealthy);
  auto unavailable = unhealthy_auth.Authenticate(context);
  const auto* unavailable_error = std::get_if<sec::PeerAuthFailure>(&unavailable);
  Check(unavailable_error && unavailable_error->reason == sec::PeerAuthFailureReason::ClockUntrusted &&
        unavailable_error->disposition == sec::PeerAuthDisposition::ApplicationUnavailable,
        "untrusted wall clock yields application-unavailable disposition");

  TestClock malformed({record->validity.not_before.unix_seconds, 1'000'000'000U});
  sec::PeerAuthenticator malformed_auth(fixture.registry, malformed);
  auto malformed_result = malformed_auth.Authenticate(context);
  const auto* malformed_error = std::get_if<sec::PeerAuthFailure>(&malformed_result);
  Check(malformed_error && malformed_error->reason == sec::PeerAuthFailureReason::ClockUntrusted &&
        malformed_error->disposition == sec::PeerAuthDisposition::ApplicationUnavailable,
        "invalid trusted-wall-clock tuple fails closed");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: peer_authenticator_test <policy-fixture-path>\n";
    return 2;
  }
  TestAuthenticatedPrincipalAndLifetime(argv[1]);
  TestRejectedTransportIdentityAndPem(argv[1]);
  TestFreshValidityAndClockFailures(argv[1]);
  if (failures != 0) {
    std::cerr << failures << " peer-authenticator checks failed\n";
    return 1;
  }
  std::cout << "peer authenticator checks passed\n";
  return 0;
}
