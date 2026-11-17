#include "rateguard/security/certificate_registry.h"
#include "policy/policy_loader.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace sec = rateguard::security;
namespace pol = rateguard::policy;
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
unsigned case_count = 0;
[[noreturn]] void Fail(std::string_view label) {
  std::cerr << "FAIL registry_profile " << label << '\n';
  std::exit(1);
}
void Require(bool value, std::string_view label) { if (!value) Fail(label); }
struct Profile {
  int curve = NID_X9_62_prime256v1;
  bool sha384 = false;
  const char* constraints = nullptr;
  const char* usage = nullptr;
  const char* eku = nullptr;
  const char* before = nullptr;
  const char* after = nullptr;
  bool noncanonical_before = false;
  bool corrupt_signature = false;
  bool omit_san = false;
  bool duplicate_san = false;
};
Key NewKey(int curve) {
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
  Require(context && EVP_PKEY_keygen_init(context.get()) == 1 &&
          EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), curve) == 1,
          "fixture_key_setup");
  EVP_PKEY* key = nullptr;
  Require(EVP_PKEY_keygen(context.get(), &key) == 1, "fixture_keygen");
  return Key(key, EVP_PKEY_free);
}
void Extension(X509* cert, X509* issuer, int nid, const std::string& value) {
  X509V3_CTX context{};
  X509V3_set_ctx(&context, issuer, cert, nullptr, nullptr, 0);
  std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
      X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value.c_str())),
      X509_EXTENSION_free);
  Require(extension && X509_add_ext(cert, extension.get(), -1) == 1,
          "fixture_extension");
}
Cert NewCertificate(EVP_PKEY* key, X509* root, EVP_PKEY* root_key,
                    pol::PrincipalRole role, std::string_view uri,
                    const Profile& profile) {
  static long serial = 1;
  Cert cert(X509_new(), X509_free);
  Require(cert && X509_set_version(cert.get(), 2) == 1 &&
          ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial++) == 1 &&
          X509_set_pubkey(cert.get(), key) == 1, "fixture_certificate");
  Require(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) &&
          X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600), "fixture_time");
  if (profile.before)
    Require(ASN1_TIME_set_string_X509(X509_getm_notBefore(cert.get()), profile.before) == 1,
            "fixture_before");
  if (profile.after)
    Require(ASN1_TIME_set_string_X509(X509_getm_notAfter(cert.get()), profile.after) == 1,
            "fixture_after");
  if (profile.noncanonical_before) {
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> time(
        ASN1_STRING_type_new(V_ASN1_GENERALIZEDTIME), ASN1_TIME_free);
    Require(time && ASN1_STRING_set(time.get(), "20200101000000Z", 15) == 1 &&
            X509_set1_notBefore(cert.get(), time.get()) == 1, "fixture_noncanonical");
  }
  X509_NAME* subject = X509_get_subject_name(cert.get());
  const char* name = root ? "Registry profile leaf" : "Registry profile root";
  Require(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
          reinterpret_cast<const unsigned char*>(name), -1, -1, 0) == 1 &&
          X509_set_issuer_name(cert.get(), root ? X509_get_subject_name(root) : subject) == 1,
          "fixture_names");
  X509* issuer = root ? root : cert.get();
  Extension(cert.get(), issuer, NID_basic_constraints,
      profile.constraints ? profile.constraints : root ? "critical,CA:FALSE" : "critical,CA:TRUE,pathlen:0");
  Extension(cert.get(), issuer, NID_key_usage,
      profile.usage ? profile.usage : root ? "critical,digitalSignature" : "critical,keyCertSign,cRLSign");
  Extension(cert.get(), issuer, NID_subject_key_identifier, "hash");
  Extension(cert.get(), issuer, NID_authority_key_identifier, "keyid:always");
  if (root) {
    const char* eku = profile.eku ? profile.eku : role == pol::PrincipalRole::Adapter ?
        "clientAuth" : role == pol::PrincipalRole::Authority ? "serverAuth" : "clientAuth,serverAuth";
    Extension(cert.get(), issuer, NID_ext_key_usage, eku);
    if (!profile.omit_san)
      Extension(cert.get(), issuer, NID_subject_alt_name, "URI:" + std::string(uri));
    if (profile.duplicate_san)
      Extension(cert.get(), issuer, NID_subject_alt_name, "URI:" + std::string(uri));
  }
  Require(X509_sign(cert.get(), root ? root_key : key,
                   profile.sha384 ? EVP_sha384() : EVP_sha256()) > 0,
          "fixture_sign");
  if (profile.corrupt_signature) {
    const int count = i2d_X509(cert.get(), nullptr);
    Require(count > 0, "fixture_corrupt_size");
    std::vector<unsigned char> bytes(static_cast<std::size_t>(count));
    auto* destination = bytes.data();
    Require(i2d_X509(cert.get(), &destination) == count, "fixture_corrupt_der");
    bytes.back() ^= 1;
    const auto* source = bytes.data();
    cert.reset(d2i_X509(nullptr, &source, count));
    Require(static_cast<bool>(cert), "fixture_corrupt_parse");
  }
  return cert;
}
std::string Pem(X509* cert) {
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
  Require(bio && PEM_write_bio_X509(bio.get(), cert) == 1, "fixture_pem");
  char* bytes = nullptr;
  const long size = BIO_get_mem_data(bio.get(), &bytes);
  Require(size > 0 && bytes, "fixture_pem_bytes");
  return {bytes, static_cast<std::size_t>(size)};
}
std::string RootHash(X509* cert) {
  unsigned char digest[EVP_MAX_MD_SIZE]{};
  unsigned int size = 0;
  Require(X509_digest(cert, EVP_sha256(), digest, &size) == 1 && size == 32,
          "fixture_root_hash");
  constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (unsigned int i = 0; i < size; ++i) {
    result.push_back(hex[digest[i] >> 4]); result.push_back(hex[digest[i] & 15]);
  }
  return result;
}
class Clock final : public sec::ITrustedWallClock {
 public:
  Clock() : now_{std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count(), 0} {}
  sec::TrustedWallClockResult<sec::WallTime> Now() override { return now_; }
  bool Healthy() const override { return true; }
 private:
  sec::WallTime now_;
};
void Run(const nlohmann::json& fixture, std::string_view label, const Profile& root_profile,
         const Profile& leaf_profile, std::optional<sec::CertificateRegistryErrorCode> expected) {
  ++case_count;
  Key root_key = NewKey(root_profile.curve);
  Cert root = NewCertificate(root_key.get(), nullptr, nullptr,
      pol::PrincipalRole::Authority, "", root_profile);
  auto json = fixture;
  json["trust_root_sha256"] = RootHash(root.get());
  auto loaded = pol::PolicyLoader::Load(json.dump());
  Require(std::holds_alternative<std::shared_ptr<const pol::PolicySnapshot>>(loaded),
          "fixture_policy");
  auto policy = std::get<std::shared_ptr<const pol::PolicySnapshot>>(loaded);
  std::vector<std::string> leafs;
  for (const auto& principal : policy->principals()) {
    const Profile profile = principal.role == pol::PrincipalRole::Adapter ? leaf_profile : Profile{};
    Key key = NewKey(profile.curve);
    Cert leaf = NewCertificate(key.get(), root.get(), root_key.get(), principal.role,
                              principal.uri, profile);
    leafs.push_back(Pem(leaf.get()));
  }
  std::vector<std::string_view> views;
  for (const auto& pem : leafs) views.emplace_back(pem);
  Clock clock;
  const auto result = sec::CertificateRegistryLoader::Load(policy, Pem(root.get()), views, clock);
  if (expected) {
    const auto* error = std::get_if<sec::CertificateRegistryError>(&result);
    Require(error && error->code == *expected, label);
  } else {
    const auto* registry = std::get_if<std::shared_ptr<const sec::CertificateRegistry>>(&result);
    Require(registry && *registry, label);
    Require((*registry)->AllValidAt(std::get<sec::WallTime>(clock.Now())), label);
  }
}
}  // namespace

int main(int argc, char** argv) {
  Require(argc == 2, "usage");
  std::ifstream input(argv[1]);
  Require(static_cast<bool>(input), "fixture_open");
  const auto fixture = nlohmann::json::parse(input);
  using Error = sec::CertificateRegistryErrorCode;
  Run(fixture, "positive", {}, {}, std::nullopt);
  Profile root;
  root.curve = NID_secp384r1;
  Run(fixture, "root_p384", root, {}, Error::InvalidRootProfile);
  root = {}; root.sha384 = true;
  Run(fixture, "root_sha384", root, {}, Error::InvalidRootProfile);
  root = {}; root.constraints = "critical,CA:FALSE";
  Run(fixture, "root_non_ca", root, {}, Error::InvalidRootProfile);
  root = {}; root.constraints = "critical,CA:TRUE,pathlen:1";
  Run(fixture, "root_path_length", root, {}, Error::InvalidRootProfile);
  root = {}; root.usage = "critical,digitalSignature";
  Run(fixture, "root_no_certificate_sign", root, {}, Error::InvalidRootProfile);
  root = {}; root.corrupt_signature = true;
  Run(fixture, "root_invalid_self_signature", root, {}, Error::InvalidRootProfile);
  root = {}; root.noncanonical_before = true;
  Run(fixture, "root_generalized_before_2050", root, {}, Error::InvalidRootProfile);
  root = {}; root.before = "690101000000Z"; root.after = "99991231235959Z";
  Run(fixture, "root_signed_pre_epoch_maximum_year", root, {}, std::nullopt);
  root = {}; root.before = "200101000000Z"; root.after = "210101000000Z";
  Run(fixture, "root_expired", root, {}, Error::CertificateExpired);
  root = {}; root.before = "20500101000000Z"; root.after = "99991231235959Z";
  Run(fixture, "root_future", root, {}, Error::CertificateNotYetValid);
  Profile leaf;
  leaf.curve = NID_secp384r1;
  Run(fixture, "leaf_p384", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.sha384 = true;
  Run(fixture, "leaf_sha384", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.constraints = "critical,CA:TRUE,pathlen:0";
  Run(fixture, "leaf_ca", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.usage = "critical,keyEncipherment";
  Run(fixture, "leaf_no_digital_signature", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.eku = "clientAuth,serverAuth";
  Run(fixture, "adapter_extra_server_eku", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.eku = "anyExtendedKeyUsage";
  Run(fixture, "leaf_any_eku", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.noncanonical_before = true;
  Run(fixture, "leaf_generalized_before_2050", {}, leaf, Error::InvalidLeafProfile);
  leaf = {}; leaf.before = "690101000000Z";
  Run(fixture, "leaf_signed_pre_epoch", {}, leaf, std::nullopt);
  leaf = {}; leaf.omit_san = true;
  Run(fixture, "leaf_missing_san", {}, leaf, Error::IdentityMismatch);
  leaf = {}; leaf.duplicate_san = true;
  Run(fixture, "leaf_duplicate_san_extension", {}, leaf, Error::IdentityMismatch);
  std::cout << "PASS registry_profile_cases=" << case_count << '\n';
}
