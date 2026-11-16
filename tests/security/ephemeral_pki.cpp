#include "ephemeral_pki.h"

#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace rateguard::security::test {
namespace {
template <typename T, void (*Free)(T*)>
using OsslPtr = std::unique_ptr<T, decltype(Free)>;
using Pkey = OsslPtr<EVP_PKEY, EVP_PKEY_free>;
using X509Ptr = OsslPtr<X509, X509_free>;
using Bio = OsslPtr<BIO, BIO_free>;

Pkey GenerateKey() {
  EVP_PKEY_CTX* raw = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (!raw) throw std::runtime_error("EC key context unavailable");
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw, EVP_PKEY_CTX_free);
  char group[] = "prime256v1";
  OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0), OSSL_PARAM_construct_end()};
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0)
    throw std::runtime_error("EC P-256 setup failed");
  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &key) <= 0 || key == nullptr)
    throw std::runtime_error("EC P-256 generation failed");
  return Pkey(key, EVP_PKEY_free);
}

void AddExtension(X509* cert, X509* issuer, int nid, const char* value) {
  X509V3_CTX context{};
  X509V3_set_ctx(&context, issuer, cert, nullptr, nullptr, 0);
  X509_EXTENSION* raw = X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value));
  if (!raw) throw std::runtime_error("certificate extension construction failed");
  std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(raw, X509_EXTENSION_free);
  if (X509_add_ext(cert, ext.get(), -1) != 1) throw std::runtime_error("certificate extension append failed");
}

X509Ptr MakeCert(EVP_PKEY* key, const std::string& uri, PeerRole role,
                 X509* issuer, EVP_PKEY* issuer_key, long serial, bool is_ca,
                 long not_before_delta = -60, long not_after_delta = 24 * 60 * 60,
                 const std::string* explicit_san = nullptr) {
  X509* raw = X509_new();
  if (!raw) throw std::runtime_error("X509_new failed");
  X509Ptr cert(raw, X509_free);
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), not_before_delta);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), not_after_delta);
  X509_set_pubkey(cert.get(), key);
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>("RateGuard test"), -1, -1, 0);
  X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : name);
  if (is_ca) {
    AddExtension(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    AddExtension(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
  } else {
    AddExtension(cert.get(), issuer, NID_basic_constraints, "critical,CA:FALSE");
    AddExtension(cert.get(), issuer, NID_key_usage, "critical,digitalSignature");
    const char* eku = role == PeerRole::kReplica ? "clientAuth,serverAuth" :
                      role == PeerRole::kAdapter ? "clientAuth" : "serverAuth";
    AddExtension(cert.get(), issuer, NID_ext_key_usage, eku);
    const std::string san = explicit_san ? *explicit_san : "URI:" + uri;
    AddExtension(cert.get(), issuer, NID_subject_alt_name, san.c_str());
  }
  if (X509_sign(cert.get(), issuer_key ? issuer_key : key, EVP_sha256()) <= 0)
    throw std::runtime_error("X509_sign failed");
  return cert;
}

std::string CertPem(X509* cert) {
  Bio bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) throw std::runtime_error("certificate PEM encoding failed");
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio.get(), &data);
  if (size <= 0 || data == nullptr) throw std::runtime_error("certificate PEM extraction failed");
  return std::string(data, static_cast<std::size_t>(size));
}

std::string KeyPem(EVP_PKEY* key) {
  Bio bio(BIO_new(BIO_s_mem()), BIO_free);
  if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    throw std::runtime_error("private key in-memory encoding failed");
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio.get(), &data);
  if (size <= 0 || data == nullptr) throw std::runtime_error("private key PEM extraction failed");
  return std::string(data, static_cast<std::size_t>(size));
}

Sha256Digest DigestDer(X509* cert) {
  const int n = i2d_X509(cert, nullptr);
  if (n <= 0 || n > 64 * 1024) throw std::runtime_error("DER encoding failed");
  std::string der(static_cast<std::size_t>(n), '\0');
  unsigned char* p = reinterpret_cast<unsigned char*>(der.data());
  if (i2d_X509(cert, &p) != n) throw std::runtime_error("DER encoding failed");
  Sha256Digest digest{};
  unsigned int size = 0;
  if (EVP_Digest(der.data(), der.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1 || size != digest.size())
    throw std::runtime_error("SHA-256 unavailable");
  return digest;
}
}  // namespace

struct EphemeralPki::Impl {
  Pkey root_key{nullptr, EVP_PKEY_free};
  X509Ptr root_cert{nullptr, X509_free};
  std::string root_pem;
  long serial = 1;
  std::vector<std::unique_ptr<EphemeralIdentity>> identities;
};

EphemeralPki::EphemeralPki() : impl_(new Impl) {
  impl_->root_key = GenerateKey();
  impl_->root_cert = MakeCert(impl_->root_key.get(), "", PeerRole::kAuthority,
                              nullptr, nullptr, impl_->serial++, true);
  impl_->root_pem = CertPem(impl_->root_cert.get());
}
EphemeralPki::~EphemeralPki() { delete impl_; }
const std::string& EphemeralPki::root_certificate_pem() const { return impl_->root_pem; }

const EphemeralIdentity& EphemeralPki::Issue(PeerRole role, std::string uri) {
  return IssueWithValidity(role, std::move(uri), -60, 24 * 60 * 60);
}

const EphemeralIdentity& EphemeralPki::IssueWithValidity(
    PeerRole role, std::string uri, long not_before_seconds_from_now,
    long not_after_seconds_from_now) {
  Pkey key = GenerateKey();
  X509Ptr cert = MakeCert(key.get(), uri, role, impl_->root_cert.get(), impl_->root_key.get(),
                          impl_->serial++, false, not_before_seconds_from_now,
                          not_after_seconds_from_now);
  auto identity = std::make_unique<EphemeralIdentity>();
  identity->registered.uri = std::move(uri);
  identity->registered.role = role;
  identity->registered.leaf_der_sha256 = DigestDer(cert.get());
  identity->certificate_pem = CertPem(cert.get());
  identity->private_key_pem = KeyPem(key.get());
  impl_->identities.push_back(std::move(identity));
  return *impl_->identities.back();
}

const EphemeralIdentity& EphemeralPki::IssueWithUriSans(
    PeerRole role, std::vector<std::string> uri_sans) {
  if (uri_sans.empty()) throw std::runtime_error("URI SAN fixture must not be empty");
  std::string san;
  for (const auto& uri : uri_sans) {
    if (!san.empty()) san += ",";
    san += "URI:" + uri;
  }
  Pkey key = GenerateKey();
  X509Ptr cert = MakeCert(key.get(), uri_sans.front(), role, impl_->root_cert.get(),
                          impl_->root_key.get(), impl_->serial++, false, -60,
                          24 * 60 * 60, &san);
  auto identity = std::make_unique<EphemeralIdentity>();
  identity->registered.uri = uri_sans.front();
  identity->registered.role = role;
  identity->registered.leaf_der_sha256 = DigestDer(cert.get());
  identity->certificate_pem = CertPem(cert.get());
  identity->private_key_pem = KeyPem(key.get());
  impl_->identities.push_back(std::move(identity));
  return *impl_->identities.back();
}

}  // namespace rateguard::security::test
