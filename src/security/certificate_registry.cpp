#include "rateguard/security/certificate_registry.h"

#include "policy/policy_loader.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <set>
#include <string>
#include <utility>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace rateguard::security {
namespace {

using ErrorCode = CertificateRegistryErrorCode;
using Error = CertificateRegistryError;
using PolicyRole = policy::PrincipalRole;

template <typename T, void (*Free)(T*)>
using OsslPtr = std::unique_ptr<T, decltype(Free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = OsslPtr<X509, X509_free>;
using StorePtr = OsslPtr<X509_STORE, X509_STORE_free>;
using StoreContextPtr = OsslPtr<X509_STORE_CTX, X509_STORE_CTX_free>;
using PublicKeyPtr = OsslPtr<EVP_PKEY, EVP_PKEY_free>;
using BasicConstraintsPtr = OsslPtr<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free>;
using KeyUsagePtr = OsslPtr<ASN1_BIT_STRING, ASN1_BIT_STRING_free>;
using ExtendedUsagePtr = OsslPtr<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free>;
using GeneralNamesPtr = OsslPtr<GENERAL_NAMES, GENERAL_NAMES_free>;

template <typename T>
using InternalResult = std::variant<T, ErrorCode>;

bool IsAsciiWhitespace(unsigned char c) noexcept {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

bool IsDigit(unsigned char c) noexcept { return c >= '0' && c <= '9'; }

bool DecodeSingleCertificatePem(std::string_view pem, X509Ptr* out) {
  constexpr std::string_view kBegin = "-----BEGIN CERTIFICATE-----";
  if (out == nullptr || pem.empty() || pem.size() > CertificateRegistry::kMaxCertificatePemBytes ||
      pem.find('\0') != std::string_view::npos) return false;
  std::size_t first = 0;
  while (first < pem.size() && IsAsciiWhitespace(static_cast<unsigned char>(pem[first]))) ++first;
  if (pem.substr(first, kBegin.size()) != kBegin) return false;

  BIO* raw_bio = BIO_new_mem_buf(pem.data() + first, static_cast<int>(pem.size() - first));
  if (raw_bio == nullptr) return false;
  BioPtr bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (raw_cert == nullptr) return false;
  X509Ptr cert(raw_cert, X509_free);
  char trailing[512];
  for (;;) {
    const int count = BIO_read(bio.get(), trailing, sizeof(trailing));
    if (count < 0) return false;
    if (count == 0) break;
    for (int i = 0; i < count; ++i)
      if (!IsAsciiWhitespace(static_cast<unsigned char>(trailing[i]))) return false;
  }
  *out = std::move(cert);
  return true;
}

template <typename T, void (*Free)(T*)>
bool HasExactlyOneExtension(X509* cert, int nid,
                            std::unique_ptr<T, decltype(Free)>* extension) {
  const int index = X509_get_ext_by_NID(cert, nid, -1);
  if (index < 0 || X509_get_ext_by_NID(cert, nid, index) >= 0) return false;
  int critical = -1;
  T* raw = static_cast<T*>(X509_get_ext_d2i(cert, nid, &critical, nullptr));
  if (raw == nullptr || critical == -2) {
    if (raw != nullptr) Free(raw);
    return false;
  }
  extension->reset(raw);
  return true;
}

bool HasExpectedEku(X509* cert, PolicyRole role) {
  ExtendedUsagePtr usage(nullptr, EXTENDED_KEY_USAGE_free);
  if (!HasExactlyOneExtension<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free>(
          cert, NID_ext_key_usage, &usage)) return false;
  const int count = sk_ASN1_OBJECT_num(usage.get());
  int expected_client = 0;
  int expected_server = 0;
  switch (role) {
    case PolicyRole::Adapter: expected_client = 1; break;
    case PolicyRole::Replica: expected_client = 1; expected_server = 1; break;
    case PolicyRole::Authority: expected_server = 1; break;
    default: return false;
  }
  if (count != expected_client + expected_server) return false;
  int clients = 0;
  int servers = 0;
  for (int i = 0; i < count; ++i) {
    const int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(usage.get(), i));
    if (nid == NID_client_auth) ++clients;
    else if (nid == NID_server_auth) ++servers;
    else return false;  // Reject anyExtendedKeyUsage and every extra purpose.
  }
  return clients == expected_client && servers == expected_server;
}

bool HasExpectedKeyUsage(X509* cert, bool root) {
  KeyUsagePtr usage(nullptr, ASN1_BIT_STRING_free);
  if (!HasExactlyOneExtension<ASN1_BIT_STRING, ASN1_BIT_STRING_free>(
          cert, NID_key_usage, &usage)) return false;
  if (root) {
    return ASN1_BIT_STRING_get_bit(usage.get(), 5) == 1;
  }
  return ASN1_BIT_STRING_get_bit(usage.get(), 0) == 1 &&
         ASN1_BIT_STRING_get_bit(usage.get(), 5) == 0;
}

bool HasExpectedBasicConstraints(X509* cert, bool root) {
  BasicConstraintsPtr constraints(nullptr, BASIC_CONSTRAINTS_free);
  if (!HasExactlyOneExtension<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free>(
          cert, NID_basic_constraints, &constraints)) return false;
  if (root) {
    if (constraints->ca == 0 || constraints->pathlen == nullptr) return false;
    std::int64_t path_length = -1;
    return ASN1_INTEGER_get_int64(&path_length, constraints->pathlen) == 1 &&
           path_length == 0;
  }
  return constraints->ca == 0 && constraints->pathlen == nullptr;
}

bool HasP256Sha256Profile(X509* cert) {
  if (X509_get_signature_nid(cert) != NID_ecdsa_with_SHA256) return false;
  PublicKeyPtr key(X509_get_pubkey(cert), EVP_PKEY_free);
  if (!key || EVP_PKEY_is_a(key.get(), "EC") != 1) return false;
  std::array<char, 80> group{};
  std::size_t group_size = 0;
  if (EVP_PKEY_get_utf8_string_param(key.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                     group.data(), group.size(), &group_size) != 1)
    return false;
  const std::string_view name(group.data(), group_size);
  return name == "prime256v1" || name == "secp256r1";
}

bool ParseCertificateTime(const ASN1_TIME* value, WallTime* out) {
  if (value == nullptr || out == nullptr || ASN1_TIME_check(value) != 1) return false;
  const int type = ASN1_STRING_type(value);
  const int length = ASN1_STRING_length(value);
  const unsigned char* data = ASN1_STRING_get0_data(value);
  const int digits = type == V_ASN1_UTCTIME ? 12 :
                     type == V_ASN1_GENERALIZEDTIME ? 14 : -1;
  if (digits < 0 || length != digits + 1 || data == nullptr || data[digits] != 'Z')
    return false;
  for (int i = 0; i < digits; ++i)
    if (!IsDigit(data[i])) return false;

  std::tm fields{};
  if (ASN1_TIME_to_tm(value, &fields) != 1) return false;
  const int full_year = fields.tm_year + 1900;
  // RFC 5280 requires UTCTime through 2049 and GeneralizedTime from 2050.
  if ((type == V_ASN1_UTCTIME && (full_year < 1950 || full_year > 2049)) ||
      (type == V_ASN1_GENERALIZEDTIME && (full_year < 2050 || full_year > 9999)))
    return false;
  const std::chrono::year_month_day date{
      std::chrono::year{full_year},
      std::chrono::month{static_cast<unsigned>(fields.tm_mon + 1)},
      std::chrono::day{static_cast<unsigned>(fields.tm_mday)}};
  if (!date.ok() || fields.tm_hour < 0 || fields.tm_hour > 23 ||
      fields.tm_min < 0 || fields.tm_min > 59 ||
      fields.tm_sec < 0 || fields.tm_sec > 59) return false;
  const auto days = std::chrono::sys_days{date}.time_since_epoch().count();
  constexpr std::int64_t kSecondsPerDay = 86'400;
  // ASN.1 years are bounded to 0000..9999, so this checked multiplication is
  // far below int64 limits; keep the check explicit to avoid future narrowing.
  if (days > std::numeric_limits<std::int64_t>::max() / kSecondsPerDay ||
      days < std::numeric_limits<std::int64_t>::min() / kSecondsPerDay) return false;
  const std::int64_t day_seconds = days * kSecondsPerDay;
  const std::int64_t second_of_day = fields.tm_hour * 3600LL + fields.tm_min * 60LL + fields.tm_sec;
  if (day_seconds > std::numeric_limits<std::int64_t>::max() - second_of_day) return false;
  *out = WallTime{day_seconds + second_of_day, 0};
  return true;
}

InternalResult<CertificateValidityWindow> GetValidity(
    X509* cert, WallTime now, ErrorCode invalid_time_code) {
  CertificateValidityWindow window{};
  if (!ParseCertificateTime(X509_get0_notBefore(cert), &window.not_before) ||
      !ParseCertificateTime(X509_get0_notAfter(cert), &window.not_after) ||
      !(window.not_before < window.not_after)) return invalid_time_code;
  if (now < window.not_before) return ErrorCode::CertificateNotYetValid;
  if (!(now < window.not_after)) return ErrorCode::CertificateExpired;
  return window;
}

bool GetDerAndDigest(X509* cert, std::vector<std::uint8_t>* der,
                     policy::Digest32* digest) {
  if (der == nullptr || digest == nullptr) return false;
  const int size = i2d_X509(cert, nullptr);
  if (size <= 0 || static_cast<std::size_t>(size) > CertificateRegistry::kMaxCertificatePemBytes)
    return false;
  der->resize(static_cast<std::size_t>(size));
  unsigned char* cursor = der->data();
  if (i2d_X509(cert, &cursor) != size) return false;
  unsigned int digest_size = 0;
  return EVP_Digest(der->data(), der->size(), digest->data(), &digest_size,
                    EVP_sha256(), nullptr) == 1 && digest_size == digest->size();
}

bool VerifyLeafPurpose(X509* leaf, X509* root, WallTime now, int purpose) {
  PublicKeyPtr root_key(X509_get_pubkey(root), EVP_PKEY_free);
  if (!root_key || X509_NAME_cmp(X509_get_issuer_name(leaf),
                                 X509_get_subject_name(root)) != 0 ||
      X509_verify(leaf, root_key.get()) != 1) return false;
  StorePtr store(X509_STORE_new(), X509_STORE_free);
  if (!store || X509_STORE_add_cert(store.get(), root) != 1 ||
      X509_STORE_set_flags(store.get(), X509_V_FLAG_X509_STRICT) != 1) return false;
  StoreContextPtr context(X509_STORE_CTX_new(), X509_STORE_CTX_free);
  if (!context || X509_STORE_CTX_init(context.get(), store.get(), leaf, nullptr) != 1)
    return false;
  X509_VERIFY_PARAM* params = X509_STORE_CTX_get0_param(context.get());
  if (params == nullptr || X509_VERIFY_PARAM_set_flags(params, X509_V_FLAG_X509_STRICT) != 1)
    return false;
  if constexpr (std::numeric_limits<time_t>::is_signed) {
    if (now.unix_seconds < static_cast<std::int64_t>(std::numeric_limits<time_t>::min()) ||
        now.unix_seconds > static_cast<std::int64_t>(std::numeric_limits<time_t>::max())) return false;
  } else {
    if (now.unix_seconds < 0 ||
        static_cast<std::uint64_t>(now.unix_seconds) > std::numeric_limits<time_t>::max()) return false;
  }
  X509_VERIFY_PARAM_set_time(params, static_cast<time_t>(now.unix_seconds));
  if (X509_STORE_CTX_set_purpose(context.get(), purpose) != 1) return false;
  return X509_verify_cert(context.get()) == 1;
}

bool VerifyRootSelfSignature(X509* root) {
  if (X509_NAME_cmp(X509_get_subject_name(root), X509_get_issuer_name(root)) != 0)
    return false;
  PublicKeyPtr root_key(X509_get_pubkey(root), EVP_PKEY_free);
  return root_key && X509_verify(root, root_key.get()) == 1;
}

PeerRole ToPeerRole(PolicyRole role) {
  switch (role) {
    case PolicyRole::Adapter: return PeerRole::kAdapter;
    case PolicyRole::Replica: return PeerRole::kReplica;
    case PolicyRole::Authority: return PeerRole::kAuthority;
  }
  return static_cast<PeerRole>(0);
}

int PurposeFor(PolicyRole role) {
  return role == PolicyRole::Authority ? X509_PURPOSE_SSL_SERVER
                                       : X509_PURPOSE_SSL_CLIENT;
}

}  // namespace

CertificateRegistry::CertificateRegistry(
    std::shared_ptr<const policy::PolicySnapshot> policy,
    policy::Digest32 policy_digest, policy::Digest32 root_der_sha256,
    CertificateValidityWindow root_validity,
    std::vector<RegisteredCertificate> peers,
    std::shared_ptr<const PeerRegistry> peer_pins, WallTime validated_at)
    : policy_(std::move(policy)), policy_digest_(policy_digest),
      root_der_sha256_(root_der_sha256), root_validity_(root_validity),
      peers_(std::move(peers)), peer_pins_(std::move(peer_pins)),
      validated_at_(validated_at) {}

const RegisteredCertificate* CertificateRegistry::Find(
    std::string_view exact_uri) const noexcept {
  const auto found = std::lower_bound(peers_.begin(), peers_.end(), exact_uri,
      [](const RegisteredCertificate& peer, std::string_view uri) {
        return std::string_view(peer.peer.uri) < uri;
      });
  return found != peers_.end() && std::string_view(found->peer.uri) == exact_uri
             ? &*found : nullptr;
}

const policy::Id16& CertificateRegistry::epoch_id() const noexcept {
  return policy_->epoch_id();
}
const policy::Id16& CertificateRegistry::authority_incarnation() const noexcept {
  return policy_->authority_incarnation();
}
const policy::PolicySnapshot& CertificateRegistry::policy() const noexcept {
  return *policy_;
}
bool CertificateRegistry::AllValidAt(WallTime time) const noexcept {
  if (time.unix_seconds < 0 || time.nanoseconds >= 1'000'000'000U ||
      !root_validity_.Contains(time)) return false;
  return std::all_of(peers_.begin(), peers_.end(),
                     [time](const auto& peer) { return peer.validity.Contains(time); });
}

CertificateRegistryResult<std::shared_ptr<const CertificateRegistry>>
CertificateRegistryLoader::Load(
    std::shared_ptr<const policy::PolicySnapshot> snapshot,
    std::string_view root_certificate_pem,
    std::span<const std::string_view> leaf_certificate_pems,
    ITrustedWallClock& trusted_clock) try {
  if (!snapshot) return Error{ErrorCode::NullPolicy};
  if (root_certificate_pem.size() > CertificateRegistry::kMaxCertificatePemBytes ||
      leaf_certificate_pems.size() > policy::PolicyLoader::kMaxPrincipals)
    return Error{ErrorCode::ResourceLimit};
  std::size_t total_bytes = root_certificate_pem.size();
  for (const auto pem : leaf_certificate_pems) {
    if (pem.size() > CertificateRegistry::kMaxCertificatePemBytes ||
        pem.size() > CertificateRegistry::kMaxAggregatePemBytes - total_bytes)
      return Error{ErrorCode::ResourceLimit};
    total_bytes += pem.size();
  }
  if (total_bytes > CertificateRegistry::kMaxAggregatePemBytes)
    return Error{ErrorCode::ResourceLimit};
  if (leaf_certificate_pems.size() != snapshot->principals().size() ||
      leaf_certificate_pems.size() > CertificateRegistry::kMaxPrincipalCount)
    return Error{ErrorCode::LeafCountMismatch};

  auto now_result = trusted_clock.Now();
  const auto* now = std::get_if<WallTime>(&now_result);
  if (now == nullptr || !trusted_clock.Healthy() || now->unix_seconds < 0 ||
      now->nanoseconds >= 1'000'000'000U)
    return Error{ErrorCode::ClockUntrusted};
  const WallTime validated_at = *now;

  auto digest_result = policy::CanonicalPolicyCodec::Digest(*snapshot);
  const auto* policy_digest = std::get_if<policy::Digest32>(&digest_result);
  if (policy_digest == nullptr) {
    const auto& error = std::get<policy::PolicyError>(digest_result);
    if (error.code == policy::PolicyErrorCode::ResourceLimit)
      return Error{ErrorCode::ResourceLimit};
    if (error.code == policy::PolicyErrorCode::CryptoFailure)
      return Error{ErrorCode::CryptoFailure};
    return Error{ErrorCode::PolicyDigestFailure};
  }

  X509Ptr root(nullptr, X509_free);
  if (!DecodeSingleCertificatePem(root_certificate_pem, &root))
    return Error{ErrorCode::InvalidPem};
  if (!HasP256Sha256Profile(root.get()) || !HasExpectedBasicConstraints(root.get(), true) ||
      !HasExpectedKeyUsage(root.get(), true) || X509_check_ca(root.get()) <= 0 ||
      !VerifyRootSelfSignature(root.get()))
    return Error{ErrorCode::InvalidRootProfile};

  std::vector<std::uint8_t> root_der;
  policy::Digest32 root_digest{};
  if (!GetDerAndDigest(root.get(), &root_der, &root_digest))
    return Error{ErrorCode::CryptoFailure};
  if (root_digest != snapshot->trust_root_sha256())
    return Error{ErrorCode::RootFingerprintMismatch};
  auto root_validity_result = GetValidity(root.get(), validated_at,
                                           ErrorCode::InvalidRootProfile);
  if (const auto* error = std::get_if<ErrorCode>(&root_validity_result))
    return Error{*error};
  const auto root_validity = std::get<CertificateValidityWindow>(root_validity_result);

  std::vector<RegisteredCertificate> registered;
  std::vector<RegisteredPeer> pins;
  registered.reserve(leaf_certificate_pems.size());
  pins.reserve(leaf_certificate_pems.size());
  std::set<std::string, std::less<>> seen;
  for (const auto pem : leaf_certificate_pems) {
    X509Ptr leaf(nullptr, X509_free);
    if (!DecodeSingleCertificatePem(pem, &leaf)) return Error{ErrorCode::InvalidPem};
    GeneralNamesPtr names(nullptr, GENERAL_NAMES_free);
    if (!HasExactlyOneExtension<GENERAL_NAMES, GENERAL_NAMES_free>(
            leaf.get(), NID_subject_alt_name, &names))
      return Error{ErrorCode::IdentityMismatch};
    std::string uri;
    std::size_t uri_count = 0;
    const int general_name_count = sk_GENERAL_NAME_num(names.get());
    for (int i = 0; i < general_name_count; ++i) {
      const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), i);
      if (name == nullptr || name->type != GEN_URI) continue;
      ++uri_count;
      const ASN1_IA5STRING* value = name->d.uniformResourceIdentifier;
      const int length = ASN1_STRING_length(value);
      const unsigned char* data = ASN1_STRING_get0_data(value);
      if (length <= 0 || length > 256 || data == nullptr ||
          std::memchr(data, '\0', static_cast<std::size_t>(length)) != nullptr)
        return Error{ErrorCode::IdentityMismatch};
      uri.assign(reinterpret_cast<const char*>(data), static_cast<std::size_t>(length));
      for (unsigned char c : uri) if (c > 0x7f) return Error{ErrorCode::IdentityMismatch};
    }
    if (uri_count != 1) return Error{ErrorCode::IdentityMismatch};
    const policy::Principal* principal = snapshot->FindPrincipal(uri);
    if (principal == nullptr) return Error{ErrorCode::UnknownPrincipal};
    if (!seen.insert(uri).second) return Error{ErrorCode::DuplicateLeaf};

    if (!HasP256Sha256Profile(leaf.get()) ||
        !HasExpectedBasicConstraints(leaf.get(), false) ||
        !HasExpectedKeyUsage(leaf.get(), false) || !HasExpectedEku(leaf.get(), principal->role) ||
        X509_check_ca(leaf.get()) != 0)
      return Error{ErrorCode::InvalidLeafProfile};
    auto validity_result = GetValidity(leaf.get(), validated_at,
                                        ErrorCode::InvalidLeafProfile);
    if (const auto* error = std::get_if<ErrorCode>(&validity_result)) return Error{*error};
    if (!VerifyLeafPurpose(leaf.get(), root.get(), validated_at,
                           PurposeFor(principal->role)))
      return Error{ErrorCode::InvalidChain};
    if (principal->role == PolicyRole::Replica &&
        !VerifyLeafPurpose(leaf.get(), root.get(), validated_at, X509_PURPOSE_SSL_SERVER))
      return Error{ErrorCode::InvalidChain};
    std::vector<std::uint8_t> leaf_der;
    policy::Digest32 leaf_digest{};
    if (!GetDerAndDigest(leaf.get(), &leaf_der, &leaf_digest))
      return Error{ErrorCode::CryptoFailure};
    RegisteredPeer peer_pin{uri, ToPeerRole(principal->role), leaf_digest};
    RegisteredCertificate certificate{peer_pin,
        std::get<CertificateValidityWindow>(validity_result)};
    pins.push_back(std::move(peer_pin));
    registered.push_back(std::move(certificate));
  }
  if (seen.size() != snapshot->principals().size()) return Error{ErrorCode::MissingPrincipal};
  std::sort(registered.begin(), registered.end(), [](const auto& a, const auto& b) {
    return a.peer.uri < b.peer.uri;
  });
  auto pin_registry = std::make_shared<const PeerRegistry>(std::move(pins));
  if (!pin_registry->valid()) return Error{ErrorCode::DuplicateLeaf};
  return std::shared_ptr<const CertificateRegistry>(new CertificateRegistry(
      std::move(snapshot), *policy_digest, root_digest, root_validity,
      std::move(registered), std::move(pin_registry), validated_at));
} catch (const std::bad_alloc&) {
  return Error{ErrorCode::ResourceLimit};
} catch (const std::exception&) {
  return Error{ErrorCode::CryptoFailure};
} catch (...) {
  return Error{ErrorCode::CryptoFailure};
}

}  // namespace rateguard::security
