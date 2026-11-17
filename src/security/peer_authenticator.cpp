#include "rateguard/security/peer_authenticator.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <limits>
#include <memory>
#include <new>
#include <string_view>
#include <vector>

namespace rateguard::security {
namespace {

PeerAuthFailure Failure(PeerAuthFailureReason reason,
                        PeerAuthDisposition disposition) noexcept {
  return PeerAuthFailure{reason, disposition};
}

enum class DigestResult : std::uint8_t { Success, InvalidPem, CryptoFailure };

bool IsAsciiWhitespace(unsigned char c) noexcept {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

bool IsAscii(std::string_view value) noexcept {
  for (unsigned char c : value) {
    if (c > 0x7fU) return false;
  }
  return true;
}

bool HasOnlyWhitespaceRemainder(BIO* bio) noexcept {
  std::array<char, 256> bytes{};
  int count = 0;
  while ((count = BIO_read(bio, bytes.data(), static_cast<int>(bytes.size()))) > 0) {
    for (int i = 0; i < count; ++i) {
      if (!IsAsciiWhitespace(static_cast<unsigned char>(bytes[static_cast<std::size_t>(i)]))) {
        return false;
      }
    }
  }
  return count == 0;
}

DigestResult LeafPemDigest(std::string_view pem, Sha256Digest* digest) {
  if (digest == nullptr || pem.empty() ||
      pem.size() > CertificateRegistry::kMaxCertificatePemBytes ||
      pem.find('\0') != std::string_view::npos ||
      pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return DigestResult::InvalidPem;
  }

  constexpr std::string_view kBeginCertificate = "-----BEGIN CERTIFICATE-----";
  std::size_t first = 0;
  while (first < pem.size() && IsAsciiWhitespace(static_cast<unsigned char>(pem[first]))) {
    ++first;
  }
  if (pem.substr(first, kBeginCertificate.size()) != kBeginCertificate) {
    return DigestResult::InvalidPem;
  }

  const std::size_t length = pem.size() - first;
  BIO* raw_bio = BIO_new_mem_buf(pem.data() + first, static_cast<int>(length));
  if (raw_bio == nullptr) return DigestResult::CryptoFailure;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, &BIO_free);
  X509* raw_certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (raw_certificate == nullptr) return DigestResult::InvalidPem;
  std::unique_ptr<X509, decltype(&X509_free)> certificate(raw_certificate, &X509_free);
  if (!HasOnlyWhitespaceRemainder(bio.get())) return DigestResult::InvalidPem;

  const int der_size = i2d_X509(certificate.get(), nullptr);
  if (der_size <= 0) return DigestResult::CryptoFailure;
  if (der_size > static_cast<int>(CertificateRegistry::kMaxCertificatePemBytes)) {
    return DigestResult::InvalidPem;
  }
  std::vector<unsigned char> der(static_cast<std::size_t>(der_size));
  unsigned char* cursor = der.data();
  if (i2d_X509(certificate.get(), &cursor) != der_size) return DigestResult::CryptoFailure;

  unsigned int digest_size = 0;
  if (EVP_Digest(der.data(), der.size(), digest->data(), &digest_size,
                 EVP_sha256(), nullptr) != 1 || digest_size != digest->size()) {
    return DigestResult::CryptoFailure;
  }
  return DigestResult::Success;
}

template <typename T>
bool ExactlyOne(const std::vector<T>& values) noexcept {
  return values.size() == 1;
}

}  // namespace

std::variant<AuthenticatedPeer, PeerAuthFailure> PeerAuthenticator::Authenticate(
    const grpc::AuthContext& auth_context) const noexcept {
  try {
    if (!registry_) {
      return Failure(PeerAuthFailureReason::NullRegistry,
                     PeerAuthDisposition::ApplicationUnavailable);
    }
    if (!auth_context.IsPeerAuthenticated()) {
      return Failure(PeerAuthFailureReason::UnauthenticatedContext,
                     PeerAuthDisposition::Unauthenticated);
    }

    const auto transports = auth_context.FindPropertyValues(
        GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME);
    if (!ExactlyOne(transports)) {
      return Failure(PeerAuthFailureReason::MissingOrAmbiguousTransport,
                     PeerAuthDisposition::Unauthenticated);
    }
    if (transports.front().data() == nullptr) {
      return Failure(PeerAuthFailureReason::UnsupportedTransport,
                     PeerAuthDisposition::Unauthenticated);
    }
    const std::string_view transport(transports.front().data(), transports.front().size());
    if (transport != GRPC_TLS_TRANSPORT_SECURITY_TYPE) {
      return Failure(PeerAuthFailureReason::UnsupportedTransport,
                     PeerAuthDisposition::Unauthenticated);
    }

    const auto uris = auth_context.FindPropertyValues(GRPC_PEER_URI_PROPERTY_NAME);
    if (!ExactlyOne(uris)) {
      return Failure(PeerAuthFailureReason::MissingOrAmbiguousUri,
                     PeerAuthDisposition::Unauthenticated);
    }
    if (uris.front().data() == nullptr) {
      return Failure(PeerAuthFailureReason::InvalidUri,
                     PeerAuthDisposition::Unauthenticated);
    }
    const std::string_view uri(uris.front().data(), uris.front().size());
    if (uri.empty() || uri.size() > 256 || uri.find('\0') != std::string_view::npos ||
        !IsAscii(uri)) {
      return Failure(PeerAuthFailureReason::InvalidUri,
                     PeerAuthDisposition::Unauthenticated);
    }

    const auto leaves = auth_context.FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    if (!ExactlyOne(leaves)) {
      return Failure(PeerAuthFailureReason::MissingOrAmbiguousLeaf,
                     PeerAuthDisposition::Unauthenticated);
    }
    if (leaves.front().data() == nullptr) {
      return Failure(PeerAuthFailureReason::InvalidLeafPem,
                     PeerAuthDisposition::Unauthenticated);
    }
    const std::string_view leaf_pem(leaves.front().data(), leaves.front().size());
    if (leaf_pem.size() > CertificateRegistry::kMaxCertificatePemBytes) {
      return Failure(PeerAuthFailureReason::OversizedLeaf,
                     PeerAuthDisposition::Unauthenticated);
    }

    const RegisteredCertificate* registered = registry_->Find(uri);
    if (registered == nullptr) {
      return Failure(PeerAuthFailureReason::UnregisteredUri,
                     PeerAuthDisposition::Unauthenticated);
    }

    Sha256Digest presented_digest{};
    const auto digest_result = LeafPemDigest(leaf_pem, &presented_digest);
    if (digest_result == DigestResult::InvalidPem) {
      return Failure(PeerAuthFailureReason::InvalidLeafPem,
                     PeerAuthDisposition::Unauthenticated);
    }
    if (digest_result == DigestResult::CryptoFailure) {
      return Failure(PeerAuthFailureReason::CryptoFailure,
                     PeerAuthDisposition::ApplicationUnavailable);
    }
    if (presented_digest != registered->peer.leaf_der_sha256) {
      return Failure(PeerAuthFailureReason::LeafPinMismatch,
                     PeerAuthDisposition::Unauthenticated);
    }

    if (!trusted_clock_.Healthy()) {
      return Failure(PeerAuthFailureReason::ClockUntrusted,
                     PeerAuthDisposition::ApplicationUnavailable);
    }
    auto current_time = trusted_clock_.Now();
    const auto* now = std::get_if<WallTime>(&current_time);
    if (now == nullptr || !trusted_clock_.Healthy()) {
      return Failure(PeerAuthFailureReason::ClockUntrusted,
                     PeerAuthDisposition::ApplicationUnavailable);
    }
    if (now->unix_seconds < 0 || now->nanoseconds >= 1'000'000'000U) {
      return Failure(PeerAuthFailureReason::ClockUntrusted,
                     PeerAuthDisposition::ApplicationUnavailable);
    }
    if (!registry_->root_validity().Contains(*now) ||
        !registered->validity.Contains(*now)) {
      const auto& window = !registry_->root_validity().Contains(*now)
                               ? registry_->root_validity()
                               : registered->validity;
      const auto reason = *now < window.not_before
                              ? PeerAuthFailureReason::CertificateNotYetValid
                              : PeerAuthFailureReason::CertificateExpired;
      return Failure(reason, PeerAuthDisposition::Unauthenticated);
    }

    const AuthenticatedPeer authenticated(registry_, registered);
    return std::variant<AuthenticatedPeer, PeerAuthFailure>(
        std::in_place_index<0>, authenticated);
  } catch (const std::bad_alloc&) {
    return Failure(PeerAuthFailureReason::CryptoFailure,
                   PeerAuthDisposition::ApplicationUnavailable);
  } catch (...) {
    return Failure(PeerAuthFailureReason::CryptoFailure,
                   PeerAuthDisposition::ApplicationUnavailable);
  }
}

}  // namespace rateguard::security
