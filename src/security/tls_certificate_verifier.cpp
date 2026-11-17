#include "rateguard/security/tls_certificate_verifier.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace rateguard::security {
namespace {

grpc::Status Reject(const char* why) {
  return {grpc::StatusCode::UNAUTHENTICATED, why};
}

bool LeafDigest(std::string_view pem, Sha256Digest* out) {
  if (pem.empty() || pem.size() > 64 * 1024 || out == nullptr) return false;
  BIO* raw_bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (raw_bio == nullptr) return false;
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(raw_bio, BIO_free);
  X509* raw_cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (raw_cert == nullptr) return false;
  std::unique_ptr<X509, decltype(&X509_free)> cert(raw_cert, X509_free);
  char trailing[256];
  for (;;) {
    const int n = BIO_read(bio.get(), trailing, sizeof(trailing));
    if (n <= 0) break;
    for (int i = 0; i < n; ++i) {
      const unsigned char c = static_cast<unsigned char>(trailing[i]);
      if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return false;
    }
  }
  const int der_size = i2d_X509(cert.get(), nullptr);
  if (der_size <= 0 || der_size > 64 * 1024) return false;
  std::string der(static_cast<std::size_t>(der_size), '\0');
  unsigned char* cursor = reinterpret_cast<unsigned char*>(der.data());
  if (i2d_X509(cert.get(), &cursor) != der_size) return false;
  unsigned int digest_size = 0;
  return EVP_Digest(der.data(), der.size(), out->data(), &digest_size,
                    EVP_sha256(), nullptr) == 1 && digest_size == out->size();
}

bool HasNul(grpc::string_ref value) {
  return std::memchr(value.data(), '\0', value.size()) != nullptr;
}

}  // namespace

PeerRegistry::PeerRegistry(std::vector<RegisteredPeer> records) {
  if (records.empty() || records.size() > 10000) { valid_ = false; return; }
  for (auto& record : records) {
    const bool valid_role = record.role == PeerRole::kAdapter ||
                            record.role == PeerRole::kReplica ||
                            record.role == PeerRole::kAuthority;
    if (record.uri.empty() || record.uri.size() > 256 ||
        record.uri.find('\0') != std::string::npos || !valid_role ||
        !records_.emplace(record.uri, record).second) {
      valid_ = false;
      records_.clear();
      return;
    }
  }
}

const RegisteredPeer* PeerRegistry::Find(std::string_view exact_uri) const noexcept {
  auto it = records_.find(exact_uri);
  return it == records_.end() ? nullptr : &it->second;
}

PinnedPeerVerifier::PinnedPeerVerifier(std::shared_ptr<const PeerRegistry> registry,
                                       std::optional<ExpectedPeer> expected)
    : registry_(std::move(registry)), expected_(std::move(expected)) {}

bool PinnedPeerVerifier::Verify(
    grpc::experimental::TlsCustomVerificationCheckRequest* request,
    std::function<void(grpc::Status)>, grpc::Status* sync_status) {
  if (sync_status == nullptr) std::abort();
  *sync_status = Reject("peer certificate identity rejected");
  if (request == nullptr || !registry_ || !registry_->valid()) return true;
  const auto uris = request->uri_names();
  if (uris.size() != 1 || uris[0].empty() || HasNul(uris[0])) return true;
  const std::string_view uri(uris[0].data(), uris[0].size());
  const RegisteredPeer* record = registry_->Find(uri);
  if (record == nullptr) return true;
  Sha256Digest digest{};
  const auto pem = request->peer_cert();
  if (!LeafDigest(std::string_view(pem.data(), pem.size()), &digest)) return true;
  if (expected_) {
    if (uri != expected_->exact_uri || digest != expected_->leaf_der_sha256 ||
        record->role != expected_->role ||
        record->leaf_der_sha256 != expected_->leaf_der_sha256) return true;
  } else if (digest != record->leaf_der_sha256) {
    return true;
  }
  *sync_status = grpc::Status::OK;
  return true;
}

}  // namespace rateguard::security
