#pragma once

#include "rateguard/security/peer_identity.h"
#include "security/trusted_wall_clock.h"
#include "policy/canonical_codec.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace rateguard::security {

struct CertificateValidityWindow final {
  WallTime not_before;
  WallTime not_after;
  [[nodiscard]] bool Contains(WallTime time) const noexcept {
    if (time.unix_seconds < 0 || time.nanoseconds >= 1'000'000'000U) return false;
    return !(time < not_before) && time < not_after;
  }
};

struct RegisteredCertificate final {
  RegisteredPeer peer;
  CertificateValidityWindow validity;
};

enum class CertificateRegistryErrorCode : std::uint8_t {
  NullPolicy,
  ClockUntrusted,
  ResourceLimit,
  InvalidPem,
  InvalidRootProfile,
  RootFingerprintMismatch,
  LeafCountMismatch,
  DuplicateLeaf,
  UnknownPrincipal,
  MissingPrincipal,
  IdentityMismatch,
  InvalidLeafProfile,
  InvalidChain,
  CertificateNotYetValid,
  CertificateExpired,
  PolicyDigestFailure,
  CryptoFailure,
};

// Intentionally contains only a bounded code, never parser input or OpenSSL text.
struct CertificateRegistryError final {
  CertificateRegistryErrorCode code;
};

template <class T>
using CertificateRegistryResult = std::variant<T, CertificateRegistryError>;

class CertificateRegistry final {
 public:
  static constexpr std::size_t kMaxCertificatePemBytes = 64U * 1024U;
  static constexpr std::size_t kMaxAggregatePemBytes = 64U * 1024U * 1024U;
  static constexpr std::size_t kMaxPrincipalCount = 10'000;

  [[nodiscard]] const RegisteredCertificate* Find(
      std::string_view exact_uri) const noexcept;
  [[nodiscard]] const CertificateValidityWindow& root_validity() const noexcept {
    return root_validity_;
  }
  [[nodiscard]] const policy::Digest32& root_der_sha256() const noexcept {
    return root_der_sha256_;
  }
  [[nodiscard]] const policy::Digest32& policy_digest() const noexcept {
    return policy_digest_;
  }
  [[nodiscard]] const policy::Id16& epoch_id() const noexcept;
  [[nodiscard]] const policy::Id16& authority_incarnation() const noexcept;
  [[nodiscard]] const policy::PolicySnapshot& policy() const noexcept;
  [[nodiscard]] const std::vector<RegisteredCertificate>& peers() const noexcept {
    return peers_;
  }
  [[nodiscard]] std::shared_ptr<const PeerRegistry> peer_pins() const noexcept {
    return peer_pins_;
  }
  [[nodiscard]] WallTime validated_at() const noexcept { return validated_at_; }
  [[nodiscard]] bool AllValidAt(WallTime time) const noexcept;

 private:
  friend class CertificateRegistryLoader;
  CertificateRegistry(std::shared_ptr<const policy::PolicySnapshot> policy,
                      policy::Digest32 policy_digest,
                      policy::Digest32 root_der_sha256,
                      CertificateValidityWindow root_validity,
                      std::vector<RegisteredCertificate> peers,
                      std::shared_ptr<const PeerRegistry> peer_pins,
                      WallTime validated_at);

  std::shared_ptr<const policy::PolicySnapshot> policy_;
  policy::Digest32 policy_digest_{};
  policy::Digest32 root_der_sha256_{};
  CertificateValidityWindow root_validity_{};
  std::vector<RegisteredCertificate> peers_;
  std::shared_ptr<const PeerRegistry> peer_pins_;
  WallTime validated_at_{};
};

// Validates typed, already-owned public certificate material against the
// immutable policy. No manifest encoding, filesystem access, or private keys.
class CertificateRegistryLoader final {
 public:
  [[nodiscard]] static CertificateRegistryResult<
      std::shared_ptr<const CertificateRegistry>>
  Load(std::shared_ptr<const policy::PolicySnapshot> policy,
       std::string_view root_certificate_pem,
       std::span<const std::string_view> leaf_certificate_pems,
       ITrustedWallClock& trusted_clock);
};

}  // namespace rateguard::security
