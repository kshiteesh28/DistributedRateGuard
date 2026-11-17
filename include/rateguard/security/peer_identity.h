#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rateguard::security {

enum class PeerRole : std::uint32_t { kAdapter = 1, kReplica = 2, kAuthority = 3 };
using Sha256Digest = std::array<std::uint8_t, 32>;

struct RegisteredPeer final {
  std::string uri;
  PeerRole role;
  Sha256Digest leaf_der_sha256;
};

// Construct only from an already validated, immutable epoch manifest. URI
// values are exact byte strings; this class performs no URI normalization.
class PeerRegistry final {
 public:
  explicit PeerRegistry(std::vector<RegisteredPeer> records);
  const RegisteredPeer* Find(std::string_view exact_uri) const noexcept;
  bool valid() const noexcept { return valid_; }

 private:
  std::map<std::string, RegisteredPeer, std::less<>> records_;
  bool valid_ = true;
};

struct ExpectedPeer final {
  std::string exact_uri;
  Sha256Digest leaf_der_sha256;
  PeerRole role;
};

}  // namespace rateguard::security
