#pragma once

#include "policy_snapshot.h"

#include <array>
#include <cstdint>
#include <vector>

namespace rateguard::policy {

class CanonicalPolicyCodec final {
 public:
  [[nodiscard]] static Result<std::vector<std::uint8_t>> Encode(
      const PolicySnapshot& snapshot);
  [[nodiscard]] static Result<Digest32> Digest(
      const PolicySnapshot& snapshot);
};

}  // namespace rateguard::policy
