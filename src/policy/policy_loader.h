#pragma once

#include "policy_snapshot.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace rateguard::policy {

class PolicyLoader final {
 public:
  static constexpr std::size_t kMaxJsonBytes = 64U * 1024U * 1024U;
  static constexpr std::size_t kMaxCanonicalBytes = 64U * 1024U * 1024U;
  static constexpr std::size_t kMaxJsonDepth = 32;
  static constexpr std::size_t kMaxTenants = 10'000;
  static constexpr std::size_t kMaxSlots = 8;
  static constexpr std::size_t kMaxOperationsPerTenant = 64;
  static constexpr std::size_t kMaxOperationsTotal = 100'000;
  static constexpr std::size_t kMaxPrincipals = 10'000;
  static constexpr std::size_t kMaxPermissionPairs = 100'000;
  static constexpr std::size_t kMaxIdentifierBytes = 128;
  static constexpr std::size_t kMaxPrincipalUriBytes = 256;

  [[nodiscard]] static Result<std::shared_ptr<const PolicySnapshot>> Load(
      std::string_view json);
};

}  // namespace rateguard::policy
