#pragma once

// Pure v1 names and codecs for artifacts inside one supervisor runtime root:
// epoch-<id>/intent.json, optionally epoch-<id>/manifest-store/{owner.lock,
// manifest.json}. `intent.tmp` and `manifest.tmp` are transient artifacts and
// indicate an uncertain/incomplete recovery scan. No witness or journal names
// are recognized in v1. This header performs no filesystem access and grants
// no ownership/fencing authority.

#include "supervisor/epoch_gate.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace rateguard::supervisor::epoch_layout_v1 {

inline constexpr char kEpochDirectoryPrefix[] = "epoch-";
inline constexpr char kIntentFileName[] = "intent.json";
inline constexpr char kIntentTemporaryFileName[] = "intent.tmp";
inline constexpr char kManifestStoreDirectoryName[] = "manifest-store";
inline constexpr char kManifestStoreLockFileName[] = "owner.lock";
inline constexpr char kManifestFileName[] = "manifest.json";
inline constexpr char kManifestTemporaryFileName[] = "manifest.tmp";

enum class LayoutError : std::uint8_t {
  ZeroEpochId,
  AllocationFailure,
};

[[nodiscard]] inline bool IsZeroEpochId(const EpochId& id) noexcept {
  for (const auto byte : id) {
    if (byte != 0) return false;
  }
  return true;
}

[[nodiscard]] inline int HexNibble(char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

// Accepts exactly the shared BootstrapStore/BootstrapRecoveryReader grammar:
// `epoch-` followed by 32 lowercase hexadecimal digits, encoding nonzero ID.
[[nodiscard]] inline std::optional<EpochId> ParseEpochDirectoryName(
    std::string_view name) noexcept {
  constexpr std::size_t kPrefixLength = sizeof(kEpochDirectoryPrefix) - 1;
  constexpr std::size_t kCanonicalLength = kPrefixLength + 32;
  if (name.size() != kCanonicalLength ||
      name.substr(0, kPrefixLength) != kEpochDirectoryPrefix) {
    return std::nullopt;
  }

  EpochId epoch{};
  for (std::size_t i = 0; i < epoch.size(); ++i) {
    const int high = HexNibble(name[kPrefixLength + (2 * i)]);
    const int low = HexNibble(name[kPrefixLength + (2 * i) + 1]);
    if (high < 0 || low < 0) return std::nullopt;
    epoch[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  if (IsZeroEpochId(epoch)) return std::nullopt;
  return epoch;
}

[[nodiscard]] inline std::variant<std::string, LayoutError> FormatEpochDirectoryName(
    const EpochId& epoch) noexcept {
  if (IsZeroEpochId(epoch)) return LayoutError::ZeroEpochId;
  constexpr char kHex[] = "0123456789abcdef";
  constexpr std::size_t kPrefixLength = sizeof(kEpochDirectoryPrefix) - 1;
  constexpr std::size_t kCanonicalLength = kPrefixLength + 32;
  try {
    std::string name;
    name.reserve(kCanonicalLength);
    name.append(kEpochDirectoryPrefix, kPrefixLength);
    for (const auto byte : epoch) {
      name.push_back(kHex[(byte >> 4) & 0x0f]);
      name.push_back(kHex[byte & 0x0f]);
    }
    return name;
  } catch (...) {
    return LayoutError::AllocationFailure;
  }
}

}  // namespace rateguard::supervisor::epoch_layout_v1
