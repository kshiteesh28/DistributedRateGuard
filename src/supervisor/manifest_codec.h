#pragma once

// Strict, bounded codec for the supervisor's version-1 epoch manifest.
// A valid digest detects accidental modification; it does not authenticate a
// writer or prove that an older valid manifest was not rolled back.

#include "supervisor/epoch_gate.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

namespace rateguard::supervisor {

inline constexpr std::size_t kMaxManifestBytes = 4U * 1024U * 1024U;

enum class ManifestPhase : std::uint8_t { Prepared = 1, Active = 2, Draining = 3, Closed = 4 };
enum class ManifestCodecError : std::uint8_t {
  InvalidValue,
  TooLarge,
  InvalidJson,
  DuplicateKey,
  UnknownKey,
  MissingKey,
  UnsupportedSchema,
  NonCanonical,
  DigestMismatch,
  DigestFailure,
  AllocationFailure,
};

struct ManifestV1 {
  EpochCandidate candidate;
  ManifestPhase phase{ManifestPhase::Prepared};
  std::uint64_t generation{1};
  OperationId transition_operation_id{};
};

using ManifestEncodeResult = std::variant<std::string, ManifestCodecError>;
using ManifestDecodeResult = std::variant<ManifestV1, ManifestCodecError>;
using ManifestDigestResult = std::variant<std::array<std::uint8_t, 32>, ManifestCodecError>;

// The payload is canonical compact JSON with sorted object keys. The envelope
// contains exactly {"manifest": payload, "sha256": lowercase_hex_digest};
// SHA-256 covers the compact canonical payload bytes only.
[[nodiscard]] ManifestEncodeResult EncodeManifestV1(const ManifestV1& manifest) noexcept;
[[nodiscard]] ManifestDecodeResult DecodeManifestV1(std::string_view envelope) noexcept;
[[nodiscard]] ManifestDigestResult ManifestDigestV1(const ManifestV1& manifest) noexcept;

}  // namespace rateguard::supervisor
