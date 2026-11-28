#pragma once

// Read-only diagnostic scan of bootstrap artifacts under an existing,
// recovery-mode RuntimeOwner. The result is never a serving or fencing token.

#include "supervisor/bootstrap_inventory.h"
#include "supervisor/manifest_codec.h"
#include "supervisor/runtime_owner.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace rateguard::supervisor {

inline constexpr std::size_t kMaxRecoveryEpochDirectories = 1024;
inline constexpr std::size_t kMaxRecoveryRootEntries = 4096;
inline constexpr std::size_t kMaxRecoveryChildEntries = 16;
inline constexpr std::size_t kMaxRecoveryManifestStoreEntries = 16;
inline constexpr std::size_t kMaxRecoveryAggregateBytes = 64U * 1024U * 1024U;
inline constexpr std::size_t kMaxRecoveryAggregateParticipants = 16'384;
inline constexpr std::size_t kMaxRecoveryIssues = 256;
inline constexpr std::size_t kMaxRecoveryEpochIssues = 16;

struct RecoveryFileIdentity final {
  std::uint64_t device{};
  std::uint64_t inode{};
  std::uint64_t owner_id{};
  std::uint64_t link_count{};
  std::uint32_t mode{};
  std::uint64_t size{};
  std::int64_t mtime_seconds{};
  std::uint32_t mtime_nanoseconds{};
  std::int64_t ctime_seconds{};
  std::uint32_t ctime_nanoseconds{};
  friend bool operator==(const RecoveryFileIdentity&, const RecoveryFileIdentity&) = default;
};

enum class RecoveryIssueCode : std::uint8_t {
  RootEntryStatFailed,
  UnexpectedRootEntry,
  InvalidEpochDirectoryName,
  InvalidEpochDirectory,
  EpochDirectoryChanged,
  EpochHasUnexpectedEntry,
  TooManyChildEntries,
  MissingIntent,
  InvalidIntentFile,
  IntentReadFailed,
  IntentChanged,
  IntentTooLarge,
  AggregateByteLimit,
  AggregateParticipantLimit,
  InvalidEncoding,
  DigestFailure,
  DigestMismatch,
  DomainMismatch,
  EpochMismatch,
  IdentityCollisionAcrossEpochs,
  RecoveryAlreadyLatched,
  EmptyRoot,
  NoValidIntents,
  TooManyRootEntries,
  TooManyEpochDirectories,
  RootEnumerationFailed,
  RootChangedDuringScan,
  OwnerChangedDuringScan,
  ResourceLimit,
  InvalidManifestStoreDirectory,
  ManifestStoreChanged,
  ManifestStoreHasUnexpectedEntry,
  TooManyManifestStoreEntries,
  MissingManifestStoreFile,
  InvalidManifestStoreFile,
  ManifestStoreReadFailed,
  ManifestStoreFileChanged,
  ManifestStoreFileTooLarge,
  InvalidManifestEncoding,
  ManifestCodecDigestMismatch,
  ManifestCandidateMismatch,
  ManifestBootstrapNotReady,
};

struct RecoveryEpochDiagnostic final {
  // Canonical `epoch-<32 lowercase hex>` form only; never an arbitrary name.
  std::string directory_name;
  RecoveryFileIdentity directory_identity{};
  std::optional<RecoveryFileIdentity> intent_identity;
  std::shared_ptr<const BootstrapInventory> inventory;
  std::optional<std::array<std::uint8_t, 32>> canonical_digest;
  // Present only when the optional `manifest-store` child existed and was
  // inspected. A decoded manifest is diagnostic data, never an activation,
  // stop, reset, or successor-epoch authorization.
  struct ManifestDiagnostic final {
    RecoveryFileIdentity directory_identity{};
    std::optional<RecoveryFileIdentity> owner_lock_identity;
    std::optional<RecoveryFileIdentity> manifest_identity;
    std::shared_ptr<const ManifestV1> decoded_manifest;
    std::optional<std::array<std::uint8_t, 32>> canonical_digest;
  };
  std::optional<ManifestDiagnostic> manifest_store;
  std::vector<RecoveryIssueCode> issues;
  bool issues_truncated{};
};

struct RecoveryIssue final {
  RecoveryIssueCode code{};
  // Index into snapshot.epochs for an epoch-local issue; absent for root scope.
  // Raw arbitrary filesystem names are deliberately never returned.
  std::optional<std::size_t> epoch_index;
};

struct BootstrapRecoverySnapshot final {
  RuntimeDomainId domain_id{};
  // Diagnostic structural result only. False for unknown/temp entries,
  // recovery-latched or colliding inventories, mutation, or resource limits.
  // True never proves prior fsync, process exit, or permission to serve/reset.
  // This is a bounded scan, not an atomic cross-epoch snapshot or protection
  // against hostile same-UID mutation; each known inventory is independently
  // decoded and retains its historical clock provenance without current-time
  // comparison.
  bool scan_complete{};
  std::vector<RecoveryEpochDiagnostic> epochs;
  std::vector<RecoveryIssue> issues;
  bool issues_truncated{};
};

enum class RecoveryReaderFatal : std::uint8_t {
  OwnerNotRecoveryMode,
  OwnerInvalid,
  RootDescriptorUnavailable,
  AllocationFailure,
};

using BootstrapRecoveryReadResult =
    std::variant<std::shared_ptr<const BootstrapRecoverySnapshot>, RecoveryReaderFatal>;

enum class RecoveryReaderIoPoint : std::uint8_t {
  ValidateOwnerBefore,
  DuplicateRoot,
  EnumerateRootFirst,
  EnumerateRootSecond,
  StatRootEntry,
  OpenEpochDirectory,
  EnumerateEpoch,
  StatIntent,
  OpenIntent,
  ReadIntent,
  RevalidateEntry,
  ValidateOwnerAfter,
  OpenManifestStoreDirectory,
  EnumerateManifestStore,
  StatManifestStoreEntry,
  OpenManifestLock,
  RevalidateManifestLock,
  OpenManifestFile,
  ReadManifestFile,
  RevalidateManifestFile,
  RevalidateManifestStore,
};

class IRecoveryReaderIo {
 public:
  virtual ~IRecoveryReaderIo() = default;
  // Test hook only; it must outlive the read call. Failure is fail-closed.
  [[nodiscard]] virtual bool FailAt(RecoveryReaderIoPoint point) noexcept = 0;
};

class BootstrapRecoveryReader final {
 public:
  [[nodiscard]] static BootstrapRecoveryReadResult Read(
      const RuntimeOwner& owner, IRecoveryReaderIo* test_io = nullptr) noexcept;
};

}  // namespace rateguard::supervisor
