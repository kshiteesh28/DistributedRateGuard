#pragma once

// POSIX durable store for one immutable epoch manifest. Directory locking is
// local to this path; it is not global supervisor ownership or epoch fencing.

#include "supervisor/manifest_codec.h"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <variant>

namespace rateguard::supervisor {

enum class ManifestIoPoint : std::uint8_t {
  Mkdir,
  SyncParentDirectory,
  OpenDirectory,
  ValidateDirectory,
  CreateLock,
  OpenLock,
  AcquireLock,
  SyncLock,
  CheckLockIdentity,
  CreateTemp,
  WriteTemp,
  SyncTemp,
  RenameManifest,
  SyncDirectory,
  OpenManifest,
  ReadManifest,
  CleanupTemp,
};

// Internal deterministic fault-injection seam. Returning true makes the
// corresponding operation fail before its POSIX syscall is attempted.
class IManifestFileOps {
 public:
  virtual ~IManifestFileOps() = default;
  [[nodiscard]] virtual bool FailAt(ManifestIoPoint point) noexcept = 0;
};

enum class ManifestStoreError : std::uint8_t {
  AlreadyExists,
  NotFound,
  InvalidPath,
  InvalidDirectory,
  InvalidLock,
  LockBusy,
  LockIdentityChanged,
  Busy,
  InvalidManifestFile,
  MissingManifest,
  ManifestTooLarge,
  CodecFailure,
  ReadFailure,
  WriteFailure,
  FileSyncFailure,
  RenameFailure,
  DirectorySyncFailure,
  DurabilityUncertain,
  RecoveryReadOnly,
  WriterLatched,
  CompareAndSwapMismatch,
  IllegalTransition,
  OperationIdInvalid,
  GenerationExhausted,
  AllocationFailure,
};

enum class ManifestVisibility : std::uint8_t {
  NotVisible,
  Durable,
  VisibleDurabilityUnknown,
};

struct ManifestWriteResult {
  ManifestVisibility visibility{ManifestVisibility::NotVisible};
  std::optional<ManifestStoreError> error;
  std::uint64_t generation{};
  ManifestPhase phase{ManifestPhase::Prepared};
  std::array<std::uint8_t, 32> digest{};
};

using ManifestStoreOpenResult =
    std::variant<std::unique_ptr<class ManifestStore>, ManifestStoreError>;

[[nodiscard]] inline std::optional<std::uint64_t> TryNextManifestGeneration(
    std::uint64_t current) noexcept {
  if (current == 0 || current == UINT64_MAX) return std::nullopt;
  return current + 1;
}

class ManifestStore {
 public:
  ManifestStore(const ManifestStore&) = delete;
  ManifestStore& operator=(const ManifestStore&) = delete;
  ~ManifestStore();

  // Creates a new private directory; EEXIST is always an error. The supplied
  // inventory is validated and persisted in Prepared phase before success.
  [[nodiscard]] static ManifestStoreOpenResult CreateNew(
      const std::string& directory, const EpochCandidate& candidate,
      const OperationId& creation_operation_id,
      IManifestFileOps* test_hooks = nullptr) noexcept;

  // Recovery-only. Opens and locks existing files without creating or
  // promoting anything. A persisted ACTIVE epoch is never adopted.
  [[nodiscard]] static ManifestStoreOpenResult OpenExisting(
      const std::string& directory, IManifestFileOps* test_hooks = nullptr) noexcept;

  [[nodiscard]] bool recovery_only() const noexcept;
  [[nodiscard]] bool writable() const noexcept;
  // Returns the last complete in-memory snapshot immediately. During a write
  // it may reflect the prior durable generation until the write outcome lands.
  [[nodiscard]] ManifestV1 snapshot() const;
  [[nodiscard]] std::array<std::uint8_t, 32> digest() const;

  // CAS transition in this store's already-owned epoch. OpenExisting handles
  // are always read-only. Post-rename directory-sync failure is reported as
  // VisibleDurabilityUnknown and permanently disables writes on this handle.
  [[nodiscard]] ManifestWriteResult Transition(
      std::uint64_t expected_generation, const std::array<std::uint8_t, 32>& expected_digest,
      ManifestPhase next_phase, const OperationId& operation_id);

 private:
  ManifestStore(int directory_fd, int lock_fd, std::string directory,
                ManifestV1 manifest, std::array<std::uint8_t, 32> digest,
                bool recovery_only, IManifestFileOps* test_hooks);
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace rateguard::supervisor
