#pragma once

// Exclusive ownership of one configured runtime root. This is not a process
// controller, durable epoch-fencing proof, or global lock across other paths.

#include "supervisor/epoch_gate.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <variant>

namespace rateguard::supervisor {

using RuntimeDomainId = std::array<std::uint8_t, 16>;

enum class RuntimeOwnerMode : std::uint8_t { Fresh, RecoveryRequired };
enum class RuntimeOwnerIoPoint : std::uint8_t {
  ResolveParent,
  MkdirRoot,
  SyncParent,
  OpenRoot,
  ValidateRoot,
  CreateLock,
  OpenLock,
  OpenAnchor,
  AcquireLock,
  SyncLock,
  SyncRoot,
  CreateAnchorTemp,
  WriteAnchor,
  SyncAnchor,
  RenameAnchor,
  CheckRootIdentity,
  CheckLockIdentity,
  CheckAnchorIdentity,
  ReadAnchor,
  EnumerateRoot,
  DuplicateRoot,
  CleanupTemp,
};

class IRuntimeOwnerIo {
 public:
  virtual ~IRuntimeOwnerIo() = default;
  [[nodiscard]] virtual bool FailAt(RuntimeOwnerIoPoint point) noexcept = 0;
};

enum class RuntimeOwnerError : std::uint8_t {
  InvalidPath,
  InvalidDomainId,
  AlreadyExists,
  NotFound,
  InvalidRoot,
  InvalidLock,
  LockBusy,
  InvalidAnchor,
  AnchorMissing,
  DomainMismatch,
  RootPathMismatch,
  OwnerProcessChanged,
  RootIdentityChanged,
  LockIdentityChanged,
  AnchorIdentityChanged,
  UnexpectedRootEntry,
  RecoveryRequired,
  InitialClaimAlreadyUsed,
  Busy,
  InvalidEpochId,
  IoFailure,
  DurabilityUncertain,
  AllocationFailure,
};

using RuntimeOwnerOpenResult =
    std::variant<std::unique_ptr<class RuntimeOwner>, RuntimeOwnerError>;
using RuntimeOwnerCheck = std::variant<std::monostate, RuntimeOwnerError>;
using DuplicateFdResult = std::variant<int, RuntimeOwnerError>;

namespace detail {
struct RuntimeOwnerState;
}

class InitialEpochClaim {
 public:
  InitialEpochClaim(const InitialEpochClaim&) = delete;
  InitialEpochClaim& operator=(const InitialEpochClaim&) = delete;
  InitialEpochClaim(InitialEpochClaim&&) noexcept = default;
  InitialEpochClaim& operator=(InitialEpochClaim&&) noexcept = default;

  [[nodiscard]] const EpochId& epoch_id() const noexcept { return epoch_id_; }
  // Use after ValidateOwnership(); a moved-from claim returns default metadata.
  [[nodiscard]] RuntimeDomainId domain_id() const noexcept;
  [[nodiscard]] const std::string& root_path() const noexcept;
  [[nodiscard]] RuntimeOwnerCheck ValidateOwnership() const noexcept;
  // Caller owns the returned CLOEXEC descriptor and must close it.
  [[nodiscard]] DuplicateFdResult DuplicateRootFd() const noexcept;

 private:
  friend class RuntimeOwner;
  InitialEpochClaim(std::shared_ptr<detail::RuntimeOwnerState> state, EpochId epoch_id) noexcept
      : state_(std::move(state)), epoch_id_(epoch_id) {}
  std::shared_ptr<detail::RuntimeOwnerState> state_;
  EpochId epoch_id_{};
};

using InitialClaimResult = std::variant<InitialEpochClaim, RuntimeOwnerError>;

class RuntimeOwner {
 public:
  RuntimeOwner(const RuntimeOwner&) = delete;
  RuntimeOwner& operator=(const RuntimeOwner&) = delete;
  ~RuntimeOwner();

  // Must be an absolute, new path. EEXIST never initializes an existing root.
  [[nodiscard]] static RuntimeOwnerOpenResult CreateNew(
      const std::string& absolute_root, const RuntimeDomainId& domain_id,
      IRuntimeOwnerIo* test_io = nullptr) noexcept;

  // Opens existing files only. Every successful OpenExisting handle is
  // RecoveryRequired and has no initial-bootstrap claim capability.
  [[nodiscard]] static RuntimeOwnerOpenResult OpenExisting(
      const std::string& absolute_root, const RuntimeDomainId& expected_domain_id,
      IRuntimeOwnerIo* test_io = nullptr) noexcept;

  [[nodiscard]] RuntimeOwnerMode mode() const noexcept;
  [[nodiscard]] const RuntimeDomainId& domain_id() const noexcept;
  [[nodiscard]] const std::string& root_path() const noexcept;
  [[nodiscard]] RuntimeOwnerCheck ValidateOwnership() const noexcept;
  // Caller owns the returned CLOEXEC descriptor and must close it.
  [[nodiscard]] DuplicateFdResult DuplicateRootFd() const noexcept;
  // A new root can issue exactly one in-process bootstrap claim. This only
  // proves fresh-root ownership, not that a process has launched safely.
  [[nodiscard]] InitialClaimResult ClaimInitialEpoch(const EpochId& epoch_id) noexcept;

 private:
  explicit RuntimeOwner(std::shared_ptr<detail::RuntimeOwnerState> state) noexcept
      : state_(std::move(state)) {}
  std::shared_ptr<detail::RuntimeOwnerState> state_;
};

}  // namespace rateguard::supervisor
