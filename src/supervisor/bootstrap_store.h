#pragma once

#include "supervisor/bootstrap_inventory.h"
#include "supervisor/runtime_owner.h"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <variant>

namespace rateguard::supervisor {

enum class BootstrapStoreIoPoint : std::uint8_t {
  CheckOwner,
  CheckRoot,
  CheckChild,
  MakeChild,
  SyncRootAfterMkdir,
  OpenChild,
  CheckCurrentFile,
  ReadCurrentFile,
  CreateTemp,
  WriteTemp,
  SyncTemp,
  CloseTemp,
  RenameTemp,
  SyncChild,
};

class IBootstrapStoreIo {
 public:
  virtual ~IBootstrapStoreIo() = default;
  [[nodiscard]] virtual bool FailAt(BootstrapStoreIoPoint point) noexcept = 0;
};

enum class BootstrapStoreError : std::uint8_t {
  None,
  InvalidClaim,
  DomainMismatch,
  EpochMismatch,
  InvalidPlan,
  ExistingEpoch,
  InvalidRoot,
  InvalidChild,
  InvalidIntent,
  OwnerLost,
  Busy,
  Conflict,
  RecoveryRequired,
  IncompleteRoster,
  IoFailure,
  DurabilityUncertain,
  StorageUncertain,
  AllocationFailure,
};

enum class BootstrapVisibility : std::uint8_t { NotVisible, Durable, VisibleDurabilityUnknown };

struct BootstrapStoreUpdate final {
  std::shared_ptr<const BootstrapInventory> snapshot;
  BootstrapVisibility visibility{BootstrapVisibility::NotVisible};
  BootstrapStoreError store_error{BootstrapStoreError::None};
  BootstrapError transition_status{BootstrapError::None};
};

struct BootstrapStoreOpenResult final {
  std::unique_ptr<class BootstrapStore> store;
  BootstrapVisibility visibility{BootstrapVisibility::NotVisible};
  BootstrapStoreError error{BootstrapStoreError::None};
  [[nodiscard]] bool ok() const noexcept { return store != nullptr && error == BootstrapStoreError::None; }
};
using BootstrapCandidateResult = std::variant<EpochCandidate, BootstrapStoreError>;

// Initial-epoch-only durable bootstrap store. There is intentionally no API to
// open an existing intent for serving or to infer process-start evidence.
class BootstrapStore final {
 public:
  struct State;  // Opaque implementation state; exposed only for private helpers.
  BootstrapStore(const BootstrapStore&) = delete;
  BootstrapStore& operator=(const BootstrapStore&) = delete;
  ~BootstrapStore();

  // Takes ownership of `claim`; it is consumed on success or failure.
  [[nodiscard]] static BootstrapStoreOpenResult CreateNew(
      InitialEpochClaim claim, const BootstrapPlan& plan,
      IBootstrapStoreIo* test_io = nullptr) noexcept;

  // Returns the last fully durable in-memory snapshot without file I/O.
  [[nodiscard]] std::shared_ptr<const BootstrapInventory> Snapshot() const noexcept;

  // CAS by durable revision and canonical payload digest. A mismatch is a
  // conflict and does not poison a healthy store. Store publication follows
  // successful atomic replacement and fsync; uncertain writes make it unready.
  [[nodiscard]] BootstrapStoreUpdate RecordIdentity(
      std::uint64_t expected_revision, const std::array<std::uint8_t, 32>& expected_digest,
      const ObservedBootstrapIdentity& observed) noexcept;

  // Pure data handoff after ownership and on-disk validation. This does not
  // activate participants or establish actual process-control evidence.
  [[nodiscard]] BootstrapCandidateResult ReadyCandidate() noexcept;

 private:
  explicit BootstrapStore(std::unique_ptr<State> state) noexcept;
  std::unique_ptr<State> state_;
};

}  // namespace rateguard::supervisor
