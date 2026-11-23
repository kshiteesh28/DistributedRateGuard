#include "supervisor/manifest_store.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace rateguard::supervisor;

namespace {

void Check(bool condition, const char* what) {
  if (!condition) throw std::runtime_error(what);
}

class OneShotFault final : public IManifestFileOps {
 public:
  ManifestIoPoint target{ManifestIoPoint::Mkdir};
  unsigned remaining{};
  bool FailAt(ManifestIoPoint point) noexcept override {
    if (remaining == 0 || point != target) return false;
    if (--remaining == 0) return true;
    return false;
  }
};

EpochCandidate Candidate() {
  EpochCandidate c;
  c.epoch_id[0] = 1;
  c.authority_incarnation[0] = 2;
  c.policy_digest[0] = 3;
  c.clock_identity.boot_uuid[0] = 4;
  c.clock_identity.namespace_device = 11;
  c.clock_identity.namespace_inode = 12;
  c.clock_identity.clock_id = 1;
  const auto add = [&](ParticipantRole role, std::uint32_t slot, const char* participant,
                       std::uint8_t incarnation, char container, std::uint64_t pid) {
    Participant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = participant;
    p.incarnation[0] = incarnation;
    if (role == ParticipantRole::Authority) p.incarnation = c.authority_incarnation;
    p.process.container_id = std::string(64, container);
    p.process.pid = pid;
    p.process.pid_start_ticks = pid + 100;
    p.clock_identity = c.clock_identity;
    c.participants.push_back(std::move(p));
  };
  add(ParticipantRole::Authority, 0, "authority", 2, 'a', 101);
  add(ParticipantRole::Witness, 0, "witness", 5, 'b', 102);
  add(ParticipantRole::Replica, 0, "replica-zero", 6, 'c', 103);
  add(ParticipantRole::Adapter, 0, "adapter", 8, 'd', 104);
  return c;
}

OperationId Operation(std::uint8_t first) {
  OperationId op{};
  op[0] = first;
  return op;
}

std::string FreshPath(const char* suffix) {
  const char* tmp = std::getenv("TMPDIR");
  const std::string root = tmp != nullptr && *tmp != '\0' ? tmp : "/tmp";
  return root + "/rateguard-manifest-" + std::to_string(::getpid()) + "-" + suffix;
}

std::unique_ptr<ManifestStore> Create(const std::string& path,
                                     IManifestFileOps* faults = nullptr) {
  auto result = ManifestStore::CreateNew(path, Candidate(), Operation(1), faults);
  if (auto* error = std::get_if<ManifestStoreError>(&result))
    std::cerr << "CreateNew error enum=" << static_cast<int>(*error) << '\n';
  Check(std::holds_alternative<std::unique_ptr<ManifestStore>>(result),
        "CreateNew failed");
  return std::get<std::unique_ptr<ManifestStore>>(std::move(result));
}

void TestDurableLifecycleAndRecovery() {
  const auto path = FreshPath("normal");
  std::filesystem::remove_all(path);
  auto store = Create(path);
  Check(store->writable() && !store->recovery_only(), "new handle not writable");
  Check(store->snapshot().phase == ManifestPhase::Prepared, "initial phase not Prepared");
  Check(store->snapshot().generation == 1, "initial generation not one");
  struct stat st {};
  Check(::stat(path.c_str(), &st) == 0 && (st.st_mode & 07777) == 0700,
        "store directory mode mismatch");
  Check(::stat((path + "/owner.lock").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600,
        "lock file mode mismatch");
  Check(::stat((path + "/manifest.json").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600,
        "manifest file mode mismatch");

  const auto before_digest = store->digest();
  const auto activated = store->Transition(1, before_digest, ManifestPhase::Active, Operation(2));
  Check(activated.visibility == ManifestVisibility::Durable && !activated.error,
        "Prepared to Active was not durable");
  Check(activated.generation == 2 && activated.phase == ManifestPhase::Active,
        "transition metadata mismatch");
  auto duplicate_create = ManifestStore::CreateNew(path, Candidate(), Operation(1));
  Check(std::get_if<ManifestStoreError>(&duplicate_create) != nullptr &&
            std::get<ManifestStoreError>(duplicate_create) == ManifestStoreError::AlreadyExists,
        "CreateNew reused existing directory");
  auto locked_open = ManifestStore::OpenExisting(path);
  Check(std::get_if<ManifestStoreError>(&locked_open) != nullptr &&
            std::get<ManifestStoreError>(locked_open) == ManifestStoreError::LockBusy,
        "second owner lock was not rejected");
  store.reset();

  auto recovered = ManifestStore::OpenExisting(path);
  Check(std::holds_alternative<std::unique_ptr<ManifestStore>>(recovered),
        "OpenExisting failed");
  auto recovery = std::get<std::unique_ptr<ManifestStore>>(std::move(recovered));
  Check(recovery->recovery_only() && !recovery->writable(), "recovery handle writable");
  Check(recovery->snapshot().phase == ManifestPhase::Active, "recovery phase mismatch");
  const auto forbidden = recovery->Transition(2, recovery->digest(), ManifestPhase::Draining,
                                              Operation(3));
  Check(forbidden.error == ManifestStoreError::RecoveryReadOnly,
        "OpenExisting modified an active epoch");
  recovery.reset();
  std::filesystem::remove_all(path);
}

void TestPreRenameFailureLatchesWriter() {
  const auto path = FreshPath("pre-rename");
  std::filesystem::remove_all(path);
  OneShotFault faults;
  auto store = Create(path, &faults);
  faults.target = ManifestIoPoint::WriteTemp;
  faults.remaining = 1;
  const auto result = store->Transition(1, store->digest(), ManifestPhase::Active, Operation(2));
  Check(result.visibility == ManifestVisibility::NotVisible &&
            result.error == ManifestStoreError::WriteFailure,
        "pre-rename failure visibility mismatch");
  Check(!store->writable() && store->snapshot().phase == ManifestPhase::Prepared,
        "failed write did not latch prior state");
  const auto retry = store->Transition(1, store->digest(), ManifestPhase::Active, Operation(2));
  Check(retry.error == ManifestStoreError::WriterLatched, "failed writer was reused");
  store.reset();
  std::filesystem::remove_all(path);
}

void TestPostRenameDirectorySyncIsUncertain() {
  const auto path = FreshPath("uncertain");
  std::filesystem::remove_all(path);
  OneShotFault faults;
  auto store = Create(path, &faults);
  faults.target = ManifestIoPoint::SyncDirectory;
  // Creation's syncs are complete before this fault is armed.
  faults.remaining = 1;
  const auto result = store->Transition(1, store->digest(), ManifestPhase::Active, Operation(2));
  Check(result.visibility == ManifestVisibility::VisibleDurabilityUnknown &&
            result.error == ManifestStoreError::DurabilityUncertain,
        "post-rename sync failure was not reported uncertain");
  Check(!store->writable() && store->snapshot().phase == ManifestPhase::Active,
        "visible snapshot not retained/latch missing");
  store.reset();
  auto reopened = ManifestStore::OpenExisting(path);
  Check(std::holds_alternative<std::unique_ptr<ManifestStore>>(reopened),
        "visible uncertain manifest could not be inspected");
  auto recovery = std::get<std::unique_ptr<ManifestStore>>(std::move(reopened));
  Check(recovery->snapshot().phase == ManifestPhase::Active,
        "post-rename manifest was not visible");
  recovery.reset();
  std::filesystem::remove_all(path);
}

void TestGenerationBoundaries() {
  Check(TryNextManifestGeneration(1) == 2, "generation did not advance");
  Check(TryNextManifestGeneration(UINT64_MAX - 1) == UINT64_MAX,
        "last generation step rejected");
  Check(!TryNextManifestGeneration(UINT64_MAX), "generation wrapped");
  Check(!TryNextManifestGeneration(0), "zero generation accepted");
}

}  // namespace

int main() {
  try {
    TestDurableLifecycleAndRecovery();
    TestPreRenameFailureLatchesWriter();
    TestPostRenameDirectorySyncIsUncertain();
    TestGenerationBoundaries();
    std::cout << "manifest store tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "manifest store test failure: " << error.what() << '\n';
    return 1;
  }
}
