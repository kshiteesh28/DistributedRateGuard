#include "supervisor/bootstrap_store.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>

namespace {
using namespace rateguard::supervisor;

#define CHECK(condition) do { \
  if (!(condition)) { \
    std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    std::abort(); \
  } \
} while (false)

struct TempRoot {
  std::string parent;
  std::string root;
  TempRoot() {
    std::array<char, 64> pattern{};
    const std::string seed = "/tmp/rateguard-bootstrap-store-XXXXXX";
    std::copy(seed.begin(), seed.end(), pattern.begin());
    char* made = ::mkdtemp(pattern.data());
    CHECK(made != nullptr);
    parent = made;
    root = parent + "/runtime";
  }
  ~TempRoot() { std::error_code ignored; std::filesystem::remove_all(parent, ignored); }
};

BootstrapPlan MakePlan() {
  BootstrapPlan plan;
  plan.domain_id.fill(0x10);
  plan.epoch_id.fill(0x11);
  plan.authority_incarnation.fill(0x22);
  plan.policy_digest.fill(0x33);
  plan.expected_clock_identity = {};
  plan.expected_clock_identity.boot_uuid.fill(0x44);
  plan.expected_clock_identity.namespace_device = 7;
  plan.expected_clock_identity.namespace_inode = 9;
  plan.expected_clock_identity.monotonic_offset_seconds = 0;
  plan.expected_clock_identity.monotonic_offset_nanoseconds = 0;
  plan.expected_clock_identity.boottime_offset_seconds = 0;
  plan.expected_clock_identity.boottime_offset_nanoseconds = 0;
  plan.expected_clock_identity.clock_id = 1;
  const auto make = [](ParticipantRole role, std::uint32_t slot, std::string id,
                       std::uint8_t incarnation, char suffix) {
    PlannedParticipant p;
    p.role = role; p.slot_id = slot; p.participant_id = std::move(id);
    p.incarnation.fill(incarnation); p.container_id = std::string(63, 'a') + suffix;
    return p;
  };
  plan.participants = {
      make(ParticipantRole::Authority, 0, "authority", 0x22, '1'),
      make(ParticipantRole::Replica, 77, "replica", 0x55, '2'),
      make(ParticipantRole::Adapter, 0, "adapter", 0x66, '3'),
      make(ParticipantRole::Witness, 0, "witness", 0x77, '4'),
  };
  return plan;
}

struct FailureOnce final : IBootstrapStoreIo {
  BootstrapStoreIoPoint point;
  std::size_t occurrence;
  std::size_t seen{};
  bool consumed{};
  explicit FailureOnce(BootstrapStoreIoPoint p, std::size_t nth = 1) : point(p), occurrence(nth) {}
  bool FailAt(BootstrapStoreIoPoint candidate) noexcept override {
    if (!consumed && candidate == point && ++seen == occurrence) { consumed = true; return true; }
    return false;
  }
};

struct ReplaceAtRename final : IBootstrapStoreIo {
  std::string path;
  std::size_t target_occurrence;
  std::size_t seen{};
  explicit ReplaceAtRename(std::string file, std::size_t occurrence)
      : path(std::move(file)), target_occurrence(occurrence) {}
  bool FailAt(BootstrapStoreIoPoint point) noexcept override {
    if (point != BootstrapStoreIoPoint::RenameTemp) return false;
    if (++seen != target_occurrence) return false;
    try {
      std::ofstream output(path, std::ios::binary | std::ios::trunc);
      output << "external replacement";
      output.close();
      return false;  // Simulate a concurrent edit without forcing the hook itself to fail.
    } catch (...) { return true; }
  }
};

std::unique_ptr<BootstrapStore> OpenStore(const std::string& root, const BootstrapPlan& plan,
                                          IBootstrapStoreIo* io = nullptr) {
  auto owner_result = RuntimeOwner::CreateNew(root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  auto store_result = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), plan, io);
  CHECK(store_result.ok());
  CHECK(store_result.visibility == BootstrapVisibility::Durable);
  return std::move(store_result.store);
}

std::array<std::uint8_t, 32> Digest(const BootstrapInventory& inventory) {
  const auto result = BootstrapDigestV1(inventory);
  CHECK((std::holds_alternative<std::array<std::uint8_t, 32>>(result)));
  return std::get<std::array<std::uint8_t, 32>>(result);
}

ObservedBootstrapIdentity Observe(const BootstrapPlan& plan, std::size_t index, std::uint64_t pid) {
  return ObservedBootstrapIdentity{plan.participants[index], pid, pid + 1000, plan.expected_clock_identity};
}

void TestDurableProgressAndReadyCandidate() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto store = OpenStore(temp.root, plan);
  auto snapshot = store->Snapshot();
  CHECK(snapshot != nullptr && snapshot->revision() == 1 && snapshot->recorded_count() == 0);
  CHECK(std::holds_alternative<BootstrapStoreError>(store->ReadyCandidate()));
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::IncompleteRoster);

  const auto epoch_name = "epoch-11111111111111111111111111111111";
  const auto intent = temp.root + "/" + epoch_name + "/intent.json";
  struct stat st{};
  CHECK(::stat(intent.c_str(), &st) == 0);
  CHECK(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0600 && st.st_nlink == 1);

  for (std::size_t n = 0; n < plan.participants.size(); ++n) {
    const auto expected_revision = snapshot->revision();
    const auto expected_digest = Digest(*snapshot);
    const auto updated = store->RecordIdentity(expected_revision, expected_digest, Observe(plan, n, 500 + n));
    CHECK(updated.store_error == BootstrapStoreError::None);
    CHECK(updated.visibility == BootstrapVisibility::Durable);
    CHECK(updated.transition_status == BootstrapError::None);
    CHECK(updated.snapshot->revision() == expected_revision + 1);
    snapshot = updated.snapshot;
  }
  const auto candidate = store->ReadyCandidate();
  CHECK(std::holds_alternative<EpochCandidate>(candidate));
  CHECK(std::get<EpochCandidate>(candidate).participants.size() == 4);
  CHECK(std::get<EpochCandidate>(candidate).participants[1].slot_id == 77);

  const auto repeated = store->RecordIdentity(snapshot->revision(), Digest(*snapshot), Observe(plan, 0, 500));
  CHECK(repeated.store_error == BootstrapStoreError::None);
  CHECK(repeated.visibility == BootstrapVisibility::Durable);
  CHECK(repeated.snapshot->revision() == snapshot->revision());
  CHECK(std::holds_alternative<EpochCandidate>(store->ReadyCandidate()));
}

void TestConflictDoesNotPoisonStore() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto store = OpenStore(temp.root, plan);
  auto snapshot = store->Snapshot();
  auto stale_digest = Digest(*snapshot);
  stale_digest[0] ^= 1;
  auto conflict = store->RecordIdentity(snapshot->revision(), stale_digest, Observe(plan, 0, 600));
  CHECK(conflict.store_error == BootstrapStoreError::Conflict);
  CHECK(conflict.visibility == BootstrapVisibility::NotVisible);
  CHECK(conflict.snapshot == snapshot);
  CHECK(store->Snapshot()->revision() == 1);
  CHECK(store->RecordIdentity(snapshot->revision(), Digest(*snapshot), Observe(plan, 0, 600)).store_error ==
        BootstrapStoreError::None);
}

void TestDurabilityFailureLatchesStoreUnready() {
  TempRoot temp;
  const auto plan = MakePlan();
  FailureOnce fail(BootstrapStoreIoPoint::SyncChild, 2);
  auto store = OpenStore(temp.root, plan, &fail);
  auto snapshot = store->Snapshot();
  auto failed = store->RecordIdentity(snapshot->revision(), Digest(*snapshot), Observe(plan, 0, 700));
  CHECK(failed.store_error == BootstrapStoreError::DurabilityUncertain);
  CHECK(failed.visibility == BootstrapVisibility::VisibleDurabilityUnknown);
  CHECK(failed.snapshot == snapshot);
  CHECK(store->Snapshot() == snapshot);
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::StorageUncertain);
}

void TestPreRenameFailureIsNotVisibleAndLatches() {
  TempRoot temp;
  const auto plan = MakePlan();
  FailureOnce fail(BootstrapStoreIoPoint::WriteTemp, 2);
  auto store = OpenStore(temp.root, plan, &fail);
  auto snapshot = store->Snapshot();
  auto failed = store->RecordIdentity(snapshot->revision(), Digest(*snapshot), Observe(plan, 0, 800));
  CHECK(failed.store_error == BootstrapStoreError::IoFailure);
  CHECK(failed.visibility == BootstrapVisibility::NotVisible);
  CHECK(failed.snapshot == snapshot);
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::StorageUncertain);
}

void TestInvalidClaimBindingAndNoExistingChildReuse() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto owner_result = RuntimeOwner::CreateNew(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  auto wrong = plan;
  wrong.epoch_id[0] ^= 0x10;
  auto mismatch = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), wrong);
  CHECK(mismatch.error == BootstrapStoreError::EpochMismatch);
}

void TestPreexistingEpochChildIsNeverReused() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto owner_result = RuntimeOwner::CreateNew(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  const auto child = temp.root + "/epoch-11111111111111111111111111111111";
  CHECK(std::filesystem::create_directory(child));
  auto result = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), plan);
  CHECK(result.error == BootstrapStoreError::ExistingEpoch);
  CHECK(result.visibility == BootstrapVisibility::NotVisible);
}

void TestInitialIntentAppearingBeforePublishIsNotOverwritten() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto owner_result = RuntimeOwner::CreateNew(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  const auto child = temp.root + "/epoch-11111111111111111111111111111111";
  const auto intent = child + "/intent.json";
  ReplaceAtRename mutate(intent, 1);
  auto result = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), plan, &mutate);
  CHECK(!result.ok());
  CHECK(result.visibility == BootstrapVisibility::NotVisible);
  CHECK(result.error == BootstrapStoreError::InvalidIntent);
  std::ifstream input(intent, std::ios::binary);
  const std::string contents((std::istreambuf_iterator<char>(input)), {});
  CHECK(contents == "external replacement");
}

void TestExistingIntentChangedBeforeReplaceIsPreserved() {
  TempRoot temp;
  const auto plan = MakePlan();
  const auto child = temp.root + "/epoch-11111111111111111111111111111111";
  const auto intent = child + "/intent.json";
  ReplaceAtRename mutate(intent, 2);  // First rename point is initial intent publication.
  auto store = OpenStore(temp.root, plan, &mutate);
  const auto snapshot = store->Snapshot();
  const auto update = store->RecordIdentity(snapshot->revision(), Digest(*snapshot), Observe(plan, 0, 900));
  CHECK(update.visibility == BootstrapVisibility::NotVisible);
  CHECK(update.store_error == BootstrapStoreError::StorageUncertain);
  CHECK(update.snapshot == snapshot);
  std::ifstream input(intent, std::ios::binary);
  const std::string contents((std::istreambuf_iterator<char>(input)), {});
  CHECK(contents == "external replacement");
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::StorageUncertain);
}

}  // namespace

int main() {
  TestDurableProgressAndReadyCandidate();
  TestConflictDoesNotPoisonStore();
  TestDurabilityFailureLatchesStoreUnready();
  TestPreRenameFailureIsNotVisibleAndLatches();
  TestInvalidClaimBindingAndNoExistingChildReuse();
  TestPreexistingEpochChildIsNeverReused();
  TestInitialIntentAppearingBeforePublishIsNotOverwritten();
  TestExistingIntentChangedBeforeReplaceIsPreserved();
  return 0;
}
