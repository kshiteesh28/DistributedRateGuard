#include "supervisor/bootstrap_store.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <functional>
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

struct ActionOnce final : IBootstrapStoreIo {
  BootstrapStoreIoPoint point;
  std::size_t occurrence;
  std::size_t seen{};
  bool consumed{};
  std::function<void()> action;
  ActionOnce(BootstrapStoreIoPoint p, std::size_t nth, std::function<void()> fn)
      : point(p), occurrence(nth), action(std::move(fn)) {}
  bool FailAt(BootstrapStoreIoPoint candidate) noexcept override {
    if (!consumed && candidate == point && ++seen == occurrence) {
      consumed = true;
      action();
    }
    return false;
  }
};

std::string ReadBytes(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  CHECK(in.good());
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

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

void TestMismatchCanBeDurablyRecordedWithoutBecomingReady() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto store = OpenStore(temp.root, plan);
  const auto before = store->Snapshot();
  auto mismatched = Observe(plan, 0, 840);
  mismatched.participant.container_id.back() = 'z';
  const auto update = store->RecordIdentity(before->revision(), Digest(*before), mismatched);
  CHECK(update.store_error == BootstrapStoreError::None);
  CHECK(update.visibility == BootstrapVisibility::Durable);
  CHECK(update.transition_status == BootstrapError::IdentityMismatch);
  CHECK(update.snapshot->revision() == before->revision() + 1);
  CHECK(update.snapshot->recovery_required());
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::RecoveryRequired);
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

void TestPreRenameFailureIsNotVisibleAndDoesNotPublish() {
  TempRoot temp;
  const auto plan = MakePlan();
  // CreateNew performs the first WriteTemp; fail the second, during identity
  // registration. The old durable manifest must remain the visible state.
  FailureOnce fail(BootstrapStoreIoPoint::WriteTemp, 2);
  auto store = OpenStore(temp.root, plan, &fail);
  const auto before = store->Snapshot();
  const std::string intent = temp.root + "/epoch-11111111111111111111111111111111/intent.json";
  const auto old_bytes = ReadBytes(intent);
  const auto update = store->RecordIdentity(before->revision(), Digest(*before), Observe(plan, 0, 810));
  CHECK(update.store_error != BootstrapStoreError::None);
  CHECK(update.visibility == BootstrapVisibility::NotVisible);
  CHECK(update.snapshot == before);
  CHECK(store->Snapshot() == before);
  CHECK(ReadBytes(intent) == old_bytes);
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::StorageUncertain);
}

void TestPostRenameUncertaintyLeavesDiskAheadButNeverReady() {
  TempRoot temp;
  const auto plan = MakePlan();
  // Initial create syncs the child once; the second SyncChild is after the
  // registration rename. A failure there means visibility is uncertain.
  FailureOnce fail(BootstrapStoreIoPoint::SyncChild, 2);
  auto store = OpenStore(temp.root, plan, &fail);
  const auto before = store->Snapshot();
  const std::string intent = temp.root + "/epoch-11111111111111111111111111111111/intent.json";
  const auto old_bytes = ReadBytes(intent);
  const auto update = store->RecordIdentity(before->revision(), Digest(*before), Observe(plan, 0, 820));
  CHECK(update.store_error == BootstrapStoreError::DurabilityUncertain);
  CHECK(update.visibility == BootstrapVisibility::VisibleDurabilityUnknown);
  CHECK(update.snapshot == before);
  CHECK(store->Snapshot() == before);
  const auto disk_bytes = ReadBytes(intent);
  CHECK(disk_bytes != old_bytes);  // rename was visible, directory durability was not proven
  const auto decoded = DecodeBootstrapInventoryV1(disk_bytes);
  CHECK(std::holds_alternative<BootstrapInventory>(decoded));
  CHECK(std::get<BootstrapInventory>(decoded).recorded_count() == 1);
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::StorageUncertain);
  const auto again = store->RecordIdentity(before->revision(), Digest(*before), Observe(plan, 0, 820));
  CHECK(again.store_error == BootstrapStoreError::StorageUncertain);
  CHECK(again.visibility == BootstrapVisibility::VisibleDurabilityUnknown);
}

void TestCreateNewDoesNotPublishOnPostRenameUncertainty() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto owner_result = RuntimeOwner::CreateNew(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  // CreateNew's initial intent is the first child sync. The second sync
  // failure occurs after rename, so no usable store handle may escape.
  FailureOnce fail(BootstrapStoreIoPoint::SyncChild, 1);
  auto result = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), plan, &fail);
  CHECK(!result.ok());
  CHECK(result.store == nullptr);
  CHECK(result.visibility == BootstrapVisibility::VisibleDurabilityUnknown);
  CHECK(result.error == BootstrapStoreError::DurabilityUncertain);
}

void TestExistingIntentReplacementRaceIsNotOverwritten() {
  TempRoot temp;
  const auto plan = MakePlan();
  const std::string intent = temp.root + "/epoch-11111111111111111111111111111111/intent.json";
  ActionOnce replace(BootstrapStoreIoPoint::RenameTemp, 2, [&] {
    const std::string external = "external replacement survives";
    const auto replacement = intent + ".external";
    {
      std::ofstream out(replacement, std::ios::binary | std::ios::trunc);
      out.write(external.data(), static_cast<std::streamsize>(external.size()));
      out.close();
    }
    CHECK(::chmod(replacement.c_str(), 0600) == 0);
    CHECK(::rename(replacement.c_str(), intent.c_str()) == 0);
  });
  auto store = OpenStore(temp.root, plan, &replace);
  const auto before = store->Snapshot();
  const auto update = store->RecordIdentity(before->revision(), Digest(*before), Observe(plan, 0, 830));
  CHECK(replace.consumed);
  CHECK(update.visibility == BootstrapVisibility::NotVisible);
  CHECK(update.store_error == BootstrapStoreError::StorageUncertain);
  CHECK(update.snapshot == before);
  CHECK(ReadBytes(intent) == "external replacement survives");
  CHECK(store->Snapshot() == before);
  CHECK(std::get<BootstrapStoreError>(store->ReadyCandidate()) == BootstrapStoreError::StorageUncertain);
}

void TestInitialIntentAppearingBeforePublishIsNeverOverwritten() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto owner_result = RuntimeOwner::CreateNew(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  const std::string intent = temp.root + "/epoch-11111111111111111111111111111111/intent.json";
  const std::string external = "intent installed by competing publisher";
  ActionOnce install(BootstrapStoreIoPoint::RenameTemp, 1, [&] {
    std::ofstream out(intent, std::ios::binary | std::ios::trunc);
    out.write(external.data(), static_cast<std::streamsize>(external.size()));
    out.close();
    CHECK(out.good());
    CHECK(::chmod(intent.c_str(), 0600) == 0);
  });
  auto result = BootstrapStore::CreateNew(
      std::move(std::get<InitialEpochClaim>(claim_result)), plan, &install);
  CHECK(install.consumed);
  CHECK(!result.ok());
  CHECK(result.store == nullptr);
  CHECK(result.visibility == BootstrapVisibility::NotVisible);
  CHECK(result.error == BootstrapStoreError::InvalidIntent);
  CHECK(ReadBytes(intent) == external);
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

}  // namespace

int main() {
  TestDurableProgressAndReadyCandidate();
  TestConflictDoesNotPoisonStore();
  TestMismatchCanBeDurablyRecordedWithoutBecomingReady();
  TestDurabilityFailureLatchesStoreUnready();
  TestPreRenameFailureIsNotVisibleAndDoesNotPublish();
  TestPostRenameUncertaintyLeavesDiskAheadButNeverReady();
  TestCreateNewDoesNotPublishOnPostRenameUncertainty();
  TestExistingIntentReplacementRaceIsNotOverwritten();
  TestInitialIntentAppearingBeforePublishIsNeverOverwritten();
  TestInvalidClaimBindingAndNoExistingChildReuse();
  return 0;
}
