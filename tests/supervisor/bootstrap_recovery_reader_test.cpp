#include "supervisor/bootstrap_recovery_reader.h"
#include "supervisor/bootstrap_store.h"

#include <algorithm>
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

struct TempRoot final {
  std::string parent;
  std::string root;
  TempRoot() {
    std::array<char, 64> pattern{};
    const std::string seed = "/tmp/rateguard-bootstrap-recovery-XXXXXX";
    std::copy(seed.begin(), seed.end(), pattern.begin());
    char* made = ::mkdtemp(pattern.data());
    CHECK(made != nullptr);
    parent = made;
    root = parent + "/runtime";
  }
  ~TempRoot() { std::error_code ignored; std::filesystem::remove_all(parent, ignored); }
};

BootstrapPlan MakePlan(std::uint8_t epoch_byte = 0x11) {
  BootstrapPlan plan;
  plan.domain_id.fill(0x10);
  plan.epoch_id.fill(epoch_byte);
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
    p.role = role;
    p.slot_id = slot;
    p.participant_id = std::move(id);
    p.incarnation.fill(incarnation);
    p.container_id = std::string(63, 'a') + suffix;
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

ObservedBootstrapIdentity Observe(const BootstrapPlan& plan, std::size_t index, std::uint64_t pid) {
  return {plan.participants[index], pid, pid + 1000, plan.expected_clock_identity};
}

std::string EpochName(const EpochId& epoch) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result = "epoch-";
  for (auto byte : epoch) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

void CreateHistory(const std::string& root, const BootstrapPlan& plan, bool record_one = true) {
  auto owner_result = RuntimeOwner::CreateNew(root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  auto store_result = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), plan);
  CHECK(store_result.ok() && store_result.visibility == BootstrapVisibility::Durable);
  if (record_one) {
    const auto initial = store_result.store->Snapshot();
    const auto digest = BootstrapDigestV1(*initial);
    CHECK((std::holds_alternative<std::array<std::uint8_t, 32>>(digest)));
    auto update = store_result.store->RecordIdentity(initial->revision(),
        std::get<std::array<std::uint8_t, 32>>(digest), Observe(plan, 0, 515));
    CHECK(update.store_error == BootstrapStoreError::None);
    CHECK(update.visibility == BootstrapVisibility::Durable);
  }
  store_result.store.reset();
  owner.reset();
}

std::unique_ptr<RuntimeOwner> OpenRecoveryOwner(const TempRoot& temp, const BootstrapPlan& plan) {
  auto result = RuntimeOwner::OpenExisting(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(result));
  CHECK(owner->mode() == RuntimeOwnerMode::RecoveryRequired);
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
  return owner;
}

bool HasIssue(const BootstrapRecoverySnapshot& snapshot, RecoveryIssueCode wanted) {
  if (std::any_of(snapshot.issues.begin(), snapshot.issues.end(),
      [&](const auto& issue) { return issue.code == wanted; })) return true;
  for (const auto& epoch : snapshot.epochs)
    if (std::find(epoch.issues.begin(), epoch.issues.end(), wanted) != epoch.issues.end()) return true;
  return false;
}

struct FailOnce final : IRecoveryReaderIo {
  RecoveryReaderIoPoint point;
  bool consumed{};
  explicit FailOnce(RecoveryReaderIoPoint p) : point(p) {}
  bool FailAt(RecoveryReaderIoPoint candidate) noexcept override {
    if (!consumed && candidate == point) { consumed = true; return true; }
    return false;
  }
};

struct MutateIntentAtReadback final : IRecoveryReaderIo {
  std::string path;
  bool consumed{};
  explicit MutateIntentAtReadback(std::string p) : path(std::move(p)) {}
  bool FailAt(RecoveryReaderIoPoint point) noexcept override {
    if (consumed || point != RecoveryReaderIoPoint::RevalidateEntry) return false;
    consumed = true;
    return ::chmod(path.c_str(), 0640) != 0;
  }
};

void TestRecoveryScanRetainsPendingRosterAndCanRepeat() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateHistory(temp.root, plan, true);  // Other planned participants remain pending.
  auto owner = OpenRecoveryOwner(temp, plan);
  const auto first = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(first));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(first);
  CHECK(snapshot->scan_complete);
  CHECK(snapshot->domain_id == plan.domain_id);
  CHECK(snapshot->epochs.size() == 1);
  CHECK(snapshot->epochs[0].inventory != nullptr);
  CHECK(snapshot->epochs[0].inventory->recorded_count() == 1);
  CHECK(snapshot->epochs[0].inventory->records().size() == plan.participants.size());

  const auto second = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(second));
  const auto repeated = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(second);
  CHECK(repeated->scan_complete && repeated->epochs.size() == 1);
  CHECK(repeated->epochs[0].inventory->recorded_count() == 1);
}

void TestUnexpectedSiblingDoesNotHideKnownIntent() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateHistory(temp.root, plan);
  const auto child = temp.root + "/" + EpochName(plan.epoch_id);
  const auto extra = child + "/intent.tmp";
  { std::ofstream out(extra); out << "untrusted partial data"; }
  CHECK(::chmod(extra.c_str(), 0600) == 0);
  auto owner = OpenRecoveryOwner(temp, plan);
  const auto result = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1 && snapshot->epochs[0].inventory != nullptr);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::EpochHasUnexpectedEntry));
}

void TestUnknownRootEntryDoesNotHideKnownIntent() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateHistory(temp.root, plan);
  const auto extra = temp.root + "/unrecognized-entry";
  { std::ofstream out(extra); out << "opaque"; }
  CHECK(::chmod(extra.c_str(), 0600) == 0);
  auto owner = OpenRecoveryOwner(temp, plan);
  const auto result = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1 && snapshot->epochs[0].inventory != nullptr);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::UnexpectedRootEntry));
}

void TestEmptyAndMissingIntentRemainUnknown() {
  TempRoot empty;
  const auto plan = MakePlan();
  auto create_owner = RuntimeOwner::CreateNew(empty.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(create_owner));
  std::get<std::unique_ptr<RuntimeOwner>>(create_owner).reset();
  auto empty_owner = OpenRecoveryOwner(empty, plan);
  auto empty_result = BootstrapRecoveryReader::Read(*empty_owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(empty_result));
  const auto empty_snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(empty_result);
  CHECK(!empty_snapshot->scan_complete && empty_snapshot->epochs.empty());
  CHECK(HasIssue(*empty_snapshot, RecoveryIssueCode::NoValidIntents));

  TempRoot missing;
  CreateHistory(missing.root, plan);
  const auto intent = missing.root + "/" + EpochName(plan.epoch_id) + "/intent.json";
  CHECK(::unlink(intent.c_str()) == 0);
  auto missing_owner = OpenRecoveryOwner(missing, plan);
  auto missing_result = BootstrapRecoveryReader::Read(*missing_owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(missing_result));
  const auto missing_snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(missing_result);
  CHECK(!missing_snapshot->scan_complete);
  CHECK(HasIssue(*missing_snapshot, RecoveryIssueCode::MissingIntent));
}

void TestWrongModeAndInjectedReadFailure() {
  TempRoot temp;
  const auto plan = MakePlan();
  auto fresh_result = RuntimeOwner::CreateNew(temp.root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(fresh_result));
  auto fresh = std::move(std::get<std::unique_ptr<RuntimeOwner>>(fresh_result));
  const auto wrong_mode = BootstrapRecoveryReader::Read(*fresh);
  CHECK(std::get<RecoveryReaderFatal>(wrong_mode) == RecoveryReaderFatal::OwnerNotRecoveryMode);
  fresh.reset();

  TempRoot history;
  CreateHistory(history.root, plan);
  auto owner = OpenRecoveryOwner(history, plan);
  FailOnce fail(RecoveryReaderIoPoint::ReadIntent);
  const auto read_error = BootstrapRecoveryReader::Read(*owner, &fail);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(read_error));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(read_error);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1 && snapshot->epochs[0].inventory == nullptr);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::IntentReadFailed));
}

void TestPostReadModeChangeIsDetected() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateHistory(temp.root, plan);
  auto owner = OpenRecoveryOwner(temp, plan);
  const auto intent = temp.root + "/" + EpochName(plan.epoch_id) + "/intent.json";
  MutateIntentAtReadback mutate(intent);
  const auto result = BootstrapRecoveryReader::Read(*owner, &mutate);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::IntentChanged));
}

void TestCrossEpochContainerCollisionIsReported() {
  TempRoot temp;
  const auto first = MakePlan(0x11);
  CreateHistory(temp.root, first);
  auto owner = OpenRecoveryOwner(temp, first);

  auto second = MakePlan(0x12);  // Deliberately reuse the same planned container IDs.
  const auto model = BootstrapInventory::Create(second);
  CHECK(std::holds_alternative<BootstrapInventory>(model));
  const auto encoded = EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(model));
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto child = temp.root + "/" + EpochName(second.epoch_id);
  CHECK(::mkdir(child.c_str(), 0700) == 0);
  const auto intent = child + "/intent.json";
  { std::ofstream out(intent, std::ios::binary); out << std::get<std::string>(encoded); }
  CHECK(::chmod(intent.c_str(), 0600) == 0);

  const auto result = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 2);
  CHECK(std::all_of(snapshot->epochs.begin(), snapshot->epochs.end(),
      [](const auto& epoch) { return epoch.inventory != nullptr; }));
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::IdentityCollisionAcrossEpochs));
}


std::string ContainerId(std::uint8_t epoch_byte, std::uint64_t index) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(46, '0');
  result.push_back(digits[epoch_byte >> 4]);
  result.push_back(digits[epoch_byte & 15]);
  for (int shift = 60; shift >= 0; shift -= 4)
    result.push_back(digits[(index >> shift) & 15]);
  CHECK(result.size() == 64);
  return result;
}

BootstrapPlan MakeMaxParticipantPlan(std::uint8_t epoch_byte) {
  BootstrapPlan plan = MakePlan(epoch_byte);
  plan.participants.clear();
  const auto add = [&](ParticipantRole role, std::uint32_t slot, std::string id,
                       std::uint8_t incarnation, std::uint64_t ordinal) {
    PlannedParticipant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = std::move(id);
    p.incarnation.fill(incarnation);
    p.container_id = ContainerId(epoch_byte, ordinal);
    plan.participants.push_back(std::move(p));
  };
  std::uint64_t ordinal = 0;
  add(ParticipantRole::Authority, 0, "authority", 0x22, ordinal++);
  for (std::uint32_t slot = 1; slot <= kMaxReplicaSlots; ++slot)
    add(ParticipantRole::Replica, slot, "replica-" + std::to_string(slot),
        static_cast<std::uint8_t>(0x30 + slot), ordinal++);
  for (std::uint32_t n = 0; n < 1014; ++n)
    add(ParticipantRole::Adapter, 0, "adapter-" + std::to_string(n), 0x66, ordinal++);
  add(ParticipantRole::Witness, 0, "witness", 0x77, ordinal++);
  CHECK(plan.participants.size() == kMaxParticipants);
  return plan;
}

BootstrapPlan MakePlanOrdinal(std::uint16_t ordinal) {
  BootstrapPlan plan = MakePlan(0x30);
  plan.epoch_id.fill(0);
  plan.epoch_id[0] = 0x30;
  plan.epoch_id[1] = static_cast<std::uint8_t>(ordinal >> 8);
  plan.epoch_id[2] = static_cast<std::uint8_t>(ordinal & 0xff);
  for (std::size_t index = 0; index < plan.participants.size(); ++index)
    plan.participants[index].container_id = ContainerId(0x30,
        (static_cast<std::uint64_t>(ordinal) << 32) | index);
  return plan;
}

void CreateOwnerOnly(const std::string& root, const RuntimeDomainId& domain) {
  auto result = RuntimeOwner::CreateNew(root, domain);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(result));
  std::get<std::unique_ptr<RuntimeOwner>>(result).reset();
}

void WriteInventoryDirectory(const std::string& root, const BootstrapPlan& plan) {
  const auto child = root + "/" + EpochName(plan.epoch_id);
  CHECK(::mkdir(child.c_str(), 0700) == 0);
  auto model = BootstrapInventory::Create(plan);
  CHECK(std::holds_alternative<BootstrapInventory>(model));
  auto encoded = EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(model));
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto intent = child + "/intent.json";
  { std::ofstream out(intent, std::ios::binary); out << std::get<std::string>(encoded); }
  CHECK(::chmod(intent.c_str(), 0600) == 0);
}

void TestAggregateParticipantLimitRetainsPriorInventories() {
  TempRoot temp;
  const auto first = MakeMaxParticipantPlan(0x11);
  CreateOwnerOnly(temp.root, first.domain_id);
  for (std::uint8_t n = 0x11; n < 0x22; ++n)
    WriteInventoryDirectory(temp.root, MakeMaxParticipantPlan(n));
  auto owner = OpenRecoveryOwner(temp, first);
  const auto result = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 17);
  CHECK(std::count_if(snapshot->epochs.begin(), snapshot->epochs.end(),
      [](const auto& epoch) { return epoch.inventory != nullptr; }) == 16);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::AggregateParticipantLimit));
}

struct ReadIntentCounter final : IRecoveryReaderIo {
  std::size_t reads{};
  bool FailAt(RecoveryReaderIoPoint point) noexcept override {
    if (point == RecoveryReaderIoPoint::ReadIntent) ++reads;
    return false;
  }
};

void TestAggregateByteLimitIsReservedBeforeRead() {
  TempRoot temp;
  const auto valid = MakePlan(0x11);
  CreateOwnerOnly(temp.root, valid.domain_id);
  WriteInventoryDirectory(temp.root, valid);
  const std::string invalid(4U * 1024U * 1024U, 'x');
  for (std::uint8_t n = 0x21; n < 0x31; ++n) {
    const auto child = temp.root + "/" + EpochName(MakePlan(n).epoch_id);
    CHECK(::mkdir(child.c_str(), 0700) == 0);
    const auto intent = child + "/intent.json";
    { std::ofstream out(intent, std::ios::binary); out.write(invalid.data(), static_cast<std::streamsize>(invalid.size())); }
    CHECK(::chmod(intent.c_str(), 0600) == 0);
  }
  auto owner = OpenRecoveryOwner(temp, valid);
  ReadIntentCounter counter;
  const auto result = BootstrapRecoveryReader::Read(*owner, &counter);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(!snapshot->epochs.empty() && snapshot->epochs.front().inventory != nullptr);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::AggregateByteLimit));
  CHECK(counter.reads < 17);  // The next over-budget file is rejected before reading.
}

void TestEpochDirectoryLimitRetainsEarlierInventory() {
  TempRoot temp;
  const auto valid = MakePlan(0x11);
  CreateOwnerOnly(temp.root, valid.domain_id);
  WriteInventoryDirectory(temp.root, valid);
  for (std::uint16_t n = 0; n < kMaxRecoveryEpochDirectories; ++n) {
    const auto plan = MakePlanOrdinal(n);
    WriteInventoryDirectory(temp.root, plan);
  }
  auto owner = OpenRecoveryOwner(temp, valid);
  const auto result = BootstrapRecoveryReader::Read(*owner);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  const auto snapshot = std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result);
  CHECK(!snapshot->scan_complete);
  CHECK(!snapshot->epochs.empty() && snapshot->epochs.front().inventory != nullptr);
  CHECK(HasIssue(*snapshot, RecoveryIssueCode::TooManyEpochDirectories));
}

}  // namespace

int main() {
  TestRecoveryScanRetainsPendingRosterAndCanRepeat();
  TestUnexpectedSiblingDoesNotHideKnownIntent();
  TestUnknownRootEntryDoesNotHideKnownIntent();
  TestEmptyAndMissingIntentRemainUnknown();
  TestWrongModeAndInjectedReadFailure();
  TestPostReadModeChangeIsDetected();
  TestCrossEpochContainerCollisionIsReported();
  TestAggregateParticipantLimitRetainsPriorInventories();
  TestAggregateByteLimitIsReservedBeforeRead();
  TestEpochDirectoryLimitRetainsEarlierInventory();
}
