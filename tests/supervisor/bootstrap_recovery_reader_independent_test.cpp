#include "supervisor/bootstrap_recovery_reader.h"
#include "supervisor/bootstrap_store.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
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
    const std::string seed = "/tmp/rateguard-recovery-qa-XXXXXX";
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

std::string EpochDirectory(const std::string& root, const EpochId& epoch) {
  constexpr char digits[] = "0123456789abcdef";
  std::string hex;
  for (auto b : epoch) { hex.push_back(digits[b >> 4]); hex.push_back(digits[b & 15]); }
  return root + "/epoch-" + hex;
}

ObservedBootstrapIdentity Observe(const BootstrapPlan& plan, std::size_t index, std::uint64_t pid) {
  return ObservedBootstrapIdentity{plan.participants[index], pid, pid + 1000,
                                   plan.expected_clock_identity};
}

std::array<std::uint8_t, 32> Digest(const BootstrapInventory& inventory) {
  const auto result = BootstrapDigestV1(inventory);
  CHECK((std::holds_alternative<std::array<std::uint8_t, 32>>(result)));
  return std::get<std::array<std::uint8_t, 32>>(result);
}

// Populate one durable bootstrap inventory, then close all fresh-owner handles
// so the reader receives only an OpenExisting recovery-mode RuntimeOwner.
void CreateArtifacts(const std::string& root, const BootstrapPlan& plan, bool complete = false) {
  auto owner_result = RuntimeOwner::CreateNew(root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(owner_result));
  auto claim_result = owner->ClaimInitialEpoch(plan.epoch_id);
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  auto store_result = BootstrapStore::CreateNew(std::move(std::get<InitialEpochClaim>(claim_result)), plan);
  CHECK(store_result.ok());
  CHECK(store_result.visibility == BootstrapVisibility::Durable);
  auto store = std::move(store_result.store);
  if (complete) {
    auto snapshot = store->Snapshot();
    for (std::size_t i = 0; i < plan.participants.size(); ++i) {
      auto updated = store->RecordIdentity(snapshot->revision(), Digest(*snapshot), Observe(plan, i, 100 + i));
      CHECK(updated.store_error == BootstrapStoreError::None);
      CHECK(updated.visibility == BootstrapVisibility::Durable);
      snapshot = std::move(updated.snapshot);
    }
  }
  store.reset();
  owner.reset();
}

std::unique_ptr<RuntimeOwner> OpenRecoveryOwner(const std::string& root, const BootstrapPlan& plan) {
  auto opened = RuntimeOwner::OpenExisting(root, plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(opened));
  auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(opened));
  CHECK(owner->mode() == RuntimeOwnerMode::RecoveryRequired);
  return owner;
}

std::shared_ptr<const BootstrapRecoverySnapshot> ReadRecovery(const RuntimeOwner& owner,
                                                               IRecoveryReaderIo* hooks = nullptr) {
  auto result = BootstrapRecoveryReader::Read(owner, hooks);
  CHECK(std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result));
  return std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(std::move(result));
}

bool HasIssue(const std::vector<RecoveryIssue>& issues, RecoveryIssueCode code) {
  return std::any_of(issues.begin(), issues.end(), [code](const auto& issue) { return issue.code == code; });
}
bool HasEpochIssue(const RecoveryEpochDiagnostic& epoch, RecoveryIssueCode code) {
  return std::find(epoch.issues.begin(), epoch.issues.end(), code) != epoch.issues.end();
}

struct FailOne final : IRecoveryReaderIo {
  RecoveryReaderIoPoint point;
  bool consumed{};
  explicit FailOne(RecoveryReaderIoPoint p) : point(p) {}
  bool FailAt(RecoveryReaderIoPoint candidate) noexcept override {
    if (!consumed && candidate == point) { consumed = true; return true; }
    return false;
  }
};

struct ActionOnce final : IRecoveryReaderIo {
  RecoveryReaderIoPoint point;
  bool consumed{};
  std::function<void()> action;
  ActionOnce(RecoveryReaderIoPoint p, std::function<void()> fn)
      : point(p), action(std::move(fn)) {}
  bool FailAt(RecoveryReaderIoPoint candidate) noexcept override {
    if (!consumed && candidate == point) {
      consumed = true;
      action();
    }
    return false;
  }
};

void WriteInventoryArtifact(const std::string& root, const BootstrapPlan& plan, bool complete,
                            std::uint64_t pid_base = 100) {
  const auto directory = EpochDirectory(root, plan.epoch_id);
  CHECK(::mkdir(directory.c_str(), 0700) == 0);
  auto model = BootstrapInventory::Create(plan);
  CHECK(std::holds_alternative<BootstrapInventory>(model));
  auto inventory = std::get<BootstrapInventory>(std::move(model));
  if (complete) {
    for (std::size_t i = 0; i < plan.participants.size(); ++i)
      inventory = inventory.RecordIdentity(Observe(plan, i, pid_base + i)).next;
  }
  auto encoded = EncodeBootstrapInventoryV1(inventory);
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto& bytes = std::get<std::string>(encoded);
  const auto path = directory + "/intent.json";
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  out.close();
  CHECK(out.good());
  CHECK(::chmod(path.c_str(), 0600) == 0);
}

void TestPendingAndCompleteAreStructuralDiagnosticsOnly() {
  for (const bool complete : {false, true}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, complete);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(snapshot->domain_id == plan.domain_id);
    CHECK(snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    const auto& epoch = snapshot->epochs.front();
    CHECK(epoch.directory_name == "epoch-11111111111111111111111111111111");
    CHECK(epoch.inventory != nullptr);
    CHECK(epoch.canonical_digest.has_value());
    CHECK(epoch.inventory->recorded_count() == (complete ? plan.participants.size() : 0));
    CHECK(epoch.inventory->epoch_id() == plan.epoch_id);
    CHECK(epoch.inventory->expected_clock_identity() == plan.expected_clock_identity);
    CHECK(snapshot->issues.empty());
    // This type has only diagnostic fields; neither scan_complete nor decoded
    // inventory is an EpochCandidate/permission to activate or reset.
  }
}

void TestReaderRequiresRecoveryModeAndDoesNotModifyFiles() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto recovery = OpenRecoveryOwner(temp.root, plan);
  const auto dir = EpochDirectory(temp.root, plan.epoch_id);
  const auto intent = dir + "/intent.json";
  const auto before = std::filesystem::last_write_time(intent);
  std::ifstream in(intent, std::ios::binary);
  const std::string bytes((std::istreambuf_iterator<char>(in)), {});
  in.close();
  auto first = ReadRecovery(*recovery);
  auto second = ReadRecovery(*recovery);
  CHECK(first->scan_complete && second->scan_complete);
  CHECK(first->epochs.front().inventory->revision() == second->epochs.front().inventory->revision());
  CHECK(first->epochs.front().canonical_digest == second->epochs.front().canonical_digest);
  CHECK(std::filesystem::last_write_time(intent) == before);
  std::ifstream after_in(intent, std::ios::binary);
  CHECK(std::string((std::istreambuf_iterator<char>(after_in)), {}) == bytes);

  auto fresh_result = RuntimeOwner::CreateNew(temp.parent + "/fresh", plan.domain_id);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(fresh_result));
  auto fresh = std::move(std::get<std::unique_ptr<RuntimeOwner>>(fresh_result));
  auto rejected = BootstrapRecoveryReader::Read(*fresh);
  CHECK(std::holds_alternative<RecoveryReaderFatal>(rejected));
  CHECK(std::get<RecoveryReaderFatal>(rejected) == RecoveryReaderFatal::OwnerNotRecoveryMode);
}

void TestUnknownAndTemporaryChildArtifactsPreserveKnownInventory() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  const auto dir = EpochDirectory(temp.root, plan.epoch_id);
  { std::ofstream out(dir + "/intent.tmp", std::ios::binary); out << "pending"; }
  { std::ofstream out(dir + "/operator-note", std::ios::binary); out << "unknown"; }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().inventory->recorded_count() == plan.participants.size());
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::EpochHasUnexpectedEntry));
}

void TestUnknownRootEntryPreservesKnownEpochWithoutExposingRawName() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  { std::ofstream out(temp.root + "/unexpected-secret-label"); out << "x"; }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1 && snapshot->epochs.front().inventory != nullptr);
  CHECK(HasIssue(snapshot->issues, RecoveryIssueCode::UnexpectedRootEntry));
  for (const auto& issue : snapshot->issues) {
    (void)issue;
  }
}

void TestIssueCapIsBoundedAndKnownIntentIsRetained() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  for (std::size_t i = 0; i < kMaxRecoveryIssues + 8; ++i) {
    std::ofstream out(temp.root + "/unexpected-" + std::to_string(i));
    out << "x";
  }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->issues.size() <= kMaxRecoveryIssues);
  CHECK(snapshot->issues_truncated);
  CHECK(!snapshot->epochs.empty());
  CHECK(snapshot->epochs.front().inventory != nullptr);
}

void TestRootEntryCapIsBoundedAndKeepsSortedKnownIntent() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  for (std::size_t i = 0; i < kMaxRecoveryRootEntries + 2; ++i) {
    std::ofstream out(temp.root + "/overflow-" + std::to_string(i));
    out << "x";
  }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(HasIssue(snapshot->issues, RecoveryIssueCode::TooManyRootEntries));
  CHECK(snapshot->issues.size() <= kMaxRecoveryIssues);
  for (const auto& epoch : snapshot->epochs) {
    if (epoch.inventory != nullptr) {
      CHECK(epoch.canonical_digest.has_value());
      CHECK(epoch.inventory->epoch_id() != EpochId{});
    }
  }
}

void TestEpochDirectoryCapStopsBoundedScan() {
  TempRoot temp;
  const auto plan = MakePlan(0x70);
  CreateArtifacts(temp.root, plan, true);
  for (std::uint32_t i = 1; i <= kMaxRecoveryEpochDirectories; ++i) {
    EpochId id{};
    id[12] = static_cast<std::uint8_t>((i >> 24) & 0xffU);
    id[13] = static_cast<std::uint8_t>((i >> 16) & 0xffU);
    id[14] = static_cast<std::uint8_t>((i >> 8) & 0xffU);
    id[15] = static_cast<std::uint8_t>(i & 0xffU);
    CHECK(::mkdir(EpochDirectory(temp.root, id).c_str(), 0700) == 0);
  }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() <= kMaxRecoveryEpochDirectories);
  CHECK(snapshot->issues.size() <= kMaxRecoveryIssues);
  CHECK(snapshot->issues_truncated);
  for (const auto& epoch : snapshot->epochs)
    if (epoch.inventory) CHECK(epoch.canonical_digest.has_value());
}

void TestAggregateReadByteCapRetainsEarlierValidInventory() {
  TempRoot temp;
  const auto valid = MakePlan(0x01);  // sorts before the malformed large artifacts
  CreateArtifacts(temp.root, valid, true);
  constexpr std::size_t chunk = kMaxBootstrapBytes;
  const auto chunks = kMaxRecoveryAggregateBytes / chunk;
  for (std::size_t i = 2; i < 2 + chunks; ++i) {
    EpochId id{};
    id.fill(0x02);
    id[15] = static_cast<std::uint8_t>(i);
    const auto dir = EpochDirectory(temp.root, id);
    CHECK(::mkdir(dir.c_str(), 0700) == 0);
    const auto intent = dir + "/intent.json";
    { std::ofstream out(intent, std::ios::binary); out.put('{'); }
    CHECK(::chmod(intent.c_str(), 0600) == 0);
    std::filesystem::resize_file(intent, chunk);
  }
  auto owner = OpenRecoveryOwner(temp.root, valid);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.back(), RecoveryIssueCode::AggregateByteLimit) ||
        HasIssue(snapshot->issues, RecoveryIssueCode::AggregateByteLimit));
  CHECK(snapshot->epochs.front().inventory->epoch_id() == valid.epoch_id);
}

void TestMissingCorruptAndWrongBindingArtifactsAreIncomplete() {
  for (const int mode : {0, 1, 2, 3}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    const auto dir = EpochDirectory(temp.root, plan.epoch_id);
    const auto intent = dir + "/intent.json";
    if (mode == 0) CHECK(::unlink(intent.c_str()) == 0);
    if (mode == 1) { std::ofstream out(intent, std::ios::binary | std::ios::trunc); out << "{"; }
    if (mode >= 2) {
      auto wrong = MakePlan(mode == 2 ? 0x11 : 0x12);
      if (mode == 2)
        wrong.domain_id[0] ^= 0x55;
      else {
        const auto moved = dir + ".moved";
        CHECK(::rename(dir.c_str(), moved.c_str()) == 0);
        CHECK(::mkdir(dir.c_str(), 0700) == 0);
      }
      auto model = BootstrapInventory::Create(wrong);
      CHECK(std::holds_alternative<BootstrapInventory>(model));
      auto encoded = EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(model));
      CHECK(std::holds_alternative<std::string>(encoded));
      std::ofstream out(intent, std::ios::binary | std::ios::trunc);
      const auto& bytes = std::get<std::string>(encoded);
      out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
      out.close();
      CHECK(out.good());
      CHECK(::chmod(intent.c_str(), 0600) == 0);
    }
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    if (mode == 0) {
      CHECK(snapshot->epochs.front().inventory == nullptr);
      CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::MissingIntent));
    } else if (mode == 1) {
      CHECK(snapshot->epochs.front().inventory == nullptr);
      CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::InvalidEncoding));
    } else if (mode == 2) {
      CHECK(snapshot->epochs.front().inventory == nullptr);
      CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::DomainMismatch));
    } else {
      CHECK(snapshot->epochs.front().inventory == nullptr);
      CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::EpochMismatch));
    }
  }
}

void TestDuplicateContainerAcrossEpochsIsReportedWithoutChoosingLatest() {
  TempRoot temp;
  const auto first = MakePlan(0x11);
  CreateArtifacts(temp.root, first, true);
  const auto second = MakePlan(0x12);
  WriteInventoryArtifact(temp.root, second, true, 100);  // duplicate process and container identities
  auto owner = OpenRecoveryOwner(temp.root, first);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 2);
  CHECK(snapshot->epochs[0].inventory != nullptr && snapshot->epochs[1].inventory != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs[0], RecoveryIssueCode::IdentityCollisionAcrossEpochs) ||
        HasEpochIssue(snapshot->epochs[1], RecoveryIssueCode::IdentityCollisionAcrossEpochs));
}

void TestRootEntryChangesDuringScanAreReported() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto owner = OpenRecoveryOwner(temp.root, plan);
  ActionOnce hook(RecoveryReaderIoPoint::EnumerateRootSecond, [&] {
    std::ofstream out(temp.root + "/arrived-during-scan");
    out << "x";
  });
  auto snapshot = ReadRecovery(*owner, &hook);
  CHECK(hook.consumed);
  CHECK(!snapshot->scan_complete);
  CHECK(HasIssue(snapshot->issues, RecoveryIssueCode::RootChangedDuringScan));
  CHECK(snapshot->epochs.size() == 1 && snapshot->epochs.front().inventory != nullptr);
}

void TestIntentReplacementDuringReadIsIncomplete() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  const auto intent = EpochDirectory(temp.root, plan.epoch_id) + "/intent.json";
  auto owner = OpenRecoveryOwner(temp.root, plan);
  ActionOnce hook(RecoveryReaderIoPoint::RevalidateEntry, [&] {
    const auto replacement = intent + ".replacement";
    { std::ofstream out(replacement, std::ios::binary | std::ios::trunc); out << "replacement"; }
    CHECK(::chmod(replacement.c_str(), 0600) == 0);
    CHECK(::rename(replacement.c_str(), intent.c_str()) == 0);
  });
  auto snapshot = ReadRecovery(*owner, &hook);
  CHECK(hook.consumed);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1);
  CHECK(snapshot->epochs.front().inventory == nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::IntentChanged));
}

void TestUnsafeFileTypesDoNotBlockAndPreserveOtherRecords() {
  for (const bool use_symlink : {false, true}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    const auto dir = EpochDirectory(temp.root, plan.epoch_id);
    const auto intent = dir + "/intent.json";
    CHECK(::unlink(intent.c_str()) == 0);
    if (use_symlink) CHECK(::symlink("/etc/passwd", intent.c_str()) == 0);
    else CHECK(::mkfifo(intent.c_str(), 0600) == 0);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    CHECK(snapshot->epochs.front().inventory == nullptr);
    CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::InvalidIntentFile));
  }
}

void TestHardLinkedIntentIsRejected() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  const auto dir = EpochDirectory(temp.root, plan.epoch_id);
  CHECK(::link((dir + "/intent.json").c_str(), (dir + "/second-link").c_str()) == 0);
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1);
  CHECK(snapshot->epochs.front().inventory == nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::EpochHasUnexpectedEntry));
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::InvalidIntentFile));
}

void TestBoundedChildEntriesRetainDecodedInventory() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  const auto dir = EpochDirectory(temp.root, plan.epoch_id);
  for (std::size_t i = 0; i < kMaxRecoveryChildEntries; ++i) {
    std::ofstream out(dir + "/extra-" + std::to_string(i));
    out << "x";
  }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::TooManyChildEntries));
  CHECK(snapshot->epochs.front().issues.size() <= kMaxRecoveryEpochIssues);
  CHECK(snapshot->epochs.front().issues_truncated);
  CHECK(snapshot->issues.size() <= kMaxRecoveryIssues);
}

void TestReadFaultsNeverProduceCompleteSnapshot() {
  const std::array points{
      RecoveryReaderIoPoint::ValidateOwnerBefore,
      RecoveryReaderIoPoint::DuplicateRoot,
      RecoveryReaderIoPoint::EnumerateRootFirst,
      RecoveryReaderIoPoint::EnumerateRootSecond,
      RecoveryReaderIoPoint::StatRootEntry,
      RecoveryReaderIoPoint::OpenEpochDirectory,
      RecoveryReaderIoPoint::EnumerateEpoch,
      RecoveryReaderIoPoint::StatIntent,
      RecoveryReaderIoPoint::OpenIntent,
      RecoveryReaderIoPoint::ReadIntent,
      RecoveryReaderIoPoint::RevalidateEntry,
      RecoveryReaderIoPoint::ValidateOwnerAfter,
  };
  for (const auto point : points) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    FailOne hook(point);
    auto result = BootstrapRecoveryReader::Read(*owner, &hook);
    CHECK(hook.consumed);
    if (std::holds_alternative<std::shared_ptr<const BootstrapRecoverySnapshot>>(result))
      CHECK(!std::get<std::shared_ptr<const BootstrapRecoverySnapshot>>(result)->scan_complete);
    else
      CHECK(std::get<RecoveryReaderFatal>(result) != RecoveryReaderFatal::OwnerNotRecoveryMode);
  }
}

}  // namespace

int main() {
  TestPendingAndCompleteAreStructuralDiagnosticsOnly();
  TestReaderRequiresRecoveryModeAndDoesNotModifyFiles();
  TestUnknownAndTemporaryChildArtifactsPreserveKnownInventory();
  TestUnknownRootEntryPreservesKnownEpochWithoutExposingRawName();
  TestIssueCapIsBoundedAndKnownIntentIsRetained();
  TestRootEntryCapIsBoundedAndKeepsSortedKnownIntent();
  TestEpochDirectoryCapStopsBoundedScan();
  TestAggregateReadByteCapRetainsEarlierValidInventory();
  TestMissingCorruptAndWrongBindingArtifactsAreIncomplete();
  TestDuplicateContainerAcrossEpochsIsReportedWithoutChoosingLatest();
  TestRootEntryChangesDuringScanAreReported();
  TestIntentReplacementDuringReadIsIncomplete();
  TestUnsafeFileTypesDoNotBlockAndPreserveOtherRecords();
  TestHardLinkedIntentIsRejected();
  TestBoundedChildEntriesRetainDecodedInventory();
  TestReadFaultsNeverProduceCompleteSnapshot();
  return 0;
}
