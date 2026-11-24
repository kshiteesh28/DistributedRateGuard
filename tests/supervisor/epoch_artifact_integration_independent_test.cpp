#include "supervisor/bootstrap_recovery_reader.h"
#include "supervisor/bootstrap_store.h"
#include "supervisor/manifest_store.h"

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

BootstrapPlan MakeLargePlan(std::uint8_t epoch_byte, std::size_t participant_count,
                           std::uint64_t container_base) {
  BootstrapPlan plan = MakePlan(epoch_byte);
  plan.participants.clear();
  constexpr char hex[] = "0123456789abcdef";
  auto add = [&](ParticipantRole role, std::uint32_t slot, std::string id,
                 std::uint8_t incarnation, std::size_t local_index) {
    PlannedParticipant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = std::move(id);
    p.incarnation.fill(incarnation);
    p.container_id.assign(64, '0');
    const auto unique = container_base + local_index;
    for (std::size_t n = 0; n < 16; ++n) {
      const auto shift = static_cast<unsigned>((15 - n) * 4);
      p.container_id[48 + n] = hex[(unique >> shift) & 0xfU];
    }
    plan.participants.push_back(std::move(p));
  };
  add(ParticipantRole::Authority, 0, "authority", 0x22, 0);
  for (std::uint32_t i = 0; i < 8; ++i)
    add(ParticipantRole::Replica, i, "replica-" + std::to_string(i), 0x55, 1 + i);
  const std::size_t adapter_count = participant_count - 10;
  for (std::size_t i = 0; i < adapter_count; ++i)
    add(ParticipantRole::Adapter, 0, "adapter-" + std::to_string(i), 0x66, 9 + i);
  add(ParticipantRole::Witness, 0, "witness", 0x77, 9 + adapter_count);
  CHECK(plan.participants.size() == participant_count);
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

OperationId Operation(std::uint8_t value) {
  OperationId id{};
  id.fill(value);
  return id;
}

EpochCandidate CandidateFor(const BootstrapPlan& plan, std::uint64_t pid_base = 100) {
  auto result = BootstrapInventory::Create(plan);
  CHECK(std::holds_alternative<BootstrapInventory>(result));
  auto inventory = std::get<BootstrapInventory>(std::move(result));
  for (std::size_t i = 0; i < plan.participants.size(); ++i)
    inventory = inventory.RecordIdentity(Observe(plan, i, pid_base + i)).next;
  auto candidate = inventory.ReadyCandidate();
  CHECK(std::holds_alternative<EpochCandidate>(candidate));
  return std::get<EpochCandidate>(std::move(candidate));
}

void CreateLayoutWithInventoryAndManifest(const std::string& root, const BootstrapPlan& plan,
                                          std::uint64_t pid_base, std::uint8_t operation_byte) {
  auto created = BootstrapInventory::Create(plan);
  CHECK(std::holds_alternative<BootstrapInventory>(created));
  auto inventory = std::get<BootstrapInventory>(std::move(created));
  for (std::size_t i = 0; i < plan.participants.size(); ++i)
    inventory = inventory.RecordIdentity(Observe(plan, i, pid_base + i)).next;
  auto ready = inventory.ReadyCandidate();
  CHECK(std::holds_alternative<EpochCandidate>(ready));
  auto encoded = EncodeBootstrapInventoryV1(inventory);
  CHECK(std::holds_alternative<std::string>(encoded));
  const auto epoch_dir = EpochDirectory(root, plan.epoch_id);
  CHECK(::mkdir(epoch_dir.c_str(), 0700) == 0);
  const auto intent = epoch_dir + "/intent.json";
  {
    std::ofstream out(intent, std::ios::binary);
    const auto& bytes = std::get<std::string>(encoded);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  CHECK(::chmod(intent.c_str(), 0600) == 0);
  const auto manifest_dir = epoch_dir + "/manifest-store";
  auto operation = Operation(operation_byte);
  auto manifest = ManifestStore::CreateNew(manifest_dir, std::get<EpochCandidate>(ready), operation);
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(manifest));
}

std::unique_ptr<ManifestStore> CreateManifestAt(const std::string& root,
                                                const BootstrapPlan& plan,
                                                ManifestPhase phase = ManifestPhase::Prepared,
                                                bool alter_policy = false,
                                                bool alter_epoch = false,
                                                bool alter_identity = false) {
  auto candidate = CandidateFor(plan);
  if (alter_policy) candidate.policy_digest[0] ^= 0xff;
  if (alter_epoch) candidate.epoch_id[0] ^= 0x80;
  if (alter_identity) candidate.participants.front().process.container_id.back() = 'f';
  const auto path = EpochDirectory(root, plan.epoch_id) + "/manifest-store";
  auto result = ManifestStore::CreateNew(path, candidate, Operation(0x81));
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(result));
  auto store = std::move(std::get<std::unique_ptr<ManifestStore>>(result));
  std::uint8_t op = 0x82;
  while (store->snapshot().phase != phase) {
    const auto current = store->snapshot();
    ManifestPhase next{};
    switch (current.phase) {
      case ManifestPhase::Prepared: next = ManifestPhase::Active; break;
      case ManifestPhase::Active: next = ManifestPhase::Draining; break;
      case ManifestPhase::Draining: next = ManifestPhase::Closed; break;
      case ManifestPhase::Closed: CHECK(false); break;
    }
    const auto updated = store->Transition(current.generation, store->digest(), next, Operation(op++));
    CHECK(updated.visibility == ManifestVisibility::Durable);
    CHECK(!updated.error.has_value());
  }
  return store;
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

void TestManifestStoreIsOptionalAndAllPhasesAreDiagnostic() {
  {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    CHECK(!snapshot->epochs.front().manifest_store.has_value());
  }
  for (const auto phase : {ManifestPhase::Prepared, ManifestPhase::Active,
                           ManifestPhase::Draining, ManifestPhase::Closed}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto manifest_store = CreateManifestAt(temp.root, plan, phase);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    const auto& epoch = snapshot->epochs.front();
    CHECK(epoch.inventory != nullptr);
    CHECK(epoch.manifest_store.has_value());
    CHECK(epoch.manifest_store->decoded_manifest != nullptr);
    CHECK(epoch.manifest_store->canonical_digest.has_value());
    CHECK(epoch.manifest_store->decoded_manifest->phase == phase);
    CHECK(epoch.manifest_store->decoded_manifest->candidate.epoch_id == plan.epoch_id);
    CHECK(epoch.manifest_store->decoded_manifest->candidate.policy_digest == plan.policy_digest);
    CHECK(!HasEpochIssue(epoch, RecoveryIssueCode::IdentityCollisionAcrossEpochs));
    // A readable manifest phase is historical data. It does not activate,
    // adopt, close, or otherwise authorize the recovery-mode runtime.
    (void)manifest_store;
  }
}

void TestValidManifestSurvivesPendingOrInvalidBootstrapIntent() {
  for (const int kind : {0, 1, 2}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, kind != 0);
    auto manifest_store = CreateManifestAt(temp.root, plan, ManifestPhase::Active);
    const auto intent = EpochDirectory(temp.root, plan.epoch_id) + "/intent.json";
    if (kind == 1) { std::ofstream out(intent, std::ios::binary | std::ios::trunc); out << "invalid"; }
    if (kind == 2) CHECK(::unlink(intent.c_str()) == 0);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete || kind == 0);
    CHECK(snapshot->epochs.size() == 1);
    const auto& epoch = snapshot->epochs.front();
    CHECK(epoch.manifest_store.has_value());
    CHECK(epoch.manifest_store->decoded_manifest != nullptr);
    CHECK(epoch.manifest_store->decoded_manifest->phase == ManifestPhase::Active);
    if (kind == 0) {
      CHECK(epoch.inventory != nullptr);
      CHECK(epoch.inventory->recorded_count() == 0);
      CHECK(!HasEpochIssue(epoch, RecoveryIssueCode::ManifestCandidateMismatch));
      CHECK(HasEpochIssue(epoch, RecoveryIssueCode::ManifestBootstrapNotReady));
    } else {
      CHECK(epoch.inventory == nullptr);
      CHECK(HasEpochIssue(epoch, kind == 1 ? RecoveryIssueCode::InvalidEncoding
                                           : RecoveryIssueCode::MissingIntent));
    }
    (void)manifest_store;
  }
}

void TestManifestCandidateMismatchIsReportedButDecodedDataIsKept() {
  for (const int field : {0, 1, 2}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto manifest_store = CreateManifestAt(temp.root, plan, ManifestPhase::Closed,
                                            field == 0, field == 1, field == 2);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    const auto& epoch = snapshot->epochs.front();
    CHECK(epoch.inventory != nullptr);
    CHECK(epoch.manifest_store.has_value());
    CHECK(epoch.manifest_store->decoded_manifest != nullptr);
    CHECK(epoch.manifest_store->decoded_manifest->phase == ManifestPhase::Closed);
    CHECK(HasEpochIssue(epoch, RecoveryIssueCode::ManifestCandidateMismatch));
    if (field == 0)
      CHECK(epoch.manifest_store->decoded_manifest->candidate.policy_digest[0] != plan.policy_digest[0]);
    if (field == 1)
      CHECK(epoch.manifest_store->decoded_manifest->candidate.epoch_id != plan.epoch_id);
    if (field == 2)
      CHECK(epoch.manifest_store->decoded_manifest->candidate.participants.front().process.container_id !=
            plan.participants.front().container_id);
    (void)manifest_store;
  }
}

void TestInvalidManifestArtifactsDoNotHideBootstrapInventory() {
  for (const int mode : {0, 1, 2, 3, 4}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto manifest_store = CreateManifestAt(temp.root, plan);
    const auto dir = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store";
    if (mode == 0) CHECK(::unlink((dir + "/owner.lock").c_str()) == 0);
    if (mode == 1) CHECK(::unlink((dir + "/manifest.json").c_str()) == 0);
    if (mode == 2) { std::ofstream out(dir + "/manifest.tmp"); out << "pending"; }
    if (mode == 3 || mode == 4) CHECK(::unlink((dir + "/manifest.json").c_str()) == 0);
    if (mode == 3) CHECK(::symlink("/etc/passwd", (dir + "/manifest.json").c_str()) == 0);
    if (mode == 4) CHECK(::mkfifo((dir + "/manifest.json").c_str(), 0600) == 0);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    const auto& epoch = snapshot->epochs.front();
    CHECK(epoch.inventory != nullptr);
    CHECK(epoch.manifest_store.has_value());
    if (mode == 0 || mode == 2) {
      CHECK(epoch.manifest_store->decoded_manifest != nullptr);
      if (mode == 2) CHECK(HasEpochIssue(epoch, RecoveryIssueCode::ManifestStoreHasUnexpectedEntry));
    } else {
      CHECK(!epoch.manifest_store->decoded_manifest);
    }
    if (mode == 0 || mode == 1) CHECK(HasEpochIssue(epoch, RecoveryIssueCode::MissingManifestStoreFile));
    if (mode == 3 || mode == 4) CHECK(HasEpochIssue(epoch, RecoveryIssueCode::InvalidManifestStoreFile));
    (void)manifest_store;
  }
}

void TestManifestHardlinkAndModeAreRejected() {
  for (const bool use_hardlink : {false, true}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto manifest_store = CreateManifestAt(temp.root, plan);
    const auto dir = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store";
    const auto manifest = dir + "/manifest.json";
    if (use_hardlink) CHECK(::link(manifest.c_str(), (dir + "/extra-link").c_str()) == 0);
    else CHECK(::chmod(manifest.c_str(), 0644) == 0);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.front().inventory != nullptr);
    CHECK(snapshot->epochs.front().manifest_store.has_value());
    CHECK(!snapshot->epochs.front().manifest_store->decoded_manifest);
    CHECK(HasEpochIssue(snapshot->epochs.front(), use_hardlink
        ? RecoveryIssueCode::ManifestStoreHasUnexpectedEntry
        : RecoveryIssueCode::InvalidManifestStoreFile));
    (void)manifest_store;
  }
}

void TestNonemptyOwnerLockIsIncompleteButManifestIsRetained() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto manifest_store = CreateManifestAt(temp.root, plan);
  const auto lock = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store/owner.lock";
  { std::ofstream out(lock, std::ios::binary | std::ios::trunc); out << "unexpected"; }
  CHECK(::chmod(lock.c_str(), 0600) == 0);
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().manifest_store.has_value());
  CHECK(snapshot->epochs.front().manifest_store->decoded_manifest != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::InvalidManifestStoreFile));
  (void)manifest_store;
}

void TestNestedReadHooksFailClosedWithoutLosingBootstrapDiagnostic() {
  const std::array points{
      RecoveryReaderIoPoint::OpenManifestStoreDirectory,
      RecoveryReaderIoPoint::EnumerateManifestStore,
      RecoveryReaderIoPoint::StatManifestStoreEntry,
      RecoveryReaderIoPoint::OpenManifestLock,
      RecoveryReaderIoPoint::RevalidateManifestLock,
      RecoveryReaderIoPoint::OpenManifestFile,
      RecoveryReaderIoPoint::ReadManifestFile,
      RecoveryReaderIoPoint::RevalidateManifestFile,
      RecoveryReaderIoPoint::RevalidateManifestStore,
  };
  for (const auto point : points) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto manifest_store = CreateManifestAt(temp.root, plan);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    FailOne hook(point);
    auto snapshot = ReadRecovery(*owner, &hook);
    CHECK(hook.consumed);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    CHECK(snapshot->epochs.front().inventory != nullptr);
    (void)manifest_store;
  }
}

void TestNestedListingMutationRetainsDecodedManifestButMarksIncomplete() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto manifest_store = CreateManifestAt(temp.root, plan);
  const auto store_dir = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store";
  auto owner = OpenRecoveryOwner(temp.root, plan);
  ActionOnce hook(RecoveryReaderIoPoint::EnumerateManifestStore, [&] {
    std::ofstream out(store_dir + "/manifest.tmp");
    out << "new temp artifact";
  });
  auto snapshot = ReadRecovery(*owner, &hook);
  CHECK(hook.consumed);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().manifest_store.has_value());
  CHECK(snapshot->epochs.front().manifest_store->decoded_manifest != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::ManifestStoreHasUnexpectedEntry) ||
        HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::ManifestStoreChanged));
  (void)manifest_store;
}

void TestManifestReplacementDuringFileRevalidationIsNotKnown() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto manifest_store = CreateManifestAt(temp.root, plan);
  const auto path = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store/manifest.json";
  auto owner = OpenRecoveryOwner(temp.root, plan);
  ActionOnce hook(RecoveryReaderIoPoint::RevalidateManifestFile, [&] {
    const auto replacement = path + ".replacement";
    { std::ofstream out(replacement, std::ios::binary | std::ios::trunc); out << "replaced"; }
    CHECK(::chmod(replacement.c_str(), 0600) == 0);
    CHECK(::rename(replacement.c_str(), path.c_str()) == 0);
  });
  auto snapshot = ReadRecovery(*owner, &hook);
  CHECK(hook.consumed);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().manifest_store.has_value());
  CHECK(!snapshot->epochs.front().manifest_store->decoded_manifest);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::ManifestStoreFileChanged));
  (void)manifest_store;
}

void TestReplacementAfterDecodeRetainsHistoricalManifestAsIncomplete() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto manifest_store = CreateManifestAt(temp.root, plan);
  const auto path = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store/manifest.json";
  auto owner = OpenRecoveryOwner(temp.root, plan);
  ActionOnce hook(RecoveryReaderIoPoint::RevalidateManifestStore, [&] {
    const auto replacement = path + ".replacement";
    { std::ofstream out(replacement, std::ios::binary | std::ios::trunc); out << "replaced"; }
    CHECK(::chmod(replacement.c_str(), 0600) == 0);
    CHECK(::rename(replacement.c_str(), path.c_str()) == 0);
  });
  auto snapshot = ReadRecovery(*owner, &hook);
  CHECK(hook.consumed);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().manifest_store.has_value());
  CHECK(snapshot->epochs.front().manifest_store->decoded_manifest != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::ManifestStoreChanged));
  (void)manifest_store;
}

void TestManifestStoreAppearingDuringIntentReadIsReported() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto owner = OpenRecoveryOwner(temp.root, plan);
  std::unique_ptr<ManifestStore> inserted_manifest;
  ActionOnce hook(RecoveryReaderIoPoint::ReadIntent, [&] {
    inserted_manifest = CreateManifestAt(temp.root, plan, ManifestPhase::Prepared);
  });
  auto snapshot = ReadRecovery(*owner, &hook);
  CHECK(hook.consumed);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.size() == 1);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().manifest_store.has_value());
  CHECK(snapshot->epochs.front().manifest_store->decoded_manifest != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::ManifestStoreChanged));
  (void)inserted_manifest;
}

void TestManifestStoreSymlinkAndFifoDirectoriesAreRejected() {
  for (const bool fifo : {false, true}) {
    TempRoot temp;
    const auto plan = MakePlan();
    CreateArtifacts(temp.root, plan, true);
    auto manifest_store = CreateManifestAt(temp.root, plan);
    manifest_store.reset();
    const auto store_dir = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store";
    std::error_code remove_error;
    std::filesystem::remove_all(store_dir, remove_error);
    CHECK(!remove_error);
    if (fifo) CHECK(::mkfifo(store_dir.c_str(), 0700) == 0);
    else CHECK(::symlink("/tmp", store_dir.c_str()) == 0);
    auto owner = OpenRecoveryOwner(temp.root, plan);
    auto snapshot = ReadRecovery(*owner);
    CHECK(!snapshot->scan_complete);
    CHECK(snapshot->epochs.size() == 1);
    CHECK(snapshot->epochs.front().inventory != nullptr);
    CHECK(snapshot->epochs.front().manifest_store.has_value());
    CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::InvalidManifestStoreDirectory));
  }
}

void TestNestedEntryCapStillReadsAllowlistedFiles() {
  TempRoot temp;
  const auto plan = MakePlan();
  CreateArtifacts(temp.root, plan, true);
  auto manifest_store = CreateManifestAt(temp.root, plan);
  const auto store_dir = EpochDirectory(temp.root, plan.epoch_id) + "/manifest-store";
  for (std::size_t i = 0; i < kMaxRecoveryManifestStoreEntries; ++i) {
    std::ofstream out(store_dir + "/temporary-" + std::to_string(i));
    out << "x";
  }
  auto owner = OpenRecoveryOwner(temp.root, plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(snapshot->epochs.front().manifest_store.has_value());
  CHECK(snapshot->epochs.front().manifest_store->decoded_manifest != nullptr);
  CHECK(HasEpochIssue(snapshot->epochs.front(), RecoveryIssueCode::TooManyManifestStoreEntries));
  (void)manifest_store;
}

void TestBootstrapAndManifestBytesShareAggregateReadBudget() {
  TempRoot temp;
  const auto first = MakePlan(0x01);
  CreateArtifacts(temp.root, first, false);
  const auto chunks = kMaxRecoveryAggregateBytes / kMaxManifestBytes;
  for (std::size_t i = 0; i < chunks; ++i) {
    auto plan = MakePlan(0x02);
    plan.epoch_id.fill(0x02);
    plan.epoch_id[15] = static_cast<std::uint8_t>(i + 1);
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t j = 0; j < plan.participants.size(); ++j) {
      const auto value = 64 + i * plan.participants.size() + j;
      plan.participants[j].container_id[plan.participants[j].container_id.size() - 2] = hex[value >> 4];
      plan.participants[j].container_id.back() = hex[value & 0x0f];
    }
    auto model = BootstrapInventory::Create(plan);
    CHECK(std::holds_alternative<BootstrapInventory>(model));
    auto encoded = EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(model));
    CHECK(std::holds_alternative<std::string>(encoded));
    const auto dir = EpochDirectory(temp.root, plan.epoch_id);
    CHECK(::mkdir(dir.c_str(), 0700) == 0);
    const auto intent = dir + "/intent.json";
    {
      std::ofstream out(intent, std::ios::binary);
      const auto& bytes = std::get<std::string>(encoded);
      out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    CHECK(::chmod(intent.c_str(), 0600) == 0);
    const auto store_dir = dir + "/manifest-store";
    CHECK(::mkdir(store_dir.c_str(), 0700) == 0);
    const auto lock = store_dir + "/owner.lock";
    { std::ofstream out(lock, std::ios::binary); }
    CHECK(::chmod(lock.c_str(), 0600) == 0);
    const auto manifest = store_dir + "/manifest.json";
    { std::ofstream out(manifest, std::ios::binary); out.put('{'); }
    CHECK(::chmod(manifest.c_str(), 0600) == 0);
    std::filesystem::resize_file(manifest, kMaxManifestBytes);
  }
  auto owner = OpenRecoveryOwner(temp.root, first);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(!snapshot->epochs.empty());
  CHECK(snapshot->epochs.front().inventory != nullptr);
  CHECK(HasIssue(snapshot->issues, RecoveryIssueCode::AggregateByteLimit));
  for (const auto& epoch : snapshot->epochs) {
    if (epoch.inventory) CHECK(epoch.canonical_digest.has_value());
    if (epoch.manifest_store && epoch.manifest_store->decoded_manifest)
      CHECK(epoch.manifest_store->canonical_digest.has_value());
  }
}

void TestBootstrapAndManifestRecordsShareAggregateParticipantBudget() {
  TempRoot temp;
  const auto first_plan = MakeLargePlan(0x10, 256, 0x100000);
  {
    auto created = RuntimeOwner::CreateNew(temp.root, first_plan.domain_id);
    CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(created));
    auto owner = std::move(std::get<std::unique_ptr<RuntimeOwner>>(created));
    auto claim = owner->ClaimInitialEpoch(first_plan.epoch_id);
    CHECK(std::holds_alternative<InitialEpochClaim>(claim));
  }

  constexpr std::size_t paired_epochs = kMaxRecoveryAggregateParticipants / (2 * 256);
  static_assert(paired_epochs == 32);
  for (std::size_t i = 0; i < paired_epochs; ++i) {
    const auto epoch_byte = static_cast<std::uint8_t>(0x10 + i);
    auto plan = MakeLargePlan(epoch_byte, 256, 0x100000 + i * 1000);
    CreateLayoutWithInventoryAndManifest(temp.root, plan,
        10'000'000 + i * 1000, epoch_byte);
  }
  // A final valid bootstrap history adds participant records beyond the shared
  // cap. Its inventory must not be presented as retained if the conservative
  // count check stops before retention.
  const auto overflow_plan = MakeLargePlan(0x40, 11, 0x200000);
  CreateLayoutWithInventoryAndManifest(temp.root, overflow_plan, 20'000'000, 0x40);

  auto owner = OpenRecoveryOwner(temp.root, first_plan);
  auto snapshot = ReadRecovery(*owner);
  CHECK(!snapshot->scan_complete);
  CHECK(HasIssue(snapshot->issues, RecoveryIssueCode::AggregateParticipantLimit));
  std::size_t retained_records = 0;
  std::size_t retained_manifest_participants = 0;
  for (const auto& epoch : snapshot->epochs) {
    if (epoch.inventory) retained_records += epoch.inventory->records().size();
    if (epoch.manifest_store && epoch.manifest_store->decoded_manifest)
      retained_manifest_participants += epoch.manifest_store->decoded_manifest->candidate.participants.size();
  }
  CHECK(retained_records + retained_manifest_participants == kMaxRecoveryAggregateParticipants);
  CHECK(snapshot->epochs.size() == paired_epochs + 1);
  CHECK(snapshot->epochs.back().inventory == nullptr);
  CHECK(snapshot->epochs.back().manifest_store == std::nullopt);
}

}  // namespace

int main() {
  TestManifestStoreIsOptionalAndAllPhasesAreDiagnostic();
  TestValidManifestSurvivesPendingOrInvalidBootstrapIntent();
  TestManifestCandidateMismatchIsReportedButDecodedDataIsKept();
  TestInvalidManifestArtifactsDoNotHideBootstrapInventory();
  TestManifestHardlinkAndModeAreRejected();
  TestNonemptyOwnerLockIsIncompleteButManifestIsRetained();
  TestNestedReadHooksFailClosedWithoutLosingBootstrapDiagnostic();
  TestNestedListingMutationRetainsDecodedManifestButMarksIncomplete();
  TestManifestReplacementDuringFileRevalidationIsNotKnown();
  TestReplacementAfterDecodeRetainsHistoricalManifestAsIncomplete();
  TestManifestStoreAppearingDuringIntentReadIsReported();
  TestManifestStoreSymlinkAndFifoDirectoriesAreRejected();
  TestNestedEntryCapStillReadsAllowlistedFiles();
  TestBootstrapAndManifestBytesShareAggregateReadBudget();
  TestBootstrapAndManifestRecordsShareAggregateParticipantBudget();
  return 0;
}
