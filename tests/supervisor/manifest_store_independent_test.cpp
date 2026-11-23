#include "supervisor/manifest_store.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>
#include <sys/stat.h>

using namespace rateguard::supervisor;
namespace fs = std::filesystem;

#define CHECK(expr) do { if (!(expr)) { \
  std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << ": " #expr << '\n'; \
  std::abort(); \
} } while (false)

namespace {

class TempRoot {
 public:
  TempRoot() {
    std::string pattern = "/tmp/rg006-manifest-qa.XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    char* made = ::mkdtemp(writable.data());
    CHECK(made != nullptr);
    path_ = made;
  }
  ~TempRoot() { std::error_code ignored; fs::remove_all(path_, ignored); }
  const fs::path& path() const { return path_; }
 private:
  fs::path path_;
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
  const auto add = [&](ParticipantRole role, std::uint32_t slot, const char* id,
                       std::uint8_t incarnation, char container, std::uint64_t pid) {
    Participant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = id;
    p.incarnation[0] = incarnation;
    if (role == ParticipantRole::Authority) p.incarnation = c.authority_incarnation;
    p.process.container_id = std::string(64, container);
    p.process.pid = pid;
    p.process.pid_start_ticks = pid + 100;
    p.clock_identity = c.clock_identity;
    c.participants.push_back(p);
  };
  add(ParticipantRole::Authority, 0, "authority", 2, 'a', 101);
  add(ParticipantRole::Witness, 0, "witness", 5, 'b', 102);
  add(ParticipantRole::Replica, 0, "replica-zero", 6, 'c', 103);
  add(ParticipantRole::Replica, UINT32_MAX, "replica-max", 7, 'd', 104);
  add(ParticipantRole::Adapter, 0, "adapter-a", 8, 'e', 105);
  add(ParticipantRole::Adapter, 0, "adapter-b", 9, 'f', 106);
  return c;
}

OperationId Op(std::uint8_t n) { OperationId op{}; op[0] = n; return op; }

class FailOnce final : public IManifestFileOps {
 public:
  explicit FailOnce(ManifestIoPoint point) : point_(point) {}
  bool FailAt(ManifestIoPoint point) noexcept override {
    if (point == point_ && !used_.exchange(true)) return true;
    return false;
  }
  bool used() const { return used_.load(); }
 private:
  ManifestIoPoint point_;
  std::atomic<bool> used_{false};
};

class FailNth final : public IManifestFileOps {
 public:
  FailNth(ManifestIoPoint point, unsigned nth) : point_(point), nth_(nth) {}
  bool FailAt(ManifestIoPoint point) noexcept override {
    if (point != point_) return false;
    if (++seen_ == nth_) { triggered_ = true; return true; }
    return false;
  }
  unsigned seen() const { return seen_; }
  bool triggered() const { return triggered_; }
 private:
  ManifestIoPoint point_;
  unsigned nth_;
  unsigned seen_{};
  bool triggered_{};
};

class ExitAtNth final : public IManifestFileOps {
 public:
  ExitAtNth(ManifestIoPoint point, unsigned nth, int exit_code)
      : point_(point), nth_(nth), exit_code_(exit_code) {}
  bool FailAt(ManifestIoPoint point) noexcept override {
    if (point == point_ && ++seen_ == nth_) ::_exit(exit_code_);
    return false;
  }
 private:
  ManifestIoPoint point_;
  unsigned nth_;
  int exit_code_;
  unsigned seen_{};
};

class BlockAt final : public IManifestFileOps {
 public:
  BlockAt(ManifestIoPoint point, unsigned nth) : point_(point), nth_(nth) {}
  bool FailAt(ManifestIoPoint point) noexcept override {
    if (point != point_) return false;
    std::unique_lock lock(mutex_);
    if (++seen_ != nth_) return false;
    if (arrived_) return false;
    arrived_ = true;
    condition_.notify_all();
    condition_.wait(lock, [&] { return released_; });
    return false;
  }
  void WaitUntilArrived() {
    std::unique_lock lock(mutex_);
    CHECK(condition_.wait_for(lock, std::chrono::seconds(5), [&] { return arrived_; }));
  }
  void Release() {
    std::lock_guard lock(mutex_);
    released_ = true;
    condition_.notify_all();
  }
 private:
  ManifestIoPoint point_;
  unsigned nth_;
  unsigned seen_{};
  std::mutex mutex_;
  std::condition_variable condition_;
  bool arrived_{};
  bool released_{};
};

std::unique_ptr<ManifestStore> Create(const fs::path& path,
                                      const EpochCandidate& candidate = Candidate(),
                                      const OperationId& op = Op(10),
                                      IManifestFileOps* hooks = nullptr) {
  auto result = ManifestStore::CreateNew(path.string(), candidate, op, hooks);
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(result));
  return std::move(std::get<std::unique_ptr<ManifestStore>>(result));
}

std::string ReadFile(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  CHECK(in.good());
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void WriteFile(const fs::path& path, std::string_view bytes) {
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  CHECK(fd >= 0);
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t wrote = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    CHECK(wrote > 0);
    offset += static_cast<std::size_t>(wrote);
  }
  CHECK(::fsync(fd) == 0);
  CHECK(::close(fd) == 0);
}

void TestExclusiveCreateAndRecoveryReadOnly() {
  TempRoot root;
  const fs::path dir = root.path() / "epoch";
  auto store = Create(dir);
  CHECK(store->writable());
  CHECK(!store->recovery_only());
  CHECK(store->snapshot().phase == ManifestPhase::Prepared);
  CHECK(store->snapshot().generation == 1);
  CHECK(store->snapshot().transition_operation_id == Op(10));
  struct stat st{};
  CHECK(::stat(dir.c_str(), &st) == 0 && (st.st_mode & 0777) == 0700);
  CHECK(::stat((dir / "owner.lock").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
  CHECK(::stat((dir / "manifest.json").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
  const std::string before_duplicate = ReadFile(dir / "manifest.json");
  auto duplicate = ManifestStore::CreateNew(dir.string(), Candidate(), Op(11));
  CHECK(std::get_if<ManifestStoreError>(&duplicate) != nullptr);
  CHECK(std::get<ManifestStoreError>(duplicate) == ManifestStoreError::AlreadyExists);
  CHECK(ReadFile(dir / "manifest.json") == before_duplicate);

  const auto old_digest = store->digest();
  auto stale = store->Transition(7, old_digest, ManifestPhase::Active, Op(12));
  CHECK(stale.visibility == ManifestVisibility::NotVisible);
  CHECK(stale.error == ManifestStoreError::CompareAndSwapMismatch);
  CHECK(store->snapshot().phase == ManifestPhase::Prepared);
  auto active = store->Transition(1, old_digest, ManifestPhase::Active, Op(13));
  CHECK(active.visibility == ManifestVisibility::Durable && !active.error);
  CHECK(active.phase == ManifestPhase::Active && active.generation == 2);
  store.reset();

  auto opened = ManifestStore::OpenExisting(dir.string());
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(opened));
  auto recovery = std::move(std::get<std::unique_ptr<ManifestStore>>(opened));
  CHECK(recovery->recovery_only() && !recovery->writable());
  CHECK(recovery->snapshot().phase == ManifestPhase::Active);
  const auto recovered_digest = recovery->digest();
  auto forbidden = recovery->Transition(2, recovered_digest, ManifestPhase::Draining, Op(14));
  CHECK(forbidden.visibility == ManifestVisibility::NotVisible);
  CHECK(forbidden.error == ManifestStoreError::RecoveryReadOnly);
  CHECK(recovery->snapshot().phase == ManifestPhase::Active);
}

void TestUnsortedInventoryCanonicalizationAndZeroCreationId() {
  TempRoot root;
  auto candidate = Candidate();
  std::reverse(candidate.participants.begin(), candidate.participants.end());
  auto store = Create(root.path() / "unsorted", candidate, Op(50));
  const auto original_digest = store->digest();
  const auto active = store->Transition(1, original_digest, ManifestPhase::Active, Op(51));
  CHECK(active.visibility == ManifestVisibility::Durable && !active.error);
  CHECK(active.generation == 2);
  CHECK(active.phase == ManifestPhase::Active);
  store.reset();

  auto reopened = ManifestStore::OpenExisting((root.path() / "unsorted").string());
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(reopened));
  const auto reopened_manifest = std::get<std::unique_ptr<ManifestStore>>(reopened)->snapshot();
  const auto& participants = reopened_manifest.candidate.participants;
  CHECK(participants.size() == candidate.participants.size());
  CHECK(std::is_sorted(participants.begin(), participants.end(), [](const Participant& a,
                                                                     const Participant& b) {
    if (a.role != b.role) return static_cast<std::uint8_t>(a.role) < static_cast<std::uint8_t>(b.role);
    if (a.participant_id != b.participant_id) return a.participant_id < b.participant_id;
    return a.slot_id < b.slot_id;
  }));

  TempRoot zero_root;
  const OperationId zero{};
  auto zero_op = ManifestStore::CreateNew((zero_root.path() / "zero").string(), Candidate(), zero);
  CHECK(std::get_if<ManifestStoreError>(&zero_op) != nullptr);
  CHECK(std::get<ManifestStoreError>(zero_op) == ManifestStoreError::OperationIdInvalid);
  CHECK(!fs::exists(zero_root.path() / "zero"));
}

void TestMissingAndCorruptManifestNeverInitialize() {
  TempRoot root;
  const auto dir = root.path() / "missing";
  auto store = Create(dir);
  store.reset();
  CHECK(::unlink((dir / "manifest.json").c_str()) == 0);
  auto missing = ManifestStore::OpenExisting(dir.string());
  CHECK(std::get_if<ManifestStoreError>(&missing) != nullptr);
  CHECK(std::get<ManifestStoreError>(missing) == ManifestStoreError::MissingManifest);
  CHECK(!fs::exists(dir / "manifest.json"));

  TempRoot root2;
  const auto corrupt_dir = root2.path() / "corrupt";
  auto corrupt_store = Create(corrupt_dir);
  corrupt_store.reset();
  WriteFile(corrupt_dir / "manifest.json", "{not valid json");
  auto corrupt = ManifestStore::OpenExisting(corrupt_dir.string());
  CHECK(std::get_if<ManifestStoreError>(&corrupt) != nullptr);
  CHECK(!std::holds_alternative<std::unique_ptr<ManifestStore>>(corrupt));
  CHECK(ReadFile(corrupt_dir / "manifest.json") == "{not valid json");

  TempRoot root3;
  const auto huge_dir = root3.path() / "oversized";
  auto huge_store = Create(huge_dir);
  huge_store.reset();
  std::string oversized(kMaxManifestBytes + 1, ' ');
  WriteFile(huge_dir / "manifest.json", oversized);
  auto too_large = ManifestStore::OpenExisting(huge_dir.string());
  CHECK(std::get_if<ManifestStoreError>(&too_large) != nullptr);
  CHECK(std::get<ManifestStoreError>(too_large) == ManifestStoreError::ManifestTooLarge);
  CHECK(ReadFile(huge_dir / "manifest.json").size() == kMaxManifestBytes + 1);
}

void TestValidDigestDoesNotAuthenticateInventoryAndStaleCasRejects() {
  TempRoot root;
  const auto dir = root.path() / "edited";
  auto original = Create(dir);
  const auto original_digest = original->digest();
  auto edited = original->snapshot();
  auto adapter = std::find_if(edited.candidate.participants.begin(), edited.candidate.participants.end(),
                              [](const Participant& p) { return p.role == ParticipantRole::Adapter; });
  CHECK(adapter != edited.candidate.participants.end());
  adapter->process.pid = 9'000'001;
  adapter->process.pid_start_ticks = 9'000'101;
  auto encoded = EncodeManifestV1(edited);
  CHECK(std::holds_alternative<std::string>(encoded));
  WriteFile(dir / "manifest.json", std::get<std::string>(encoded));
  const auto stale = original->Transition(1, original_digest, ManifestPhase::Active, Op(61));
  CHECK(stale.visibility == ManifestVisibility::NotVisible);
  CHECK(stale.error == ManifestStoreError::CompareAndSwapMismatch);
  CHECK(original->snapshot().phase == ManifestPhase::Prepared);
  original.reset();

  // The checksum is corruption detection, not authentication: a modified but
  // structurally valid inventory with a recomputed digest is accepted as data.
  auto opened = ManifestStore::OpenExisting(dir.string());
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(opened));
  auto recovery = std::move(std::get<std::unique_ptr<ManifestStore>>(opened));
  const auto loaded = recovery->snapshot();
  const auto edited_adapter = std::find_if(loaded.candidate.participants.begin(),
                                           loaded.candidate.participants.end(),
      [](const Participant& p) { return p.role == ParticipantRole::Adapter; });
  CHECK(edited_adapter != loaded.candidate.participants.end());
  CHECK(edited_adapter->process.pid == 9'000'001);
}

void TestDirectoryLockContendsAcrossProcess() {
  TempRoot root;
  const auto dir = root.path() / "locked";
  auto owner = Create(dir);
  int pipefd[2]{};
  CHECK(::pipe(pipefd) == 0);
  const pid_t child = ::fork();
  CHECK(child >= 0);
  if (child == 0) {
    ::close(pipefd[0]);
    auto attempt = ManifestStore::OpenExisting(dir.string());
    const int code = std::get_if<ManifestStoreError>(&attempt) &&
                     std::get<ManifestStoreError>(attempt) == ManifestStoreError::LockBusy ? 1 : 0;
    (void)::write(pipefd[1], &code, sizeof(code));
    ::close(pipefd[1]);
    ::_exit(0);
  }
  ::close(pipefd[1]);
  int code = 0;
  CHECK(::read(pipefd[0], &code, sizeof(code)) == sizeof(code));
  CHECK(::close(pipefd[0]) == 0);
  int status = 0;
  CHECK(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(code == 1);
  CHECK(owner->writable());
}

void TestProcessExitAroundRenameKeepsOnlyVisibleSnapshot() {
  for (const bool exit_after_rename : {false, true}) {
    TempRoot root;
    const auto dir = root.path() / (exit_after_rename ? "after" : "before");
    const auto point = exit_after_rename ? ManifestIoPoint::SyncDirectory
                                         : ManifestIoPoint::RenameManifest;
    // For SyncDirectory, CreateNew uses initial dir sync and Prepared-manifest
    // sync before the transition's post-rename directory sync.
    const unsigned nth = exit_after_rename ? 3U : 2U;
    auto crash = std::make_unique<ExitAtNth>(point, nth, 73);
    auto store = Create(dir, Candidate(), Op(10), crash.get());
    int pipefd[2]{};
    CHECK(::pipe(pipefd) == 0);
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
      ::close(pipefd[0]);
      auto transitioned = store->Transition(1, store->digest(), ManifestPhase::Active, Op(71));
      const int code = transitioned.visibility == ManifestVisibility::Durable ? 0 : 2;
      (void)::write(pipefd[1], &code, sizeof(code));
      ::_exit(0);
    }
    ::close(pipefd[1]);
    int unexpected = 0;
    const ssize_t got = ::read(pipefd[0], &unexpected, sizeof(unexpected));
    CHECK(got == 0);  // The child exits at the injected crash boundary.
    ::close(pipefd[0]);
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 73);
    store.reset();

    auto reopened = ManifestStore::OpenExisting(dir.string());
    CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(reopened));
    const auto recovered = std::get<std::unique_ptr<ManifestStore>>(reopened)->snapshot();
    CHECK(recovered.phase == (exit_after_rename ? ManifestPhase::Active : ManifestPhase::Prepared));
    CHECK(recovered.generation == (exit_after_rename ? 2U : 1U));
    CHECK(std::get<std::unique_ptr<ManifestStore>>(reopened)->recovery_only());
  }
}

void TestSymlinksModesAndLockIdentityFailClosed() {
  TempRoot root;
  const auto dir = root.path() / "bad-lock";
  auto store = Create(dir);
  store.reset();
  CHECK(::unlink((dir / "owner.lock").c_str()) == 0);
  CHECK(::symlink((root.path() / "target").c_str(), (dir / "owner.lock").c_str()) == 0);
  auto bad_lock = ManifestStore::OpenExisting(dir.string());
  CHECK(std::get_if<ManifestStoreError>(&bad_lock) != nullptr);
  CHECK(!std::holds_alternative<std::unique_ptr<ManifestStore>>(bad_lock));

  TempRoot root2;
  const auto mode_dir = root2.path() / "bad-mode";
  auto mode_store = Create(mode_dir);
  mode_store.reset();
  CHECK(::chmod(mode_dir.c_str(), 0755) == 0);
  auto bad_mode = ManifestStore::OpenExisting(mode_dir.string());
  CHECK(std::get_if<ManifestStoreError>(&bad_mode) != nullptr);
  CHECK(!std::holds_alternative<std::unique_ptr<ManifestStore>>(bad_mode));

  TempRoot root3;
  const auto manifest_dir = root3.path() / "bad-manifest-link";
  auto manifest_store = Create(manifest_dir);
  manifest_store.reset();
  CHECK(::unlink((manifest_dir / "manifest.json").c_str()) == 0);
  WriteFile(root3.path() / "outside.json", "{}");
  CHECK(::symlink((root3.path() / "outside.json").c_str(),
                  (manifest_dir / "manifest.json").c_str()) == 0);
  auto bad_manifest = ManifestStore::OpenExisting(manifest_dir.string());
  CHECK(std::get_if<ManifestStoreError>(&bad_manifest) != nullptr);
  CHECK(!std::holds_alternative<std::unique_ptr<ManifestStore>>(bad_manifest));
  CHECK(ReadFile(root3.path() / "outside.json") == "{}");
}

void TestFailureBoundariesAndWriterLatch() {
  const std::array before_rename{ManifestIoPoint::CreateTemp, ManifestIoPoint::WriteTemp,
                                 ManifestIoPoint::SyncTemp, ManifestIoPoint::RenameManifest};
  for (const auto point : before_rename) {
    TempRoot root;
    const auto dir = root.path() / "epoch";
    // The first occurrence creates the initial Prepared manifest; fail the
    // second occurrence, which belongs to the requested phase transition.
    auto fail = std::make_unique<FailNth>(point, 2);
    auto store = Create(dir, Candidate(), Op(10), fail.get());
    const auto digest = store->digest();
    const auto result = store->Transition(1, digest, ManifestPhase::Active, Op(20));
    CHECK(fail->triggered());
    CHECK(result.visibility == ManifestVisibility::NotVisible);
    CHECK(result.error.has_value());
    CHECK(store->snapshot().phase == ManifestPhase::Prepared);
    CHECK(!store->writable());
    store.reset();
    auto opened = ManifestStore::OpenExisting(dir.string());
    CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(opened));
    CHECK(std::get<std::unique_ptr<ManifestStore>>(opened)->snapshot().phase ==
          ManifestPhase::Prepared);
  }

  TempRoot root;
  const auto dir = root.path() / "uncertain";
  // Initial directory durability, Prepared-file durability, then transition
  // durability: the third directory-sync is the post-transition rename fence.
  auto fail = std::make_unique<FailNth>(ManifestIoPoint::SyncDirectory, 3);
  auto store = Create(dir, Candidate(), Op(10), fail.get());
  const auto result = store->Transition(1, store->digest(), ManifestPhase::Active, Op(21));
  CHECK(fail->triggered());
  CHECK(result.visibility == ManifestVisibility::VisibleDurabilityUnknown);
  CHECK(result.error == ManifestStoreError::DurabilityUncertain);
  CHECK(store->snapshot().phase == ManifestPhase::Active);
  CHECK(!store->writable());
  auto second = store->Transition(2, store->digest(), ManifestPhase::Draining, Op(22));
  CHECK(second.visibility == ManifestVisibility::NotVisible);
  CHECK(second.error == ManifestStoreError::WriterLatched);
  store.reset();
  auto recovery = ManifestStore::OpenExisting(dir.string());
  CHECK(std::holds_alternative<std::unique_ptr<ManifestStore>>(recovery));
  CHECK(std::get<std::unique_ptr<ManifestStore>>(recovery)->snapshot().phase ==
        ManifestPhase::Active);
}

void TestReplacedLockAndStaleTempBlockCommit() {
  TempRoot root;
  const auto replaced_dir = root.path() / "replaced-lock";
  auto replaced = Create(replaced_dir);
  const auto before = ReadFile(replaced_dir / "manifest.json");
  CHECK(::unlink((replaced_dir / "owner.lock").c_str()) == 0);
  WriteFile(replaced_dir / "owner.lock", "replacement");
  auto lock_failure = replaced->Transition(1, replaced->digest(), ManifestPhase::Active, Op(81));
  CHECK(lock_failure.visibility == ManifestVisibility::NotVisible);
  CHECK(lock_failure.error == ManifestStoreError::LockIdentityChanged);
  CHECK(ReadFile(replaced_dir / "manifest.json") == before);
  CHECK(!replaced->writable());
  replaced.reset();

  TempRoot root2;
  const auto temp_dir = root2.path() / "stale-temp";
  auto temp_store = Create(temp_dir);
  WriteFile(temp_dir / "manifest.tmp", "stale incomplete write");
  const auto initial = ReadFile(temp_dir / "manifest.json");
  auto blocked = temp_store->Transition(1, temp_store->digest(), ManifestPhase::Active, Op(82));
  CHECK(blocked.visibility == ManifestVisibility::NotVisible);
  CHECK(blocked.error == ManifestStoreError::WriteFailure);
  CHECK(ReadFile(temp_dir / "manifest.json") == initial);
  CHECK(!temp_store->writable());
}

void TestCreationFailureDoesNotTurnExistingPathIntoNewEpoch() {
  const std::array create_points{ManifestIoPoint::Mkdir, ManifestIoPoint::SyncParentDirectory,
                                 ManifestIoPoint::OpenDirectory,
                                 ManifestIoPoint::ValidateDirectory, ManifestIoPoint::CreateLock,
                                 ManifestIoPoint::AcquireLock, ManifestIoPoint::SyncLock,
                                 ManifestIoPoint::CheckLockIdentity};
  for (const auto point : create_points) {
    TempRoot root;
    const auto dir = root.path() / "epoch";
    FailOnce fail(point);
    auto created = ManifestStore::CreateNew(dir.string(), Candidate(), Op(30), &fail);
    CHECK(fail.used());
    CHECK(std::get_if<ManifestStoreError>(&created) != nullptr);
    CHECK(!std::holds_alternative<std::unique_ptr<ManifestStore>>(created));
    // A failed partial initialization cannot be reopened as a valid epoch.
    if (fs::exists(dir)) {
      auto open = ManifestStore::OpenExisting(dir.string());
      CHECK(std::get_if<ManifestStoreError>(&open) != nullptr);
      CHECK(!std::holds_alternative<std::unique_ptr<ManifestStore>>(open));
    }
  }
}

void TestGenerationBoundsAndIndependentDirectoryLocks() {
  CHECK(TryNextManifestGeneration(1) == 2);
  CHECK(TryNextManifestGeneration(UINT64_MAX - 1) == UINT64_MAX);
  CHECK(!TryNextManifestGeneration(UINT64_MAX));
  CHECK(!TryNextManifestGeneration(0));

  TempRoot root;
  auto first = Create(root.path() / "one");
  auto second = Create(root.path() / "two");
  CHECK(first->writable() && second->writable());
  // Store locks are per directory. This does not prove a global supervisor lock.
}

void TestLegalPhaseGraphAndOperationIds() {
  TempRoot root;
  auto store = Create(root.path() / "phases");
  auto digest = store->digest();
  const OperationId zero{};
  auto zero_operation = store->Transition(1, digest, ManifestPhase::Draining, zero);
  CHECK(zero_operation.visibility == ManifestVisibility::NotVisible);
  CHECK(zero_operation.error == ManifestStoreError::OperationIdInvalid);
  CHECK(store->snapshot().phase == ManifestPhase::Prepared);

  auto active = store->Transition(1, digest, ManifestPhase::Active, Op(91));
  CHECK(active.visibility == ManifestVisibility::Durable && !active.error);
  auto illegal_same = store->Transition(2, active.digest, ManifestPhase::Active, Op(92));
  CHECK(illegal_same.visibility == ManifestVisibility::NotVisible);
  CHECK(illegal_same.error == ManifestStoreError::IllegalTransition);
  CHECK(store->writable());
  auto draining = store->Transition(2, active.digest, ManifestPhase::Draining, Op(93));
  CHECK(draining.visibility == ManifestVisibility::Durable && !draining.error);
  auto closed = store->Transition(3, draining.digest, ManifestPhase::Closed, Op(94));
  CHECK(closed.visibility == ManifestVisibility::Durable && !closed.error);
  auto reopened = store->Transition(4, closed.digest, ManifestPhase::Prepared, Op(95));
  CHECK(reopened.visibility == ManifestVisibility::NotVisible);
  CHECK(reopened.error == ManifestStoreError::IllegalTransition);
  CHECK(store->snapshot().phase == ManifestPhase::Closed);
}

void TestInProcessTransitionSerialization() {
  TempRoot root;
  auto pause = std::make_unique<BlockAt>(ManifestIoPoint::WriteTemp, 2);
  auto store = Create(root.path() / "epoch", Candidate(), Op(40), pause.get());
  const auto digest = store->digest();
  std::optional<ManifestWriteResult> result;
  std::thread writer([&] {
    result = store->Transition(1, digest, ManifestPhase::Active, Op(41));
  });
  pause->WaitUntilArrived();
  CHECK(store->snapshot().phase == ManifestPhase::Prepared);
  CHECK(store->snapshot().generation == 1);
  CHECK(store->digest() == digest);
  auto competing = store->Transition(1, digest, ManifestPhase::Active, Op(42));
  CHECK(competing.visibility == ManifestVisibility::NotVisible);
  CHECK(competing.error == ManifestStoreError::Busy);
  pause->Release();
  writer.join();
  CHECK(result.has_value());
  CHECK(result->visibility == ManifestVisibility::Durable && !result->error);
  CHECK(store->snapshot().phase == ManifestPhase::Active);
}

}  // namespace

int main() {
  static_assert(kMaxManifestBytes == 4U * 1024U * 1024U);
  TestExclusiveCreateAndRecoveryReadOnly();
  TestUnsortedInventoryCanonicalizationAndZeroCreationId();
  TestMissingAndCorruptManifestNeverInitialize();
  TestValidDigestDoesNotAuthenticateInventoryAndStaleCasRejects();
  TestDirectoryLockContendsAcrossProcess();
  TestProcessExitAroundRenameKeepsOnlyVisibleSnapshot();
  TestSymlinksModesAndLockIdentityFailClosed();
  TestFailureBoundariesAndWriterLatch();
  TestReplacedLockAndStaleTempBlockCommit();
  TestCreationFailureDoesNotTurnExistingPathIntoNewEpoch();
  TestGenerationBoundsAndIndependentDirectoryLocks();
  TestLegalPhaseGraphAndOperationIds();
  TestInProcessTransitionSerialization();
  std::cout << "independent manifest store checks passed\n";
}
