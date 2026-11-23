#include "supervisor/runtime_owner.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <mutex>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <variant>
#include <vector>

using namespace rateguard::supervisor;
namespace fs = std::filesystem;

#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  std::abort(); \
} } while (false)

namespace {

class TempRoot {
 public:
  TempRoot() {
    std::string pattern = "/tmp/rg006-runtime-qa.XXXXXX";
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

RuntimeDomainId Domain(std::uint8_t value) {
  RuntimeDomainId id{};
  id[0] = value;
  return id;
}

EpochId Epoch(std::uint8_t value) {
  EpochId id{};
  id[0] = value;
  return id;
}

std::string ReadFile(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  CHECK(in.good());
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void WriteFile(const fs::path& path, std::string_view bytes) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  CHECK(fd >= 0);
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t n = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    CHECK(n > 0);
    offset += static_cast<std::size_t>(n);
  }
  CHECK(::fsync(fd) == 0);
  CHECK(::close(fd) == 0);
}

class FailOnce final : public IRuntimeOwnerIo {
 public:
  explicit FailOnce(RuntimeOwnerIoPoint point) : point_(point) {}
  bool FailAt(RuntimeOwnerIoPoint point) noexcept override {
    if (point == point_ && !fired_) { fired_ = true; return true; }
    return false;
  }
  bool fired() const { return fired_; }
 private:
  RuntimeOwnerIoPoint point_;
  bool fired_{};
};

class ArmableFailOnce final : public IRuntimeOwnerIo {
 public:
  explicit ArmableFailOnce(RuntimeOwnerIoPoint point) : point_(point) {}
  void Arm() noexcept { armed_ = true; }
  bool fired() const noexcept { return fired_; }
  bool FailAt(RuntimeOwnerIoPoint point) noexcept override {
    if (armed_ && point == point_ && !fired_) { fired_ = true; return true; }
    return false;
  }
 private:
  RuntimeOwnerIoPoint point_;
  bool armed_{};
  bool fired_{};
};

class FailNth final : public IRuntimeOwnerIo {
 public:
  FailNth(RuntimeOwnerIoPoint point, unsigned nth) : point_(point), nth_(nth) {}
  bool FailAt(RuntimeOwnerIoPoint point) noexcept override {
    if (point != point_) return false;
    if (++seen_ == nth_) { fired_ = true; return true; }
    return false;
  }
  bool fired() const noexcept { return fired_; }
 private:
  RuntimeOwnerIoPoint point_;
  unsigned nth_;
  unsigned seen_{};
  bool fired_{};
};

class ExitAtNth final : public IRuntimeOwnerIo {
 public:
  ExitAtNth(RuntimeOwnerIoPoint point, unsigned nth, int status)
      : point_(point), nth_(nth), status_(status) {}
  bool FailAt(RuntimeOwnerIoPoint point) noexcept override {
    if (point == point_ && ++seen_ == nth_) ::_exit(status_);
    return false;
  }
 private:
  RuntimeOwnerIoPoint point_;
  unsigned nth_;
  int status_;
  unsigned seen_{};
};

std::unique_ptr<RuntimeOwner> MustCreate(const fs::path& path, RuntimeDomainId domain = Domain(1),
                                         IRuntimeOwnerIo* hooks = nullptr) {
  auto result = RuntimeOwner::CreateNew(path.string(), domain, hooks);
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(result));
  return std::move(std::get<std::unique_ptr<RuntimeOwner>>(result));
}

void CheckCloexecFd(const DuplicateFdResult& result) {
  CHECK(std::holds_alternative<int>(result));
  const int fd = std::get<int>(result);
  CHECK(fd >= 0);
  const int flags = ::fcntl(fd, F_GETFD);
  CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
  CHECK(::close(fd) == 0);
}

void CheckOwnerError(const RuntimeOwnerCheck& result, RuntimeOwnerError expected) {
  CHECK(std::get_if<RuntimeOwnerError>(&result) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(result) == expected);
}

void TestFreshCreateClaimAndExistingRecovery() {
  TempRoot tmp;
  const auto root = tmp.path() / "runtime";
  auto owner = MustCreate(root);
  CHECK(owner->mode() == RuntimeOwnerMode::Fresh);
  CHECK(owner->domain_id() == Domain(1));
  CHECK(owner->root_path() == (fs::canonical(root.parent_path()) / root.filename()).string());
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
  CheckCloexecFd(owner->DuplicateRootFd());
  struct stat st{};
  CHECK(::stat(root.c_str(), &st) == 0 && (st.st_mode & 07777) == 0700);
  CHECK(::stat((root / "owner.lock").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600);
  CHECK(::stat((root / "runtime-anchor.json").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600);

  auto claim_result = owner->ClaimInitialEpoch(Epoch(7));
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  auto claim = std::move(std::get<InitialEpochClaim>(claim_result));
  CHECK(claim.epoch_id() == Epoch(7));
  CHECK(claim.domain_id() == Domain(1));
  CHECK(claim.root_path() == owner->root_path());
  CHECK(std::holds_alternative<std::monostate>(claim.ValidateOwnership()));
  CheckCloexecFd(claim.DuplicateRootFd());
  const auto second_claim = owner->ClaimInitialEpoch(Epoch(8));
  CHECK(std::get_if<RuntimeOwnerError>(&second_claim) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(second_claim) == RuntimeOwnerError::InitialClaimAlreadyUsed);
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));

  auto busy = RuntimeOwner::OpenExisting(root.string(), Domain(1));
  CHECK(std::get_if<RuntimeOwnerError>(&busy) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(busy) == RuntimeOwnerError::LockBusy);
  auto duplicate = RuntimeOwner::CreateNew(root.string(), Domain(2));
  CHECK(std::get_if<RuntimeOwnerError>(&duplicate) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(duplicate) == RuntimeOwnerError::AlreadyExists);

  // A claimed epoch keeps the exclusive lock alive after its owner wrapper is dropped.
  owner.reset();
  auto still_busy = RuntimeOwner::OpenExisting(root.string(), Domain(1));
  CHECK(std::get_if<RuntimeOwnerError>(&still_busy) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(still_busy) == RuntimeOwnerError::LockBusy);
  // Claim remains alive in this scope; the lock cannot be released by resetting the owner.
}

void TestOpenExistingRequiresValidAnchorAndNeverCreates() {
  TempRoot tmp;
  const auto missing = tmp.path() / "missing";
  auto absent = RuntimeOwner::OpenExisting(missing.string(), Domain(1));
  CHECK(std::get_if<RuntimeOwnerError>(&absent) != nullptr);
  CHECK(!fs::exists(missing));

  const auto root = tmp.path() / "runtime";
  {
    auto owner = MustCreate(root);
    CHECK(owner->ClaimInitialEpoch(Epoch(9)).index() == 0);
  }
  auto recovery = RuntimeOwner::OpenExisting(root.string(), Domain(1));
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(recovery));
  auto existing = std::move(std::get<std::unique_ptr<RuntimeOwner>>(recovery));
  CHECK(existing->mode() == RuntimeOwnerMode::RecoveryRequired);
  CHECK(std::holds_alternative<std::monostate>(existing->ValidateOwnership()));
  auto forbidden = existing->ClaimInitialEpoch(Epoch(10));
  CHECK(std::get_if<RuntimeOwnerError>(&forbidden) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(forbidden) == RuntimeOwnerError::RecoveryRequired);
  existing.reset();

  CHECK(::unlink((root / "runtime-anchor.json").c_str()) == 0);
  auto missing_anchor = RuntimeOwner::OpenExisting(root.string(), Domain(1));
  CHECK(std::get_if<RuntimeOwnerError>(&missing_anchor) != nullptr);
  CHECK(!std::holds_alternative<std::unique_ptr<RuntimeOwner>>(missing_anchor));
  auto cannot_reinitialize = RuntimeOwner::CreateNew(root.string(), Domain(1));
  CHECK(std::get_if<RuntimeOwnerError>(&cannot_reinitialize) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(cannot_reinitialize) == RuntimeOwnerError::AlreadyExists);
  CHECK(!fs::exists(root / "runtime-anchor.json"));
}

void TestDomainAndPathBinding() {
  TempRoot tmp;
  const auto root = tmp.path() / "runtime";
  auto owner = MustCreate(root, Domain(3));
  const auto bytes = ReadFile(root / "runtime-anchor.json");
  owner.reset();
  auto wrong_domain = RuntimeOwner::OpenExisting(root.string(), Domain(4));
  CHECK(std::get_if<RuntimeOwnerError>(&wrong_domain) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(wrong_domain) == RuntimeOwnerError::DomainMismatch);
  CHECK(ReadFile(root / "runtime-anchor.json") == bytes);

  auto relative = RuntimeOwner::CreateNew("relative/root", Domain(1));
  CHECK(std::get_if<RuntimeOwnerError>(&relative) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(relative) == RuntimeOwnerError::InvalidPath);
  CHECK(!fs::exists("relative"));
}

void TestRootLockSurvivesTokenAndSeparatesConfiguredRoots() {
  TempRoot tmp;
  const auto root_a = tmp.path() / "a";
  const auto root_b = tmp.path() / "b";
  auto a = MustCreate(root_a, Domain(5));
  auto claim_result = a->ClaimInitialEpoch(Epoch(11));
  CHECK(std::holds_alternative<InitialEpochClaim>(claim_result));
  auto claim = std::move(std::get<InitialEpochClaim>(claim_result));
  a.reset();
  auto b = MustCreate(root_b, Domain(5));
  CHECK(b->mode() == RuntimeOwnerMode::Fresh);
  auto locked_a = RuntimeOwner::OpenExisting(root_a.string(), Domain(5));
  CHECK(std::get_if<RuntimeOwnerError>(&locked_a) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(locked_a) == RuntimeOwnerError::LockBusy);
  // Distinct roots are intentionally independent; deployment reconciliation is external.
}

void TestForkedOwnerCannotValidateOrClaim() {
  TempRoot tmp;
  const auto root = tmp.path() / "runtime";
  auto owner = MustCreate(root, Domain(8));
  int pipefd[2]{};
  CHECK(::pipe(pipefd) == 0);
  const pid_t child = ::fork();
  CHECK(child >= 0);
  if (child == 0) {
    ::close(pipefd[0]);
    const auto validation = owner->ValidateOwnership();
    const int valid_error = std::get_if<RuntimeOwnerError>(&validation)
        ? static_cast<int>(std::get<RuntimeOwnerError>(validation)) : -1;
    auto claim = owner->ClaimInitialEpoch(Epoch(12));
    const int claim_error = std::get_if<RuntimeOwnerError>(&claim)
        ? static_cast<int>(std::get<RuntimeOwnerError>(claim)) : -1;
    const int values[] = {valid_error, claim_error};
    if (::write(pipefd[1], values, sizeof(values)) != sizeof(values)) ::_exit(74);
    ::_exit(0);
  }
  ::close(pipefd[1]);
  int values[2] = {-1, -1};
  CHECK(::read(pipefd[0], values, sizeof(values)) == sizeof(values));
  CHECK(::close(pipefd[0]) == 0);
  int status = 0;
  CHECK(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  CHECK(values[0] == static_cast<int>(RuntimeOwnerError::OwnerProcessChanged));
  CHECK(values[1] == static_cast<int>(RuntimeOwnerError::RecoveryRequired));
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
}

void TestAnchorLockAndRootReplacementFailClosed() {
  TempRoot tmp;
  const auto root = tmp.path() / "root-anchor";
  auto owner = MustCreate(root, Domain(13));
  const auto anchor = ReadFile(root / "runtime-anchor.json");
  CHECK(::unlink((root / "runtime-anchor.json").c_str()) == 0);
  WriteFile(root / "runtime-anchor.json", anchor);
  const auto changed_anchor = owner->ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&changed_anchor) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(changed_anchor) == RuntimeOwnerError::AnchorIdentityChanged);
  const auto displaced = tmp.path() / "original-anchor";
  CHECK(::rename((root / "runtime-anchor.json").c_str(), displaced.c_str()) == 0);
  WriteFile(root / "runtime-anchor.json", anchor);
  CheckOwnerError(owner->ValidateOwnership(), RuntimeOwnerError::AnchorIdentityChanged);
  CHECK(::unlink((root / "runtime-anchor.json").c_str()) == 0);
  CHECK(::rename(displaced.c_str(), (root / "runtime-anchor.json").c_str()) == 0);
  const auto restored_anchor = owner->ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&restored_anchor) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(restored_anchor) == RuntimeOwnerError::AnchorIdentityChanged);
  CHECK(owner->mode() == RuntimeOwnerMode::RecoveryRequired);

  TempRoot tmp2;
  const auto lock_root = tmp2.path() / "root-lock";
  auto locked = MustCreate(lock_root, Domain(14));
  CHECK(::unlink((lock_root / "owner.lock").c_str()) == 0);
  WriteFile(lock_root / "owner.lock", "new inode");
  const auto changed_lock = locked->ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&changed_lock) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(changed_lock) == RuntimeOwnerError::LockIdentityChanged);
  CHECK(locked->mode() == RuntimeOwnerMode::RecoveryRequired);

  TempRoot tmp3;
  const auto replaced_root = tmp3.path() / "root-path";
  auto rooted = MustCreate(replaced_root, Domain(15));
  const auto moved = tmp3.path() / "old-root";
  CHECK(::rename(replaced_root.c_str(), moved.c_str()) == 0);
  CHECK(::mkdir(replaced_root.c_str(), 0700) == 0);
  const auto changed_root = rooted->ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&changed_root) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(changed_root) == RuntimeOwnerError::RootIdentityChanged);
  CHECK(::rmdir(replaced_root.c_str()) == 0);
  CHECK(::rename(moved.c_str(), replaced_root.c_str()) == 0);
  const auto restored_root = rooted->ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&restored_root) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(restored_root) == RuntimeOwnerError::RootIdentityChanged);
  CHECK(rooted->mode() == RuntimeOwnerMode::RecoveryRequired);
}

void TestAnchorSymlinkAndUnexpectedEntry() {
  TempRoot tmp;
  const auto root = tmp.path() / "anchor-link";
  {
    auto owner = MustCreate(root, Domain(17));
  }
  const auto outside = tmp.path() / "outside";
  WriteFile(outside, "not an anchor");
  CHECK(::unlink((root / "runtime-anchor.json").c_str()) == 0);
  CHECK(::symlink(outside.c_str(), (root / "runtime-anchor.json").c_str()) == 0);
  auto symlink_anchor = RuntimeOwner::OpenExisting(root.string(), Domain(17));
  CHECK(std::get_if<RuntimeOwnerError>(&symlink_anchor) != nullptr);

  TempRoot tmp2;
  const auto extra_root = tmp2.path() / "extra";
  auto owner = MustCreate(extra_root, Domain(18));
  const EpochId zero_epoch{};
  const auto invalid_epoch = owner->ClaimInitialEpoch(zero_epoch);
  CHECK(std::get_if<RuntimeOwnerError>(&invalid_epoch) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(invalid_epoch) == RuntimeOwnerError::InvalidEpochId);
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
  WriteFile(extra_root / "unregistered", "unexpected");
  const auto unexpected = owner->ClaimInitialEpoch(Epoch(18));
  CHECK(std::get_if<RuntimeOwnerError>(&unexpected) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(unexpected) == RuntimeOwnerError::UnexpectedRootEntry);
}

void TestOneOwnershipFailurePoisonsOwnerAndClaim() {
  TempRoot tmp;
  auto io = std::make_unique<ArmableFailOnce>(RuntimeOwnerIoPoint::CheckRootIdentity);
  auto owner = MustCreate(tmp.path() / "poison", Domain(19), io.get());
  auto result = owner->ClaimInitialEpoch(Epoch(19));
  CHECK(std::holds_alternative<InitialEpochClaim>(result));
  auto claim = std::move(std::get<InitialEpochClaim>(result));
  io->Arm();

  const auto first = claim.ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&first) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(first) == RuntimeOwnerError::RootIdentityChanged);
  CHECK(owner->mode() == RuntimeOwnerMode::RecoveryRequired);
  const auto later = owner->ValidateOwnership();
  CHECK(std::get_if<RuntimeOwnerError>(&later) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(later) == RuntimeOwnerError::RootIdentityChanged);
  const auto duplicate = owner->DuplicateRootFd();
  CHECK(std::get_if<RuntimeOwnerError>(&duplicate) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(duplicate) == RuntimeOwnerError::RootIdentityChanged);
  const auto other_claim = owner->ClaimInitialEpoch(Epoch(20));
  CHECK(std::get_if<RuntimeOwnerError>(&other_claim) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(other_claim) == RuntimeOwnerError::RecoveryRequired);
}

void TestSecondClaimAfterLegitimateChildDoesNotPoisonWinner() {
  TempRoot tmp;
  auto io = std::make_unique<ArmableFailOnce>(RuntimeOwnerIoPoint::EnumerateRoot);
  auto owner = MustCreate(tmp.path() / "runtime", Domain(20), io.get());
  auto first_result = owner->ClaimInitialEpoch(Epoch(20));
  CHECK(std::holds_alternative<InitialEpochClaim>(first_result));
  auto token = std::move(std::get<InitialEpochClaim>(first_result));
  const auto root_fd = token.DuplicateRootFd();
  CHECK(std::holds_alternative<int>(root_fd));
  const int fd = std::get<int>(root_fd);
  CHECK(::mkdirat(fd, "epoch-0001", 0700) == 0);
  CHECK(::close(fd) == 0);

  // A later claimant must check the already-consumed flag before inspecting a
  // root whose authorized bootstrap has now added an epoch child entry.
  io->Arm();
  const auto second = owner->ClaimInitialEpoch(Epoch(21));
  CHECK(std::get_if<RuntimeOwnerError>(&second) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(second) == RuntimeOwnerError::InitialClaimAlreadyUsed);
  CHECK(!io->fired());
  CHECK(owner->mode() == RuntimeOwnerMode::Fresh);
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
  CHECK(std::holds_alternative<std::monostate>(token.ValidateOwnership()));
}

void TestConcurrentClaimHasOneWinnerWithoutPoisoning() {
  TempRoot tmp;
  auto owner = MustCreate(tmp.path() / "runtime", Domain(24));
  std::barrier start(3);
  std::atomic<int> success{0};
  std::atomic<int> already_used{0};
  std::atomic<int> busy{0};
  std::atomic<int> unexpected{0};
  const auto worker = [&](std::uint8_t epoch_byte) {
    start.arrive_and_wait();
    auto result = owner->ClaimInitialEpoch(Epoch(epoch_byte));
    if (std::holds_alternative<InitialEpochClaim>(result)) {
      success.fetch_add(1, std::memory_order_relaxed);
    } else if (std::get<RuntimeOwnerError>(result) == RuntimeOwnerError::InitialClaimAlreadyUsed) {
      already_used.fetch_add(1, std::memory_order_relaxed);
    } else if (std::get<RuntimeOwnerError>(result) == RuntimeOwnerError::Busy) {
      busy.fetch_add(1, std::memory_order_relaxed);
    } else {
      unexpected.fetch_add(1, std::memory_order_relaxed);
    }
  };
  std::thread one(worker, 25);
  std::thread two(worker, 26);
  start.arrive_and_wait();
  one.join();
  two.join();
  CHECK(success.load(std::memory_order_relaxed) == 1);
  CHECK(already_used.load(std::memory_order_relaxed) + busy.load(std::memory_order_relaxed) == 1);
  CHECK(unexpected.load(std::memory_order_relaxed) == 0);
  CHECK(owner->mode() == RuntimeOwnerMode::Fresh);
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
}

void TestExternalDirectoryScanDoesNotAdvanceOwnerEnumeration() {
  TempRoot tmp;
  auto owner = MustCreate(tmp.path() / "runtime", Domain(27));
  auto duplicate = owner->DuplicateRootFd();
  CHECK(std::holds_alternative<int>(duplicate));
  DIR* directory = ::fdopendir(std::get<int>(duplicate));
  CHECK(directory != nullptr);
  bool saw_anchor = false;
  bool saw_lock = false;
  while (dirent* entry = ::readdir(directory)) {
    const std::string name(entry->d_name);
    if (name == "runtime-anchor.json") saw_anchor = true;
    if (name == "owner.lock") saw_lock = true;
  }
  CHECK(saw_anchor && saw_lock);
  CHECK(::closedir(directory) == 0);

  const auto claim = owner->ClaimInitialEpoch(Epoch(27));
  CHECK(std::holds_alternative<InitialEpochClaim>(claim));
  CHECK(std::holds_alternative<std::monostate>(owner->ValidateOwnership()));
}

void TestCreateFailureNeverBecomesFreshOrReinitializes() {
  const std::array fail_points{
      RuntimeOwnerIoPoint::ResolveParent,
      RuntimeOwnerIoPoint::MkdirRoot,
      RuntimeOwnerIoPoint::SyncParent,
      RuntimeOwnerIoPoint::OpenRoot,
      RuntimeOwnerIoPoint::ValidateRoot,
      RuntimeOwnerIoPoint::CreateLock,
      RuntimeOwnerIoPoint::AcquireLock,
      RuntimeOwnerIoPoint::SyncLock,
      RuntimeOwnerIoPoint::SyncRoot,
      RuntimeOwnerIoPoint::CreateAnchorTemp,
      RuntimeOwnerIoPoint::WriteAnchor,
      RuntimeOwnerIoPoint::SyncAnchor,
      RuntimeOwnerIoPoint::RenameAnchor,
  };
  for (const auto point : fail_points) {
    TempRoot tmp;
    const auto root = tmp.path() / "runtime";
    FailNth hooks(point, 1U);
    auto created = RuntimeOwner::CreateNew(root.string(), Domain(21), &hooks);
    CHECK(hooks.fired());
    CHECK(std::get_if<RuntimeOwnerError>(&created) != nullptr);
    CHECK(!std::holds_alternative<std::unique_ptr<RuntimeOwner>>(created));
    if (fs::exists(root)) {
      auto reopened = RuntimeOwner::OpenExisting(root.string(), Domain(21));
      if (std::holds_alternative<std::unique_ptr<RuntimeOwner>>(reopened)) {
        auto recovery = std::move(std::get<std::unique_ptr<RuntimeOwner>>(reopened));
        CHECK(recovery->mode() == RuntimeOwnerMode::RecoveryRequired);
        const auto claim = recovery->ClaimInitialEpoch(Epoch(22));
        CHECK(std::get_if<RuntimeOwnerError>(&claim) != nullptr);
      }
      auto retry = RuntimeOwner::CreateNew(root.string(), Domain(21));
      CHECK(std::get_if<RuntimeOwnerError>(&retry) != nullptr);
      CHECK(std::get<RuntimeOwnerError>(retry) == RuntimeOwnerError::AlreadyExists);
    }
  }

  // Isolate the after-rename but before root-fsync boundary: the anchor may be
  // visible, but only recovery can open it and no initial claim is issued.
  TempRoot tmp;
  const auto root = tmp.path() / "uncertain";
  FailNth after_rename(RuntimeOwnerIoPoint::SyncRoot, 2);
  auto uncertain = RuntimeOwner::CreateNew(root.string(), Domain(22), &after_rename);
  CHECK(after_rename.fired());
  CHECK(std::get_if<RuntimeOwnerError>(&uncertain) != nullptr);
  CHECK(std::get<RuntimeOwnerError>(uncertain) == RuntimeOwnerError::DurabilityUncertain);
  auto recovery = RuntimeOwner::OpenExisting(root.string(), Domain(22));
  CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(recovery));
  auto recovered = std::move(std::get<std::unique_ptr<RuntimeOwner>>(recovery));
  CHECK(recovered->mode() == RuntimeOwnerMode::RecoveryRequired);
  auto no_claim = recovered->ClaimInitialEpoch(Epoch(23));
  CHECK(std::get_if<RuntimeOwnerError>(&no_claim) != nullptr);
}

int OpenExistingErrorBounded(const std::string& path, RuntimeDomainId domain) {
  int fds[2]{};
  CHECK(::pipe(fds) == 0);
  const pid_t child = ::fork();
  CHECK(child >= 0);
  if (child == 0) {
    ::close(fds[0]);
    auto opened = RuntimeOwner::OpenExisting(path, domain);
    const int code = std::get_if<RuntimeOwnerError>(&opened)
        ? static_cast<int>(std::get<RuntimeOwnerError>(opened)) : -1;
    if (::write(fds[1], &code, sizeof(code)) != sizeof(code)) ::_exit(74);
    ::_exit(0);
  }
  ::close(fds[1]);
  pollfd event{fds[0], POLLIN, 0};
  const int ready = ::poll(&event, 1, 3000);
  if (ready != 1) {
    (void)::kill(child, SIGKILL);
    int ignored = 0;
    (void)::waitpid(child, &ignored, 0);
    ::close(fds[0]);
    CHECK(false && "OpenExisting must reject FIFO entries without blocking");
  }
  int code = -1;
  CHECK(::read(fds[0], &code, sizeof(code)) == sizeof(code));
  CHECK(::close(fds[0]) == 0);
  int status = 0;
  CHECK(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  return code;
}

void TestOpenExistingRejectsFifoLockAndAnchorWithoutBlocking() {
  TempRoot tmp;
  const auto root = tmp.path() / "fifo-anchor";
  {
    auto owner = MustCreate(root, Domain(31));
  }
  CHECK(::unlink((root / "runtime-anchor.json").c_str()) == 0);
  CHECK(::mkfifo((root / "runtime-anchor.json").c_str(), 0600) == 0);
  CHECK(OpenExistingErrorBounded(root.string(), Domain(31)) ==
        static_cast<int>(RuntimeOwnerError::InvalidAnchor));

  TempRoot tmp2;
  const auto lock_root = tmp2.path() / "fifo-lock";
  {
    auto owner = MustCreate(lock_root, Domain(32));
  }
  CHECK(::unlink((lock_root / "owner.lock").c_str()) == 0);
  CHECK(::mkfifo((lock_root / "owner.lock").c_str(), 0600) == 0);
  CHECK(OpenExistingErrorBounded(lock_root.string(), Domain(32)) ==
        static_cast<int>(RuntimeOwnerError::InvalidLock));
}

void TestProcessCrashBeforeAndAfterAnchorRename() {
  for (const bool after_rename : {false, true}) {
    TempRoot tmp;
    const auto root = tmp.path() / "runtime";
    const auto target = after_rename ? RuntimeOwnerIoPoint::SyncRoot
                                     : RuntimeOwnerIoPoint::RenameAnchor;
    const unsigned nth = after_rename ? 2U : 1U;
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
      ExitAtNth crash(target, nth, 79);
      (void)RuntimeOwner::CreateNew(root.string(), Domain(41), &crash);
      ::_exit(0);
    }
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 79);

    auto opened = RuntimeOwner::OpenExisting(root.string(), Domain(41));
    if (after_rename) {
      CHECK(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(opened));
      auto recovery = std::move(std::get<std::unique_ptr<RuntimeOwner>>(opened));
      CHECK(recovery->mode() == RuntimeOwnerMode::RecoveryRequired);
      CHECK(std::get<RuntimeOwnerError>(recovery->ClaimInitialEpoch(Epoch(42))) ==
            RuntimeOwnerError::RecoveryRequired);
    } else {
      CHECK(std::get_if<RuntimeOwnerError>(&opened) != nullptr);
      CHECK(std::get<RuntimeOwnerError>(opened) == RuntimeOwnerError::AnchorMissing);
    }
    auto cannot_reinit = RuntimeOwner::CreateNew(root.string(), Domain(41));
    CHECK(std::get_if<RuntimeOwnerError>(&cannot_reinit) != nullptr);
    CHECK(std::get<RuntimeOwnerError>(cannot_reinit) == RuntimeOwnerError::AlreadyExists);
  }
}

}  // namespace

int main() {
  TestFreshCreateClaimAndExistingRecovery();
  TestOpenExistingRequiresValidAnchorAndNeverCreates();
  TestDomainAndPathBinding();
  TestRootLockSurvivesTokenAndSeparatesConfiguredRoots();
  TestForkedOwnerCannotValidateOrClaim();
  TestAnchorLockAndRootReplacementFailClosed();
  TestAnchorSymlinkAndUnexpectedEntry();
  TestOneOwnershipFailurePoisonsOwnerAndClaim();
  TestSecondClaimAfterLegitimateChildDoesNotPoisonWinner();
  TestConcurrentClaimHasOneWinnerWithoutPoisoning();
  TestExternalDirectoryScanDoesNotAdvanceOwnerEnumeration();
  TestCreateFailureNeverBecomesFreshOrReinitializes();
  TestOpenExistingRejectsFifoLockAndAnchorWithoutBlocking();
  TestProcessCrashBeforeAndAfterAnchorRename();
  std::puts("independent runtime owner checks passed");
}
