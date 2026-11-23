#include "supervisor/runtime_owner.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace rateguard::supervisor;

namespace {

void Check(bool condition, const char* what) {
  if (!condition) throw std::runtime_error(what);
}

class OneShotFault final : public IRuntimeOwnerIo {
 public:
  RuntimeOwnerIoPoint target{RuntimeOwnerIoPoint::MkdirRoot};
  unsigned remaining{};
  bool FailAt(RuntimeOwnerIoPoint point) noexcept override {
    if (remaining == 0 || point != target) return false;
    if (--remaining == 0) return true;
    return false;
  }
};

RuntimeDomainId Domain() { RuntimeDomainId id{}; id[0] = 1; return id; }
EpochId Epoch() { EpochId id{}; id[0] = 9; return id; }

std::string FreshPath(const char* suffix) {
  const char* tmp = std::getenv("TMPDIR");
  const std::string root = tmp != nullptr && *tmp != '\0' ? tmp : "/tmp";
  return root + "/rateguard-runtime-owner-" + std::to_string(::getpid()) + "-" + suffix;
}

std::unique_ptr<RuntimeOwner> Create(const std::string& path,
                                     const RuntimeDomainId& domain = Domain(),
                                     IRuntimeOwnerIo* io = nullptr) {
  auto result = RuntimeOwner::CreateNew(path, domain, io);
  if (auto* error = std::get_if<RuntimeOwnerError>(&result))
    std::cerr << "CreateNew error=" << static_cast<int>(*error) << '\n';
  Check(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(result), "CreateNew failed");
  return std::get<std::unique_ptr<RuntimeOwner>>(std::move(result));
}

void TestFreshClaimAndRecoveryOnlyOpen() {
  const auto path = FreshPath("fresh");
  std::filesystem::remove_all(path);
  auto owner = Create(path);
  Check(owner->mode() == RuntimeOwnerMode::Fresh, "new root not Fresh");
  Check(std::holds_alternative<std::monostate>(owner->ValidateOwnership()),
        "fresh owner validation failed");
  struct stat st {};
  Check(::stat(path.c_str(), &st) == 0 && (st.st_mode & 07777) == 0700,
        "root mode is not 0700");
  Check(::stat((path + "/owner.lock").c_str(), &st) == 0 && (st.st_mode & 07777) == 0600,
        "lock mode is not 0600");
  Check(::stat((path + "/runtime-anchor.json").c_str(), &st) == 0 &&
            (st.st_mode & 07777) == 0600, "anchor mode is not 0600");

  {
    auto claim_result = owner->ClaimInitialEpoch(Epoch());
    Check(std::holds_alternative<InitialEpochClaim>(claim_result), "fresh claim rejected");
    auto claim = std::get<InitialEpochClaim>(std::move(claim_result));
    Check(claim.epoch_id() == Epoch() && claim.domain_id() == Domain() &&
              claim.root_path() == owner->root_path(), "claim binding mismatch");
    Check(std::holds_alternative<std::monostate>(claim.ValidateOwnership()),
          "claim validation failed");
    auto duplicate_fd = claim.DuplicateRootFd();
    Check(std::holds_alternative<int>(duplicate_fd), "claim failed to duplicate root fd");
    ::close(std::get<int>(duplicate_fd));
    Check(std::filesystem::create_directory(path + "/epoch-intents"),
          "create bootstrap intent directory");
    auto second_claim = owner->ClaimInitialEpoch(Epoch());
    Check(std::get_if<RuntimeOwnerError>(&second_claim) != nullptr &&
              std::get<RuntimeOwnerError>(second_claim) == RuntimeOwnerError::InitialClaimAlreadyUsed,
          "second initial claim succeeded");
    Check(std::holds_alternative<std::monostate>(claim.ValidateOwnership()),
          "second claim invalidated the live bootstrap token");
    auto locked_open = RuntimeOwner::OpenExisting(path, Domain());
    Check(std::get_if<RuntimeOwnerError>(&locked_open) != nullptr &&
              std::get<RuntimeOwnerError>(locked_open) == RuntimeOwnerError::LockBusy,
          "second process owner lock was not rejected");
    owner.reset();
    // The move-only bootstrap claim retains the flock after RuntimeOwner dies.
    locked_open = RuntimeOwner::OpenExisting(path, Domain());
    Check(std::get<RuntimeOwnerError>(locked_open) == RuntimeOwnerError::LockBusy,
          "claim failed to retain ownership lock");
  }
  auto new_owner_result = RuntimeOwner::OpenExisting(path, Domain());
  Check(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(new_owner_result),
        "OpenExisting did not succeed after claim release");
  auto recovery_owner = std::get<std::unique_ptr<RuntimeOwner>>(std::move(new_owner_result));
  Check(recovery_owner->mode() == RuntimeOwnerMode::RecoveryRequired,
        "existing root was not RecoveryRequired");
  Check(std::holds_alternative<RuntimeOwnerError>(recovery_owner->ClaimInitialEpoch(Epoch())),
        "recovery root issued initial claim");
  recovery_owner.reset();
  std::filesystem::remove_all(path);
}

void TestDomainAndMissingAnchorFailClosed() {
  const auto path = FreshPath("domain");
  std::filesystem::remove_all(path);
  auto owner = Create(path);
  owner.reset();
  auto wrong_domain = RuntimeOwner::OpenExisting(path, RuntimeDomainId{});
  Check(std::holds_alternative<RuntimeOwnerError>(wrong_domain), "zero domain accepted");
  auto other = Domain(); other[1] = 2;
  wrong_domain = RuntimeOwner::OpenExisting(path, other);
  Check(std::get_if<RuntimeOwnerError>(&wrong_domain) != nullptr &&
            std::get<RuntimeOwnerError>(wrong_domain) == RuntimeOwnerError::DomainMismatch,
        "wrong domain accepted");
  std::filesystem::remove(path + "/runtime-anchor.json");
  auto missing = RuntimeOwner::OpenExisting(path, Domain());
  Check(std::get_if<RuntimeOwnerError>(&missing) != nullptr &&
            std::get<RuntimeOwnerError>(missing) == RuntimeOwnerError::AnchorMissing,
        "missing anchor was recreated or accepted");
  std::filesystem::remove_all(path);
}

void TestAnchorFifoIsRejectedWithoutBlocking() {
  const auto path = FreshPath("anchor-fifo");
  std::filesystem::remove_all(path);
  auto owner = Create(path);
  owner.reset();
  Check(std::filesystem::remove(path + "/runtime-anchor.json"), "remove anchor for fifo test");
  Check(::mkfifo((path + "/runtime-anchor.json").c_str(), 0600) == 0,
        "create anchor fifo");
  auto result = RuntimeOwner::OpenExisting(path, Domain());
  Check(std::get_if<RuntimeOwnerError>(&result) != nullptr &&
            std::get<RuntimeOwnerError>(result) == RuntimeOwnerError::InvalidAnchor,
        "FIFO anchor was not rejected");
  std::filesystem::remove_all(path);
}

void TestAnchorTamperLatchesFreshOwner() {
  const auto path = FreshPath("tamper");
  std::filesystem::remove_all(path);
  auto owner = Create(path);
  const auto backup = path + "/anchor.save";
  std::filesystem::rename(path + "/runtime-anchor.json", backup);
  {
    FILE* fp = std::fopen((path + "/runtime-anchor.json").c_str(), "wb");
    Check(fp != nullptr, "create tamper anchor");
    const char data[] = "{}";
    Check(std::fwrite(data, 1, sizeof(data) - 1, fp) == sizeof(data) - 1,
          "write tamper anchor");
    Check(std::fclose(fp) == 0, "close tamper anchor");
    Check(::chmod((path + "/runtime-anchor.json").c_str(), 0600) == 0,
          "chmod tamper anchor");
  }
  auto failed = owner->ValidateOwnership();
  Check(std::get_if<RuntimeOwnerError>(&failed) != nullptr,
        "tampered anchor passed validation");
  std::filesystem::remove(path + "/runtime-anchor.json");
  std::filesystem::rename(backup, path + "/runtime-anchor.json");
  Check(owner->mode() == RuntimeOwnerMode::RecoveryRequired,
        "owner regained Fresh mode after anchor restore");
  Check(std::holds_alternative<RuntimeOwnerError>(owner->ClaimInitialEpoch(Epoch())),
        "latched owner issued initial claim");
  owner.reset();
  std::filesystem::remove_all(path);
}

void TestUnexpectedRootEntryBlocksClaim() {
  const auto path = FreshPath("extra-entry");
  std::filesystem::remove_all(path);
  auto owner = Create(path);
  {
    FILE* fp = std::fopen((path + "/unexpected").c_str(), "wb");
    Check(fp != nullptr, "create extra file");
    Check(std::fclose(fp) == 0, "close extra file");
  }
  auto claim = owner->ClaimInitialEpoch(Epoch());
  Check(std::get_if<RuntimeOwnerError>(&claim) != nullptr &&
            std::get<RuntimeOwnerError>(claim) == RuntimeOwnerError::UnexpectedRootEntry,
        "unexpected root entry did not block claim");
  Check(owner->mode() == RuntimeOwnerMode::RecoveryRequired,
        "unexpected entry did not latch owner");
  owner.reset();
  std::filesystem::remove_all(path);
}

void TestFailureBoundaries() {
  const auto parent_sync_path = FreshPath("parent-sync");
  std::filesystem::remove_all(parent_sync_path);
  OneShotFault fault;
  fault.target = RuntimeOwnerIoPoint::SyncParent;
  fault.remaining = 1;
  auto result = RuntimeOwner::CreateNew(parent_sync_path, Domain(), &fault);
  Check(std::get_if<RuntimeOwnerError>(&result) != nullptr &&
            std::get<RuntimeOwnerError>(result) == RuntimeOwnerError::DurabilityUncertain,
        "parent sync failure not uncertain");
  auto retry = RuntimeOwner::CreateNew(parent_sync_path, Domain());
  Check(std::get_if<RuntimeOwnerError>(&retry) != nullptr &&
            std::get<RuntimeOwnerError>(retry) == RuntimeOwnerError::AlreadyExists,
        "partial root was reset after parent sync uncertainty");
  std::filesystem::remove_all(parent_sync_path);

  const auto anchor_sync_path = FreshPath("anchor-sync");
  std::filesystem::remove_all(anchor_sync_path);
  fault.target = RuntimeOwnerIoPoint::SyncRoot;
  fault.remaining = 2;  // First is pre-anchor root sync; second is after anchor rename.
  result = RuntimeOwner::CreateNew(anchor_sync_path, Domain(), &fault);
  Check(std::get_if<RuntimeOwnerError>(&result) != nullptr &&
            std::get<RuntimeOwnerError>(result) == RuntimeOwnerError::DurabilityUncertain,
        "post-anchor root sync failure not uncertain");
  auto recovery = RuntimeOwner::OpenExisting(anchor_sync_path, Domain());
  Check(std::holds_alternative<std::unique_ptr<RuntimeOwner>>(recovery),
        "visible anchor after uncertain sync unavailable for recovery");
  Check(std::get<std::unique_ptr<RuntimeOwner>>(recovery)->mode() ==
            RuntimeOwnerMode::RecoveryRequired,
        "uncertain created root not recovery-only");
  recovery = RuntimeOwnerError::IoFailure;
  std::filesystem::remove_all(anchor_sync_path);
}

void TestForkedHandleIsRejected() {
  const auto path = FreshPath("fork");
  std::filesystem::remove_all(path);
  auto owner = Create(path);
  const pid_t child = ::fork();
  Check(child >= 0, "fork failed");
  if (child == 0) {
    const auto result = owner->ValidateOwnership();
    _exit(std::get_if<RuntimeOwnerError>(&result) != nullptr &&
                  std::get<RuntimeOwnerError>(result) == RuntimeOwnerError::OwnerProcessChanged
              ? 0 : 1);
  }
  int status = 0;
  Check(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "fork-inherited owner was accepted");
  Check(owner->mode() == RuntimeOwnerMode::Fresh,
        "child invalidation incorrectly changed parent owner");
  owner.reset();
  std::filesystem::remove_all(path);
}

}  // namespace

int main() {
  try {
    TestFreshClaimAndRecoveryOnlyOpen();
    TestDomainAndMissingAnchorFailClosed();
    TestAnchorFifoIsRejectedWithoutBlocking();
    TestAnchorTamperLatchesFreshOwner();
    TestUnexpectedRootEntryBlocksClaim();
    TestFailureBoundaries();
    TestForkedHandleIsRejected();
    std::cout << "runtime owner tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "runtime owner test failure: " << error.what() << '\n';
    return 1;
  }
}
