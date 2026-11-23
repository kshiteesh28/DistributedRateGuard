#include "supervisor/bootstrap_store.h"

#include "platform/file_io.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace rateguard::supervisor {
namespace {
using platform::file::ReadAll;
using platform::file::Sync;
using platform::file::UniqueFd;
using platform::file::WriteAll;

constexpr char kIntentName[] = "intent.json";
constexpr char kTempName[] = "intent.tmp";

bool Fail(IBootstrapStoreIo* io, BootstrapStoreIoPoint point) noexcept {
  return io != nullptr && io->FailAt(point);
}

std::string Hex(const auto& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (auto byte : bytes) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 15]);
  }
  return out;
}

bool SameInode(const struct stat& a, const struct stat& b) noexcept {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

bool ValidOwnedDir(const struct stat& st) noexcept {
  return S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() && (st.st_mode & 07777) == 0700;
}

bool ValidIntentFile(const struct stat& st) noexcept {
  return S_ISREG(st.st_mode) && st.st_uid == ::geteuid() &&
      (st.st_mode & 07777) == 0600 && st.st_nlink == 1 && st.st_size >= 0 &&
      static_cast<std::uint64_t>(st.st_size) <= kMaxBootstrapBytes;
}

bool CloseChecked(UniqueFd& fd) noexcept {
  const int raw = fd.release();
  if (raw < 0) return true;
  // close(EINTR) is treated as uncertain; do not retry a possibly reused fd.
  return ::close(raw) == 0;
}

}  // namespace

struct BootstrapStore::State {
  InitialEpochClaim claim;
  UniqueFd root_fd;
  UniqueFd child_fd;
  struct stat root_stat {};
  struct stat child_stat {};
  struct stat intent_stat {};
  bool intent_identity_valid{};
  std::string child_name;
  std::shared_ptr<const BootstrapInventory> committed;
  std::array<std::uint8_t, 32> digest{};
  std::string committed_bytes;
  IBootstrapStoreIo* test_io{};
  mutable std::mutex mutex;
  bool busy{};
  bool writable{};
  bool storage_uncertain{};
  BootstrapVisibility last_visibility{BootstrapVisibility::NotVisible};

  explicit State(InitialEpochClaim value) : claim(std::move(value)) {}
};

namespace {

BootstrapStoreError CheckLocation(BootstrapStore::State& state) noexcept {
  if (Fail(state.test_io, BootstrapStoreIoPoint::CheckOwner)) return BootstrapStoreError::OwnerLost;
  const auto ownership = state.claim.ValidateOwnership();
  if (std::holds_alternative<RuntimeOwnerError>(ownership)) return BootstrapStoreError::OwnerLost;
  if (Fail(state.test_io, BootstrapStoreIoPoint::CheckRoot)) return BootstrapStoreError::InvalidRoot;
  struct stat current_root{};
  if (::fstat(state.root_fd.get(), &current_root) != 0 || !ValidOwnedDir(current_root) ||
      !SameInode(current_root, state.root_stat)) return BootstrapStoreError::InvalidRoot;
  if (Fail(state.test_io, BootstrapStoreIoPoint::CheckChild)) return BootstrapStoreError::InvalidChild;
  struct stat child_fd{}, child_path{};
  if (::fstat(state.child_fd.get(), &child_fd) != 0 ||
      ::fstatat(state.root_fd.get(), state.child_name.c_str(), &child_path, AT_SYMLINK_NOFOLLOW) != 0 ||
      !ValidOwnedDir(child_fd) || !S_ISDIR(child_path.st_mode) || !SameInode(child_fd, state.child_stat) ||
      !SameInode(child_path, state.child_stat)) return BootstrapStoreError::InvalidChild;
  return BootstrapStoreError::None;
}

BootstrapStoreError CheckRootOnly(BootstrapStore::State& state) noexcept {
  if (Fail(state.test_io, BootstrapStoreIoPoint::CheckOwner)) return BootstrapStoreError::OwnerLost;
  if (std::holds_alternative<RuntimeOwnerError>(state.claim.ValidateOwnership()))
    return BootstrapStoreError::OwnerLost;
  if (Fail(state.test_io, BootstrapStoreIoPoint::CheckRoot)) return BootstrapStoreError::InvalidRoot;
  struct stat current_root{};
  if (::fstat(state.root_fd.get(), &current_root) != 0 || !ValidOwnedDir(current_root) ||
      !SameInode(current_root, state.root_stat)) return BootstrapStoreError::InvalidRoot;
  return BootstrapStoreError::None;
}

struct PersistResult final {
  BootstrapVisibility visibility{BootstrapVisibility::NotVisible};
  BootstrapStoreError error{BootstrapStoreError::None};
};

PersistResult NotPersisted(BootstrapStoreError error) noexcept {
  return {BootstrapVisibility::NotVisible, error};
}

BootstrapStoreError ReadIntent(BootstrapStore::State& state, std::string& bytes,
                               struct stat* final_identity = nullptr) noexcept {
  try {
    auto checked = CheckLocation(state);
    if (checked != BootstrapStoreError::None) return checked;
    if (Fail(state.test_io, BootstrapStoreIoPoint::CheckCurrentFile)) return BootstrapStoreError::InvalidIntent;
    struct stat path_stat{};
    if (::fstatat(state.child_fd.get(), kIntentName, &path_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
        !ValidIntentFile(path_stat)) return BootstrapStoreError::InvalidIntent;
    checked = CheckLocation(state);
    if (checked != BootstrapStoreError::None) return checked;
    UniqueFd file(::openat(state.child_fd.get(), kIntentName,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) return BootstrapStoreError::InvalidIntent;
    struct stat fd_stat{}, entry_stat{};
    if (::fstat(file.get(), &fd_stat) != 0 || !ValidIntentFile(fd_stat) ||
        !SameInode(fd_stat, path_stat) ||
        ::fstatat(state.child_fd.get(), kIntentName, &entry_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
        !SameInode(fd_stat, entry_stat)) return BootstrapStoreError::InvalidIntent;
    checked = CheckLocation(state);
    if (checked != BootstrapStoreError::None) return checked;
    if (Fail(state.test_io, BootstrapStoreIoPoint::ReadCurrentFile)) return BootstrapStoreError::IoFailure;
    if (!ReadAll(file.get(), bytes, static_cast<std::size_t>(fd_stat.st_size))) return BootstrapStoreError::IoFailure;
    struct stat after_fd{}, after_path{};
    if (::fstat(file.get(), &after_fd) != 0 ||
        ::fstatat(state.child_fd.get(), kIntentName, &after_path, AT_SYMLINK_NOFOLLOW) != 0 ||
        !SameInode(after_fd, after_path) || !SameInode(after_fd, path_stat) || !ValidIntentFile(after_fd))
      return BootstrapStoreError::InvalidIntent;
    checked = CheckLocation(state);
    if (checked != BootstrapStoreError::None) return checked;
    if (!CloseChecked(file)) return BootstrapStoreError::IoFailure;
    if (final_identity != nullptr) *final_identity = after_fd;
    return BootstrapStoreError::None;
  } catch (...) { return BootstrapStoreError::AllocationFailure; }
}

PersistResult AtomicReplace(BootstrapStore::State& state, std::string_view bytes,
                            bool require_existing) noexcept {
  auto checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (require_existing) {
    std::string old_bytes;
    struct stat old_identity{};
    const auto read_result = ReadIntent(state, old_bytes, &old_identity);
    if (read_result != BootstrapStoreError::None) return NotPersisted(read_result);
    if (old_bytes != state.committed_bytes || !state.intent_identity_valid ||
        !SameInode(old_identity, state.intent_stat)) return NotPersisted(BootstrapStoreError::StorageUncertain);
  } else {
    struct stat existing{};
    if (::fstatat(state.child_fd.get(), kIntentName, &existing, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
      return NotPersisted(BootstrapStoreError::InvalidIntent);
  }
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (Fail(state.test_io, BootstrapStoreIoPoint::CreateTemp)) return NotPersisted(BootstrapStoreError::IoFailure);
  UniqueFd temp(::openat(state.child_fd.get(), kTempName,
      O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600));
  if (temp.get() < 0) return NotPersisted(BootstrapStoreError::IoFailure);
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  struct stat temp_stat{}, temp_path{};
  if (::fchmod(temp.get(), 0600) != 0 || ::fstat(temp.get(), &temp_stat) != 0 ||
      !ValidIntentFile(temp_stat) ||
      ::fstatat(state.child_fd.get(), kTempName, &temp_path, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(temp_stat, temp_path)) return NotPersisted(BootstrapStoreError::IoFailure);
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (Fail(state.test_io, BootstrapStoreIoPoint::WriteTemp) ||
      !WriteAll(temp.get(), bytes.data(), bytes.size())) return NotPersisted(BootstrapStoreError::IoFailure);
  struct stat written_fd{}, written_path{};
  if (::fstat(temp.get(), &written_fd) != 0 || !ValidIntentFile(written_fd) ||
      static_cast<std::uint64_t>(written_fd.st_size) != bytes.size() ||
      ::fstatat(state.child_fd.get(), kTempName, &written_path, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(written_fd, written_path)) return NotPersisted(BootstrapStoreError::IoFailure);
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (Fail(state.test_io, BootstrapStoreIoPoint::SyncTemp) || !Sync(temp.get()))
    return NotPersisted(BootstrapStoreError::IoFailure);
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (Fail(state.test_io, BootstrapStoreIoPoint::CloseTemp) || !CloseChecked(temp))
    return NotPersisted(BootstrapStoreError::IoFailure);
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (Fail(state.test_io, BootstrapStoreIoPoint::RenameTemp))
    return NotPersisted(BootstrapStoreError::IoFailure);
  // Revalidate the target after temp fsync/close and immediately before the
  // rename so a changed file is never silently overwritten.
  if (require_existing) {
    std::string latest;
    struct stat latest_identity{};
    const auto latest_result = ReadIntent(state, latest, &latest_identity);
    if (latest_result != BootstrapStoreError::None || latest != state.committed_bytes ||
        !SameInode(latest_identity, state.intent_stat)) return NotPersisted(
            latest_result == BootstrapStoreError::None ? BootstrapStoreError::StorageUncertain : latest_result);
  } else {
    struct stat target{};
    if (::fstatat(state.child_fd.get(), kIntentName, &target, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
      return NotPersisted(BootstrapStoreError::InvalidIntent);
  }
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None) return NotPersisted(checked);
  if (require_existing) {
    // The runtime root is held by one trusted owner. Revalidate the exact old
    // file immediately before this atomic replacement; hostile same-UID
    // concurrent writers are outside the runtime-owner trust model.
    if (::renameat(state.child_fd.get(), kTempName, state.child_fd.get(), kIntentName) != 0)
      return NotPersisted(BootstrapStoreError::IoFailure);
  } else {
    // linkat provides POSIX no-replace publication. The temporary second link
    // is removed before directory fsync; any failure after link visibility is
    // reported as VisibleDurabilityUnknown and permanently blocks readiness.
    if (::linkat(state.child_fd.get(), kTempName, state.child_fd.get(), kIntentName, 0) != 0)
      return NotPersisted(BootstrapStoreError::IoFailure);
    checked = CheckLocation(state);
    if (checked != BootstrapStoreError::None)
      return {BootstrapVisibility::VisibleDurabilityUnknown, checked};
    struct stat temp_link{}, intent_link{};
    if (::fstatat(state.child_fd.get(), kTempName, &temp_link, AT_SYMLINK_NOFOLLOW) != 0 ||
        ::fstatat(state.child_fd.get(), kIntentName, &intent_link, AT_SYMLINK_NOFOLLOW) != 0 ||
        !SameInode(temp_link, intent_link) || !S_ISREG(temp_link.st_mode) || temp_link.st_nlink != 2)
      return {BootstrapVisibility::VisibleDurabilityUnknown, BootstrapStoreError::InvalidIntent};
    if (::unlinkat(state.child_fd.get(), kTempName, 0) != 0)
      return {BootstrapVisibility::VisibleDurabilityUnknown, BootstrapStoreError::DurabilityUncertain};
  }
  checked = CheckLocation(state);
  if (checked != BootstrapStoreError::None)
    return {BootstrapVisibility::VisibleDurabilityUnknown, checked};
  if (Fail(state.test_io, BootstrapStoreIoPoint::SyncChild) || !Sync(state.child_fd.get()))
    return {BootstrapVisibility::VisibleDurabilityUnknown, BootstrapStoreError::DurabilityUncertain};
  std::string verify;
  struct stat new_identity{};
  const auto read_result = ReadIntent(state, verify, &new_identity);
  if (read_result != BootstrapStoreError::None)
    return {BootstrapVisibility::VisibleDurabilityUnknown, read_result};
  if (verify != bytes) return {BootstrapVisibility::VisibleDurabilityUnknown, BootstrapStoreError::DurabilityUncertain};
  state.intent_stat = new_identity;
  state.intent_identity_valid = true;
  return {BootstrapVisibility::Durable, BootstrapStoreError::None};
}

void MarkUnwritable(BootstrapStore::State& state, BootstrapVisibility visibility) noexcept {
  std::lock_guard lock(state.mutex);
  state.writable = false;
  state.storage_uncertain = true;
  state.last_visibility = visibility;
  state.busy = false;
}

}  // namespace

BootstrapStore::BootstrapStore(std::unique_ptr<State> state) noexcept : state_(std::move(state)) {}
BootstrapStore::~BootstrapStore() = default;

BootstrapStoreOpenResult BootstrapStore::CreateNew(InitialEpochClaim claim, const BootstrapPlan& plan,
                                                    IBootstrapStoreIo* test_io) noexcept {
  const auto failure = [](BootstrapStoreError error,
                          BootstrapVisibility visibility = BootstrapVisibility::NotVisible) {
    return BootstrapStoreOpenResult{nullptr, visibility, error};
  };
  try {
    if (std::holds_alternative<RuntimeOwnerError>(claim.ValidateOwnership()))
      return failure(BootstrapStoreError::InvalidClaim);
    if (plan.domain_id != claim.domain_id()) return failure(BootstrapStoreError::DomainMismatch);
    if (plan.epoch_id != claim.epoch_id()) return failure(BootstrapStoreError::EpochMismatch);
    auto model = BootstrapInventory::Create(plan);
    if (std::holds_alternative<BootstrapError>(model))
      return failure(BootstrapStoreError::InvalidPlan);
    const auto encoded = EncodeBootstrapInventoryV1(std::get<BootstrapInventory>(model));
    if (const auto* error = std::get_if<BootstrapError>(&encoded))
      return failure(*error == BootstrapError::AllocationFailure ? BootstrapStoreError::AllocationFailure : BootstrapStoreError::InvalidPlan);
    const std::string bytes = std::get<std::string>(encoded);
    const auto digest_result = BootstrapDigestV1(std::get<BootstrapInventory>(model));
    if (const auto* error = std::get_if<BootstrapError>(&digest_result))
      return failure(*error == BootstrapError::AllocationFailure ? BootstrapStoreError::AllocationFailure : BootstrapStoreError::InvalidPlan);

    auto state = std::make_unique<State>(std::move(claim));
    state->test_io = test_io;
    state->child_name = "epoch-" + Hex(plan.epoch_id);
    state->committed = std::make_shared<const BootstrapInventory>(std::get<BootstrapInventory>(model));
    state->digest = std::get<std::array<std::uint8_t, 32>>(digest_result);
    state->committed_bytes = bytes;
    auto root_dup = state->claim.DuplicateRootFd();
    if (const auto* error = std::get_if<RuntimeOwnerError>(&root_dup)) {
      (void)error; return failure(BootstrapStoreError::InvalidClaim);
    }
    state->root_fd = UniqueFd(std::get<int>(root_dup));
    if (::fstat(state->root_fd.get(), &state->root_stat) != 0 || !ValidOwnedDir(state->root_stat))
      return failure(BootstrapStoreError::InvalidRoot);
    auto store = std::unique_ptr<BootstrapStore>(new BootstrapStore(std::move(state)));
    auto& store_state = *store->state_;
    auto check = CheckRootOnly(store_state);
    if (check != BootstrapStoreError::None) return failure(check);
    if (Fail(test_io, BootstrapStoreIoPoint::MakeChild)) return failure(BootstrapStoreError::IoFailure);
    if (::mkdirat(store_state.root_fd.get(), store_state.child_name.c_str(), 0700) != 0)
      return failure(errno == EEXIST ? BootstrapStoreError::ExistingEpoch : BootstrapStoreError::IoFailure);
    check = CheckRootOnly(store_state);
    if (check != BootstrapStoreError::None) return failure(check);
    if (Fail(test_io, BootstrapStoreIoPoint::SyncRootAfterMkdir) || !Sync(store_state.root_fd.get()))
      return failure(BootstrapStoreError::DurabilityUncertain);
    check = CheckRootOnly(store_state);
    if (check != BootstrapStoreError::None) return failure(check);
    if (Fail(test_io, BootstrapStoreIoPoint::OpenChild)) return failure(BootstrapStoreError::IoFailure);
    store_state.child_fd = UniqueFd(::openat(store_state.root_fd.get(), store_state.child_name.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (store_state.child_fd.get() < 0 || ::fstat(store_state.child_fd.get(), &store_state.child_stat) != 0 ||
        !ValidOwnedDir(store_state.child_stat)) return failure(BootstrapStoreError::InvalidChild);
    struct stat child_path{};
    if (::fstatat(store_state.root_fd.get(), store_state.child_name.c_str(), &child_path, AT_SYMLINK_NOFOLLOW) != 0 ||
        !SameInode(child_path, store_state.child_stat)) return failure(BootstrapStoreError::InvalidChild);
    check = CheckLocation(store_state);
    if (check != BootstrapStoreError::None) return failure(check);
    if (::fchmod(store_state.child_fd.get(), 0700) != 0 ||
        ::fstat(store_state.child_fd.get(), &store_state.child_stat) != 0 ||
        !ValidOwnedDir(store_state.child_stat)) return failure(BootstrapStoreError::InvalidChild);
    check = CheckLocation(store_state);
    if (check != BootstrapStoreError::None) return failure(check);
    const auto written = AtomicReplace(store_state, bytes, false);
    if (written.error != BootstrapStoreError::None)
      return failure(written.error, written.visibility);
    store_state.writable = true;
    store_state.last_visibility = BootstrapVisibility::Durable;
    return {std::move(store), BootstrapVisibility::Durable, BootstrapStoreError::None};
  } catch (...) { return failure(BootstrapStoreError::AllocationFailure); }
}

std::shared_ptr<const BootstrapInventory> BootstrapStore::Snapshot() const noexcept {
  std::lock_guard lock(state_->mutex);
  return state_->committed;
}

BootstrapStoreUpdate BootstrapStore::RecordIdentity(
    std::uint64_t expected_revision, const std::array<std::uint8_t, 32>& expected_digest,
    const ObservedBootstrapIdentity& observed) noexcept {
  std::shared_ptr<const BootstrapInventory> current;
  {
    std::lock_guard lock(state_->mutex);
    if (state_->busy) return {state_->committed, BootstrapVisibility::NotVisible,
                              BootstrapStoreError::Busy, BootstrapError::None};
    if (!state_->writable || state_->storage_uncertain)
      return {state_->committed, state_->last_visibility,
              BootstrapStoreError::StorageUncertain, BootstrapError::None};
    current = state_->committed;
    if (current->revision() != expected_revision || state_->digest != expected_digest)
      return {current, BootstrapVisibility::NotVisible, BootstrapStoreError::Conflict, BootstrapError::None};
    state_->busy = true;
  }
  auto finish_error = [&](BootstrapStoreError error, BootstrapError transition = BootstrapError::None,
                          BootstrapVisibility visibility = BootstrapVisibility::NotVisible) {
    if (error != BootstrapStoreError::Conflict && error != BootstrapStoreError::Busy)
      MarkUnwritable(*state_, visibility);
    else { std::lock_guard lock(state_->mutex); state_->busy = false; }
    return BootstrapStoreUpdate{Snapshot(), visibility, error, transition};
  };
  try {
    if (std::holds_alternative<RuntimeOwnerError>(state_->claim.ValidateOwnership()))
      return finish_error(BootstrapStoreError::OwnerLost);
    const auto applied = current->RecordIdentity(observed);
    const auto encoded = EncodeBootstrapInventoryV1(applied.next);
    if (const auto* error = std::get_if<BootstrapError>(&encoded))
      return finish_error(*error == BootstrapError::AllocationFailure ? BootstrapStoreError::AllocationFailure : BootstrapStoreError::InvalidIntent,
                          applied.status);
    const auto bytes = std::get<std::string>(encoded);
    const auto digest_result = BootstrapDigestV1(applied.next);
    if (const auto* error = std::get_if<BootstrapError>(&digest_result))
      return finish_error(*error == BootstrapError::AllocationFailure ? BootstrapStoreError::AllocationFailure : BootstrapStoreError::InvalidIntent,
                          applied.status);
    const auto digest = std::get<std::array<std::uint8_t, 32>>(digest_result);
    if (bytes == state_->committed_bytes) {
      std::string on_disk;
      const auto read = ReadIntent(*state_, on_disk);
      if (read != BootstrapStoreError::None || on_disk != bytes)
        return finish_error(read == BootstrapStoreError::None ? BootstrapStoreError::StorageUncertain : read,
                            applied.status, BootstrapVisibility::NotVisible);
      std::lock_guard lock(state_->mutex);
      state_->busy = false;
      state_->last_visibility = BootstrapVisibility::Durable;
      return {current, BootstrapVisibility::Durable, BootstrapStoreError::None, applied.status};
    }
    auto next = std::make_shared<const BootstrapInventory>(applied.next);
    auto published = next;
    std::string committed_bytes = bytes;
    const auto written = AtomicReplace(*state_, bytes, true);
    if (written.error != BootstrapStoreError::None)
      return finish_error(written.error, applied.status, written.visibility);
    {
      std::lock_guard lock(state_->mutex);
      state_->committed = std::move(next);
      state_->digest = digest;
      state_->committed_bytes = std::move(committed_bytes);
      state_->last_visibility = BootstrapVisibility::Durable;
      state_->busy = false;
    }
    return {std::move(published), BootstrapVisibility::Durable, BootstrapStoreError::None, applied.status};
  } catch (...) { return finish_error(BootstrapStoreError::StorageUncertain); }
}

BootstrapCandidateResult BootstrapStore::ReadyCandidate() noexcept {
  {
    std::lock_guard lock(state_->mutex);
    if (state_->busy) return BootstrapStoreError::Busy;
    if (!state_->writable || state_->storage_uncertain) return BootstrapStoreError::StorageUncertain;
    state_->busy = true;
  }
  auto finish = [&](BootstrapStoreError error) -> BootstrapCandidateResult {
    if (error == BootstrapStoreError::RecoveryRequired || error == BootstrapStoreError::IncompleteRoster) {
      std::lock_guard lock(state_->mutex);
      state_->busy = false;
    } else if (error != BootstrapStoreError::None) MarkUnwritable(*state_, BootstrapVisibility::NotVisible);
    else { std::lock_guard lock(state_->mutex); state_->busy = false; }
    return error;
  };
  try {
    if (state_->committed->recovery_required()) return finish(BootstrapStoreError::RecoveryRequired);
    if (std::holds_alternative<RuntimeOwnerError>(state_->claim.ValidateOwnership()))
      return finish(BootstrapStoreError::OwnerLost);
    std::string on_disk;
    const auto read = ReadIntent(*state_, on_disk);
    if (read != BootstrapStoreError::None) return finish(read);
    if (on_disk != state_->committed_bytes) return finish(BootstrapStoreError::StorageUncertain);
    const auto decoded = DecodeBootstrapInventoryV1(on_disk);
    if (const auto* error = std::get_if<BootstrapError>(&decoded)) {
      (void)error; return finish(BootstrapStoreError::InvalidIntent);
    }
    const auto& disk = std::get<BootstrapInventory>(decoded);
    const auto disk_digest = BootstrapDigestV1(disk);
    if (const auto* error = std::get_if<BootstrapError>(&disk_digest)) {
      (void)error; return finish(BootstrapStoreError::InvalidIntent);
    }
    if (std::get<std::array<std::uint8_t, 32>>(disk_digest) != state_->digest ||
        disk.domain_id() != state_->claim.domain_id() || disk.epoch_id() != state_->claim.epoch_id())
      return finish(BootstrapStoreError::InvalidIntent);
    auto candidate = state_->committed->ReadyCandidate();
    if (const auto* error = std::get_if<BootstrapError>(&candidate)) {
      if (*error == BootstrapError::RecoveryRequired) return finish(BootstrapStoreError::RecoveryRequired);
      if (*error == BootstrapError::IncompleteRoster) return finish(BootstrapStoreError::IncompleteRoster);
      return finish(BootstrapStoreError::InvalidPlan);
    }
    auto ready = std::get<EpochCandidate>(std::move(candidate));
    BootstrapCandidateResult result(std::in_place_type<EpochCandidate>, std::move(ready));
    { std::lock_guard lock(state_->mutex); state_->busy = false; }
    return result;
  } catch (...) { return finish(BootstrapStoreError::StorageUncertain); }
}

}  // namespace rateguard::supervisor
