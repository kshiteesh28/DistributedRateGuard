#include "supervisor/manifest_store.h"

#include "supervisor/epoch_gate.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace rateguard::supervisor {
namespace {

constexpr char kLockName[] = "owner.lock";
constexpr char kManifestName[] = "manifest.json";
constexpr char kTempName[] = "manifest.tmp";
constexpr std::size_t kMaxDirectoryPathBytes = 4096;

bool ValidPath(const std::string& path) noexcept;

class UniqueFd {
 public:
  explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
      if (fd_ >= 0) ::close(fd_);
      fd_ = other.release();
    }
    return *this;
  }
  ~UniqueFd() { if (fd_ >= 0) ::close(fd_); }
  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] int release() noexcept { const int value = fd_; fd_ = -1; return value; }
 private:
  int fd_;
};

struct ParentLocation {
  UniqueFd fd;
  std::string leaf;
};

std::optional<ParentLocation> OpenParent(const std::string& path) {
  if (!ValidPath(path) || path.back() == '/') return std::nullopt;
  const auto slash = path.find_last_of('/');
  const std::string parent = slash == std::string::npos ? "." :
                             slash == 0 ? "/" : path.substr(0, slash);
  const std::string leaf = slash == std::string::npos ? path : path.substr(slash + 1);
  if (leaf.empty() || leaf == "." || leaf == "..") return std::nullopt;
  const int fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return std::nullopt;
  return ParentLocation{UniqueFd(fd), leaf};
}

bool Fail(IManifestFileOps* hooks, ManifestIoPoint point) noexcept {
  return hooks != nullptr && hooks->FailAt(point);
}

bool ValidPath(const std::string& path) noexcept {
  return !path.empty() && path.size() < kMaxDirectoryPathBytes &&
         path.find('\0') == std::string::npos;
}

bool ExactMode(const struct stat& st, mode_t mode) noexcept {
  return (st.st_mode & 07777) == mode;
}

bool ValidDirectory(int fd) noexcept {
  struct stat st {};
  return ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() &&
         ExactMode(st, 0700);
}

bool SameInode(const struct stat& a, const struct stat& b) noexcept {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

bool ValidRegularFile(const struct stat& st, mode_t mode) noexcept {
  return S_ISREG(st.st_mode) && st.st_uid == ::geteuid() && ExactMode(st, mode) &&
         st.st_nlink == 1;
}

bool NormalizeManifest(const ManifestV1& input, ManifestV1& output) noexcept {
  try {
    auto encoded = EncodeManifestV1(input);
    if (std::holds_alternative<ManifestCodecError>(encoded)) return false;
    const auto& bytes = std::get<std::string>(encoded);
    if (bytes.size() > kMaxManifestBytes) return false;
    auto decoded = DecodeManifestV1(bytes);
    if (std::holds_alternative<ManifestCodecError>(decoded)) return false;
    output = std::get<ManifestV1>(std::move(decoded));
    return true;
  } catch (...) {
    return false;
  }
}

ManifestStoreError CodecError(ManifestCodecError) noexcept {
  return ManifestStoreError::CodecFailure;
}

bool ValidOperation(const OperationId& id) noexcept {
  return std::any_of(id.begin(), id.end(), [](std::uint8_t v) { return v != 0; });
}

bool LegalTransition(ManifestPhase from, ManifestPhase to) noexcept {
  return (from == ManifestPhase::Prepared &&
          (to == ManifestPhase::Active || to == ManifestPhase::Draining)) ||
         (from == ManifestPhase::Active && to == ManifestPhase::Draining) ||
         (from == ManifestPhase::Draining && to == ManifestPhase::Closed);
}

bool WriteAll(int fd, const char* data, std::size_t size) noexcept {
  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t n = ::write(fd, data + offset, size - offset);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    offset += static_cast<std::size_t>(n);
  }
  return true;
}

bool Sync(int fd) noexcept {
  int result;
  do { result = ::fsync(fd); } while (result != 0 && errno == EINTR);
  return result == 0;
}

bool ReadAll(int fd, std::string& out, std::size_t size) {
  out.resize(size);
  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t n = ::read(fd, out.data() + offset, size - offset);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    offset += static_cast<std::size_t>(n);
  }
  char extra = 0;
  ssize_t trailing;
  do { trailing = ::read(fd, &extra, 1); } while (trailing < 0 && errno == EINTR);
  return trailing == 0;
}

std::variant<std::pair<ManifestV1, std::array<std::uint8_t, 32>>, ManifestStoreError>
ReadManifest(int dirfd, IManifestFileOps* hooks) {
  if (Fail(hooks, ManifestIoPoint::OpenManifest)) return ManifestStoreError::ReadFailure;
  const int fd = ::openat(dirfd, kManifestName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    if (errno == ENOENT) return ManifestStoreError::MissingManifest;
    return ManifestStoreError::ReadFailure;
  }
  struct FdGuard { int fd; ~FdGuard() { if (fd >= 0) ::close(fd); } } guard{fd};
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !ValidRegularFile(st, 0600) || st.st_size < 0)
    return ManifestStoreError::InvalidManifestFile;
  struct stat named {};
  if (::fstatat(dirfd, kManifestName, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(st, named) || !ValidRegularFile(named, 0600))
    return ManifestStoreError::InvalidManifestFile;
  if (static_cast<std::uint64_t>(st.st_size) > kMaxManifestBytes)
    return ManifestStoreError::ManifestTooLarge;
  if (Fail(hooks, ManifestIoPoint::ReadManifest)) return ManifestStoreError::ReadFailure;
  std::string bytes;
  if (!ReadAll(fd, bytes, static_cast<std::size_t>(st.st_size)))
    return ManifestStoreError::ReadFailure;
  auto decoded = DecodeManifestV1(bytes);
  if (auto* error = std::get_if<ManifestCodecError>(&decoded)) return CodecError(*error);
  auto manifest = std::get<ManifestV1>(std::move(decoded));
  auto digest_result = ManifestDigestV1(manifest);
  if (auto* error = std::get_if<ManifestCodecError>(&digest_result)) return CodecError(*error);
  return std::pair<ManifestV1, std::array<std::uint8_t, 32>>{
      std::move(manifest), std::get<std::array<std::uint8_t, 32>>(std::move(digest_result))};
}

bool ValidateLock(int dirfd, int lockfd, IManifestFileOps* hooks) noexcept {
  if (Fail(hooks, ManifestIoPoint::CheckLockIdentity))
    return false;
  struct stat opened {}, named {};
  if (::fstat(lockfd, &opened) != 0 ||
      ::fstatat(dirfd, kLockName, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(opened, named) || !ValidRegularFile(opened, 0600) ||
      !ValidRegularFile(named, 0600)) return false;
  return true;
}

bool LockValid(int dirfd, int lockfd, IManifestFileOps* hooks) noexcept {
  return ValidateLock(dirfd, lockfd, hooks);
}

int OpenDirectory(const std::string& path, IManifestFileOps* hooks) noexcept {
  if (Fail(hooks, ManifestIoPoint::OpenDirectory)) { errno = EIO; return -1; }
  return ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

int CreateAndLock(int dirfd, IManifestFileOps* hooks,
                  ManifestStoreError& error) noexcept {
  if (Fail(hooks, ManifestIoPoint::CreateLock)) {
    error = ManifestStoreError::InvalidLock; return -1;
  }
  const int fd = ::openat(dirfd, kLockName,
      O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) { error = ManifestStoreError::InvalidLock; return -1; }
  if (::fchmod(fd, 0600) != 0) {
    error = ManifestStoreError::InvalidLock; ::close(fd); return -1;
  }
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !ValidRegularFile(st, 0600)) {
    error = ManifestStoreError::InvalidLock; ::close(fd); return -1;
  }
  if (Fail(hooks, ManifestIoPoint::AcquireLock)) {
    errno = EIO;
    error = ManifestStoreError::InvalidLock;
    ::close(fd);
    return -1;
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    error = (errno == EWOULDBLOCK || errno == EAGAIN) ? ManifestStoreError::LockBusy
                                                       : ManifestStoreError::InvalidLock;
    ::close(fd); return -1;
  }
  if (!LockValid(dirfd, fd, hooks)) {
    error = ManifestStoreError::LockIdentityChanged; ::close(fd); return -1;
  }
  if (Fail(hooks, ManifestIoPoint::SyncLock) || !Sync(fd)) {
    error = ManifestStoreError::FileSyncFailure; ::close(fd); return -1;
  }
  return fd;
}

std::optional<ManifestStoreError> WriteNewManifest(int dirfd, int lockfd,
                                                   const ManifestV1& manifest,
                                                   IManifestFileOps* hooks) {
  if (!LockValid(dirfd, lockfd, hooks)) return ManifestStoreError::LockIdentityChanged;
  auto encoded = EncodeManifestV1(manifest);
  if (auto* error = std::get_if<ManifestCodecError>(&encoded)) return CodecError(*error);
  auto& bytes = std::get<std::string>(encoded);
  if (bytes.size() > kMaxManifestBytes) return ManifestStoreError::ManifestTooLarge;
  if (Fail(hooks, ManifestIoPoint::CreateTemp)) return ManifestStoreError::WriteFailure;
  UniqueFd tempfd(::openat(dirfd, kTempName,
      O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (tempfd.get() < 0) return ManifestStoreError::WriteFailure;
  struct stat temp_stat {};
  if (::fchmod(tempfd.get(), 0600) != 0 || ::fstat(tempfd.get(), &temp_stat) != 0 ||
      !ValidRegularFile(temp_stat, 0600)) {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
    return ManifestStoreError::WriteFailure;
  }
  if (Fail(hooks, ManifestIoPoint::WriteTemp) || !WriteAll(tempfd.get(), bytes.data(), bytes.size())) {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
    return ManifestStoreError::WriteFailure;
  }
  if (Fail(hooks, ManifestIoPoint::SyncTemp) || !Sync(tempfd.get())) {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
    return ManifestStoreError::FileSyncFailure;
  }
  const int closed_fd = tempfd.release();
  if (::close(closed_fd) != 0) {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
    return ManifestStoreError::WriteFailure;
  }
  if (!LockValid(dirfd, lockfd, hooks)) {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
    return ManifestStoreError::LockIdentityChanged;
  }
  if (Fail(hooks, ManifestIoPoint::RenameManifest) ||
      ::renameat(dirfd, kTempName, dirfd, kManifestName) != 0) {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
    return ManifestStoreError::RenameFailure;
  }
  if (Fail(hooks, ManifestIoPoint::SyncDirectory) || !Sync(dirfd))
    return ManifestStoreError::DurabilityUncertain;
  return std::nullopt;
}

struct PersistResult {
  ManifestVisibility visibility{ManifestVisibility::NotVisible};
  std::optional<ManifestStoreError> error;
};

PersistResult PersistReplacement(int dirfd, int lockfd,
                                 const ManifestV1& current,
                                 const std::array<std::uint8_t, 32>& current_digest,
                                 std::string_view bytes,
                                 IManifestFileOps* hooks) {
  if (!LockValid(dirfd, lockfd, hooks))
    return {ManifestVisibility::NotVisible, ManifestStoreError::LockIdentityChanged};
  auto on_disk = ReadManifest(dirfd, hooks);
  if (auto* error = std::get_if<ManifestStoreError>(&on_disk))
    return {ManifestVisibility::NotVisible, *error};
  auto disk = std::get<std::pair<ManifestV1, std::array<std::uint8_t, 32>>>(std::move(on_disk));
  if (disk.first.generation != current.generation || disk.second != current_digest)
    return {ManifestVisibility::NotVisible, ManifestStoreError::CompareAndSwapMismatch};

  if (Fail(hooks, ManifestIoPoint::CreateTemp))
    return {ManifestVisibility::NotVisible, ManifestStoreError::WriteFailure};
  UniqueFd tempfd(::openat(dirfd, kTempName,
      O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (tempfd.get() < 0)
    return {ManifestVisibility::NotVisible, ManifestStoreError::WriteFailure};
  const auto cleanup = [&] {
    if (!Fail(hooks, ManifestIoPoint::CleanupTemp)) (void)::unlinkat(dirfd, kTempName, 0);
  };
  struct stat temp_stat {};
  if (::fchmod(tempfd.get(), 0600) != 0 || ::fstat(tempfd.get(), &temp_stat) != 0 ||
      !ValidRegularFile(temp_stat, 0600)) {
    cleanup();
    return {ManifestVisibility::NotVisible, ManifestStoreError::WriteFailure};
  }
  if (Fail(hooks, ManifestIoPoint::WriteTemp) || !WriteAll(tempfd.get(), bytes.data(), bytes.size())) {
    cleanup();
    return {ManifestVisibility::NotVisible, ManifestStoreError::WriteFailure};
  }
  if (Fail(hooks, ManifestIoPoint::SyncTemp) || !Sync(tempfd.get())) {
    cleanup();
    return {ManifestVisibility::NotVisible, ManifestStoreError::FileSyncFailure};
  }
  const int closed_fd = tempfd.release();
  if (::close(closed_fd) != 0) {
    cleanup();
    return {ManifestVisibility::NotVisible, ManifestStoreError::WriteFailure};
  }
  if (!LockValid(dirfd, lockfd, hooks)) {
    cleanup();
    return {ManifestVisibility::NotVisible, ManifestStoreError::LockIdentityChanged};
  }
  if (Fail(hooks, ManifestIoPoint::RenameManifest) ||
      ::renameat(dirfd, kTempName, dirfd, kManifestName) != 0) {
    cleanup();
    return {ManifestVisibility::NotVisible, ManifestStoreError::RenameFailure};
  }
  if (Fail(hooks, ManifestIoPoint::SyncDirectory) || !Sync(dirfd))
    return {ManifestVisibility::VisibleDurabilityUnknown,
            ManifestStoreError::DurabilityUncertain};
  return {ManifestVisibility::Durable, std::nullopt};
}

}  // namespace

struct ManifestStore::Impl {
  int directory_fd{-1};
  int lock_fd{-1};
  std::string directory;
  ManifestV1 manifest;
  std::array<std::uint8_t, 32> digest{};
  bool recovery_only{};
  bool writable{true};
  bool transition_in_progress{};
  IManifestFileOps* test_hooks{};  // Non-owning test seam; caller outlives store.
  mutable std::mutex mutex;
};

ManifestStore::ManifestStore(int directory_fd, int lock_fd, std::string directory,
                             ManifestV1 manifest,
                             std::array<std::uint8_t, 32> digest,
                             bool recovery_only, IManifestFileOps* test_hooks)
    : impl_(std::make_unique<Impl>()) {
  impl_->directory_fd = directory_fd;
  impl_->lock_fd = lock_fd;
  impl_->directory = std::move(directory);
  impl_->manifest = std::move(manifest);
  impl_->digest = digest;
  impl_->recovery_only = recovery_only;
  impl_->writable = !recovery_only;
  impl_->test_hooks = test_hooks;
}

ManifestStore::~ManifestStore() {
  if (!impl_) return;
  if (impl_->lock_fd >= 0) ::close(impl_->lock_fd);
  if (impl_->directory_fd >= 0) ::close(impl_->directory_fd);
}

ManifestStoreOpenResult ManifestStore::CreateNew(
    const std::string& directory, const EpochCandidate& candidate,
    const OperationId& creation_operation_id, IManifestFileOps* hooks) noexcept {
  try {
    if (!ValidPath(directory)) return ManifestStoreError::InvalidPath;
    if (const auto invalid = ValidateEpochCandidate(candidate); invalid.has_value())
      return ManifestStoreError::InvalidManifestFile;
    if (!ValidOperation(creation_operation_id)) return ManifestStoreError::OperationIdInvalid;
    ManifestV1 unnormalized{candidate, ManifestPhase::Prepared, 1, creation_operation_id};
    ManifestV1 manifest;
    if (!NormalizeManifest(unnormalized, manifest)) return ManifestStoreError::CodecFailure;
    auto initial_digest = ManifestDigestV1(manifest);
    if (std::holds_alternative<ManifestCodecError>(initial_digest))
      return ManifestStoreError::CodecFailure;
    auto parent = OpenParent(directory);
    if (!parent) return ManifestStoreError::InvalidPath;
    if (Fail(hooks, ManifestIoPoint::Mkdir)) return ManifestStoreError::InvalidPath;
    if (::mkdirat(parent->fd.get(), parent->leaf.c_str(), 0700) != 0)
      return errno == EEXIST ? ManifestStoreError::AlreadyExists : ManifestStoreError::InvalidPath;
    if (Fail(hooks, ManifestIoPoint::SyncParentDirectory) || !Sync(parent->fd.get()))
      return ManifestStoreError::DurabilityUncertain;
    if (Fail(hooks, ManifestIoPoint::OpenDirectory)) return ManifestStoreError::InvalidDirectory;
    UniqueFd dirfd(::openat(parent->fd.get(), parent->leaf.c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (dirfd.get() < 0) return ManifestStoreError::InvalidDirectory;
    if (::fchmod(dirfd.get(), 0700) != 0) return ManifestStoreError::InvalidDirectory;
    if (Fail(hooks, ManifestIoPoint::ValidateDirectory) || !ValidDirectory(dirfd.get()))
      return ManifestStoreError::InvalidDirectory;
    ManifestStoreError lock_error = ManifestStoreError::InvalidLock;
    UniqueFd lockfd(CreateAndLock(dirfd.get(), hooks, lock_error));
    if (lockfd.get() < 0) return lock_error;
    if (Fail(hooks, ManifestIoPoint::SyncDirectory) || !Sync(dirfd.get()))
      return ManifestStoreError::DirectorySyncFailure;
    auto created = std::unique_ptr<ManifestStore>(new ManifestStore(
        dirfd.get(), lockfd.get(), directory, std::move(manifest),
        std::get<std::array<std::uint8_t, 32>>(std::move(initial_digest)), false, hooks));
    (void)dirfd.release();
    (void)lockfd.release();
    const auto write_result = WriteNewManifest(created->impl_->directory_fd,
                                                created->impl_->lock_fd,
                                                created->impl_->manifest, hooks);
    if (write_result.has_value()) return *write_result;
    return created;
  } catch (...) {
    return ManifestStoreError::AllocationFailure;
  }
}

ManifestStoreOpenResult ManifestStore::OpenExisting(
    const std::string& directory, IManifestFileOps* hooks) noexcept {
  try {
    if (!ValidPath(directory)) return ManifestStoreError::InvalidPath;
    UniqueFd dirfd(OpenDirectory(directory, hooks));
    if (dirfd.get() < 0) return errno == ENOENT ? ManifestStoreError::NotFound
                                                : ManifestStoreError::InvalidDirectory;
    if (Fail(hooks, ManifestIoPoint::ValidateDirectory) || !ValidDirectory(dirfd.get()))
      return ManifestStoreError::InvalidDirectory;
    if (Fail(hooks, ManifestIoPoint::OpenLock)) {
      return ManifestStoreError::InvalidLock;
    }
    UniqueFd lockfd(::openat(dirfd.get(), kLockName, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (lockfd.get() < 0) return ManifestStoreError::InvalidLock;
    struct stat st {};
    if (::fstat(lockfd.get(), &st) != 0 || !ValidRegularFile(st, 0600))
      return ManifestStoreError::InvalidLock;
    if (Fail(hooks, ManifestIoPoint::AcquireLock)) {
      return ManifestStoreError::InvalidLock;
    }
    if (::flock(lockfd.get(), LOCK_EX | LOCK_NB) != 0) {
      const auto error = (errno == EWOULDBLOCK || errno == EAGAIN)
                             ? ManifestStoreError::LockBusy : ManifestStoreError::InvalidLock;
      return error;
    }
    if (!LockValid(dirfd.get(), lockfd.get(), hooks)) return ManifestStoreError::LockIdentityChanged;
    auto loaded = ReadManifest(dirfd.get(), hooks);
    if (auto* error = std::get_if<ManifestStoreError>(&loaded)) return *error;
    if (!LockValid(dirfd.get(), lockfd.get(), hooks)) return ManifestStoreError::LockIdentityChanged;
    auto pair = std::get<std::pair<ManifestV1, std::array<std::uint8_t, 32>>>(std::move(loaded));
    auto opened = std::unique_ptr<ManifestStore>(new ManifestStore(
        dirfd.get(), lockfd.get(), directory, std::move(pair.first), pair.second, true, hooks));
    (void)dirfd.release();
    (void)lockfd.release();
    return opened;
  } catch (...) {
    return ManifestStoreError::AllocationFailure;
  }
}

bool ManifestStore::recovery_only() const noexcept { return impl_->recovery_only; }
bool ManifestStore::writable() const noexcept {
  std::lock_guard lock(impl_->mutex);
  return impl_->writable && !impl_->recovery_only;
}

ManifestV1 ManifestStore::snapshot() const {
  std::lock_guard lock(impl_->mutex);
  return impl_->manifest;
}

std::array<std::uint8_t, 32> ManifestStore::digest() const {
  std::lock_guard lock(impl_->mutex);
  return impl_->digest;
}

ManifestWriteResult ManifestStore::Transition(
    std::uint64_t expected_generation, const std::array<std::uint8_t, 32>& expected_digest,
    ManifestPhase next_phase, const OperationId& operation_id) {
  ManifestV1 current;
  std::array<std::uint8_t, 32> current_digest{};
  {
    std::lock_guard lock(impl_->mutex);
    if (impl_->transition_in_progress)
      return {ManifestVisibility::NotVisible, ManifestStoreError::Busy,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    if (impl_->recovery_only)
      return {ManifestVisibility::NotVisible, ManifestStoreError::RecoveryReadOnly,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    if (!impl_->writable)
      return {ManifestVisibility::NotVisible, ManifestStoreError::WriterLatched,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    if (impl_->manifest.generation != expected_generation || impl_->digest != expected_digest)
      return {ManifestVisibility::NotVisible, ManifestStoreError::CompareAndSwapMismatch,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    if (!LegalTransition(impl_->manifest.phase, next_phase))
      return {ManifestVisibility::NotVisible, ManifestStoreError::IllegalTransition,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    if (!ValidOperation(operation_id))
      return {ManifestVisibility::NotVisible, ManifestStoreError::OperationIdInvalid,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    const auto next_generation = TryNextManifestGeneration(impl_->manifest.generation);
    if (!next_generation)
      return {ManifestVisibility::NotVisible, ManifestStoreError::GenerationExhausted,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    try {
      current = impl_->manifest;
    } catch (...) {
      return {ManifestVisibility::NotVisible, ManifestStoreError::AllocationFailure,
              impl_->manifest.generation, impl_->manifest.phase, impl_->digest};
    }
    current_digest = impl_->digest;
    impl_->transition_in_progress = true;
  }

  const auto complete = [&](ManifestVisibility visibility,
                            std::optional<ManifestStoreError> error,
                            bool latch, ManifestV1* committed,
                            const std::array<std::uint8_t, 32>* new_digest) {
    std::lock_guard lock(impl_->mutex);
    if (committed != nullptr) {
      impl_->manifest = std::move(*committed);
      impl_->digest = *new_digest;
    }
    if (latch) impl_->writable = false;
    impl_->transition_in_progress = false;
    ManifestWriteResult out{visibility, error, impl_->manifest.generation,
                            impl_->manifest.phase, impl_->digest};
    return out;
  };

  try {
    ManifestV1 next = current;
    next.generation = current.generation + 1;  // Non-wrapping check happened before reservation.
    next.phase = next_phase;
    next.transition_operation_id = operation_id;
    auto encoded = EncodeManifestV1(next);
    auto next_digest_result = ManifestDigestV1(next);
    if (std::holds_alternative<ManifestCodecError>(encoded) ||
        std::holds_alternative<ManifestCodecError>(next_digest_result))
      return complete(ManifestVisibility::NotVisible, ManifestStoreError::CodecFailure,
                      true, nullptr, nullptr);
    auto& bytes = std::get<std::string>(encoded);
    if (bytes.size() > kMaxManifestBytes)
      return complete(ManifestVisibility::NotVisible, ManifestStoreError::ManifestTooLarge,
                      true, nullptr, nullptr);
    const auto next_digest = std::get<std::array<std::uint8_t, 32>>(
        std::move(next_digest_result));
    auto persisted = PersistReplacement(impl_->directory_fd, impl_->lock_fd, current,
                                        current_digest, bytes, impl_->test_hooks);
    if (persisted.visibility == ManifestVisibility::NotVisible)
      return complete(persisted.visibility, persisted.error, true, nullptr, nullptr);
    const bool uncertain = persisted.visibility == ManifestVisibility::VisibleDurabilityUnknown;
    return complete(persisted.visibility, persisted.error, uncertain, &next, &next_digest);
  } catch (...) {
    return complete(ManifestVisibility::NotVisible, ManifestStoreError::AllocationFailure,
                    true, nullptr, nullptr);
  }
}

}  // namespace rateguard::supervisor
