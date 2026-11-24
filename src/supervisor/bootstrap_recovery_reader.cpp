#include "supervisor/bootstrap_recovery_reader.h"
#include "supervisor/epoch_artifact_layout.h"

#include "platform/file_io.h"

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <set>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <tuple>
#include <unistd.h>

namespace rateguard::supervisor {
namespace {
using platform::file::ReadAll;
using platform::file::UniqueFd;

constexpr char kLockName[] = "owner.lock";
constexpr char kAnchorName[] = "runtime-anchor.json";
using namespace epoch_layout_v1;

bool Fail(IRecoveryReaderIo* io, RecoveryReaderIoPoint point) noexcept {
  return io != nullptr && io->FailAt(point);
}

bool SameInode(const struct stat& a, const struct stat& b) noexcept {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

RecoveryFileIdentity Identity(const struct stat& st) noexcept {
#if defined(__APPLE__)
  const auto mtime = st.st_mtimespec;
  const auto ctime = st.st_ctimespec;
#else
  const auto mtime = st.st_mtim;
  const auto ctime = st.st_ctim;
#endif
  return {static_cast<std::uint64_t>(st.st_dev), static_cast<std::uint64_t>(st.st_ino),
      static_cast<std::uint64_t>(st.st_uid), static_cast<std::uint64_t>(st.st_nlink),
      static_cast<std::uint32_t>(st.st_mode), static_cast<std::uint64_t>(st.st_size),
      static_cast<std::int64_t>(mtime.tv_sec), static_cast<std::uint32_t>(mtime.tv_nsec),
      static_cast<std::int64_t>(ctime.tv_sec), static_cast<std::uint32_t>(ctime.tv_nsec)};
}

bool IsOwnedPrivateDirectory(const struct stat& st) noexcept {
  return S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() && (st.st_mode & 07777) == 0700;
}

bool IsOwnedIntentFile(const struct stat& st) noexcept {
  return S_ISREG(st.st_mode) && st.st_uid == ::geteuid() && (st.st_mode & 07777) == 0600 &&
      st.st_nlink == 1 && st.st_size >= 0;
}

struct Entry final {
  std::string name;
  struct stat st {};
  bool stat_ok{};
};

struct Listing final {
  std::vector<Entry> entries;
  bool complete{true};
  bool empty{};
  bool limit_reached{};
};

struct ScanContext final {
  BootstrapRecoverySnapshot& snapshot;
  IRecoveryReaderIo* io{};
  std::size_t issue_count{};
  std::size_t bytes_reserved{};
  std::size_t participants_retained{};
  bool stop{};
};

void MarkIncomplete(ScanContext& ctx) noexcept { ctx.snapshot.scan_complete = false; }

void AddRootIssue(ScanContext& ctx, RecoveryIssueCode code) {
  MarkIncomplete(ctx);
  if (ctx.issue_count >= kMaxRecoveryIssues) {
    ctx.snapshot.issues_truncated = true;
    return;
  }
  if (ctx.issue_count + 1 == kMaxRecoveryIssues) {
    ctx.snapshot.issues.push_back({RecoveryIssueCode::ResourceLimit, std::nullopt});
    ++ctx.issue_count;
    ctx.snapshot.issues_truncated = true;
    return;
  }
  ctx.snapshot.issues.push_back({code, std::nullopt});
  ++ctx.issue_count;
}

void AddEpochIssue(ScanContext& ctx, std::size_t epoch_index, RecoveryIssueCode code) {
  MarkIncomplete(ctx);
  auto& epoch = ctx.snapshot.epochs[epoch_index];
  if (epoch.issues.size() >= kMaxRecoveryEpochIssues ||
      ctx.issue_count >= kMaxRecoveryIssues) {
    epoch.issues_truncated = true;
    ctx.snapshot.issues_truncated = true;
    return;
  }
  if (epoch.issues.size() + 1 == kMaxRecoveryEpochIssues ||
      ctx.issue_count + 1 == kMaxRecoveryIssues) {
    epoch.issues.push_back(RecoveryIssueCode::ResourceLimit);
    if (ctx.issue_count < kMaxRecoveryIssues)
      ctx.snapshot.issues.push_back({RecoveryIssueCode::ResourceLimit, epoch_index});
    ++ctx.issue_count;
    epoch.issues_truncated = true;
    ctx.snapshot.issues_truncated = true;
    return;
  }
  epoch.issues.push_back(code);
  ctx.snapshot.issues.push_back({code, epoch_index});
  ++ctx.issue_count;
}

Listing EnumerateDirectory(int directory_fd, ScanContext& ctx,
                           RecoveryReaderIoPoint fail_point, std::size_t cap,
                           RecoveryReaderIoPoint stat_point) {
  Listing listing;
  if (Fail(ctx.io, fail_point)) {
    listing.complete = false;
    return listing;
  }
  UniqueFd scan(::openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (scan.get() < 0) {
    listing.complete = false;
    return listing;
  }
  struct stat original{}, opened{};
  if (::fstat(directory_fd, &original) != 0 || ::fstat(scan.get(), &opened) != 0 ||
      !SameInode(original, opened) || !IsOwnedPrivateDirectory(opened)) {
    listing.complete = false;
    return listing;
  }
  listing.entries.reserve(cap);
  DIR* stream = ::fdopendir(scan.get());
  if (stream == nullptr) {
    listing.complete = false;
    return listing;
  }
  (void)scan.release();
  const auto close_directory = [](DIR* value) noexcept { if (value != nullptr) ::closedir(value); };
  std::unique_ptr<DIR, decltype(close_directory)> directory(stream, close_directory);
  for (;;) {
    errno = 0;
    dirent* item = ::readdir(directory.get());
    if (item == nullptr) {
      if (errno != 0) listing.complete = false;
      break;
    }
    const std::string_view name(item->d_name);
    if (name == "." || name == "..") continue;
    if (listing.entries.size() >= cap) {
      listing.complete = false;
      listing.limit_reached = true;
      break;
    }
    Entry entry;
    entry.name.assign(name);
    if (Fail(ctx.io, stat_point) ||
        ::fstatat(directory_fd, entry.name.c_str(), &entry.st, AT_SYMLINK_NOFOLLOW) != 0) {
      entry.stat_ok = false;
      listing.complete = false;
    } else {
      entry.stat_ok = true;
    }
    listing.entries.push_back(std::move(entry));
  }
  directory.reset();
  std::sort(listing.entries.begin(), listing.entries.end(), [](const Entry& a, const Entry& b) {
    return a.name < b.name;
  });
  listing.empty = listing.entries.empty();
  return listing;
}

bool SameListing(const Listing& a, const Listing& b) noexcept {
  if (!a.complete || !b.complete || a.entries.size() != b.entries.size()) return false;
  for (std::size_t i = 0; i < a.entries.size(); ++i) {
    const auto& left = a.entries[i];
    const auto& right = b.entries[i];
    if (left.name != right.name || left.stat_ok != right.stat_ok) return false;
    if (left.stat_ok && !(Identity(left.st) == Identity(right.st))) return false;
  }
  return true;
}

void ProcessBootstrapIntent(ScanContext& ctx, int root_fd, std::size_t epoch_index,
                            const Entry& root_entry) {
  auto& diagnostic = ctx.snapshot.epochs[epoch_index];
  UniqueFd child(::openat(root_fd, diagnostic.directory_name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (Fail(ctx.io, RecoveryReaderIoPoint::OpenEpochDirectory) || child.get() < 0) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidEpochDirectory);
    return;
  }
  struct stat child_fd_stat{}, child_path_stat{};
  if (::fstat(child.get(), &child_fd_stat) != 0 || !IsOwnedPrivateDirectory(child_fd_stat) ||
      ::fstatat(root_fd, diagnostic.directory_name.c_str(), &child_path_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(root_entry.st, child_fd_stat) || !SameInode(child_path_stat, child_fd_stat)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochDirectoryChanged);
    return;
  }
  diagnostic.directory_identity = Identity(child_fd_stat);

  Listing child_before = EnumerateDirectory(child.get(), ctx, RecoveryReaderIoPoint::EnumerateEpoch,
      kMaxRecoveryChildEntries, RecoveryReaderIoPoint::StatRootEntry);
  if (!child_before.complete) AddEpochIssue(ctx, epoch_index,
      child_before.limit_reached ? RecoveryIssueCode::TooManyChildEntries
                                  : RecoveryIssueCode::EpochDirectoryChanged);
  bool found_intent = false;
  for (const auto& entry : child_before.entries) {
    if (!entry.stat_ok) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidIntentFile);
      continue;
    }
    if (entry.name == kIntentFileName) found_intent = true;
    else if (entry.name != kManifestStoreDirectoryName)
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochHasUnexpectedEntry);
  }
  if (ctx.stop) return;
  if (!found_intent) {
    struct stat probe{};
    if (::fstatat(child.get(), kIntentFileName, &probe, AT_SYMLINK_NOFOLLOW) == 0) {
      found_intent = true;
    } else if (errno == ENOENT) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::MissingIntent);
      return;
    } else {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidIntentFile);
      return;
    }
  }

  if (Fail(ctx.io, RecoveryReaderIoPoint::StatIntent)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidIntentFile);
    return;
  }
  struct stat path_before{};
  if (::fstatat(child.get(), kIntentFileName, &path_before, AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsOwnedIntentFile(path_before)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidIntentFile);
    return;
  }
  const auto file_size = static_cast<std::uint64_t>(path_before.st_size);
  if (file_size > kMaxRecoveryAggregateBytes - ctx.bytes_reserved) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::AggregateByteLimit);
    ctx.stop = true;
    return;
  }
  // Conservatively charge the stat-reported extent before allocating or reading.
  ctx.bytes_reserved += static_cast<std::size_t>(file_size);
  if (file_size > kMaxBootstrapBytes) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentTooLarge);
    return;
  }

  if (Fail(ctx.io, RecoveryReaderIoPoint::OpenIntent)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentReadFailed);
    return;
  }
  UniqueFd intent(::openat(child.get(), kIntentFileName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (intent.get() < 0) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentReadFailed);
    return;
  }
  struct stat file_fd_before{}, path_opened{};
  if (::fstat(intent.get(), &file_fd_before) != 0 || !IsOwnedIntentFile(file_fd_before) ||
      !SameInode(path_before, file_fd_before) ||
      ::fstatat(child.get(), kIntentFileName, &path_opened, AT_SYMLINK_NOFOLLOW) != 0 ||
      !(Identity(path_opened) == Identity(file_fd_before))) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentChanged);
    return;
  }
  diagnostic.intent_identity = Identity(file_fd_before);
  if (Fail(ctx.io, RecoveryReaderIoPoint::ReadIntent)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentReadFailed);
    return;
  }
  std::string bytes;
  if (!ReadAll(intent.get(), bytes, static_cast<std::size_t>(file_size))) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentReadFailed);
    return;
  }
  struct stat file_fd_after{}, path_after{};
  if (Fail(ctx.io, RecoveryReaderIoPoint::RevalidateEntry) ||
      ::fstat(intent.get(), &file_fd_after) != 0 || !IsOwnedIntentFile(file_fd_after) ||
      ::fstatat(child.get(), kIntentFileName, &path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsOwnedIntentFile(path_after) ||
      !(Identity(file_fd_before) == Identity(file_fd_after)) ||
      !(Identity(file_fd_after) == Identity(path_after))) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentChanged);
    return;
  }
  diagnostic.intent_identity = Identity(file_fd_after);

  const auto decoded = DecodeBootstrapInventoryV1(bytes);
  if (const auto* error = std::get_if<BootstrapError>(&decoded)) {
    AddEpochIssue(ctx, epoch_index, *error == BootstrapError::DigestMismatch
        ? RecoveryIssueCode::DigestMismatch : RecoveryIssueCode::InvalidEncoding);
    return;
  }
  auto inventory = std::get<BootstrapInventory>(decoded);
  if (inventory.domain_id() != ctx.snapshot.domain_id) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::DomainMismatch);
    return;
  }
  const auto parsed_directory_epoch = ParseEpochDirectoryName(diagnostic.directory_name);
  if (!parsed_directory_epoch || inventory.epoch_id() != *parsed_directory_epoch) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochMismatch);
    return;
  }
  const auto digest = BootstrapDigestV1(inventory);
  if (const auto* error = std::get_if<BootstrapError>(&digest)) {
    (void)error;
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::DigestFailure);
    return;
  }
  const auto actual_digest = std::get<std::array<std::uint8_t, 32>>(digest);
  diagnostic.canonical_digest = actual_digest;
  if (inventory.recovery_required()) AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::RecoveryAlreadyLatched);
  if (ctx.participants_retained + inventory.records().size() > kMaxRecoveryAggregateParticipants) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::AggregateParticipantLimit);
    ctx.stop = true;
    return;
  }
  ctx.participants_retained += inventory.records().size();
  diagnostic.inventory = std::make_shared<const BootstrapInventory>(std::move(inventory));

  if (!child_before.limit_reached) {
    Listing child_after = EnumerateDirectory(child.get(), ctx, RecoveryReaderIoPoint::EnumerateEpoch,
        kMaxRecoveryChildEntries, RecoveryReaderIoPoint::StatRootEntry);
    if (!SameListing(child_before, child_after))
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochDirectoryChanged);
  }
  struct stat child_fd_after{}, child_path_after{};
  if (::fstat(child.get(), &child_fd_after) != 0 ||
      ::fstatat(root_fd, diagnostic.directory_name.c_str(), &child_path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsOwnedPrivateDirectory(child_fd_after) ||
      !(Identity(child_fd_stat) == Identity(child_fd_after)) ||
      !(Identity(child_fd_after) == Identity(child_path_after)))
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochDirectoryChanged);
}

bool IsOwnedEmptyLock(const struct stat& st) noexcept {
  return IsOwnedIntentFile(st) && st.st_size == 0;
}

bool ChargeRead(ScanContext& ctx, std::size_t bytes, std::size_t epoch_index) {
  if (bytes > kMaxRecoveryAggregateBytes - ctx.bytes_reserved) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::AggregateByteLimit);
    ctx.stop = true;
    return false;
  }
  // Charge the stat-reported extent before allocation/open/read and never
  // refund it after any parse, open, or read failure.
  ctx.bytes_reserved += bytes;
  return true;
}

void ProcessManifestStore(ScanContext& ctx, int root_fd, std::size_t epoch_index,
                          const Entry& root_entry,
                          const std::optional<RecoveryFileIdentity>& expected_store,
                          bool baseline_stat_failed) {
  auto& epoch = ctx.snapshot.epochs[epoch_index];
  UniqueFd epoch_fd(::openat(root_fd, epoch.directory_name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (epoch_fd.get() < 0) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochDirectoryChanged);
    return;
  }
  struct stat epoch_fd_stat{}, epoch_path_stat{};
  if (::fstat(epoch_fd.get(), &epoch_fd_stat) != 0 ||
      !IsOwnedPrivateDirectory(epoch_fd_stat) ||
      ::fstatat(root_fd, epoch.directory_name.c_str(), &epoch_path_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(root_entry.st, epoch_fd_stat) || !SameInode(epoch_fd_stat, epoch_path_stat)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochDirectoryChanged);
    return;
  }

  struct stat store_initial{};
  if (::fstatat(epoch_fd.get(), kManifestStoreDirectoryName, &store_initial, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno == ENOENT && !expected_store && !baseline_stat_failed)
      return;  // Bootstrap-only history is a valid diagnostic shape.
    if (errno == ENOENT && expected_store)
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreChanged);
    else
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreDirectory);
    return;
  }
  RecoveryEpochDiagnostic::ManifestDiagnostic diagnostic;
  epoch.manifest_store = diagnostic;
  auto& manifest_diag = *epoch.manifest_store;
  if (baseline_stat_failed || !expected_store || !(Identity(store_initial) == *expected_store))
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreChanged);
  if (!IsOwnedPrivateDirectory(store_initial)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreDirectory);
    return;
  }
  UniqueFd store_fd;
  if (Fail(ctx.io, RecoveryReaderIoPoint::OpenManifestStoreDirectory)) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreDirectory);
    return;
  }
  store_fd = UniqueFd(::openat(epoch_fd.get(), kManifestStoreDirectoryName,
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  struct stat store_fd_before{}, store_path_opened{};
  if (store_fd.get() < 0 || ::fstat(store_fd.get(), &store_fd_before) != 0 ||
      !IsOwnedPrivateDirectory(store_fd_before) ||
      !(Identity(store_initial) == Identity(store_fd_before)) ||
      ::fstatat(epoch_fd.get(), kManifestStoreDirectoryName, &store_path_opened, AT_SYMLINK_NOFOLLOW) != 0 ||
      !(Identity(store_fd_before) == Identity(store_path_opened))) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreDirectory);
    return;
  }
  manifest_diag.directory_identity = Identity(store_fd_before);

  Listing before = EnumerateDirectory(store_fd.get(), ctx,
      RecoveryReaderIoPoint::EnumerateManifestStore, kMaxRecoveryManifestStoreEntries,
      RecoveryReaderIoPoint::StatManifestStoreEntry);
  if (!before.complete)
    AddEpochIssue(ctx, epoch_index, before.limit_reached
        ? RecoveryIssueCode::TooManyManifestStoreEntries
        : RecoveryIssueCode::ManifestStoreChanged);
  for (const auto& entry : before.entries) {
    if (!entry.stat_ok) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreFile);
      continue;
    }
    if (entry.name == kManifestStoreLockFileName || entry.name == kManifestFileName) continue;
    else AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreHasUnexpectedEntry);
  }
  // Always probe the two allowlisted names, even when an unrelated temporary
  // or unknown entry made the listing incomplete. This preserves known data.
  const auto validate_lock = [&]() {
    struct stat path_before{};
    if (::fstatat(store_fd.get(), kManifestStoreLockFileName, &path_before, AT_SYMLINK_NOFOLLOW) != 0) {
      AddEpochIssue(ctx, epoch_index, errno == ENOENT
          ? RecoveryIssueCode::MissingManifestStoreFile
          : RecoveryIssueCode::InvalidManifestStoreFile);
      return;
    }
    if (!IsOwnedEmptyLock(path_before)) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreFile);
      return;
    }
    if (Fail(ctx.io, RecoveryReaderIoPoint::OpenManifestLock)) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreReadFailed);
      return;
    }
    UniqueFd lock(::openat(store_fd.get(), kManifestStoreLockFileName,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    struct stat fd_stat{}, path_after{};
    if (lock.get() < 0 || ::fstat(lock.get(), &fd_stat) != 0 || !IsOwnedEmptyLock(fd_stat) ||
        !(Identity(path_before) == Identity(fd_stat)) ||
        Fail(ctx.io, RecoveryReaderIoPoint::RevalidateManifestLock) ||
        ::fstatat(store_fd.get(), kManifestStoreLockFileName, &path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !(Identity(fd_stat) == Identity(path_after))) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreFileChanged);
      return;
    }
    manifest_diag.owner_lock_identity = Identity(fd_stat);
  };
  validate_lock();

  const auto read_manifest = [&]() {
    struct stat path_before{};
    if (::fstatat(store_fd.get(), kManifestFileName, &path_before, AT_SYMLINK_NOFOLLOW) != 0) {
      AddEpochIssue(ctx, epoch_index, errno == ENOENT
          ? RecoveryIssueCode::MissingManifestStoreFile
          : RecoveryIssueCode::InvalidManifestStoreFile);
      return;
    }
    if (!IsOwnedIntentFile(path_before)) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestStoreFile);
      return;
    }
    const auto size = static_cast<std::uint64_t>(path_before.st_size);
    if (size > std::numeric_limits<std::size_t>::max()) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreFileTooLarge);
      return;
    }
    if (!ChargeRead(ctx, static_cast<std::size_t>(size), epoch_index)) return;
    if (size > kMaxManifestBytes) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreFileTooLarge);
      return;
    }
    if (Fail(ctx.io, RecoveryReaderIoPoint::OpenManifestFile)) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreReadFailed);
      return;
    }
    UniqueFd file(::openat(store_fd.get(), kManifestFileName,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    struct stat fd_before{}, path_opened{};
    if (file.get() < 0 || ::fstat(file.get(), &fd_before) != 0 ||
        !IsOwnedIntentFile(fd_before) || !(Identity(path_before) == Identity(fd_before)) ||
        ::fstatat(store_fd.get(), kManifestFileName, &path_opened, AT_SYMLINK_NOFOLLOW) != 0 ||
        !(Identity(fd_before) == Identity(path_opened))) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreFileChanged);
      return;
    }
    manifest_diag.manifest_identity = Identity(fd_before);
    if (Fail(ctx.io, RecoveryReaderIoPoint::ReadManifestFile)) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreReadFailed);
      return;
    }
    std::string bytes;
    if (!ReadAll(file.get(), bytes, static_cast<std::size_t>(size))) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreReadFailed);
      return;
    }
    struct stat fd_after{}, path_after{};
    if (Fail(ctx.io, RecoveryReaderIoPoint::RevalidateManifestFile) ||
        ::fstat(file.get(), &fd_after) != 0 || !IsOwnedIntentFile(fd_after) ||
        ::fstatat(store_fd.get(), kManifestFileName, &path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !IsOwnedIntentFile(path_after) || !(Identity(fd_before) == Identity(fd_after)) ||
        !(Identity(fd_after) == Identity(path_after))) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreFileChanged);
      return;
    }
    manifest_diag.manifest_identity = Identity(fd_after);
    const auto decoded = DecodeManifestV1(bytes);
    if (const auto* codec_error = std::get_if<ManifestCodecError>(&decoded)) {
      if (*codec_error == ManifestCodecError::DigestMismatch)
        AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestCodecDigestMismatch);
      else if (*codec_error == ManifestCodecError::DigestFailure)
        AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::DigestFailure);
      else
        AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidManifestEncoding);
      return;
    }
    auto manifest = std::get<ManifestV1>(decoded);
    if (ctx.participants_retained + manifest.candidate.participants.size() >
        kMaxRecoveryAggregateParticipants) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::AggregateParticipantLimit);
      ctx.stop = true;
      return;
    }
    ctx.participants_retained += manifest.candidate.participants.size();
    const auto digest = ManifestDigestV1(manifest);
    if (const auto* codec_error = std::get_if<ManifestCodecError>(&digest)) {
      (void)codec_error;
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::DigestFailure);
      return;
    }
    manifest_diag.canonical_digest = std::get<std::array<std::uint8_t, 32>>(digest);
    manifest_diag.decoded_manifest = std::make_shared<const ManifestV1>(std::move(manifest));
    const auto& inventory = epoch.inventory;
    if (!inventory) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestBootstrapNotReady);
      return;
    }
    const auto candidate = inventory->ReadyCandidate();
    if (std::holds_alternative<BootstrapError>(candidate)) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestBootstrapNotReady);
    } else if (std::get<EpochCandidate>(candidate) != manifest_diag.decoded_manifest->candidate) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestCandidateMismatch);
    }
  };
  read_manifest();

  Listing after = EnumerateDirectory(store_fd.get(), ctx,
      RecoveryReaderIoPoint::EnumerateManifestStore, kMaxRecoveryManifestStoreEntries,
      RecoveryReaderIoPoint::StatManifestStoreEntry);
  if (!SameListing(before, after))
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreChanged);
  struct stat store_fd_after{}, store_path_after{}, epoch_fd_after{}, epoch_path_after{};
  if (Fail(ctx.io, RecoveryReaderIoPoint::RevalidateManifestStore) ||
      ::fstat(store_fd.get(), &store_fd_after) != 0 ||
      !IsOwnedPrivateDirectory(store_fd_after) ||
      !(Identity(store_fd_before) == Identity(store_fd_after)) ||
      ::fstatat(epoch_fd.get(), kManifestStoreDirectoryName, &store_path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsOwnedPrivateDirectory(store_path_after) ||
      !(Identity(store_fd_after) == Identity(store_path_after)) ||
      ::fstat(epoch_fd.get(), &epoch_fd_after) != 0 ||
      ::fstatat(root_fd, epoch.directory_name.c_str(), &epoch_path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
      !IsOwnedPrivateDirectory(epoch_fd_after) ||
      !(Identity(root_entry.st) == Identity(epoch_fd_after)) ||
      !(Identity(epoch_fd_after) == Identity(epoch_path_after)))
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::ManifestStoreChanged);
}

void ProcessEpochArtifacts(ScanContext& ctx, int root_fd, std::size_t epoch_index,
                           const Entry& root_entry) {
  std::optional<RecoveryFileIdentity> expected_store;
  bool baseline_stat_failed = false;
  UniqueFd epoch_fd(::openat(root_fd, ctx.snapshot.epochs[epoch_index].directory_name.c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (epoch_fd.get() >= 0) {
    struct stat path_stat{};
    if (::fstatat(epoch_fd.get(), kManifestStoreDirectoryName, &path_stat, AT_SYMLINK_NOFOLLOW) == 0)
      expected_store = Identity(path_stat);
    else if (errno != ENOENT)
      baseline_stat_failed = true;
  } else {
    baseline_stat_failed = true;
  }
  ProcessBootstrapIntent(ctx, root_fd, epoch_index, root_entry);
  if (!ctx.stop)
    ProcessManifestStore(ctx, root_fd, epoch_index, root_entry, expected_store, baseline_stat_failed);
}

}  // namespace

BootstrapRecoveryReadResult BootstrapRecoveryReader::Read(
    const RuntimeOwner& owner, IRecoveryReaderIo* test_io) noexcept {
  try {
    if (owner.mode() != RuntimeOwnerMode::RecoveryRequired)
      return RecoveryReaderFatal::OwnerNotRecoveryMode;
    if (Fail(test_io, RecoveryReaderIoPoint::ValidateOwnerBefore) ||
        std::holds_alternative<RuntimeOwnerError>(owner.ValidateOwnership()))
      return RecoveryReaderFatal::OwnerInvalid;
    auto root_result = [&]() -> DuplicateFdResult {
      if (Fail(test_io, RecoveryReaderIoPoint::DuplicateRoot)) return RuntimeOwnerError::IoFailure;
      return owner.DuplicateRootFd();
    }();
    if (const auto* error = std::get_if<RuntimeOwnerError>(&root_result)) {
      (void)error;
      return RecoveryReaderFatal::RootDescriptorUnavailable;
    }
    UniqueFd root(std::get<int>(root_result));
    struct stat root_stat{};
    if (::fstat(root.get(), &root_stat) != 0 || !IsOwnedPrivateDirectory(root_stat))
      return RecoveryReaderFatal::RootDescriptorUnavailable;

    auto snapshot = std::make_shared<BootstrapRecoverySnapshot>();
    snapshot->domain_id = owner.domain_id();
    snapshot->scan_complete = true;
    snapshot->epochs.reserve(kMaxRecoveryEpochDirectories);
    snapshot->issues.reserve(kMaxRecoveryIssues);
    ScanContext ctx{*snapshot, test_io};
    Listing root_before = EnumerateDirectory(root.get(), ctx, RecoveryReaderIoPoint::EnumerateRootFirst,
        kMaxRecoveryRootEntries, RecoveryReaderIoPoint::StatRootEntry);
    if (!root_before.complete) {
      AddRootIssue(ctx, root_before.limit_reached ? RecoveryIssueCode::TooManyRootEntries
                                                   : RecoveryIssueCode::RootEnumerationFailed);
    }
    std::size_t epoch_dirs = 0;
    bool found_any_epoch_dir = false;
    for (const auto& entry : root_before.entries) {
      if (ctx.stop) break;
      if (!entry.stat_ok) AddRootIssue(ctx, RecoveryIssueCode::RootEntryStatFailed);
      if (entry.name == kLockName || entry.name == kAnchorName) continue;
      if (!entry.name.starts_with(kEpochDirectoryPrefix)) {
        AddRootIssue(ctx, RecoveryIssueCode::UnexpectedRootEntry);
        continue;
      }
      found_any_epoch_dir = true;
      const auto parsed = ParseEpochDirectoryName(entry.name);
      if (!parsed) {
        AddRootIssue(ctx, RecoveryIssueCode::InvalidEpochDirectoryName);
        continue;
      }
      if (++epoch_dirs > kMaxRecoveryEpochDirectories) {
        AddRootIssue(ctx, RecoveryIssueCode::TooManyEpochDirectories);
        ctx.stop = true;
        break;
      }
      if (!entry.stat_ok || !IsOwnedPrivateDirectory(entry.st)) {
        RecoveryEpochDiagnostic bad;
        bad.directory_name = entry.name;
        if (entry.stat_ok) bad.directory_identity = Identity(entry.st);
        snapshot->epochs.push_back(std::move(bad));
        AddEpochIssue(ctx, snapshot->epochs.size() - 1, RecoveryIssueCode::InvalidEpochDirectory);
        continue;
      }
      RecoveryEpochDiagnostic diagnostic;
      diagnostic.directory_name = entry.name;
      diagnostic.directory_identity = Identity(entry.st);
      snapshot->epochs.push_back(std::move(diagnostic));
      const auto index = snapshot->epochs.size() - 1;
      ProcessEpochArtifacts(ctx, root.get(), index, entry);
    }
    if (root_before.limit_reached) ctx.stop = true;
    if (root_before.empty) {
      AddRootIssue(ctx, RecoveryIssueCode::EmptyRoot);
      ctx.stop = true;
    } else if (!found_any_epoch_dir || std::none_of(snapshot->epochs.begin(), snapshot->epochs.end(),
        [](const auto& epoch) { return epoch.inventory != nullptr; })) {
      AddRootIssue(ctx, RecoveryIssueCode::NoValidIntents);
    }

    // Compare the union of bootstrap and manifest targets across epochs.
    // Matching representations in one epoch intentionally repeat the same
    // participants; only duplicates across epoch contexts are collisions.
    std::set<std::string, std::less<>> containers;
    std::set<std::tuple<std::uint64_t, std::uint64_t, std::array<std::uint8_t, 16>>> processes;
    for (std::size_t i = 0; i < snapshot->epochs.size() && !ctx.stop; ++i) {
      std::set<std::string, std::less<>> epoch_containers;
      std::set<std::tuple<std::uint64_t, std::uint64_t, std::array<std::uint8_t, 16>>> epoch_processes;
      const auto add_target = [&](const std::string& container, std::uint64_t pid,
                                  std::uint64_t start_ticks,
                                  const std::array<std::uint8_t, 16>& boot) {
        epoch_containers.insert(container);
        if (pid != 0 && start_ticks != 0) epoch_processes.emplace(pid, start_ticks, boot);
      };
      if (const auto& inventory = snapshot->epochs[i].inventory; inventory) {
        for (const auto& record : inventory->records()) {
          add_target(record.planned.container_id, record.identity_recorded ? record.pid : 0,
              record.identity_recorded ? record.pid_start_ticks : 0,
              record.clock_identity.boot_uuid);
        }
      }
      if (const auto& manifest = snapshot->epochs[i].manifest_store;
          manifest && manifest->decoded_manifest) {
        for (const auto& participant : manifest->decoded_manifest->candidate.participants) {
          add_target(participant.process.container_id, participant.process.pid,
              participant.process.pid_start_ticks, participant.clock_identity.boot_uuid);
        }
      }
      for (const auto& container : epoch_containers) {
        if (!containers.insert(container).second) {
          AddEpochIssue(ctx, i, RecoveryIssueCode::IdentityCollisionAcrossEpochs);
          if (ctx.stop) break;
        }
      }
      for (const auto& process : epoch_processes) {
        if (!processes.insert(process).second) {
          AddEpochIssue(ctx, i, RecoveryIssueCode::IdentityCollisionAcrossEpochs);
          if (ctx.stop) break;
        }
      }
    }

    if (!ctx.stop) {
      Listing root_after = EnumerateDirectory(root.get(), ctx, RecoveryReaderIoPoint::EnumerateRootSecond,
          kMaxRecoveryRootEntries, RecoveryReaderIoPoint::StatRootEntry);
      struct stat root_after_stat{};
      if (!SameListing(root_before, root_after) || ::fstat(root.get(), &root_after_stat) != 0 ||
          !IsOwnedPrivateDirectory(root_after_stat) ||
          !(Identity(root_stat) == Identity(root_after_stat)))
        AddRootIssue(ctx, RecoveryIssueCode::RootChangedDuringScan);
    }
    if (Fail(test_io, RecoveryReaderIoPoint::ValidateOwnerAfter) ||
        std::holds_alternative<RuntimeOwnerError>(owner.ValidateOwnership()))
      AddRootIssue(ctx, RecoveryIssueCode::OwnerChangedDuringScan);
    if (!found_any_epoch_dir) snapshot->scan_complete = false;
    return std::shared_ptr<const BootstrapRecoverySnapshot>(std::move(snapshot));
  } catch (...) {
    return RecoveryReaderFatal::AllocationFailure;
  }
}

}  // namespace rateguard::supervisor
