#include "supervisor/bootstrap_recovery_reader.h"

#include "platform/file_io.h"

#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
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
constexpr char kEpochPrefix[] = "epoch-";
constexpr char kIntentName[] = "intent.json";

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

int Nibble(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

bool ParseEpochName(std::string_view name, EpochId& epoch) noexcept {
  constexpr std::size_t kNameLength = sizeof(kEpochPrefix) - 1 + 32;
  if (name.size() != kNameLength || !name.starts_with(kEpochPrefix)) return false;
  const auto hex = name.substr(sizeof(kEpochPrefix) - 1);
  for (std::size_t i = 0; i < epoch.size(); ++i) {
    const int hi = Nibble(hex[2 * i]);
    const int lo = Nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    epoch[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return std::any_of(epoch.begin(), epoch.end(), [](std::uint8_t byte) { return byte != 0; });
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
                           RecoveryReaderIoPoint fail_point) {
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
  const std::size_t cap = fail_point == RecoveryReaderIoPoint::EnumerateEpoch
      ? kMaxRecoveryChildEntries : kMaxRecoveryRootEntries;
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
    if (Fail(ctx.io, RecoveryReaderIoPoint::StatRootEntry) ||
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

void ProcessIntent(ScanContext& ctx, int root_fd, std::size_t epoch_index,
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

  Listing child_before = EnumerateDirectory(child.get(), ctx, RecoveryReaderIoPoint::EnumerateEpoch);
  if (!child_before.complete) AddEpochIssue(ctx, epoch_index,
      child_before.limit_reached ? RecoveryIssueCode::TooManyChildEntries
                                  : RecoveryIssueCode::EpochDirectoryChanged);
  bool found_intent = false;
  for (const auto& entry : child_before.entries) {
    if (!entry.stat_ok) {
      AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::InvalidIntentFile);
      continue;
    }
    if (entry.name == kIntentName) found_intent = true;
    else AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::EpochHasUnexpectedEntry);
  }
  if (ctx.stop) return;
  if (!found_intent) {
    struct stat probe{};
    if (::fstatat(child.get(), kIntentName, &probe, AT_SYMLINK_NOFOLLOW) == 0) {
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
  if (::fstatat(child.get(), kIntentName, &path_before, AT_SYMLINK_NOFOLLOW) != 0 ||
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
  UniqueFd intent(::openat(child.get(), kIntentName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
  if (intent.get() < 0) {
    AddEpochIssue(ctx, epoch_index, RecoveryIssueCode::IntentReadFailed);
    return;
  }
  struct stat file_fd_before{}, path_opened{};
  if (::fstat(intent.get(), &file_fd_before) != 0 || !IsOwnedIntentFile(file_fd_before) ||
      !SameInode(path_before, file_fd_before) ||
      ::fstatat(child.get(), kIntentName, &path_opened, AT_SYMLINK_NOFOLLOW) != 0 ||
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
      ::fstatat(child.get(), kIntentName, &path_after, AT_SYMLINK_NOFOLLOW) != 0 ||
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
  EpochId directory_epoch{};
  if (!ParseEpochName(diagnostic.directory_name, directory_epoch) || inventory.epoch_id() != directory_epoch) {
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
    Listing child_after = EnumerateDirectory(child.get(), ctx, RecoveryReaderIoPoint::EnumerateEpoch);
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
    Listing root_before = EnumerateDirectory(root.get(), ctx, RecoveryReaderIoPoint::EnumerateRootFirst);
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
      EpochId parsed_epoch{};
      if (!entry.name.starts_with(kEpochPrefix)) {
        AddRootIssue(ctx, RecoveryIssueCode::UnexpectedRootEntry);
        continue;
      }
      found_any_epoch_dir = true;
      if (!ParseEpochName(entry.name, parsed_epoch)) {
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
      ProcessIntent(ctx, root.get(), index, entry);
    }
    if (root_before.limit_reached) ctx.stop = true;
    if (root_before.empty) {
      AddRootIssue(ctx, RecoveryIssueCode::EmptyRoot);
      ctx.stop = true;
    } else if (!found_any_epoch_dir || std::none_of(snapshot->epochs.begin(), snapshot->epochs.end(),
        [](const auto& epoch) { return epoch.inventory != nullptr; })) {
      AddRootIssue(ctx, RecoveryIssueCode::NoValidIntents);
    }

    // Report duplicated identities across epoch records; do not pick a latest record.
    std::set<std::string, std::less<>> containers;
    std::set<std::tuple<std::uint64_t, std::uint64_t, std::array<std::uint8_t, 16>>> processes;
    for (std::size_t i = 0; i < snapshot->epochs.size() && !ctx.stop; ++i) {
      const auto& inventory = snapshot->epochs[i].inventory;
      if (!inventory) continue;
      for (const auto& record : inventory->records()) {
        if (!containers.insert(record.planned.container_id).second) {
          AddEpochIssue(ctx, i, RecoveryIssueCode::IdentityCollisionAcrossEpochs);
          if (ctx.stop) break;
        }
        if (!record.identity_recorded) continue;
        const auto& boot = record.clock_identity.boot_uuid;
        if (!processes.emplace(record.pid, record.pid_start_ticks, boot).second) {
          AddEpochIssue(ctx, i, RecoveryIssueCode::IdentityCollisionAcrossEpochs);
          if (ctx.stop) break;
        }
      }
    }

    if (!ctx.stop) {
      Listing root_after = EnumerateDirectory(root.get(), ctx, RecoveryReaderIoPoint::EnumerateRootSecond);
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
