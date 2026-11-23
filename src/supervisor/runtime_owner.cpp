#include "supervisor/runtime_owner.h"

#include "platform/file_io.h"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <memory>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace rateguard::supervisor {
namespace {

using Json = nlohmann::json;
constexpr char kLockName[] = "owner.lock";
constexpr char kAnchorName[] = "runtime-anchor.json";
constexpr char kAnchorTempName[] = "runtime-anchor.tmp";
constexpr std::size_t kMaxRuntimeAnchorBytes = 4U * 1024U * 1024U;
constexpr std::size_t kMaxRootPathBytes = 4096;

class AnchorJsonGuard final : public nlohmann::json_sax<Json> {
 public:
  using string_t = Json::string_t;
  using binary_t = Json::binary_t;
  using number_integer_t = Json::number_integer_t;
  using number_unsigned_t = Json::number_unsigned_t;
  using number_float_t = Json::number_float_t;
  bool null() override { return true; }
  bool boolean(bool) override { return true; }
  bool number_integer(number_integer_t) override { return true; }
  bool number_unsigned(number_unsigned_t) override { return true; }
  bool number_float(number_float_t, const string_t&) override { return false; }
  bool string(string_t&) override { return true; }
  bool binary(binary_t&) override { return false; }
  bool start_object(std::size_t) override {
    if (depth_ >= 2) return false;
    ++depth_;
    seen_keys_.push_back(0);
    return true;
  }
  bool key(string_t& value) override {
    if (seen_keys_.empty()) return false;
    std::uint8_t bit = 0;
    if (depth_ == 1) {
      if (value == "anchor") bit = 1;
      else if (value == "sha256") bit = 2;
    } else if (depth_ == 2) {
      if (value == "domain_id") bit = 1;
      else if (value == "root_path") bit = 2;
      else if (value == "schema_version") bit = 4;
    }
    if (bit == 0 || (seen_keys_.back() & bit) != 0) return false;
    seen_keys_.back() = static_cast<std::uint8_t>(seen_keys_.back() | bit);
    return true;
  }
  bool end_object() override {
    if (seen_keys_.empty() || depth_ == 0) return false;
    seen_keys_.pop_back();
    --depth_;
    return true;
  }
  bool start_array(std::size_t) override { return false; }
  bool end_array() override { return false; }
  bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) override {
    return false;
  }
 private:
  std::size_t depth_{};
  std::vector<std::uint8_t> seen_keys_;
};

using platform::file::Sync;
using platform::file::UniqueFd;
using platform::file::WriteAll;

bool Fail(IRuntimeOwnerIo* io, RuntimeOwnerIoPoint point) noexcept {
  return io != nullptr && io->FailAt(point);
}

bool AllZero(const auto& data) noexcept {
  return std::all_of(data.begin(), data.end(), [](std::uint8_t b) { return b == 0; });
}

bool ReadAllAt(int fd, std::string& out, std::size_t size) {
  out.resize(size);
  std::size_t offset = 0;
  while (offset < size) {
    const auto n = ::pread(fd, out.data() + offset, size - offset,
                           static_cast<off_t>(offset));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    offset += static_cast<std::size_t>(n);
  }
  char extra = 0;
  ssize_t n;
  do { n = ::pread(fd, &extra, 1, static_cast<off_t>(size)); } while (n < 0 && errno == EINTR);
  return n == 0;
}

bool ValidAbsoluteInput(const std::string& path) noexcept {
  return !path.empty() && path.front() == '/' && path.size() < kMaxRootPathBytes &&
         path.back() != '/' && path.find('\0') == std::string::npos;
}

bool ValidModeOwner(const struct stat& st, mode_t mode) noexcept {
  return st.st_uid == ::geteuid() && (st.st_mode & 07777) == mode;
}

bool ValidRegular(const struct stat& st, mode_t mode) noexcept {
  return S_ISREG(st.st_mode) && ValidModeOwner(st, mode) && st.st_nlink == 1;
}

bool ValidLockFile(const struct stat& st) noexcept {
  return ValidRegular(st, 0600) && st.st_size == 0;
}

bool SameInode(const struct stat& a, const struct stat& b) noexcept {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

bool AnchorTempAbsent(int root_fd) noexcept {
  struct stat st {};
  if (::fstatat(root_fd, kAnchorTempName, &st, AT_SYMLINK_NOFOLLOW) == 0) return false;
  return errno == ENOENT;
}

std::string Hex(const auto& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (std::uint8_t b : bytes) {
    result.push_back(digits[b >> 4]);
    result.push_back(digits[b & 0x0f]);
  }
  return result;
}

template <std::size_t N>
bool ParseHex(std::string_view input, std::array<std::uint8_t, N>& output) noexcept {
  if (input.size() != N * 2) return false;
  const auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < N; ++i) {
    const int hi = nibble(input[i * 2]);
    const int lo = nibble(input[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    output[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return true;
}

using Digest = std::array<std::uint8_t, 32>;
bool Sha256(std::string_view input, Digest& output) noexcept {
  unsigned int length = 0;
  return EVP_Digest(input.data(), static_cast<unsigned long>(input.size()), output.data(),
                    &length, EVP_sha256(), nullptr) == 1 && output.size() == length;
}

struct AnchorRecord {
  RuntimeDomainId domain_id{};
  std::string root_path;
  Digest digest{};
};

bool EncodeAnchor(const RuntimeDomainId& domain_id, const std::string& root_path,
                  std::string& envelope, Digest& digest) {
  Json payload = Json::object();
  payload["domain_id"] = Hex(domain_id);
  payload["root_path"] = root_path;
  payload["schema_version"] = 1;
  const std::string payload_bytes = payload.dump();
  if (!Sha256(payload_bytes, digest)) return false;
  Json whole = Json::object();
  whole["anchor"] = std::move(payload);
  whole["sha256"] = Hex(digest);
  envelope = whole.dump();
  return envelope.size() <= kMaxRuntimeAnchorBytes;
}

bool DecodeAnchor(std::string_view envelope, AnchorRecord& out) {
  if (envelope.empty() || envelope.size() > kMaxRuntimeAnchorBytes) return false;
  AnchorJsonGuard guard;
  if (!Json::sax_parse(envelope.begin(), envelope.end(), &guard)) return false;
  Json whole = Json::parse(envelope.begin(), envelope.end(), nullptr, false);
  if (whole.is_discarded() || !whole.is_object() || whole.size() != 2 ||
      !whole.contains("anchor") || !whole.contains("sha256")) return false;
  const Json& payload = whole.at("anchor");
  if (!payload.is_object() || payload.size() != 3 ||
      !payload.contains("domain_id") || !payload.contains("root_path") ||
      !payload.contains("schema_version") || !payload.at("domain_id").is_string() ||
      !payload.at("root_path").is_string() ||
      !payload.at("schema_version").is_number_unsigned() ||
      payload.at("schema_version").get<std::uint64_t>() != 1 ||
      !whole.at("sha256").is_string()) return false;
  if (!ParseHex<16>(payload.at("domain_id").get_ref<const std::string&>(), out.domain_id))
    return false;
  out.root_path = payload.at("root_path").get<std::string>();
  if (!ValidAbsoluteInput(out.root_path)) return false;
  const std::string payload_bytes = payload.dump();
  Digest computed{};
  if (!Sha256(payload_bytes, computed) ||
      !ParseHex<32>(whole.at("sha256").get_ref<const std::string&>(), out.digest) ||
      computed != out.digest) return false;
  Json canonical = Json::object();
  canonical["anchor"] = payload;
  canonical["sha256"] = Hex(computed);
  if (canonical.dump() != envelope) return false;
  return true;
}

struct CanonicalLocation {
  UniqueFd parent_fd;
  struct stat parent_stat {};
  std::string parent_path;
  std::string leaf;
  std::string full_path;
};

std::optional<CanonicalLocation> ResolveLocation(const std::string& input,
                                                 IRuntimeOwnerIo* io) {
  if (!ValidAbsoluteInput(input)) return std::nullopt;
  const auto split = input.find_last_of('/');
  const std::string parent_input = split == 0 ? "/" : input.substr(0, split);
  const std::string leaf = input.substr(split + 1);
  if (leaf.empty() || leaf == "." || leaf == "..") return std::nullopt;
  if (Fail(io, RuntimeOwnerIoPoint::ResolveParent)) return std::nullopt;
  std::unique_ptr<char, decltype(&std::free)> resolved(::realpath(parent_input.c_str(), nullptr),
                                                      &std::free);
  if (!resolved) return std::nullopt;
  std::string parent_path(resolved.get());
  UniqueFd parent_fd(::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (parent_fd.get() < 0) return std::nullopt;
  struct stat parent_stat {};
  if (::fstat(parent_fd.get(), &parent_stat) != 0 || !S_ISDIR(parent_stat.st_mode))
    return std::nullopt;
  const std::string full = parent_path == "/" ? "/" + leaf : parent_path + "/" + leaf;
  if (full.size() >= kMaxRootPathBytes) return std::nullopt;
  return CanonicalLocation{std::move(parent_fd), parent_stat, std::move(parent_path),
                           leaf, full};
}

bool RootEntryMatches(int parent_fd, const std::string& leaf, int root_fd,
                      const struct stat& expected_root) noexcept {
  struct stat fd_stat {}, entry_stat {};
  return ::fstat(root_fd, &fd_stat) == 0 && ::fstatat(parent_fd, leaf.c_str(), &entry_stat,
      AT_SYMLINK_NOFOLLOW) == 0 && SameInode(fd_stat, expected_root) &&
      SameInode(entry_stat, expected_root) && S_ISDIR(entry_stat.st_mode);
}

std::variant<AnchorRecord, RuntimeOwnerError> ReadAnchor(int root_fd, int anchor_fd,
                                                        IRuntimeOwnerIo* io) {
  if (!AnchorTempAbsent(root_fd)) return RuntimeOwnerError::InvalidAnchor;
  if (Fail(io, RuntimeOwnerIoPoint::CheckAnchorIdentity))
    return RuntimeOwnerError::AnchorIdentityChanged;
  struct stat fd_stat {}, entry_stat {};
  if (::fstat(anchor_fd, &fd_stat) != 0 ||
      ::fstatat(root_fd, kAnchorName, &entry_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(fd_stat, entry_stat) || !ValidRegular(fd_stat, 0600))
    return RuntimeOwnerError::AnchorIdentityChanged;
  if (fd_stat.st_size < 0 || static_cast<std::uint64_t>(fd_stat.st_size) > kMaxRuntimeAnchorBytes)
    return RuntimeOwnerError::InvalidAnchor;
  if (Fail(io, RuntimeOwnerIoPoint::ReadAnchor)) return RuntimeOwnerError::IoFailure;
  std::string bytes;
  if (!ReadAllAt(anchor_fd, bytes, static_cast<std::size_t>(fd_stat.st_size)))
    return RuntimeOwnerError::IoFailure;
  AnchorRecord record;
  if (!DecodeAnchor(bytes, record)) return RuntimeOwnerError::InvalidAnchor;
  return record;
}

bool RootHasOnlyAnchorAndLock(int root_fd, IRuntimeOwnerIo* io) noexcept {
  if (Fail(io, RuntimeOwnerIoPoint::EnumerateRoot)) return false;
  const int scan_fd = ::openat(root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (scan_fd < 0) return false;
  DIR* directory = ::fdopendir(scan_fd);
  if (directory == nullptr) { ::close(scan_fd); return false; }
  std::size_t count = 0;
  bool valid = true;
  errno = 0;
  while (dirent* entry = ::readdir(directory)) {
    const std::string_view name(entry->d_name);
    if (name == "." || name == "..") continue;
    ++count;
    if (name != kLockName && name != kAnchorName) valid = false;
    if (count > 2) valid = false;
  }
  if (errno != 0) valid = false;
  ::closedir(directory);
  return valid && count == 2;
}

std::optional<RuntimeOwnerError> CheckState(const detail::RuntimeOwnerState& state,
                                            IRuntimeOwnerIo* io) noexcept;

}  // namespace

namespace detail {
struct RuntimeOwnerState {
  int parent_fd{-1};
  int root_fd{-1};
  int lock_fd{-1};
  int anchor_fd{-1};
  pid_t owner_pid{};
  RuntimeOwnerMode mode{RuntimeOwnerMode::RecoveryRequired};
  mutable std::atomic<std::uint16_t> latched_error{};
  RuntimeDomainId domain_id{};
  Digest anchor_digest{};
  struct stat parent_stat {};
  struct stat root_stat {};
  struct stat lock_stat {};
  struct stat anchor_stat {};
  std::string parent_path;
  std::string leaf;
  std::string root_path;
  IRuntimeOwnerIo* test_io{};
  std::mutex claim_mutex;
  bool initial_claimed{};
  bool claim_in_progress{};
  ~RuntimeOwnerState() {
    if (anchor_fd >= 0) ::close(anchor_fd);
    if (lock_fd >= 0) ::close(lock_fd);
    if (root_fd >= 0) ::close(root_fd);
    if (parent_fd >= 0) ::close(parent_fd);
  }
};
}  // namespace detail

namespace {

std::optional<RuntimeOwnerError> Latched(const detail::RuntimeOwnerState& state) noexcept {
  const auto value = state.latched_error.load(std::memory_order_acquire);
  if (value == 0) return std::nullopt;
  return static_cast<RuntimeOwnerError>(value - 1);
}

RuntimeOwnerError Latch(const detail::RuntimeOwnerState& state, RuntimeOwnerError error) noexcept {
  const auto desired = static_cast<std::uint16_t>(error) + 1;
  std::uint16_t expected = 0;
  if (state.latched_error.compare_exchange_strong(expected, desired,
        std::memory_order_acq_rel, std::memory_order_acquire)) return error;
  return static_cast<RuntimeOwnerError>(expected - 1);
}

std::optional<RuntimeOwnerError> CheckState(const detail::RuntimeOwnerState& state,
                                            IRuntimeOwnerIo* io) noexcept {
  try {
  if (const auto previous = Latched(state)) return previous;
  const auto invalid = [&](RuntimeOwnerError error) -> std::optional<RuntimeOwnerError> {
    return Latch(state, error);
  };
  if (::getpid() != state.owner_pid) return invalid(RuntimeOwnerError::OwnerProcessChanged);
  if (Fail(io, RuntimeOwnerIoPoint::CheckRootIdentity) ||
      !RootEntryMatches(state.parent_fd, state.leaf, state.root_fd, state.root_stat))
    return invalid(RuntimeOwnerError::RootIdentityChanged);
  struct stat root_stat {}, parent_stat {}, lock_fd_stat {}, lock_entry_stat {};
  if (::fstat(state.root_fd, &root_stat) != 0 || !S_ISDIR(root_stat.st_mode) ||
      !ValidModeOwner(root_stat, 0700) || !SameInode(root_stat, state.root_stat))
    return invalid(RuntimeOwnerError::RootIdentityChanged);
  if (::fstat(state.parent_fd, &parent_stat) != 0 || !S_ISDIR(parent_stat.st_mode) ||
      !SameInode(parent_stat, state.parent_stat)) return invalid(RuntimeOwnerError::RootIdentityChanged);
  auto current = ResolveLocation(state.root_path, io);
  if (!current || !SameInode(current->parent_stat, state.parent_stat) ||
      current->leaf != state.leaf || current->full_path != state.root_path)
    return invalid(RuntimeOwnerError::RootPathMismatch);
  if (Fail(io, RuntimeOwnerIoPoint::CheckLockIdentity) ||
      ::fstat(state.lock_fd, &lock_fd_stat) != 0 ||
      ::fstatat(state.root_fd, kLockName, &lock_entry_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(lock_fd_stat, state.lock_stat) || !SameInode(lock_entry_stat, state.lock_stat) ||
      !ValidLockFile(lock_fd_stat) || !ValidLockFile(lock_entry_stat))
    return invalid(RuntimeOwnerError::LockIdentityChanged);
  if (::flock(state.lock_fd, LOCK_EX | LOCK_NB) != 0) return invalid(RuntimeOwnerError::LockBusy);
  auto anchor = ReadAnchor(state.root_fd, state.anchor_fd, io);
  if (auto* error = std::get_if<RuntimeOwnerError>(&anchor)) return invalid(*error);
  const auto& record = std::get<AnchorRecord>(anchor);
  if (record.domain_id != state.domain_id) return invalid(RuntimeOwnerError::DomainMismatch);
  if (record.root_path != state.root_path) return invalid(RuntimeOwnerError::RootPathMismatch);
  if (record.digest != state.anchor_digest) return invalid(RuntimeOwnerError::InvalidAnchor);
  return std::nullopt;
  } catch (...) {
    return Latch(state, RuntimeOwnerError::AllocationFailure);
  }
}

std::variant<int, RuntimeOwnerError> DupRoot(const detail::RuntimeOwnerState& state,
                                             IRuntimeOwnerIo* io) noexcept {
  const auto checked = CheckState(state, io);
  if (checked.has_value()) return *checked;
  if (Fail(io, RuntimeOwnerIoPoint::DuplicateRoot))
    return Latch(state, RuntimeOwnerError::IoFailure);
  const int duplicate = ::fcntl(state.root_fd, F_DUPFD_CLOEXEC, 0);
  if (duplicate < 0)
    return Latch(state, RuntimeOwnerError::IoFailure);
  const auto after_dup = CheckState(state, io);
  if (after_dup.has_value()) {
    ::close(duplicate);
    return *after_dup;
  }
  return duplicate;
}

bool DurableWriteAnchor(int root_fd, int lock_fd, const std::string& bytes,
                        IRuntimeOwnerIo* io, RuntimeOwnerError& error) noexcept {
  if (Fail(io, RuntimeOwnerIoPoint::CreateAnchorTemp)) {
    error = RuntimeOwnerError::IoFailure;
    return false;
  }
  UniqueFd temp(::openat(root_fd, kAnchorTempName,
      O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (temp.get() < 0) { error = RuntimeOwnerError::IoFailure; return false; }
  struct stat st {};
  if (::fchmod(temp.get(), 0600) != 0 || ::fstat(temp.get(), &st) != 0 ||
      !ValidRegular(st, 0600)) {
    error = RuntimeOwnerError::IoFailure;
    if (!Fail(io, RuntimeOwnerIoPoint::CleanupTemp)) (void)::unlinkat(root_fd, kAnchorTempName, 0);
    return false;
  }
  if (Fail(io, RuntimeOwnerIoPoint::WriteAnchor) || !WriteAll(temp.get(), bytes.data(), bytes.size()) ||
      Fail(io, RuntimeOwnerIoPoint::SyncAnchor) || !Sync(temp.get())) {
    error = RuntimeOwnerError::IoFailure;
    if (!Fail(io, RuntimeOwnerIoPoint::CleanupTemp)) (void)::unlinkat(root_fd, kAnchorTempName, 0);
    return false;
  }
  const int temp_fd = temp.release();
  if (::close(temp_fd) != 0) {
    error = RuntimeOwnerError::IoFailure;
    if (!Fail(io, RuntimeOwnerIoPoint::CleanupTemp)) (void)::unlinkat(root_fd, kAnchorTempName, 0);
    return false;
  }
  struct stat lock_fd_stat {}, lock_entry_stat {};
  if (Fail(io, RuntimeOwnerIoPoint::CheckLockIdentity) ||
      ::fstat(lock_fd, &lock_fd_stat) != 0 ||
      ::fstatat(root_fd, kLockName, &lock_entry_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameInode(lock_fd_stat, lock_entry_stat) || !ValidLockFile(lock_fd_stat)) {
    error = RuntimeOwnerError::LockIdentityChanged;
    if (!Fail(io, RuntimeOwnerIoPoint::CleanupTemp)) (void)::unlinkat(root_fd, kAnchorTempName, 0);
    return false;
  }
  if (Fail(io, RuntimeOwnerIoPoint::RenameAnchor) ||
      ::renameat(root_fd, kAnchorTempName, root_fd, kAnchorName) != 0) {
    error = RuntimeOwnerError::IoFailure;
    if (!Fail(io, RuntimeOwnerIoPoint::CleanupTemp)) (void)::unlinkat(root_fd, kAnchorTempName, 0);
    return false;
  }
  if (Fail(io, RuntimeOwnerIoPoint::SyncRoot) || !Sync(root_fd)) {
    error = RuntimeOwnerError::DurabilityUncertain;
    return false;
  }
  return true;
}

}  // namespace

RuntimeOwner::~RuntimeOwner() = default;

RuntimeOwnerOpenResult RuntimeOwner::CreateNew(const std::string& absolute_root,
                                               const RuntimeDomainId& domain_id,
                                               IRuntimeOwnerIo* io) noexcept {
  try {
    if (AllZero(domain_id)) return RuntimeOwnerError::InvalidDomainId;
    auto location = ResolveLocation(absolute_root, io);
    if (!location) return RuntimeOwnerError::InvalidPath;
    std::string anchor_bytes;
    Digest anchor_digest{};
    if (!EncodeAnchor(domain_id, location->full_path, anchor_bytes, anchor_digest))
      return RuntimeOwnerError::InvalidAnchor;
    if (Fail(io, RuntimeOwnerIoPoint::MkdirRoot)) return RuntimeOwnerError::IoFailure;
    if (::mkdirat(location->parent_fd.get(), location->leaf.c_str(), 0700) != 0)
      return errno == EEXIST ? RuntimeOwnerError::AlreadyExists : RuntimeOwnerError::IoFailure;
    if (Fail(io, RuntimeOwnerIoPoint::SyncParent) || !Sync(location->parent_fd.get()))
      return RuntimeOwnerError::DurabilityUncertain;
    if (Fail(io, RuntimeOwnerIoPoint::OpenRoot)) return RuntimeOwnerError::InvalidRoot;
    UniqueFd root_fd(::openat(location->parent_fd.get(), location->leaf.c_str(),
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root_fd.get() < 0 || ::fchmod(root_fd.get(), 0700) != 0 ||
        Fail(io, RuntimeOwnerIoPoint::ValidateRoot)) return RuntimeOwnerError::InvalidRoot;
    struct stat root_stat {};
    if (::fstat(root_fd.get(), &root_stat) != 0 || !S_ISDIR(root_stat.st_mode) ||
        !ValidModeOwner(root_stat, 0700)) return RuntimeOwnerError::InvalidRoot;
    if (Fail(io, RuntimeOwnerIoPoint::CreateLock)) return RuntimeOwnerError::InvalidLock;
    UniqueFd lock_fd(::openat(root_fd.get(), kLockName,
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (lock_fd.get() < 0 || ::fchmod(lock_fd.get(), 0600) != 0)
      return RuntimeOwnerError::InvalidLock;
    struct stat lock_stat {};
    if (::fstat(lock_fd.get(), &lock_stat) != 0 || !ValidLockFile(lock_stat))
      return RuntimeOwnerError::InvalidLock;
    if (Fail(io, RuntimeOwnerIoPoint::AcquireLock)) return RuntimeOwnerError::LockBusy;
    if (::flock(lock_fd.get(), LOCK_EX | LOCK_NB) != 0)
      return RuntimeOwnerError::LockBusy;
    if (Fail(io, RuntimeOwnerIoPoint::SyncLock) || !Sync(lock_fd.get()) ||
        Fail(io, RuntimeOwnerIoPoint::SyncRoot) || !Sync(root_fd.get()))
      return RuntimeOwnerError::DurabilityUncertain;

    auto state = std::make_shared<detail::RuntimeOwnerState>();
    state->owner_pid = ::getpid();
    state->mode = RuntimeOwnerMode::Fresh;
    state->domain_id = domain_id;
    state->anchor_digest = anchor_digest;
    state->parent_stat = location->parent_stat;
    state->root_stat = root_stat;
    state->lock_stat = lock_stat;
    state->parent_path = location->parent_path;
    state->leaf = location->leaf;
    state->root_path = location->full_path;
    state->test_io = io;
    auto owner = std::unique_ptr<RuntimeOwner>(new RuntimeOwner(state));
    state->parent_fd = location->parent_fd.release();
    state->root_fd = root_fd.release();
    state->lock_fd = lock_fd.release();
    RuntimeOwnerError write_error = RuntimeOwnerError::IoFailure;
    if (!DurableWriteAnchor(state->root_fd, state->lock_fd, anchor_bytes, io, write_error))
      return write_error;
    UniqueFd anchor_fd(::openat(state->root_fd, kAnchorName,
                                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    if (anchor_fd.get() < 0) return RuntimeOwnerError::DurabilityUncertain;
    struct stat anchor_stat {};
    if (::fstat(anchor_fd.get(), &anchor_stat) != 0 || !ValidRegular(anchor_stat, 0600))
      return RuntimeOwnerError::DurabilityUncertain;
    state->anchor_stat = anchor_stat;
    state->anchor_fd = anchor_fd.release();
    const auto final_check = owner->ValidateOwnership();
    if (auto* error = std::get_if<RuntimeOwnerError>(&final_check)) return *error;
    return owner;
  } catch (...) {
    return RuntimeOwnerError::AllocationFailure;
  }
}

RuntimeOwnerOpenResult RuntimeOwner::OpenExisting(const std::string& absolute_root,
                                                  const RuntimeDomainId& expected_domain_id,
                                                  IRuntimeOwnerIo* io) noexcept {
  try {
    if (AllZero(expected_domain_id)) return RuntimeOwnerError::InvalidDomainId;
    auto location = ResolveLocation(absolute_root, io);
    if (!location) return RuntimeOwnerError::InvalidPath;
    if (Fail(io, RuntimeOwnerIoPoint::OpenRoot)) return RuntimeOwnerError::InvalidRoot;
    UniqueFd root_fd(::openat(location->parent_fd.get(), location->leaf.c_str(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (root_fd.get() < 0) return errno == ENOENT ? RuntimeOwnerError::NotFound
                                                  : RuntimeOwnerError::InvalidRoot;
    if (Fail(io, RuntimeOwnerIoPoint::ValidateRoot)) return RuntimeOwnerError::InvalidRoot;
    struct stat root_stat {};
    if (::fstat(root_fd.get(), &root_stat) != 0 || !S_ISDIR(root_stat.st_mode) ||
        !ValidModeOwner(root_stat, 0700)) return RuntimeOwnerError::InvalidRoot;
    if (Fail(io, RuntimeOwnerIoPoint::OpenLock)) return RuntimeOwnerError::InvalidLock;
    UniqueFd lock_fd(::openat(root_fd.get(), kLockName,
                              O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    if (lock_fd.get() < 0) return RuntimeOwnerError::InvalidLock;
    struct stat lock_stat {};
    if (::fstat(lock_fd.get(), &lock_stat) != 0 || !ValidLockFile(lock_stat))
      return RuntimeOwnerError::InvalidLock;
    if (Fail(io, RuntimeOwnerIoPoint::AcquireLock)) return RuntimeOwnerError::LockBusy;
    if (::flock(lock_fd.get(), LOCK_EX | LOCK_NB) != 0) return RuntimeOwnerError::LockBusy;
    if (Fail(io, RuntimeOwnerIoPoint::CheckLockIdentity)) return RuntimeOwnerError::LockIdentityChanged;
    struct stat lock_entry {};
    if (::fstatat(root_fd.get(), kLockName, &lock_entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !SameInode(lock_stat, lock_entry) || !ValidLockFile(lock_entry))
      return RuntimeOwnerError::LockIdentityChanged;
    if (Fail(io, RuntimeOwnerIoPoint::OpenAnchor)) return RuntimeOwnerError::AnchorMissing;
    UniqueFd anchor_fd(::openat(root_fd.get(), kAnchorName,
                                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    if (anchor_fd.get() < 0) return errno == ENOENT ? RuntimeOwnerError::AnchorMissing
                                                     : RuntimeOwnerError::InvalidAnchor;
    struct stat anchor_stat {};
    if (::fstat(anchor_fd.get(), &anchor_stat) != 0 || !ValidRegular(anchor_stat, 0600))
      return RuntimeOwnerError::InvalidAnchor;
    if (anchor_stat.st_size < 0 ||
        static_cast<std::uint64_t>(anchor_stat.st_size) > kMaxRuntimeAnchorBytes)
      return RuntimeOwnerError::InvalidAnchor;
    if (Fail(io, RuntimeOwnerIoPoint::ReadAnchor)) return RuntimeOwnerError::IoFailure;
    std::string bytes;
    if (!ReadAllAt(anchor_fd.get(), bytes, static_cast<std::size_t>(anchor_stat.st_size)))
      return RuntimeOwnerError::IoFailure;
    AnchorRecord anchor;
    if (!DecodeAnchor(bytes, anchor)) return RuntimeOwnerError::InvalidAnchor;
    if (anchor.domain_id != expected_domain_id) return RuntimeOwnerError::DomainMismatch;
    if (anchor.root_path != location->full_path) return RuntimeOwnerError::RootPathMismatch;
    struct stat anchor_entry {};
    if (Fail(io, RuntimeOwnerIoPoint::CheckAnchorIdentity) ||
        ::fstatat(root_fd.get(), kAnchorName, &anchor_entry, AT_SYMLINK_NOFOLLOW) != 0 ||
        !SameInode(anchor_stat, anchor_entry)) return RuntimeOwnerError::AnchorIdentityChanged;

    auto state = std::make_shared<detail::RuntimeOwnerState>();
    state->owner_pid = ::getpid();
    state->mode = RuntimeOwnerMode::RecoveryRequired;
    state->domain_id = anchor.domain_id;
    state->anchor_digest = anchor.digest;
    state->parent_stat = location->parent_stat;
    state->root_stat = root_stat;
    state->lock_stat = lock_stat;
    state->anchor_stat = anchor_stat;
    state->parent_path = location->parent_path;
    state->leaf = location->leaf;
    state->root_path = location->full_path;
    state->test_io = io;
    state->parent_fd = location->parent_fd.release();
    state->root_fd = root_fd.release();
    state->lock_fd = lock_fd.release();
    state->anchor_fd = anchor_fd.release();
    auto owner = std::unique_ptr<RuntimeOwner>(new RuntimeOwner(std::move(state)));
    const auto final_check = owner->ValidateOwnership();
    if (auto* error = std::get_if<RuntimeOwnerError>(&final_check)) return *error;
    return owner;
  } catch (...) {
    return RuntimeOwnerError::AllocationFailure;
  }
}

RuntimeOwnerMode RuntimeOwner::mode() const noexcept {
  // A forked child must not inherit the parent's Fresh capability, even if
  // the parent happened to fork while another thread held claim_mutex.
  if (::getpid() != state_->owner_pid) return RuntimeOwnerMode::RecoveryRequired;
  return Latched(*state_).has_value() ? RuntimeOwnerMode::RecoveryRequired : state_->mode;
}
const RuntimeDomainId& RuntimeOwner::domain_id() const noexcept { return state_->domain_id; }
const std::string& RuntimeOwner::root_path() const noexcept { return state_->root_path; }

RuntimeOwnerCheck RuntimeOwner::ValidateOwnership() const noexcept {
  const auto error = CheckState(*state_, state_->test_io);
  return error.has_value() ? RuntimeOwnerCheck{*error}
                           : RuntimeOwnerCheck{std::monostate{}};
}

DuplicateFdResult RuntimeOwner::DuplicateRootFd() const noexcept {
  return DupRoot(*state_, state_->test_io);
}

InitialClaimResult RuntimeOwner::ClaimInitialEpoch(const EpochId& epoch_id) noexcept {
  // Check process ownership before consulting mode or touching claim_mutex:
  // after a multithreaded fork that mutex may be permanently locked in child.
  if (::getpid() != state_->owner_pid) return RuntimeOwnerError::OwnerProcessChanged;
  if (mode() != RuntimeOwnerMode::Fresh) return RuntimeOwnerError::RecoveryRequired;
  if (AllZero(epoch_id)) return RuntimeOwnerError::InvalidEpochId;
  {
    std::lock_guard lock(state_->claim_mutex);
    if (const auto previous = Latched(*state_)) return *previous;
    if (state_->initial_claimed) return RuntimeOwnerError::InitialClaimAlreadyUsed;
    if (state_->claim_in_progress) return RuntimeOwnerError::Busy;
    state_->claim_in_progress = true;
  }
  const auto finish = [&](RuntimeOwnerError error, bool latch) -> InitialClaimResult {
    std::lock_guard lock(state_->claim_mutex);
    if (latch) error = Latch(*state_, error);
    state_->claim_in_progress = false;
    return error;
  };
  const auto checked = CheckState(*state_, state_->test_io);
  if (checked.has_value()) return finish(*checked, false);
  if (!RootHasOnlyAnchorAndLock(state_->root_fd, state_->test_io))
    return finish(RuntimeOwnerError::UnexpectedRootEntry, true);
  const auto final_check = CheckState(*state_, state_->test_io);
  if (final_check.has_value()) return finish(*final_check, false);
  std::lock_guard lock(state_->claim_mutex);
  if (const auto previous = Latched(*state_)) {
    state_->claim_in_progress = false;
    return *previous;
  }
  state_->initial_claimed = true;
  state_->claim_in_progress = false;
  return InitialEpochClaim(state_, epoch_id);
}

RuntimeOwnerCheck InitialEpochClaim::ValidateOwnership() const noexcept {
  if (!state_) return RuntimeOwnerError::RecoveryRequired;
  const auto error = CheckState(*state_, state_->test_io);
  return error.has_value() ? RuntimeOwnerCheck{*error}
                           : RuntimeOwnerCheck{std::monostate{}};
}

RuntimeDomainId InitialEpochClaim::domain_id() const noexcept {
  return state_ ? state_->domain_id : RuntimeDomainId{};
}

const std::string& InitialEpochClaim::root_path() const noexcept {
  static const std::string kEmpty;
  return state_ ? state_->root_path : kEmpty;
}

DuplicateFdResult InitialEpochClaim::DuplicateRootFd() const noexcept {
  if (!state_) return RuntimeOwnerError::RecoveryRequired;
  return DupRoot(*state_, state_->test_io);
}

}  // namespace rateguard::supervisor
