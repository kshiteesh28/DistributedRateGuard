#pragma once

// POSIX durable publication for a validated strict-history snapshot.
// The caller must serialize all operations in the supplied private directory.

#include "src/events/history_exporter.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <streambuf>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace rateguard::events {

using HistoryRunId = std::array<std::uint8_t, 16>;

inline constexpr std::size_t kHistoryFileNameCapacity = 80;
inline constexpr std::string_view kHistoryFilePrefix = "rg-history-v1-";
inline constexpr std::string_view kHistoryFileSuffix = ".bin";
inline constexpr std::string_view kHistoryPartialSuffix = ".partial";

enum class FilePublishStatus : std::uint8_t {
  Published,
  IncompleteHistory,
  InvalidCreationSecond,
  InvalidDirectory,
  TemporaryNameExists,
  TemporaryOpenFailed,
  TemporaryMetadataFailed,
  WriteFailed,
  FileSyncFailed,
  FileCloseFailed,
  FinalNameExists,
  LinkFailed,
  TemporaryUnlinkFailed,
  DirectorySyncUncertain,
};

struct FilePublishResult final {
  FilePublishStatus status{FilePublishStatus::WriteFailed};
  bool final_published{false};
  bool file_synced{false};
  bool temporary_removed{false};
  bool directory_synced{false};
  std::array<char, kHistoryFileNameCapacity> final_name{};
  std::uint8_t final_name_size{0};

  [[nodiscard]] std::string_view filename() const noexcept {
    return {final_name.data(), final_name_size};
  }
};

namespace file_detail {

inline constexpr char kHex[] = "0123456789abcdef";

class FixedName final {
 public:
  [[nodiscard]] bool Append(std::string_view value) noexcept {
    if (value.size() > bytes_.size() - size_) return false;
    for (char ch : value) bytes_[size_++] = ch;
    return true;
  }
  [[nodiscard]] bool Append(char ch) noexcept {
    if (size_ == bytes_.size()) return false;
    bytes_[size_++] = ch;
    return true;
  }
  [[nodiscard]] bool AppendDecimal(std::uint64_t value) noexcept {
    std::array<char, 12> digits{};
    std::size_t count = 0;
    do {
      digits[count++] = static_cast<char>('0' + (value % 10));
      value /= 10;
    } while (value != 0 && count < digits.size());
    if (value != 0 || count > 12 || count > bytes_.size() - size_) return false;
    while (count != 0) bytes_[size_++] = digits[--count];
    return true;
  }
  [[nodiscard]] bool AppendHex(const HistoryRunId& run_id) noexcept {
    if (run_id.size() * 2 > bytes_.size() - size_) return false;
    for (std::uint8_t byte : run_id) {
      bytes_[size_++] = kHex[byte >> 4];
      bytes_[size_++] = kHex[byte & 0x0f];
    }
    return true;
  }
  [[nodiscard]] const char* data() const noexcept { return bytes_.data(); }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::string_view view() const noexcept { return {bytes_.data(), size_}; }

 private:
  std::array<char, kHistoryFileNameCapacity> bytes_{};
  std::size_t size_{0};
};

inline bool BuildNames(std::uint64_t creation_second, const HistoryRunId& run_id,
                       FixedName& final_name, FixedName& temporary_name) noexcept {
  if (creation_second > 999'999'999'999ULL) return false;
  if (!final_name.Append(kHistoryFilePrefix) || !final_name.AppendDecimal(creation_second) ||
      !final_name.Append('-') || !final_name.AppendHex(run_id) ||
      !final_name.Append(kHistoryFileSuffix)) return false;
  temporary_name = final_name;
  return temporary_name.Append(kHistoryPartialSuffix);
}

inline bool IsPrivateDirectory(int directory_fd) noexcept {
  struct stat info {};
  if (::fstat(directory_fd, &info) != 0 || !S_ISDIR(info.st_mode)) return false;
  if (info.st_uid != ::geteuid()) return false;
  return (info.st_mode & 07777) == 0700;
}

inline bool WriteAll(int fd, const char* data, std::size_t size) noexcept {
  while (size != 0) {
    const auto written = ::write(fd, data, size);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (written == 0) return false;
    data += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

class FdStreamBuffer final : public std::streambuf {
 public:
  explicit FdStreamBuffer(int fd, std::uint64_t limit) noexcept : fd_(fd), limit_(limit) {}

 protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override {
    if (count <= 0 || failed_) return 0;
    const auto size = static_cast<std::uint64_t>(count);
    if (size > std::numeric_limits<std::size_t>::max() ||
        size > limit_ - bytes_written_ ||
        !WriteAll(fd_, data, static_cast<std::size_t>(size))) {
      failed_ = true;
      return 0;
    }
    bytes_written_ += size;
    return count;
  }
  int_type overflow(int_type ch) override {
    if (traits_type::eq_int_type(ch, traits_type::eof()))
      return failed_ ? traits_type::eof() : traits_type::not_eof(ch);
    if (failed_ || bytes_written_ == limit_) return traits_type::eof();
    const char value = traits_type::to_char_type(ch);
    if (!WriteAll(fd_, &value, 1)) {
      failed_ = true;
      return traits_type::eof();
    }
    ++bytes_written_;
    return ch;
  }
  int sync() override { return failed_ ? -1 : 0; }

 public:
  [[nodiscard]] std::uint64_t bytes_written() const noexcept { return bytes_written_; }

 private:
  int fd_;
  const std::uint64_t limit_;
  bool failed_{false};
  std::uint64_t bytes_written_{0};
};

inline void CopyName(FilePublishResult& result, const FixedName& name) noexcept {
  const auto count = name.size() < result.final_name.size() ? name.size() : result.final_name.size();
  for (std::size_t i = 0; i < count; ++i) result.final_name[i] = name.data()[i];
  result.final_name_size = static_cast<std::uint8_t>(count);
}

inline bool RemoveTemporary(int directory_fd, const FixedName& name) noexcept {
  if (::unlinkat(directory_fd, name.data(), 0) == 0) return true;
  return errno == ENOENT;
}

inline int FsyncRetry(int fd) noexcept {
  int result = 0;
  do { result = ::fsync(fd); } while (result != 0 && errno == EINTR);
  return result;
}

}  // namespace file_detail

// Stream the encoded export directly to a 0600 O_EXCL temporary file in the
// caller's already-open private directory. Hard-link publication is atomic and
// no-overwrite; a final-name collision never truncates or replaces an artifact.
// The exporter flushes the stream before the file is fsynced. The file is then
// linked under its final managed name, the temporary name unlinked, and the
// directory fsynced. A failed directory fsync means the final name is visible
// but its post-crash durability is uncertain; the result keeps that explicit.
inline FilePublishResult PublishStrictHistoryFile(
    int private_directory_fd, std::uint64_t creation_second,
    const HistoryRunId& run_id, const RunPlan& expected,
    const EventSnapshotV1& snapshot) noexcept {
  FilePublishResult result;
  file_detail::FixedName final_name;
  file_detail::FixedName temporary_name;
  if (!file_detail::BuildNames(creation_second, run_id, final_name, temporary_name)) {
    result.status = FilePublishStatus::InvalidCreationSecond;
    return result;
  }
  file_detail::CopyName(result, final_name);
  if (!file_detail::IsPrivateDirectory(private_directory_fd)) {
    result.status = FilePublishStatus::InvalidDirectory;
    return result;
  }

  const int fd = ::openat(private_directory_fd, temporary_name.data(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    result.status = errno == EEXIST ? FilePublishStatus::TemporaryNameExists
                                    : FilePublishStatus::TemporaryOpenFailed;
    return result;
  }
  if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
    (void)::close(fd);
    result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
    result.status = FilePublishStatus::TemporaryMetadataFailed;
    return result;
  }

  ExportStatus export_status = ExportStatus::WriteFailed;
  std::uint64_t bytes_written = 0;
  try {
    file_detail::FdStreamBuffer buffer(fd, snapshot.planned_bytes);
    std::ostream output(&buffer);
    export_status = ExportStrictHistory(expected, snapshot, output);
    bytes_written = buffer.bytes_written();
  } catch (...) {
    (void)::close(fd);
    result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
    result.status = FilePublishStatus::WriteFailed;
    return result;
  }
  if (export_status != ExportStatus::Complete || bytes_written != snapshot.planned_bytes) {
    (void)::close(fd);
    result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
    result.status = export_status == ExportStatus::IncompleteHistory
                        ? FilePublishStatus::IncompleteHistory
                        : FilePublishStatus::WriteFailed;
    return result;
  }

  if (file_detail::FsyncRetry(fd) != 0) {
    (void)::close(fd);
    result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
    result.status = FilePublishStatus::FileSyncFailed;
    return result;
  }
  result.file_synced = true;
  if (::close(fd) != 0) {
    result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
    result.status = FilePublishStatus::FileCloseFailed;
    return result;
  }

  if (::linkat(private_directory_fd, temporary_name.data(), private_directory_fd,
               final_name.data(), 0) != 0) {
    const bool final_exists = errno == EEXIST;
    result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
    result.status = final_exists ? FilePublishStatus::FinalNameExists
                                 : FilePublishStatus::LinkFailed;
    return result;
  }
  result.final_published = true;

  result.temporary_removed = file_detail::RemoveTemporary(private_directory_fd, temporary_name);
  const int sync_result = file_detail::FsyncRetry(private_directory_fd);
  result.directory_synced = sync_result == 0;
  if (!result.directory_synced) {
    result.status = FilePublishStatus::DirectorySyncUncertain;
    return result;
  }
  result.status = result.temporary_removed ? FilePublishStatus::Published
                                           : FilePublishStatus::TemporaryUnlinkFailed;
  return result;
}

}  // namespace rateguard::events
