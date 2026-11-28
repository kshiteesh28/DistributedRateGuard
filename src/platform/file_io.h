#pragma once

// Shared POSIX descriptor ownership and I/O used by supervisor artifact stores.
// Callers validate regular-file identity and bound size before ReadAll.

#include <cerrno>
#include <cstddef>
#include <string>
#include <unistd.h>

namespace rateguard::platform::file {

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

inline bool WriteAll(int fd, const char* data, std::size_t size) noexcept {
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

inline bool Sync(int fd) noexcept {
  int result;
  do { result = ::fsync(fd); } while (result != 0 && errno == EINTR);
  return result == 0;
}

inline bool ReadAll(int fd, std::string& out, std::size_t size) {
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

}  // namespace rateguard::platform::file
