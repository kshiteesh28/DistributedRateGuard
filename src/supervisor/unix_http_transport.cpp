#include "supervisor/unix_http_transport.h"

#include "supervisor/http1_parser.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <utility>

#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace rateguard::supervisor {
namespace {

UnixHttpFailure Failure(UnixHttpFailureReason reason,
                        bool request_possibly_sent = false) noexcept {
  return UnixHttpFailure{reason, request_possibly_sent};
}

#if defined(__linux__)

class ScopedFd {
 public:
  explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
  ~ScopedFd() { if (fd_ >= 0) (void)::close(fd_); }
  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;
  [[nodiscard]] int get() const noexcept { return fd_; }
 private:
  int fd_;
};

struct SocketIdentity {
  dev_t device{};
  ino_t inode{};
  uid_t owner{};
};

bool SameSocketIdentity(const char* path,
                        const SocketIdentity& expected) noexcept {
  struct stat st {};
  return ::lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) &&
         st.st_dev == expected.device && st.st_ino == expected.inode &&
         st.st_uid == expected.owner;
}

class NativeUnixHttpTransport final : public IUnixHttpTransport {
 public:
  NativeUnixHttpTransport(std::string canonical_path, SocketIdentity identity,
                          std::uint32_t expected_peer_uid,
                          platform::IClock& clock) noexcept
      : path_(std::move(canonical_path)), identity_(identity),
        expected_peer_uid_(expected_peer_uid), clock_(clock) {}

  UnixHttpResult RoundTrip(
      UnixHttpMethod method, std::string_view target,
      platform::MonoNanos absolute_deadline,
      const std::atomic_bool& cancel_requested) noexcept override {
    bool sent = false;
    try {
      if (!detail::IsValidOriginFormTarget(target))
        return Failure(UnixHttpFailureReason::InvalidTarget);
      if (method != UnixHttpMethod::Get && method != UnixHttpMethod::Post)
        return Failure(UnixHttpFailureReason::InvalidTarget);

      const auto initial_now = SafeNow(false);
      if (std::holds_alternative<UnixHttpFailure>(initial_now))
        return std::get<UnixHttpFailure>(initial_now);
      const auto now = std::get<platform::MonoNanos>(initial_now).value;
      if (absolute_deadline.value <= now ||
          absolute_deadline.value - now > kUnixHttpMaxCallDurationNs) {
        return Failure(UnixHttpFailureReason::InvalidDeadline);
      }
      if (cancel_requested.load(std::memory_order_relaxed))
        return Failure(UnixHttpFailureReason::Cancelled);

      std::size_t active = active_calls_.load(std::memory_order_relaxed);
      for (;;) {
        if (active >= kUnixHttpMaxConcurrentCalls)
          return Failure(UnixHttpFailureReason::Overloaded);
        if (active_calls_.compare_exchange_weak(active, active + 1,
                                                std::memory_order_acq_rel,
                                                std::memory_order_relaxed)) {
          break;
        }
      }
      struct ActiveCallGuard {
        std::atomic_size_t& count;
        ~ActiveCallGuard() { count.fetch_sub(1, std::memory_order_release); }
      } active_guard{active_calls_};

      if (!SameSocketIdentity(path_.c_str(), identity_))
        return Failure(UnixHttpFailureReason::NotConfigured);

      ScopedFd socket(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                               0));
      if (socket.get() < 0)
        return Failure(UnixHttpFailureReason::SocketFailure);

      sockaddr_un address{};
      address.sun_family = AF_UNIX;
      if (path_.size() >= sizeof(address.sun_path))
        return Failure(UnixHttpFailureReason::NotConfigured);
      std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);
      const auto address_len = static_cast<socklen_t>(
          offsetof(sockaddr_un, sun_path) + path_.size() + 1);
      const auto pre_connect = CheckBeforeIo(absolute_deadline, cancel_requested, sent);
      if (std::holds_alternative<UnixHttpFailure>(pre_connect))
        return std::get<UnixHttpFailure>(pre_connect);
      int connect_result = ::connect(socket.get(),
                                     reinterpret_cast<sockaddr*>(&address),
                                     address_len);
      if (connect_result != 0 && errno != EINPROGRESS)
        return Failure(UnixHttpFailureReason::SocketFailure);
      if (connect_result != 0) {
        const auto wait = Wait(socket.get(), POLLOUT, absolute_deadline,
                               cancel_requested, sent);
        if (std::holds_alternative<UnixHttpFailure>(wait))
          return std::get<UnixHttpFailure>(wait);
        int socket_error = 0;
        socklen_t error_len = sizeof(socket_error);
        if (::getsockopt(socket.get(), SOL_SOCKET, SO_ERROR, &socket_error,
                         &error_len) != 0 || socket_error != 0) {
          return Failure(UnixHttpFailureReason::SocketFailure);
        }
      }

      if (!SameSocketIdentity(path_.c_str(), identity_))
        return Failure(UnixHttpFailureReason::NotConfigured, sent);
      ucred peer{};
      socklen_t peer_len = sizeof(peer);
      if (::getsockopt(socket.get(), SOL_SOCKET, SO_PEERCRED, &peer,
                       &peer_len) != 0 || peer_len != sizeof(peer) ||
          static_cast<std::uint32_t>(peer.uid) != expected_peer_uid_) {
        return Failure(UnixHttpFailureReason::PeerCredentialMismatch, sent);
      }

      std::string request;
      request.reserve(target.size() + 128);
      request.append(method == UnixHttpMethod::Get ? "GET " : "POST ");
      request.append(target);
      request.append(" HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      if (request.size() > kUnixHttpMaxRequestBytes)
        return Failure(UnixHttpFailureReason::InvalidTarget, sent);

      std::size_t written = 0;
      while (written < request.size()) {
        if (cancel_requested.load(std::memory_order_relaxed))
          return Failure(UnixHttpFailureReason::Cancelled, sent);
        const auto wait = Wait(socket.get(), POLLOUT, absolute_deadline,
                               cancel_requested, sent);
        if (std::holds_alternative<UnixHttpFailure>(wait))
          return std::get<UnixHttpFailure>(wait);
        const auto ready = CheckBeforeIo(absolute_deadline, cancel_requested, sent);
        if (std::holds_alternative<UnixHttpFailure>(ready))
          return std::get<UnixHttpFailure>(ready);
        const auto count = ::send(socket.get(), request.data() + written,
                                  request.size() - written, MSG_NOSIGNAL);
        if (count > 0) {
          sent = true;
          written += static_cast<std::size_t>(count);
          continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
          continue;
        return Failure(UnixHttpFailureReason::SocketFailure, sent);
      }

      std::vector<std::uint8_t> wire;
      wire.reserve(4'096);
      std::array<std::uint8_t, 4'096> buffer{};
      for (;;) {
        if (cancel_requested.load(std::memory_order_relaxed))
          return Failure(UnixHttpFailureReason::Cancelled, sent);
        const auto wait = Wait(socket.get(), POLLIN, absolute_deadline,
                               cancel_requested, sent);
        if (std::holds_alternative<UnixHttpFailure>(wait))
          return std::get<UnixHttpFailure>(wait);
        const auto ready = CheckBeforeIo(absolute_deadline, cancel_requested, sent);
        if (std::holds_alternative<UnixHttpFailure>(ready))
          return std::get<UnixHttpFailure>(ready);
        const auto count = ::recv(socket.get(), buffer.data(), buffer.size(), 0);
        if (count == 0) break;  // EOF proves Connection: close framing complete.
        if (count < 0) {
          if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
          return Failure(UnixHttpFailureReason::SocketFailure, sent);
        }
        const auto amount = static_cast<std::size_t>(count);
        if (amount > kUnixHttpMaxWireResponseBytes - wire.size())
          return Failure(UnixHttpFailureReason::ResponseTooLarge, sent);
        wire.insert(wire.end(), buffer.begin(),
                    buffer.begin() + static_cast<std::ptrdiff_t>(amount));
      }

      auto parsed = detail::ParseHttpResponse(wire);
      if (std::holds_alternative<detail::HttpParseError>(parsed)) {
        const auto error = std::get<detail::HttpParseError>(parsed);
        UnixHttpFailureReason reason = UnixHttpFailureReason::ProtocolError;
        if (error == detail::HttpParseError::TooLarge)
          reason = UnixHttpFailureReason::ResponseTooLarge;
        else if (error == detail::HttpParseError::AllocationFailure)
          reason = UnixHttpFailureReason::AllocationFailure;
        return Failure(reason, sent);
      }
      const auto final_gate = CheckBeforeIo(absolute_deadline, cancel_requested, sent);
      if (std::holds_alternative<UnixHttpFailure>(final_gate))
        return std::get<UnixHttpFailure>(final_gate);
      return std::move(std::get<UnixHttpResponse>(parsed));
    } catch (const std::bad_alloc&) {
      return Failure(UnixHttpFailureReason::AllocationFailure, sent);
    } catch (...) {
      return Failure(UnixHttpFailureReason::SocketFailure, sent);
    }
  }

 private:
  using WaitResult = std::variant<short, UnixHttpFailure>;

  using ClockSample = std::variant<platform::MonoNanos, UnixHttpFailure>;

  ClockSample SafeNow(bool sent) noexcept {
    try {
      if (!clock_.Healthy()) return Failure(UnixHttpFailureReason::ClockFailure, sent);
      const auto sample = clock_.Now();
      if (!std::holds_alternative<platform::MonoNanos>(sample) || !clock_.Healthy())
        return Failure(UnixHttpFailureReason::ClockFailure, sent);
      return std::get<platform::MonoNanos>(sample);
    } catch (...) {
      return Failure(UnixHttpFailureReason::ClockFailure, sent);
    }
  }

  WaitResult CheckBeforeIo(platform::MonoNanos deadline,
                           const std::atomic_bool& cancel_requested,
                           bool sent) noexcept {
    if (cancel_requested.load(std::memory_order_relaxed))
      return Failure(UnixHttpFailureReason::Cancelled, sent);
    const auto now_result = SafeNow(sent);
    if (std::holds_alternative<UnixHttpFailure>(now_result))
      return std::get<UnixHttpFailure>(now_result);
    if (std::get<platform::MonoNanos>(now_result).value >= deadline.value)
      return Failure(UnixHttpFailureReason::DeadlineExpired, sent);
    return static_cast<short>(0);
  }

  WaitResult Wait(int fd, short events, platform::MonoNanos deadline,
                  const std::atomic_bool& cancel_requested,
                  bool sent) noexcept {
    for (;;) {
      if (cancel_requested.load(std::memory_order_relaxed))
        return Failure(UnixHttpFailureReason::Cancelled, sent);
      const auto now_result = SafeNow(sent);
      if (std::holds_alternative<UnixHttpFailure>(now_result))
        return std::get<UnixHttpFailure>(now_result);
      const auto now = std::get<platform::MonoNanos>(now_result).value;
      if (now >= deadline.value)
        return Failure(UnixHttpFailureReason::DeadlineExpired, sent);
      const auto remaining_ns = deadline.value - now;
      const auto remaining_ms = (remaining_ns + 999'999) / 1'000'000;
      const int timeout_ms = static_cast<int>(std::min<std::uint64_t>(
          remaining_ms, 100));  // Bound cancellation observation latency.
      pollfd pfd{fd, events, 0};
      const int result = ::poll(&pfd, 1, timeout_ms);
      if (result > 0) {
        if ((pfd.revents & POLLNVAL) != 0)
          return Failure(UnixHttpFailureReason::SocketFailure, sent);
        return pfd.revents;
      }
      if (result == 0 || (result < 0 && errno == EINTR)) continue;
      return Failure(UnixHttpFailureReason::SocketFailure, sent);
    }
  }

  std::string path_;
  SocketIdentity identity_;
  std::uint32_t expected_peer_uid_;
  platform::IClock& clock_;
  std::atomic_size_t active_calls_{0};
};

#endif  // __linux__

}  // namespace

UnixHttpTransportCreateResult CreateUnixHttpTransport(
    const UnixHttpTransportConfig& config, platform::IClock& clock) noexcept {
#if defined(__linux__)
  try {
    if (config.socket_path.empty() || config.socket_path.find('\0') != std::string::npos ||
        config.socket_path.size() >= sizeof(sockaddr_un::sun_path)) {
      return Failure(UnixHttpFailureReason::NotConfigured);
    }
    char* resolved_raw = ::realpath(config.socket_path.c_str(), nullptr);
    if (resolved_raw == nullptr)
      return Failure(UnixHttpFailureReason::NotConfigured);
    std::unique_ptr<char, decltype(&std::free)> resolved_owner(resolved_raw, &std::free);
    std::string resolved(resolved_owner.get());
    if (resolved.empty() || resolved.size() >= sizeof(sockaddr_un::sun_path))
      return Failure(UnixHttpFailureReason::NotConfigured);
    struct stat st {};
    if (::lstat(resolved.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode) ||
        static_cast<std::uint32_t>(st.st_uid) != config.expected_socket_owner_uid) {
      return Failure(UnixHttpFailureReason::NotConfigured);
    }
    const SocketIdentity identity{st.st_dev, st.st_ino, st.st_uid};
    auto transport = std::make_unique<NativeUnixHttpTransport>(
        std::move(resolved), identity, config.expected_peer_uid, clock);
    return std::unique_ptr<IUnixHttpTransport>(std::move(transport));
  } catch (const std::bad_alloc&) {
    return Failure(UnixHttpFailureReason::AllocationFailure);
  } catch (...) {
    return Failure(UnixHttpFailureReason::NotConfigured);
  }
#else
  (void)config;
  (void)clock;
  return Failure(UnixHttpFailureReason::UnsupportedPlatform);
#endif
}

}  // namespace rateguard::supervisor
