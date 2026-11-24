#if defined(__linux__)
#include "supervisor/unix_http_transport.h"

#include <atomic>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

namespace {
int failures = 0;

#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr    \
                << '\n';                                                       \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

using namespace std::chrono_literals;
using rateguard::platform::ClockFailure;
using rateguard::platform::ClockFailureReason;
using rateguard::platform::ClockIdentity;
using rateguard::platform::ClockResult;
using rateguard::platform::IClock;
using rateguard::platform::MonoNanos;
using namespace rateguard::supervisor;

class TestClock final : public IClock {
 public:
  ClockResult<MonoNanos> Now() override {
    timespec ts{};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
        ts.tv_nsec < 0 || ts.tv_nsec >= 1'000'000'000L) {
      return Failure();
    }
    const auto sec = static_cast<std::uint64_t>(ts.tv_sec);
    const auto nsec = static_cast<std::uint64_t>(ts.tv_nsec);
    if (sec > (UINT64_MAX - nsec) / 1'000'000'000ULL) return Failure();
    return MonoNanos{sec * 1'000'000'000ULL + nsec};
  }
  ClockResult<ClockIdentity> Provenance() override { return Failure(); }
  bool Healthy() const override { return true; }

 private:
  static ClockFailure Failure() {
    using namespace rateguard::v1::contract;
    return {{ErrorCategory::Internal, ErrorCode::Internal,
             RetryDisposition::Never, Commitment::NotCommitted},
            ClockFailureReason::ClockSyscall};
  }
};

class ThrowingClock final : public IClock {
 public:
  explicit ThrowingClock(int throw_on_now, int throw_on_healthy)
      : throw_on_now_(throw_on_now), throw_on_healthy_(throw_on_healthy) {}
  ClockResult<MonoNanos> Now() override {
    ++now_calls_;
    if (now_calls_ == throw_on_now_) throw std::runtime_error("clock test fault");
    timespec ts{};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
        ts.tv_nsec < 0 || ts.tv_nsec >= 1'000'000'000L) {
      return TestClockFailure();
    }
    const auto sec = static_cast<std::uint64_t>(ts.tv_sec);
    const auto nsec = static_cast<std::uint64_t>(ts.tv_nsec);
    if (sec > (UINT64_MAX - nsec) / 1'000'000'000ULL) return TestClockFailure();
    return MonoNanos{sec * 1'000'000'000ULL + nsec};
  }
  ClockResult<ClockIdentity> Provenance() override { return TestClockFailure(); }
  bool Healthy() const override {
    ++healthy_calls_;
    if (healthy_calls_ == throw_on_healthy_)
      throw std::runtime_error("health test fault");
    return true;
  }

 private:
  static ClockFailure TestClockFailure() {
    using namespace rateguard::v1::contract;
    return {{ErrorCategory::Internal, ErrorCode::Internal,
             RetryDisposition::Never, Commitment::NotCommitted},
            ClockFailureReason::ClockSyscall};
  }
  int throw_on_now_;
  int throw_on_healthy_;
  int now_calls_{0};
  mutable int healthy_calls_{0};
};

struct TempDir {
  std::string path;
  TempDir() {
    std::string pattern = "/tmp/rateguard-http-independent-XXXXXX";
    std::vector<char> bytes(pattern.begin(), pattern.end());
    bytes.push_back('\0');
    if (char* result = ::mkdtemp(bytes.data()); result != nullptr) path = result;
  }
  ~TempDir() {
    if (!path.empty()) std::filesystem::remove_all(path);
  }
};

class UnixPeer {
 public:
  UnixPeer(const std::string& path, std::string response,
           std::chrono::milliseconds delay = 0ms,
           std::atomic_bool* cancel_after_request = nullptr)
      : path_(path), response_(std::move(response)), delay_(delay),
        cancel_after_request_(cancel_after_request) {
    listener_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener_ < 0) return;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(address.sun_path)) return;
    std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path_.size() + 1);
    if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
        ::listen(listener_, 4) != 0) {
      ::close(listener_);
      listener_ = -1;
      return;
    }
    worker_ = std::thread([this] { Serve(); });
  }
  ~UnixPeer() {
    stop_.store(true, std::memory_order_relaxed);
    if (worker_.joinable()) worker_.join();
    if (listener_ >= 0) {
      (void)::close(listener_);
      listener_ = -1;
    }
    (void)::unlink(path_.c_str());
  }
  UnixPeer(const UnixPeer&) = delete;
  UnixPeer& operator=(const UnixPeer&) = delete;
  [[nodiscard]] bool valid() const { return listener_ >= 0; }
  [[nodiscard]] int accepted() const { return accepted_.load(); }
  [[nodiscard]] std::string request() const {
    std::lock_guard lock(mutex_);
    return request_;
  }
  [[nodiscard]] bool WaitAccepted(std::chrono::milliseconds timeout = 2s) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout, [&] { return accepted_.load() > 0; });
  }

 private:
  void Serve() {
    const auto accept_deadline = std::chrono::steady_clock::now() + 3s;
    int connection = -1;
    while (!stop_.load(std::memory_order_relaxed) &&
           std::chrono::steady_clock::now() < accept_deadline) {
      pollfd descriptor{listener_, POLLIN, 0};
      const int ready = ::poll(&descriptor, 1, 50);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) return;
      if (ready == 0) continue;
      connection = ::accept4(listener_, nullptr, nullptr,
                             SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (connection >= 0) break;
      if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return;
    }
    if (connection < 0) return;
    accepted_.store(1);
    condition_.notify_all();
    std::string request;
    char buffer[512];
    const auto read_deadline = std::chrono::steady_clock::now() + 3s;
    while (request.find("\r\n\r\n") == std::string::npos &&
           request.size() < kUnixHttpMaxRequestBytes + 1 &&
           !stop_.load(std::memory_order_relaxed) &&
           std::chrono::steady_clock::now() < read_deadline) {
      pollfd descriptor{connection, POLLIN, 0};
      const int ready = ::poll(&descriptor, 1, 50);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0 || ready == 0) continue;
      const auto count = ::recv(connection, buffer, sizeof(buffer), 0);
      if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        continue;
      if (count <= 0) break;
      request.append(buffer, static_cast<std::size_t>(count));
    }
    {
      std::lock_guard lock(mutex_);
      request_ = std::move(request);
    }
    condition_.notify_all();
    if (cancel_after_request_ != nullptr)
      cancel_after_request_->store(true, std::memory_order_relaxed);
    if (delay_ > 0ms && delay_ <= 3s) std::this_thread::sleep_for(delay_);
    std::size_t sent = 0;
    while (sent < response_.size()) {
      const auto count = ::send(connection, response_.data() + sent,
                                response_.size() - sent, MSG_NOSIGNAL);
      if (count <= 0) break;
      sent += static_cast<std::size_t>(count);
    }
    (void)::shutdown(connection, SHUT_RDWR);
    (void)::close(connection);
  }

  std::string path_;
  std::string response_;
  std::chrono::milliseconds delay_;
  std::atomic_bool* cancel_after_request_;
  int listener_{-1};
  std::thread worker_;
  std::atomic_int accepted_{0};
  std::atomic_bool stop_{false};
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  std::string request_;
};

class FourCallPeer {
 public:
  explicit FourCallPeer(const std::string& path) : path_(path) {
    listener_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener_ < 0) return;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path_.size() + 1);
    if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
        ::listen(listener_, 8) != 0) {
      (void)::close(listener_);
      listener_ = -1;
      return;
    }
    worker_ = std::thread([this] { Serve(); });
  }
  ~FourCallPeer() {
    {
      std::lock_guard lock(mutex_);
      stop_ = true;
      release_ = true;
    }
    condition_.notify_all();
    if (worker_.joinable()) worker_.join();
    if (listener_ >= 0) (void)::close(listener_);
    (void)::unlink(path_.c_str());
  }
  FourCallPeer(const FourCallPeer&) = delete;
  FourCallPeer& operator=(const FourCallPeer&) = delete;
  [[nodiscard]] bool valid() const { return listener_ >= 0; }
  [[nodiscard]] bool WaitReady(std::chrono::milliseconds timeout = 3s) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout, [&] { return ready_ || finished_; }) && ready_;
  }
  [[nodiscard]] int accepted() const {
    std::lock_guard lock(mutex_);
    return accepted_;
  }
  void Release() {
    {
      std::lock_guard lock(mutex_);
      release_ = true;
    }
    condition_.notify_all();
  }

 private:
  bool ReadRequest(int fd) {
    std::string request;
    char buffer[512];
    const auto until = std::chrono::steady_clock::now() + 2s;
    while (request.find("\r\n\r\n") == std::string::npos &&
           request.size() < kUnixHttpMaxRequestBytes + 1 &&
           std::chrono::steady_clock::now() < until) {
      pollfd descriptor{fd, POLLIN, 0};
      const int ready = ::poll(&descriptor, 1, 50);
      if (ready < 0 && errno == EINTR) continue;
      if (ready <= 0) continue;
      const auto count = ::recv(fd, buffer, sizeof(buffer), 0);
      if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        continue;
      if (count <= 0) break;
      request.append(buffer, static_cast<std::size_t>(count));
    }
    return request.find("\r\n\r\n") != std::string::npos;
  }

  void Serve() {
    const auto accept_until = std::chrono::steady_clock::now() + 3s;
    std::vector<int> connections;
    while (connections.size() < kUnixHttpMaxConcurrentCalls &&
           std::chrono::steady_clock::now() < accept_until) {
      {
        std::lock_guard lock(mutex_);
        if (stop_) break;
      }
      pollfd descriptor{listener_, POLLIN, 0};
      const int ready = ::poll(&descriptor, 1, 50);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) break;
      if (ready == 0) continue;
      const int fd = ::accept4(listener_, nullptr, nullptr,
                               SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (fd < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        break;
      }
      connections.push_back(fd);
      if (!ReadRequest(fd)) break;
      {
        std::lock_guard lock(mutex_);
        accepted_ = static_cast<int>(connections.size());
      }
      condition_.notify_all();
    }
    {
      std::lock_guard lock(mutex_);
      ready_ = connections.size() == kUnixHttpMaxConcurrentCalls;
      finished_ = true;
    }
    condition_.notify_all();
    {
      std::unique_lock lock(mutex_);
      (void)condition_.wait_for(lock, 3s, [&] { return release_ || stop_; });
    }
    constexpr std::string_view response =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    for (const int fd : connections) {
      std::size_t sent = 0;
      while (sent < response.size()) {
        const auto count = ::send(fd, response.data() + sent,
                                  response.size() - sent, MSG_NOSIGNAL);
        if (count <= 0) break;
        sent += static_cast<std::size_t>(count);
      }
      (void)::shutdown(fd, SHUT_RDWR);
      (void)::close(fd);
    }
  }

  std::string path_;
  int listener_{-1};
  std::thread worker_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  int accepted_{0};
  bool ready_{false};
  bool finished_{false};
  bool release_{false};
  bool stop_{false};
};

MonoNanos Now(TestClock& clock) {
  const auto result = clock.Now();
  return std::get<MonoNanos>(result);
}

MonoNanos RealMonotonicNow() {
  timespec ts{};
  if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
      ts.tv_nsec < 0 || ts.tv_nsec >= 1'000'000'000L) {
    return MonoNanos{0};
  }
  return MonoNanos{static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
                   static_cast<std::uint64_t>(ts.tv_nsec)};
}

template <class ClockT>
UnixHttpTransportCreateResult CreateTransport(const std::string& path,
                                               ClockT& clock,
                                               std::uint32_t peer_uid) {
  return CreateUnixHttpTransport(
      UnixHttpTransportConfig{path, peer_uid,
                              static_cast<std::uint32_t>(::getuid())},
      clock);
}

void TestSingleExchangeExactPostAndNoRedirectFollowing() {
  TempDir dir;
  CHECK(!dir.path.empty());
  if (dir.path.empty()) return;
  const auto path = dir.path + "/daemon.sock";
  UnixPeer peer(path, "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n");
  CHECK(peer.valid());
  if (!peer.valid()) return;
  TestClock clock;
  auto created = CreateTransport(path, clock, static_cast<std::uint32_t>(::getuid()));
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancelled{false};
  const auto deadline = Now(clock).value + 2'000'000'000ULL;
  const auto result = transport.RoundTrip(
      UnixHttpMethod::Post,
      "/v1.57/containers/" + std::string(64, 'a') +
          "/stop?signal=SIGTERM&t=1",
      {deadline}, cancelled);
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result))
    CHECK(std::get<UnixHttpResponse>(result).status == 302);
  CHECK(peer.WaitAccepted());
  CHECK(peer.accepted() == 1);
  CHECK(peer.request() ==
        "POST /v1.57/containers/" + std::string(64, 'a') +
            "/stop?signal=SIGTERM&t=1 HTTP/1.1\r\nHost: docker\r\n"
            "Connection: close\r\nContent-Length: 0\r\n\r\n");
}

void TestPreDispatchCancellationAndPeerMismatch() {
  TempDir dir;
  const auto path = dir.path + "/daemon.sock";
  UnixPeer peer(path, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  CHECK(peer.valid());
  if (!peer.valid()) return;
  TestClock clock;
  auto created = CreateTransport(path, clock, static_cast<std::uint32_t>(::getuid()));
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancelled{true};
  auto result = transport.RoundTrip(UnixHttpMethod::Get, "/v1.57/version",
                                    {Now(clock).value + 2'000'000'000ULL}, cancelled);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::Cancelled);
    CHECK(!failure.request_possibly_sent);
  }
  CHECK(peer.accepted() == 0);

  cancelled.store(false, std::memory_order_relaxed);
  const auto wrong_uid = static_cast<std::uint32_t>(::getuid() == 0 ? 1 : 0);
  auto wrong_peer = CreateTransport(path, clock, wrong_uid);
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(wrong_peer));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(wrong_peer)) return;
  auto& wrong_transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(wrong_peer);
  result = wrong_transport.RoundTrip(
      UnixHttpMethod::Get, "/v1.57/version",
      {Now(clock).value + 2'000'000'000ULL}, cancelled);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::PeerCredentialMismatch);
    CHECK(!failure.request_possibly_sent);
  }
  CHECK(peer.WaitAccepted());
  CHECK(peer.accepted() == 1);
}

void TestSocketPathReplacementFailsBeforeConnect() {
  TempDir dir;
  const auto path = dir.path + "/daemon.sock";
  const auto bind_listener = [&path]() {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
        ::listen(fd, 1) != 0) {
      (void)::close(fd);
      return -1;
    }
    return fd;
  };
  const int old_listener = bind_listener();
  CHECK(old_listener >= 0);
  if (old_listener < 0) return;
  TestClock clock;
  auto created = CreateTransport(path, clock, static_cast<std::uint32_t>(::getuid()));
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) {
    (void)::close(old_listener);
    (void)::unlink(path.c_str());
    return;
  }
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);

  // Remove the original listening socket and bind a replacement at the same
  // path. The transport must compare its pinned device/inode before connect.
  CHECK(::unlink(path.c_str()) == 0);
  const int replacement_listener = bind_listener();
  CHECK(replacement_listener >= 0);
  // Keep the old socket inode alive until the replacement is bound so the
  // filesystem cannot immediately recycle its inode number.
  (void)::close(old_listener);
  if (replacement_listener < 0) return;
  std::atomic_bool cancelled{false};
  const auto result = transport.RoundTrip(
      UnixHttpMethod::Get, "/v1.57/version",
      {Now(clock).value + 2'000'000'000ULL}, cancelled);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::NotConfigured);
    CHECK(!failure.request_possibly_sent);
  }
  (void)::close(replacement_listener);
  (void)::unlink(path.c_str());
}

void TestDeadlineAfterRequestIsUncertain() {
  TempDir dir;
  const auto path = dir.path + "/daemon.sock";
  UnixPeer peer(path, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 250ms);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  TestClock clock;
  auto created = CreateTransport(path, clock, static_cast<std::uint32_t>(::getuid()));
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancelled{false};
  const auto result = transport.RoundTrip(
      UnixHttpMethod::Get, "/v1.57/version",
      {Now(clock).value + 50'000'000ULL}, cancelled);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::DeadlineExpired);
    CHECK(failure.request_possibly_sent);
  }
  CHECK(peer.WaitAccepted());
  CHECK(peer.accepted() == 1);
}

void TestCancellationAfterFullRequestIsUncertain() {
  TempDir dir;
  const auto path = dir.path + "/daemon.sock";
  std::atomic_bool cancelled{false};
  UnixPeer peer(path, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 250ms,
                &cancelled);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  TestClock clock;
  auto created = CreateTransport(path, clock, static_cast<std::uint32_t>(::getuid()));
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  const auto result = transport.RoundTrip(
      UnixHttpMethod::Post, "/v1.57/containers/id/stop?signal=SIGTERM&t=1",
      {Now(clock).value + 2'000'000'000ULL}, cancelled);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::Cancelled);
    CHECK(failure.request_possibly_sent);
  }
  CHECK(peer.WaitAccepted());
  CHECK(peer.accepted() == 1);
  CHECK(peer.request().starts_with(
      "POST /v1.57/containers/id/stop?signal=SIGTERM&t=1 HTTP/1.1\r\n"));
}

void TestConcurrentLimitRejectsFifthCallWithoutQueueing() {
  TempDir dir;
  const auto path = dir.path + "/daemon.sock";
  FourCallPeer peer(path);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  TestClock clock;
  auto created = CreateTransport(path, clock, static_cast<std::uint32_t>(::getuid()));
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancelled{false};
  std::array<std::optional<UnixHttpResult>, kUnixHttpMaxConcurrentCalls> results;
  std::vector<std::thread> clients;
  clients.reserve(kUnixHttpMaxConcurrentCalls);
  for (std::size_t index = 0; index < kUnixHttpMaxConcurrentCalls; ++index) {
    clients.emplace_back([&, index] {
      const auto deadline = Now(clock).value + 5'000'000'000ULL;
      results[index] = transport.RoundTrip(UnixHttpMethod::Get,
                                           "/v1.57/version", {deadline}, cancelled);
    });
  }
  const bool four_ready = peer.WaitReady();
  CHECK(four_ready);
  CHECK(peer.accepted() == static_cast<int>(kUnixHttpMaxConcurrentCalls));
  const auto fifth_deadline = Now(clock).value + 2'000'000'000ULL;
  const auto fifth = transport.RoundTrip(UnixHttpMethod::Get, "/v1.57/version",
                                         {fifth_deadline}, cancelled);
  CHECK(std::holds_alternative<UnixHttpFailure>(fifth));
  if (std::holds_alternative<UnixHttpFailure>(fifth)) {
    const auto failure = std::get<UnixHttpFailure>(fifth);
    CHECK(failure.reason == UnixHttpFailureReason::Overloaded);
    CHECK(!failure.request_possibly_sent);
  }
  CHECK(peer.accepted() == static_cast<int>(kUnixHttpMaxConcurrentCalls));
  peer.Release();
  for (auto& client : clients)
    if (client.joinable()) client.join();
  for (const auto& result : results) {
    CHECK(result.has_value());
    if (result.has_value()) {
      CHECK(std::holds_alternative<UnixHttpResponse>(*result));
      if (std::holds_alternative<UnixHttpResponse>(*result))
        CHECK(std::get<UnixHttpResponse>(*result).status == 200);
    }
  }
}

void TestThrowingClockCannotEscapeNoexceptRoundTrip() {
  for (const auto& [throw_on_now, throw_on_healthy] :
       {std::pair{2, 0}, std::pair{0, 4}}) {
    TempDir dir;
    const auto path = dir.path + "/daemon.sock";
    UnixPeer peer(path, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    CHECK(peer.valid());
    if (!peer.valid()) continue;
    ThrowingClock clock(throw_on_now, throw_on_healthy);
    auto created = CreateTransport(path, clock,
                                  static_cast<std::uint32_t>(::getuid()));
    CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
    if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created))
      continue;
    auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
    std::atomic_bool cancelled{false};
    // Keep the deadline comfortably in the future without sampling the
    // deliberately throwing clock.
    const auto result = transport.RoundTrip(UnixHttpMethod::Get, "/version",
                                            {RealMonotonicNow().value +
                                             2'000'000'000ULL}, cancelled);
    CHECK(std::holds_alternative<UnixHttpFailure>(result));
    if (std::holds_alternative<UnixHttpFailure>(result)) {
      const auto failure = std::get<UnixHttpFailure>(result);
      CHECK(failure.reason == UnixHttpFailureReason::ClockFailure);
      CHECK(!failure.request_possibly_sent);
    }
    CHECK(peer.accepted() == 0);
  }
}

}  // namespace

int main() {
  TestSingleExchangeExactPostAndNoRedirectFollowing();
  TestPreDispatchCancellationAndPeerMismatch();
  TestSocketPathReplacementFailsBeforeConnect();
  TestDeadlineAfterRequestIsUncertain();
  TestCancellationAfterFullRequestIsUncertain();
  TestConcurrentLimitRejectsFifthCallWithoutQueueing();
  TestThrowingClockCannotEscapeNoexceptRoundTrip();
  if (failures != 0) {
    std::cerr << failures << " independent Linux transport assertion(s) failed\n";
    return 1;
  }
  std::cout << "Independent Linux Unix HTTP checks passed\n";
  return 0;
}
#else
int main() { return 77; }
#endif
