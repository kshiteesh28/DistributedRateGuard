#if defined(__linux__)
#include "supervisor/unix_http_transport.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
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
#define CHECK(expr) do { if (!(expr)) { std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr "\n"; ++failures; } } while (false)

class LinuxTestClock final : public rateguard::platform::IClock {
 public:
  rateguard::platform::ClockResult<rateguard::platform::MonoNanos> Now() override {
    timespec ts{};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
      return Error(rateguard::platform::ClockFailureReason::ClockSyscall);
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1'000'000'000L)
      return Error(rateguard::platform::ClockFailureReason::InvalidTimespec);
    return rateguard::platform::MonoNanos{
        static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
        static_cast<std::uint64_t>(ts.tv_nsec)};
  }
  rateguard::platform::ClockResult<rateguard::platform::ClockIdentity> Provenance() override {
    return Error(rateguard::platform::ClockFailureReason::LatchedFailure);
  }
  bool Healthy() const override { return true; }
 private:
  static rateguard::platform::ClockFailure Error(
      rateguard::platform::ClockFailureReason reason) {
    using namespace rateguard::v1::contract;
    return {{ErrorCategory::Internal, ErrorCode::Internal, RetryDisposition::Never,
             Commitment::NotCommitted}, reason};
  }
};

class ThrowingTestClock final : public rateguard::platform::IClock {
 public:
  rateguard::platform::ClockResult<rateguard::platform::MonoNanos> Now() override {
    throw std::runtime_error("injected clock exception");
  }
  rateguard::platform::ClockResult<rateguard::platform::ClockIdentity> Provenance() override {
    throw std::runtime_error("injected clock exception");
  }
  bool Healthy() const override { throw std::runtime_error("injected clock exception"); }
};

struct TempDir {
  std::string path;
  TempDir() {
    std::string pattern = "/tmp/rateguard-unix-http-XXXXXX";
    std::vector<char> data(pattern.begin(), pattern.end());
    data.push_back('\0');
    char* created = ::mkdtemp(data.data());
    if (created != nullptr) path = created;
  }
  ~TempDir() { if (!path.empty()) std::filesystem::remove_all(path); }
};

class LocalPeer {
 public:
  enum class Mode { Reply, Delay, CancelAfterRequest, Hold };
  LocalPeer(const std::string& path, Mode mode,
            std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            std::atomic_bool* cancel = nullptr)
      : path_(path), mode_(mode), reply_(std::move(reply)), cancel_(cancel) {
    listener_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener_ < 0) return;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path_.c_str(), path_.size() + 1);
    const auto len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path_.size() + 1);
    if (::bind(listener_, reinterpret_cast<sockaddr*>(&addr), len) != 0 ||
        ::listen(listener_, 8) != 0) {
      ::close(listener_);
      listener_ = -1;
      return;
    }
    running_ = std::thread([this] { Serve(); });
  }
  ~LocalPeer() {
    stop_.store(true, std::memory_order_relaxed);
    Release();
    if (running_.joinable()) running_.join();
    if (listener_ >= 0) ::close(listener_);
  }
  bool valid() const { return listener_ >= 0; }
  int accepted() const { return accepted_.load(); }
  std::string request() const {
    std::lock_guard lock(mutex_);
    return request_;
  }
  void Release() {
    {
      std::lock_guard lock(mutex_);
      released_ = true;
    }
    cv_.notify_all();
  }
  bool WaitAccepted(int count, std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
    std::unique_lock lock(mutex_);
    return cv_.wait_for(lock, timeout, [&] { return accepted_.load() >= count; });
  }
 private:
  void Serve() {
    for (;;) {
      pollfd listener_poll{listener_, POLLIN, 0};
      const int ready = ::poll(&listener_poll, 1, 100);
      if (stop_.load(std::memory_order_relaxed)) break;
      if (ready == 0 || (ready < 0 && errno == EINTR)) continue;
      if (ready < 0) break;
      const int fd = ::accept4(listener_, nullptr, nullptr, SOCK_CLOEXEC);
      if (fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
        break;
      }
      ++accepted_;
      {
        std::lock_guard lock(mutex_);
        cv_.notify_all();
      }
      std::string request;
      char buffer[1024];
      while (request.find("\r\n\r\n") == std::string::npos && request.size() < 8192) {
        const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        request.append(buffer, static_cast<std::size_t>(n));
      }
      {
        std::lock_guard lock(mutex_);
        request_ = request;
        cv_.notify_all();
      }
      if (mode_ == Mode::CancelAfterRequest && cancel_ != nullptr)
        cancel_->store(true, std::memory_order_relaxed);
      if (mode_ == Mode::Delay) std::this_thread::sleep_for(std::chrono::milliseconds(300));
      if (mode_ == Mode::Hold) {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [&] { return released_; });
      }
      if (mode_ == Mode::Reply) {
        (void)::send(fd, reply_.data(), reply_.size(), MSG_NOSIGNAL);
      }
      (void)::shutdown(fd, SHUT_RDWR);
      ::close(fd);
      if (mode_ != Mode::Hold) break;
    }
  }

  std::string path_;
  Mode mode_;
  std::string reply_;
  std::atomic_bool* cancel_;
  int listener_{-1};
  std::thread running_;
  std::atomic_bool stop_{false};
  std::atomic_int accepted_{0};
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::string request_;
  bool released_{false};
};

rateguard::platform::MonoNanos Now(LinuxTestClock& clock) {
  return std::get<rateguard::platform::MonoNanos>(clock.Now());
}

rateguard::supervisor::UnixHttpTransportCreateResult MakeTransport(
    const std::string& path, LinuxTestClock& clock, uid_t uid = ::getuid()) {
  rateguard::supervisor::UnixHttpTransportConfig config;
  config.socket_path = path;
  config.expected_peer_uid = static_cast<std::uint32_t>(uid);
  config.expected_socket_owner_uid = static_cast<std::uint32_t>(::getuid());
  return rateguard::supervisor::CreateUnixHttpTransport(config, clock);
}

void TestSuccessfulRoundTripNoRetryAndExactRequest() {
  using namespace rateguard::supervisor;
  TempDir dir;
  CHECK(!dir.path.empty());
  if (dir.path.empty()) return;
  const auto path = dir.path + "/docker.sock";
  LocalPeer peer(path, LocalPeer::Mode::Reply);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  LinuxTestClock clock;
  auto created = MakeTransport(path, clock);
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancel{false};
  const auto deadline = Now(clock);
  const auto result = transport.RoundTrip(UnixHttpMethod::Get, "/v1.45/version",
                                          {deadline.value + 2'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result)) {
    const auto& response = std::get<UnixHttpResponse>(result);
    CHECK(response.status == 200);
    CHECK(std::string(response.body.begin(), response.body.end()) == "ok");
  }
  CHECK(peer.accepted() == 1);
  CHECK(peer.request() == "GET /v1.45/version HTTP/1.1\r\nHost: docker\r\n"
                          "Connection: close\r\nContent-Length: 0\r\n\r\n");
}

void TestFailureBeforeAndAfterDispatch() {
  using namespace rateguard::supervisor;
  TempDir dir;
  const auto path = dir.path + "/docker.sock";
  LocalPeer peer(path, LocalPeer::Mode::Delay);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  LinuxTestClock clock;
  auto created = MakeTransport(path, clock);
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancel{false};

  auto result = transport.RoundTrip(UnixHttpMethod::Get, "/version", {1}, cancel);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto& failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::InvalidDeadline);
    CHECK(!failure.request_possibly_sent);
  }
  CHECK(peer.accepted() == 0);

  const auto now = Now(clock);
  result = transport.RoundTrip(UnixHttpMethod::Post, "/v1.45/containers/x/stop?t=1&signal=SIGTERM",
                               {now.value + 100'000'000ULL}, cancel);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto& failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::DeadlineExpired);
    CHECK(failure.request_possibly_sent);
  }
  CHECK(peer.accepted() == 1);
}

void TestCancellationAfterDispatch() {
  using namespace rateguard::supervisor;
  TempDir dir;
  const auto path = dir.path + "/docker.sock";
  std::atomic_bool cancel{false};
  LocalPeer peer(path, LocalPeer::Mode::CancelAfterRequest, {}, &cancel);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  LinuxTestClock clock;
  auto created = MakeTransport(path, clock);
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  const auto now = Now(clock);
  const auto result = transport.RoundTrip(UnixHttpMethod::Get, "/version",
                                          {now.value + 2'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto& failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::Cancelled);
    CHECK(failure.request_possibly_sent);
  }
}

void TestThrowingClockMapsToFailureWithoutDispatch() {
  using namespace rateguard::supervisor;
  TempDir dir;
  const auto path = dir.path + "/docker.sock";
  LocalPeer peer(path, LocalPeer::Mode::Reply);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  ThrowingTestClock clock;
  UnixHttpTransportConfig config;
  config.socket_path = path;
  config.expected_peer_uid = static_cast<std::uint32_t>(::getuid());
  config.expected_socket_owner_uid = static_cast<std::uint32_t>(::getuid());
  auto created = CreateUnixHttpTransport(config, clock);
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancel{false};
  const auto result = transport.RoundTrip(UnixHttpMethod::Get, "/version", {100}, cancel);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto& failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::ClockFailure);
    CHECK(!failure.request_possibly_sent);
  }
  CHECK(peer.accepted() == 0);
}

void TestPeerUidMismatchBeforeDispatch() {
  using namespace rateguard::supervisor;
  TempDir dir;
  const auto path = dir.path + "/docker.sock";
  LocalPeer peer(path, LocalPeer::Mode::Reply);
  CHECK(peer.valid());
  if (!peer.valid()) return;
  LinuxTestClock clock;
  const auto wrong_uid = static_cast<uid_t>(::getuid() == 0 ? 1 : 0);
  auto created = MakeTransport(path, clock, wrong_uid);
  CHECK(std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created));
  if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(created)) return;
  auto& transport = *std::get<std::unique_ptr<IUnixHttpTransport>>(created);
  std::atomic_bool cancel{false};
  const auto now = Now(clock);
  const auto result = transport.RoundTrip(UnixHttpMethod::Get, "/version",
                                          {now.value + 2'000'000'000ULL}, cancel);
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto& failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::PeerCredentialMismatch);
    CHECK(!failure.request_possibly_sent);
  }
}

}  // namespace

int main() {
  TestSuccessfulRoundTripNoRetryAndExactRequest();
  TestFailureBeforeAndAfterDispatch();
  TestCancellationAfterDispatch();
  TestThrowingClockMapsToFailureWithoutDispatch();
  TestPeerUidMismatchBeforeDispatch();
  if (failures != 0) {
    std::cerr << failures << " Linux transport assertion(s) failed\n";
    return 1;
  }
  std::cout << "Linux Unix HTTP transport tests passed\n";
  return 0;
}
#else
int main() { return 77; }
#endif
