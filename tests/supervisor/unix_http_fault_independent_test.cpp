#if defined(__linux__)
#include "supervisor/unix_http_transport.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
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
using namespace std::chrono_literals;
using rateguard::platform::ClockIdentity;
using rateguard::platform::ClockResult;
using rateguard::platform::IClock;
using rateguard::platform::MonoNanos;
using namespace rateguard::supervisor;

enum class SendFault { None, EpipeBeforeBytes, OneByteThenEpipe, Fragmented };
enum class PollFaultStage { None, BeforeAnyByte, AfterAnyByte };

class FaultClock final : public IClock {
 public:
  static constexpr std::uint64_t kBase = 1'000'000'000ULL;
  ClockResult<MonoNanos> Now() override {
    return MonoNanos{kBase + elapsed_.load(std::memory_order_relaxed)};
  }
  ClockResult<ClockIdentity> Provenance() override { return ClockIdentity{}; }
  bool Healthy() const override { return true; }
  void Advance(std::uint64_t nanos) {
    elapsed_.fetch_add(nanos, std::memory_order_relaxed);
  }
 private:
  std::atomic_uint64_t elapsed_{0};
};

struct FaultPlan {
  FaultClock* clock{};
  SendFault send_fault{SendFault::None};
  bool connect_eagain{};
  PollFaultStage poll_stage{PollFaultStage::None};
  int poll_interrupts{};
  std::uint64_t advance_per_interrupt_ns{};
  bool sent_any{};
  int send_calls{};
  int connect_calls{};
  int recorded_poll_count{};
  std::array<int, 8> recorded_poll_ms{};
};

thread_local FaultPlan* active_fault = nullptr;

void RecordPoll(FaultPlan* plan, int timeout_ms) noexcept {
  if (plan == nullptr || plan->recorded_poll_count >=
                             static_cast<int>(plan->recorded_poll_ms.size()))
    return;
  plan->recorded_poll_ms[static_cast<std::size_t>(plan->recorded_poll_count++)] =
      timeout_ms;
}

bool ShouldInjectPoll(FaultPlan* plan) noexcept {
  if (plan == nullptr || plan->poll_interrupts <= 0) return false;
  if (plan->poll_stage == PollFaultStage::BeforeAnyByte && plan->sent_any)
    return false;
  if (plan->poll_stage == PollFaultStage::AfterAnyByte && !plan->sent_any)
    return false;
  return plan->poll_stage != PollFaultStage::None;
}

}  // namespace

extern "C" int __real_connect(int, const sockaddr*, socklen_t);
extern "C" ssize_t __real_send(int, const void*, size_t, int);
extern "C" int __real_poll(pollfd*, nfds_t, int);
extern "C" int __real___poll_chk(pollfd*, nfds_t, int, size_t);

namespace {
int InjectedPoll(pollfd* descriptors, nfds_t count, int timeout_ms) {
  auto* plan = active_fault;
  if (plan != nullptr) {
    const bool stage_matches =
        (plan->poll_stage == PollFaultStage::BeforeAnyByte && !plan->sent_any) ||
        (plan->poll_stage == PollFaultStage::AfterAnyByte && plan->sent_any);
    if (stage_matches) RecordPoll(plan, timeout_ms);
    if (ShouldInjectPoll(plan)) {
      --plan->poll_interrupts;
      plan->clock->Advance(plan->advance_per_interrupt_ns);
      errno = EINTR;
      return -1;
    }
  }
  return __real_poll(descriptors, count, timeout_ms);
}
}  // namespace

extern "C" int __wrap_connect(int fd, const sockaddr* address,
                               socklen_t address_length) {
  auto* plan = active_fault;
  if (plan != nullptr) {
    ++plan->connect_calls;
    if (plan->connect_eagain) {
      errno = EAGAIN;
      return -1;
    }
  }
  const int result = __real_connect(fd, address, address_length);
  if (result == 0 || errno != EINPROGRESS) return result;
  // Complete a real local connection using the unwrapped poll so injected
  // poll faults target the HTTP exchange waits, not setup timing.
  pollfd descriptor{fd, POLLOUT, 0};
  const int ready = __real_poll(&descriptor, 1, 1'000);
  if (ready <= 0) {
    if (ready == 0) errno = ETIMEDOUT;
    return -1;
  }
  int socket_error = 0;
  socklen_t error_length = sizeof(socket_error);
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) != 0)
    return -1;
  if (socket_error != 0) {
    errno = socket_error;
    return -1;
  }
  return 0;
}

extern "C" ssize_t __wrap_send(int fd, const void* buffer, size_t length,
                                int flags) {
  auto* plan = active_fault;
  if (plan == nullptr) return __real_send(fd, buffer, length, flags);
  const int call = plan->send_calls++;
  if (plan->send_fault == SendFault::EpipeBeforeBytes) {
    errno = EPIPE;
    return -1;
  }
  if (plan->send_fault == SendFault::OneByteThenEpipe) {
    if (call == 0) {
      const auto count = __real_send(fd, buffer, std::min<std::size_t>(length, 1),
                                     flags);
      if (count > 0) plan->sent_any = true;
      return count;
    }
    errno = EPIPE;
    return -1;
  }
  if (plan->send_fault == SendFault::Fragmented) {
    if (call == 0) {
      errno = EINTR;
      return -1;
    }
    if (call == 1) {
      errno = EAGAIN;
      return -1;
    }
    const auto count = __real_send(fd, buffer,
                                   std::min<std::size_t>(length, 7), flags);
    if (count > 0) plan->sent_any = true;
    return count;
  }
  const auto count = __real_send(fd, buffer, length, flags);
  if (count > 0) plan->sent_any = true;
  return count;
}

extern "C" int __wrap_poll(pollfd* descriptors, nfds_t count, int timeout_ms) {
  return InjectedPoll(descriptors, count, timeout_ms);
}

// Ubuntu's fortified headers may lower poll() to __poll_chk(). Link the test
// executable with --wrap=__poll_chk as well as --wrap=poll so sanitizer builds
// exercise the same deterministic deadline fault path.
extern "C" int __wrap___poll_chk(pollfd* descriptors, nfds_t count,
                                  int timeout_ms, size_t descriptors_bytes) {
  if (descriptors_bytes != static_cast<size_t>(-1) &&
      count > descriptors_bytes / sizeof(*descriptors)) {
    return __real___poll_chk(descriptors, count, timeout_ms, descriptors_bytes);
  }
  return InjectedPoll(descriptors, count, timeout_ms);
}

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

struct TempDir {
  std::string path;
  TempDir() {
    std::string pattern = "/tmp/rateguard-http-fault-XXXXXX";
    std::vector<char> bytes(pattern.begin(), pattern.end());
    bytes.push_back('\0');
    if (char* result = ::mkdtemp(bytes.data()); result != nullptr) path = result;
  }
  ~TempDir() {
    if (!path.empty()) std::filesystem::remove_all(path);
  }
};

class BoundedPeer {
 public:
  enum class Behavior { Reply, Hold };
  BoundedPeer(std::string path, Behavior behavior,
              std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
      : path_(std::move(path)), behavior_(behavior), response_(std::move(response)) {
    listener_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listener_ < 0) return;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(address.sun_path)) return;
    std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path_.size() + 1);
    if (::bind(listener_, reinterpret_cast<sockaddr*>(&address), length) != 0 ||
        ::listen(listener_, 4) != 0) {
      (void)::close(listener_);
      listener_ = -1;
      return;
    }
    worker_ = std::thread([this] { Serve(); });
  }
  ~BoundedPeer() {
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
  BoundedPeer(const BoundedPeer&) = delete;
  BoundedPeer& operator=(const BoundedPeer&) = delete;
  [[nodiscard]] bool valid() const { return listener_ >= 0; }
  [[nodiscard]] int accepted() const { return accepted_.load(); }
  [[nodiscard]] bool WaitAccepted(std::chrono::milliseconds timeout = 2s) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout,
                               [&] { return accepted_.load() > 0 || finished_; }) &&
           accepted_.load() > 0;
  }
  [[nodiscard]] std::string received() const {
    std::lock_guard lock(mutex_);
    return received_;
  }
  [[nodiscard]] bool WaitReceivedSize(std::size_t size,
                                     std::chrono::milliseconds timeout = 2s) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout,
                               [&] { return received_.size() >= size || finished_; }) &&
           received_.size() >= size;
  }
  [[nodiscard]] bool WaitFinished(std::chrono::milliseconds timeout = 5s) {
    std::unique_lock lock(mutex_);
    return condition_.wait_for(lock, timeout, [&] { return finished_; });
  }
  void Release() {
    {
      std::lock_guard lock(mutex_);
      release_ = true;
    }
    condition_.notify_all();
  }

 private:
  void Serve() {
    const auto accept_until = std::chrono::steady_clock::now() + 4s;
    int connection = -1;
    while (std::chrono::steady_clock::now() < accept_until) {
      {
        std::lock_guard lock(mutex_);
        if (stop_) break;
      }
      pollfd descriptor{listener_, POLLIN, 0};
      const int ready = __real_poll(&descriptor, 1, 50);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) break;
      if (ready == 0) continue;
      connection = ::accept4(listener_, nullptr, nullptr,
                             SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (connection >= 0) break;
      if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) break;
    }
    if (connection < 0) {
      std::lock_guard lock(mutex_);
      finished_ = true;
      condition_.notify_all();
      return;
    }
    accepted_.store(1);
    condition_.notify_all();

    std::string request;
    char buffer[256];
    const auto read_until = std::chrono::steady_clock::now() + 2s;
    while (request.find("\r\n\r\n") == std::string::npos &&
           request.size() <= kUnixHttpMaxRequestBytes &&
           std::chrono::steady_clock::now() < read_until) {
      pollfd descriptor{connection, POLLIN, 0};
      const int ready = __real_poll(&descriptor, 1, 50);
      if (ready < 0 && errno == EINTR) continue;
      if (ready <= 0) continue;
      const auto amount = ::recv(connection, buffer, sizeof(buffer), 0);
      if (amount < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        continue;
      if (amount <= 0) break;
      request.append(buffer, static_cast<std::size_t>(amount));
      {
        std::lock_guard lock(mutex_);
        received_ = request;
      }
      condition_.notify_all();
    }
    {
      std::lock_guard lock(mutex_);
      received_ = request;
      condition_.notify_all();
    }
    if (behavior_ == Behavior::Hold) {
      std::unique_lock lock(mutex_);
      (void)condition_.wait_for(lock, 3s, [&] { return release_ || stop_; });
    } else {
      std::size_t sent = 0;
      while (sent < response_.size()) {
        const auto amount = __real_send(connection, response_.data() + sent,
                                        response_.size() - sent, MSG_NOSIGNAL);
        if (amount <= 0) break;
        sent += static_cast<std::size_t>(amount);
      }
    }
    (void)::shutdown(connection, SHUT_RDWR);
    (void)::close(connection);
    {
      std::lock_guard lock(mutex_);
      finished_ = true;
    }
    condition_.notify_all();
  }

  std::string path_;
  Behavior behavior_;
  std::string response_;
  int listener_{-1};
  std::thread worker_;
  std::atomic_int accepted_{0};
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  bool stop_{false};
  bool release_{false};
  bool finished_{false};
  std::string received_;
};

struct Fixture {
  TempDir directory;
  FaultClock clock;
  std::string socket_path;
  UnixHttpTransportCreateResult created =
      UnixHttpFailure{UnixHttpFailureReason::NotConfigured, false};
  std::unique_ptr<IUnixHttpTransport> transport;
  Fixture() {
    socket_path = directory.path + "/daemon.sock";
  }
  bool Create() {
    auto result = CreateUnixHttpTransport(
        UnixHttpTransportConfig{socket_path,
                                static_cast<std::uint32_t>(::getuid()),
                                static_cast<std::uint32_t>(::getuid())},
        clock);
    if (!std::holds_alternative<std::unique_ptr<IUnixHttpTransport>>(result))
      return false;
    transport = std::move(std::get<std::unique_ptr<IUnixHttpTransport>>(result));
    return true;
  }
};

void TestEpipeBeforeAndAfterFirstBytePreservesUncertainty() {
  for (const auto& [fault, expected_sent, expected_bytes] : {
           std::tuple{SendFault::EpipeBeforeBytes, false, std::size_t{0}},
           std::tuple{SendFault::OneByteThenEpipe, true, std::size_t{1}}}) {
    Fixture fixture;
    BoundedPeer peer(fixture.socket_path, BoundedPeer::Behavior::Hold);
    CHECK(peer.valid());
    if (!peer.valid() || !fixture.Create()) continue;
    FaultPlan plan;
    plan.send_fault = fault;
    active_fault = &plan;
    std::atomic_bool cancelled{false};
    const auto result = fixture.transport->RoundTrip(
        UnixHttpMethod::Get, "/v1.57/version",
        {FaultClock::kBase + 2'000'000'000ULL}, cancelled);
    active_fault = nullptr;
    CHECK(std::holds_alternative<UnixHttpFailure>(result));
    if (std::holds_alternative<UnixHttpFailure>(result)) {
      const auto failure = std::get<UnixHttpFailure>(result);
      CHECK(failure.reason == UnixHttpFailureReason::SocketFailure);
      CHECK(failure.request_possibly_sent == expected_sent);
    }
    CHECK(peer.WaitAccepted());
    peer.Release();
    CHECK(peer.WaitFinished());
    const auto request = peer.received();
    CHECK(request.size() == expected_bytes);
    if (expected_bytes == 1) CHECK(request == "G");
    CHECK(plan.connect_calls == 1);
    active_fault = nullptr;
  }
}

void TestConnectEagainFailsWithoutRetryOrDispatch() {
  Fixture fixture;
  BoundedPeer peer(fixture.socket_path, BoundedPeer::Behavior::Hold);
  CHECK(peer.valid());
  if (!peer.valid() || !fixture.Create()) return;
  FaultPlan plan;
  plan.connect_eagain = true;
  active_fault = &plan;
  std::atomic_bool cancelled{false};
  const auto result = fixture.transport->RoundTrip(
      UnixHttpMethod::Get, "/v1.57/version",
      {FaultClock::kBase + 2'000'000'000ULL}, cancelled);
  active_fault = nullptr;
  CHECK(std::holds_alternative<UnixHttpFailure>(result));
  if (std::holds_alternative<UnixHttpFailure>(result)) {
    const auto failure = std::get<UnixHttpFailure>(result);
    CHECK(failure.reason == UnixHttpFailureReason::SocketFailure);
    CHECK(!failure.request_possibly_sent);
  }
  CHECK(plan.connect_calls == 1);
  CHECK(peer.accepted() == 0);
}

void TestFragmentedSendAndFiniteEintrEagainStillSendExactRequest() {
  Fixture fixture;
  BoundedPeer peer(fixture.socket_path, BoundedPeer::Behavior::Reply);
  CHECK(peer.valid());
  if (!peer.valid() || !fixture.Create()) return;
  FaultPlan plan;
  plan.send_fault = SendFault::Fragmented;
  active_fault = &plan;
  std::atomic_bool cancelled{false};
  const auto result = fixture.transport->RoundTrip(
      UnixHttpMethod::Post, "/v1.57/containers/" + std::string(64, 'a') +
                                "/stop?signal=SIGTERM&t=1",
      {FaultClock::kBase + 3'000'000'000ULL}, cancelled);
  active_fault = nullptr;
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result))
    CHECK(std::get<UnixHttpResponse>(result).status == 200);
  CHECK(peer.WaitAccepted());
  const auto expected =
      "POST /v1.57/containers/" + std::string(64, 'a') +
      "/stop?signal=SIGTERM&t=1 HTTP/1.1\r\nHost: docker\r\n"
      "Connection: close\r\nContent-Length: 0\r\n\r\n";
  CHECK(peer.received() == expected);
  CHECK(plan.send_calls > 3);
  CHECK(plan.connect_calls == 1);
}

void TestPollEintrConsumesOriginalDeadlineBeforeAndAfterSend() {
  for (const auto& stage : {PollFaultStage::BeforeAnyByte,
                            PollFaultStage::AfterAnyByte}) {
    Fixture fixture;
    BoundedPeer peer(fixture.socket_path, BoundedPeer::Behavior::Hold);
    CHECK(peer.valid());
    if (!peer.valid() || !fixture.Create()) continue;
    FaultPlan plan;
    plan.clock = &fixture.clock;
    plan.poll_stage = stage;
    plan.poll_interrupts = 3;
    plan.advance_per_interrupt_ns = 30'000'000ULL;
    active_fault = &plan;
    std::atomic_bool cancelled{false};
    const auto result = fixture.transport->RoundTrip(
        UnixHttpMethod::Get, "/v1.57/version",
        {FaultClock::kBase + 80'000'000ULL}, cancelled);
    active_fault = nullptr;
    CHECK(std::holds_alternative<UnixHttpFailure>(result));
    if (std::holds_alternative<UnixHttpFailure>(result)) {
      const auto failure = std::get<UnixHttpFailure>(result);
      CHECK(failure.reason == UnixHttpFailureReason::DeadlineExpired);
      CHECK(failure.request_possibly_sent ==
            (stage == PollFaultStage::AfterAnyByte));
    }
    CHECK(plan.recorded_poll_count >= 3);
    if (plan.recorded_poll_count >= 3) {
      CHECK(plan.recorded_poll_ms[0] == 80);
      CHECK(plan.recorded_poll_ms[1] == 50);
      CHECK(plan.recorded_poll_ms[2] == 20);
    }
    if (stage == PollFaultStage::AfterAnyByte) {
      CHECK(peer.WaitAccepted());
      CHECK(peer.WaitReceivedSize(16));
      peer.Release();
      CHECK(peer.WaitFinished());
      CHECK(peer.received().starts_with("GET /v1.57/version HTTP/1.1\r\n"));
    } else {
      CHECK(peer.accepted() <= 1);
      peer.Release();
      CHECK(peer.WaitFinished());
      CHECK(peer.received().empty());
    }
  }
}

}  // namespace

int main() {
  TestEpipeBeforeAndAfterFirstBytePreservesUncertainty();
  TestConnectEagainFailsWithoutRetryOrDispatch();
  TestFragmentedSendAndFiniteEintrEagainStillSendExactRequest();
  TestPollEintrConsumesOriginalDeadlineBeforeAndAfterSend();
  if (failures != 0) {
    std::cerr << failures << " deterministic HTTP fault assertion(s) failed\n";
    return 1;
  }
  std::cout << "Deterministic Unix HTTP fault checks passed\n";
  return 0;
}
#else
int main() { return 77; }
#endif
