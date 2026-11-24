#pragma once

#include "platform/clock.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace rateguard::supervisor {

inline constexpr std::size_t kUnixHttpMaxTargetBytes = 2'048;
inline constexpr std::size_t kUnixHttpMaxRequestBytes = 4'096;
inline constexpr std::size_t kUnixHttpMaxHeaderBytes = 8'192;
inline constexpr std::size_t kUnixHttpMaxHeaderFields = 64;
inline constexpr std::size_t kUnixHttpMaxWireResponseBytes = 512 * 1'024;
inline constexpr std::size_t kUnixHttpMaxDecodedBodyBytes = 256 * 1'024;
inline constexpr std::size_t kUnixHttpMaxChunks = 4'096;
inline constexpr std::size_t kUnixHttpMaxChunkLineBytes = 128;
inline constexpr std::size_t kUnixHttpMaxConcurrentCalls = 4;
inline constexpr std::uint64_t kUnixHttpMaxCallDurationNs = 30'000'000'000ULL;
inline constexpr std::uint32_t kDockerRootUid = 0;
inline constexpr std::size_t kUnixHttpNativeSocketPathMaxBytes = 107;

enum class UnixHttpMethod : std::uint8_t { Get, Post };

enum class UnixHttpFailureReason : std::uint8_t {
  InvalidTarget,
  InvalidDeadline,
  NotConfigured,
  UnsupportedPlatform,
  PeerCredentialMismatch,
  Overloaded,
  Cancelled,
  DeadlineExpired,
  ClockFailure,
  SocketFailure,
  ProtocolError,
  ResponseTooLarge,
  AllocationFailure,
};

struct UnixHttpResponse {
  std::uint16_t status{};
  std::vector<std::uint8_t> body;
};

// `request_possibly_sent` is false until the first request byte is written.
// Once any byte is written, every later failure is reported as possibly sent.
struct UnixHttpFailure {
  UnixHttpFailureReason reason{};
  bool request_possibly_sent{};
};

using UnixHttpResult = std::variant<UnixHttpResponse, UnixHttpFailure>;

struct UnixHttpTransportConfig {
  std::string socket_path;
  std::uint32_t expected_peer_uid{kDockerRootUid};
  std::uint32_t expected_socket_owner_uid{kDockerRootUid};
};

// Internal seam for one bounded HTTP exchange over a configured local socket.
// It has no retry, redirect, arbitrary header, or request-body facility.
class IUnixHttpTransport {
 public:
  virtual ~IUnixHttpTransport() = default;

  // Target is an origin-form path and optional query. The caller owns API
  // version selection and must pass either a fixed endpoint (for example,
  // /version) or an explicitly version-qualified endpoint (/vX/...).
  [[nodiscard]] virtual UnixHttpResult RoundTrip(
      UnixHttpMethod method, std::string_view origin_form_target,
      platform::MonoNanos absolute_deadline,
      const std::atomic_bool& cancel_requested) noexcept = 0;
};

using UnixHttpTransportCreateResult =
    std::variant<std::unique_ptr<IUnixHttpTransport>, UnixHttpFailure>;

// Resolves and validates the socket once, then binds calls to its canonical
// path and device/inode/owner identity. Production controller config must keep
// both expected UID values at root (0).
[[nodiscard]] UnixHttpTransportCreateResult CreateUnixHttpTransport(
    const UnixHttpTransportConfig& config, platform::IClock& clock) noexcept;

}  // namespace rateguard::supervisor
