#pragma once

#include "supervisor/unix_http_transport.h"

#include <span>
#include <variant>

namespace rateguard::supervisor::detail {

enum class HttpParseError : std::uint8_t {
  Malformed,
  TooLarge,
  AllocationFailure,
};

using HttpParseResult = std::variant<UnixHttpResponse, HttpParseError>;

// Parses a complete response after EOF on the Connection: close exchange.
[[nodiscard]] HttpParseResult ParseHttpResponse(
    std::span<const std::uint8_t> wire) noexcept;

[[nodiscard]] bool IsValidOriginFormTarget(std::string_view target) noexcept;

}  // namespace rateguard::supervisor::detail
