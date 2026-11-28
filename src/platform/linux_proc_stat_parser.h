#pragma once

#include "platform/linux_process_probe.h"

#include <cstdint>
#include <limits>
#include <string_view>
#include <variant>

namespace rateguard::platform::detail {

inline constexpr std::size_t kLinuxProcStatMaxBytes = 64 * 1'024;

struct ParsedProcStat final {
  std::uint64_t pid{};
  std::uint64_t start_ticks{};
  char state{};
};

enum class ProcStatParseError : std::uint8_t { Malformed, TooLarge };
using ProcStatParseResult = std::variant<ParsedProcStat, ProcStatParseError>;

inline bool ParseU64Token(std::string_view text, std::uint64_t& out) noexcept {
  if (text.empty()) return false;
  out = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') return false;
    const auto digit = static_cast<std::uint64_t>(c - '0');
    if (out > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
      return false;
    out = out * 10 + digit;
  }
  return true;
}

// Linux /proc/<pid>/stat field 2 (comm) can contain spaces and ')'. The last
// ')' separates the command from numeric/state fields; starttime is field 22,
// token 20 counting state (field 3) as token zero.
inline ProcStatParseResult ParseLinuxProcStat(std::string_view input) noexcept {
  if (input.size() > kLinuxProcStatMaxBytes) return ProcStatParseError::TooLarge;
  if (input.empty() || input.find('\0') != std::string_view::npos)
    return ProcStatParseError::Malformed;
  if (input.back() == '\n') input.remove_suffix(1);
  if (input.empty() || input.back() == '\r') return ProcStatParseError::Malformed;

  const auto first_space = input.find(' ');
  if (first_space == std::string_view::npos || first_space == 0 ||
      first_space + 1 >= input.size() || input[first_space + 1] != '(')
    return ProcStatParseError::Malformed;
  std::uint64_t pid = 0;
  if (!ParseU64Token(input.substr(0, first_space), pid) || pid == 0)
    return ProcStatParseError::Malformed;
  const auto close = input.rfind(')');
  if (close == std::string_view::npos || close <= first_space + 1 ||
      close + 2 >= input.size() || input[close + 1] != ' ')
    return ProcStatParseError::Malformed;

  auto fields = input.substr(close + 2);
  std::size_t token_index = 0;
  std::uint64_t start_ticks = 0;
  char state = 0;
  while (!fields.empty()) {
    while (!fields.empty() && (fields.front() == ' ' || fields.front() == '\t'))
      fields.remove_prefix(1);
    if (fields.empty()) break;
    std::size_t end = 0;
    while (end < fields.size() && fields[end] != ' ' && fields[end] != '\t') ++end;
    const auto token = fields.substr(0, end);
    if (token_index == 0) {
      if (token.size() != 1) return ProcStatParseError::Malformed;
      state = token.front();
      constexpr std::string_view valid_states = "RSDZTtXxKWPI";
      if (valid_states.find(state) == std::string_view::npos)
        return ProcStatParseError::Malformed;
    }
    if (token_index > 0 && token_index < 19) {
      std::string_view number = token;
      if (!number.empty() && number.front() == '-') number.remove_prefix(1);
      std::uint64_t ignored = 0;
      if (!ParseU64Token(number, ignored)) return ProcStatParseError::Malformed;
    }
    if (token_index == 19 && !ParseU64Token(token, start_ticks))
      return ProcStatParseError::Malformed;
    ++token_index;
    fields.remove_prefix(end);
  }
  if (token_index < 20 || start_ticks == 0 || state == 0)
    return ProcStatParseError::Malformed;
  return ParsedProcStat{pid, start_ticks, state};
}

}  // namespace rateguard::platform::detail
