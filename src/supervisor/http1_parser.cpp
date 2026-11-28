#include "supervisor/http1_parser.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <new>
#include <string_view>

namespace rateguard::supervisor::detail {
namespace {

constexpr std::string_view kHeaderEnd = "\r\n\r\n";
constexpr std::string_view kCrlf = "\r\n";

enum class BodyFraming { ContentLength, Chunked, CloseDelimited };

bool IsTokenChar(unsigned char c) noexcept {
  if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
      (c >= 'a' && c <= 'z')) {
    return true;
  }
  constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
  return punctuation.find(static_cast<char>(c)) != std::string_view::npos;
}

char LowerAscii(char c) noexcept {
  if (c >= 'A' && c <= 'Z') return static_cast<char>(c + ('a' - 'A'));
  return c;
}

bool EqualAsciiInsensitive(std::string_view lhs,
                           std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) return false;
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    if (LowerAscii(lhs[i]) != LowerAscii(rhs[i])) return false;
  }
  return true;
}

std::string_view TrimOws(std::string_view value) noexcept {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
    value.remove_prefix(1);
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
    value.remove_suffix(1);
  return value;
}

bool ParseUnsignedDecimal(std::string_view text,
                          std::uint64_t& value) noexcept {
  if (text.empty()) return false;
  value = 0;
  for (char c : text) {
    if (c < '0' || c > '9') return false;
    const auto digit = static_cast<std::uint64_t>(c - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
      return false;
    value = value * 10 + digit;
  }
  return true;
}

bool ParseHex(std::string_view text, std::uint64_t& value) noexcept {
  if (text.empty()) return false;
  value = 0;
  for (char c : text) {
    std::uint64_t digit;
    if (c >= '0' && c <= '9') digit = static_cast<std::uint64_t>(c - '0');
    else if (c >= 'a' && c <= 'f') digit = static_cast<std::uint64_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') digit = static_cast<std::uint64_t>(c - 'A' + 10);
    else return false;
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 16)
      return false;
    value = value * 16 + digit;
  }
  return true;
}

HttpParseResult Malformed() noexcept { return HttpParseError::Malformed; }
HttpParseResult TooLarge() noexcept { return HttpParseError::TooLarge; }

}  // namespace

bool IsValidOriginFormTarget(std::string_view target) noexcept {
  if (target.empty() || target.size() > kUnixHttpMaxTargetBytes ||
      target.front() != '/' || (target.size() > 1 && target[1] == '/')) {
    return false;
  }
  for (unsigned char c : target) {
    if (c < 0x21 || c > 0x7e || c == '#' || c == '\\') return false;
  }
  return true;
}

HttpParseResult ParseHttpResponse(
    std::span<const std::uint8_t> wire) noexcept {
  try {
    if (wire.size() > kUnixHttpMaxWireResponseBytes) return TooLarge();
    if (wire.empty()) return Malformed();
    const std::string_view bytes(reinterpret_cast<const char*>(wire.data()),
                                 wire.size());
    const auto header_end = bytes.find(kHeaderEnd);
    if (header_end == std::string_view::npos)
      return bytes.size() >= kUnixHttpMaxHeaderBytes ? TooLarge() : Malformed();
    const std::size_t header_bytes = header_end + kHeaderEnd.size();
    if (header_bytes > kUnixHttpMaxHeaderBytes) return TooLarge();

    const auto first_line_end = bytes.find(kCrlf);
    if (first_line_end == std::string_view::npos || first_line_end > header_end)
      return Malformed();
    const std::string_view status_line = bytes.substr(0, first_line_end);
    if (!(status_line.starts_with("HTTP/1.0 ") ||
          status_line.starts_with("HTTP/1.1 ")) || status_line.size() < 13) {
      return Malformed();
    }
    const std::size_t code_pos = 9;
    if (status_line[code_pos] < '0' || status_line[code_pos] > '9' ||
        status_line[code_pos + 1] < '0' || status_line[code_pos + 1] > '9' ||
        status_line[code_pos + 2] < '0' || status_line[code_pos + 2] > '9' ||
        status_line[code_pos + 3] != ' ') {
      return Malformed();
    }
    for (std::size_t i = code_pos + 4; i < status_line.size(); ++i) {
      const auto c = static_cast<unsigned char>(status_line[i]);
      if ((c < 0x20 && c != '\t') || c == 0x7f) return Malformed();
    }
    const auto status = static_cast<std::uint16_t>(
        (status_line[code_pos] - '0') * 100 +
        (status_line[code_pos + 1] - '0') * 10 +
        (status_line[code_pos + 2] - '0'));
    if (status < 100 || status > 599 || (status >= 100 && status < 200))
      return Malformed();

    bool has_content_length = false;
    std::uint64_t content_length = 0;
    bool has_transfer_encoding = false;
    bool has_content_encoding = false;
    std::size_t field_count = 0;
    std::size_t cursor = first_line_end + kCrlf.size();
    while (cursor < header_end) {
      const auto line_end = bytes.find(kCrlf, cursor);
      if (line_end == std::string_view::npos || line_end > header_end)
        return Malformed();
      const auto line = bytes.substr(cursor, line_end - cursor);
      if (line.empty() || line.front() == ' ' || line.front() == '\t')
        return Malformed();
      const auto colon = line.find(':');
      if (colon == std::string_view::npos || colon == 0) return Malformed();
      for (unsigned char c : line.substr(0, colon))
        if (!IsTokenChar(c)) return Malformed();
      const auto value = TrimOws(line.substr(colon + 1));
      for (unsigned char c : value)
        if ((c < 0x20 && c != '\t') || c == 0x7f) return Malformed();
      if (++field_count > kUnixHttpMaxHeaderFields) return TooLarge();

      const auto name = line.substr(0, colon);
      if (EqualAsciiInsensitive(name, "content-length")) {
        if (has_content_length || !ParseUnsignedDecimal(value, content_length))
          return Malformed();
        has_content_length = true;
      } else if (EqualAsciiInsensitive(name, "transfer-encoding")) {
        if (has_transfer_encoding || !EqualAsciiInsensitive(value, "chunked"))
          return Malformed();
        has_transfer_encoding = true;
      } else if (EqualAsciiInsensitive(name, "content-encoding")) {
        if (has_content_encoding || !EqualAsciiInsensitive(value, "identity"))
          return Malformed();
        has_content_encoding = true;
      }
      cursor = line_end + kCrlf.size();
    }
    if (has_content_length && has_transfer_encoding) return Malformed();

    const bool bodyless_status = status == 204 || status == 304;
    if (bodyless_status) {
      if (has_transfer_encoding || (has_content_length && content_length != 0) ||
          bytes.size() != header_bytes) {
        return Malformed();
      }
      return UnixHttpResponse{status, {}};
    }

    BodyFraming framing = BodyFraming::CloseDelimited;
    if (has_transfer_encoding) framing = BodyFraming::Chunked;
    else if (has_content_length) framing = BodyFraming::ContentLength;

    UnixHttpResponse response;
    response.status = status;
    if (framing == BodyFraming::ContentLength) {
      if (content_length > kUnixHttpMaxDecodedBodyBytes) return TooLarge();
      if (content_length != bytes.size() - header_bytes) return Malformed();
      response.body.assign(wire.begin() + static_cast<std::ptrdiff_t>(header_bytes),
                           wire.end());
      return response;
    }
    if (framing == BodyFraming::CloseDelimited) {
      const std::size_t body_size = bytes.size() - header_bytes;
      if (body_size > kUnixHttpMaxDecodedBodyBytes) return TooLarge();
      response.body.assign(wire.begin() + static_cast<std::ptrdiff_t>(header_bytes),
                           wire.end());
      return response;
    }

    cursor = header_bytes;
    std::size_t chunks = 0;
    for (;;) {
      const auto line_end = bytes.find(kCrlf, cursor);
      if (line_end == std::string_view::npos)
        return bytes.size() - cursor > kUnixHttpMaxChunkLineBytes
                   ? TooLarge() : Malformed();
      const auto line_size = line_end - cursor;
      if (line_size > kUnixHttpMaxChunkLineBytes) return TooLarge();
      const auto line = bytes.substr(cursor, line_size);
      if (line.find(';') != std::string_view::npos) return Malformed();
      std::uint64_t chunk_size = 0;
      if (!ParseHex(line, chunk_size)) return Malformed();
      cursor = line_end + kCrlf.size();
      if (chunk_size == 0) {
        if (cursor + kCrlf.size() > bytes.size() ||
            bytes.substr(cursor, kCrlf.size()) != kCrlf) {
          return Malformed();  // Empty trailers only.
        }
        cursor += kCrlf.size();
        if (cursor != bytes.size()) return Malformed();
        return response;
      }
      if (++chunks > kUnixHttpMaxChunks ||
          chunk_size > kUnixHttpMaxDecodedBodyBytes - response.body.size())
        return TooLarge();
      if (chunk_size > bytes.size() - cursor ||
          bytes.size() - cursor - static_cast<std::size_t>(chunk_size) < kCrlf.size())
        return Malformed();
      const auto chunk_end = cursor + static_cast<std::size_t>(chunk_size);
      response.body.insert(response.body.end(), wire.begin() + static_cast<std::ptrdiff_t>(cursor),
                           wire.begin() + static_cast<std::ptrdiff_t>(chunk_end));
      if (bytes.substr(chunk_end, kCrlf.size()) != kCrlf) return Malformed();
      cursor = chunk_end + kCrlf.size();
    }
  } catch (const std::bad_alloc&) {
    return HttpParseError::AllocationFailure;
  } catch (...) {
    return HttpParseError::Malformed;
  }
}

}  // namespace rateguard::supervisor::detail
