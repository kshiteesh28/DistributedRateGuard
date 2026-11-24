#include "supervisor/http1_parser.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

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

using rateguard::supervisor::UnixHttpResponse;
using rateguard::supervisor::detail::HttpParseError;
using rateguard::supervisor::detail::HttpParseResult;
using rateguard::supervisor::detail::IsValidOriginFormTarget;
using rateguard::supervisor::detail::ParseHttpResponse;

std::vector<std::uint8_t> Bytes(std::string_view value) {
  return {value.begin(), value.end()};
}

bool ParsesAs(std::string_view wire, std::uint16_t status,
              std::string_view body) {
  const auto input = Bytes(wire);
  const auto result = ParseHttpResponse(input);
  if (!std::holds_alternative<UnixHttpResponse>(result)) return false;
  const auto& response = std::get<UnixHttpResponse>(result);
  return response.status == status &&
         std::string(response.body.begin(), response.body.end()) == body;
}

bool FailsAs(std::string_view wire, HttpParseError expected) {
  const auto input = Bytes(wire);
  const auto result = ParseHttpResponse(input);
  return std::holds_alternative<HttpParseError>(result) &&
         std::get<HttpParseError>(result) == expected;
}

void TestFramingAndStatusOwnership() {
  CHECK(ParsesAs("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 200,
                 "abc"));
  CHECK(ParsesAs("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", 200, ""));
  CHECK(ParsesAs("HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n"
                 "Content-Length: 2\r\n\r\nxy", 200, "xy"));
  CHECK(ParsesAs("HTTP/1.1 200 OK\r\n\r\nclose body", 200, "close body"));
  CHECK(ParsesAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "2\r\nok\r\n0\r\n\r\n", 200, "ok"));
  CHECK(ParsesAs("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", 204,
                 ""));
  CHECK(ParsesAs("HTTP/1.1 304 Not Modified\r\n\r\n", 304, ""));

  // The parser is deliberately transport-level: it returns HTTP statuses;
  // the Docker controller must reject redirects and unexpected statuses.
  CHECK(ParsesAs("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", 302,
                 ""));
}

void TestAmbiguousOrMalformedFraming() {
  CHECK(FailsAs("HTTP/1.1 200 OK\nContent-Length: 0\n\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r", 
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 100 Continue\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 099 Invalid\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 600 Invalid\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
                "content-length: 1\r\n\r\na", HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\na",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                "transfer-encoding: chunked\r\n\r\n0\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n"
                "\r\n0\r\n\r\n", HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                "Content-Length: 0\r\n\r\n", HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\n Folded: yes\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n"
                "\r\n0\r\n\r\n", HttpParseError::Malformed));
}

void TestChunkGrammar() {
  CHECK(ParsesAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "1\r\na\r\n1\r\nb\r\n0\r\n\r\n", 200, "ab"));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "1;x=y\r\na\r\n0\r\n\r\n", HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "1\r\naX0\r\n\r\n", HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "0\r\nX-Trailer: forbidden\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "0\r\n\r\nextra", HttpParseError::Malformed));
  CHECK(FailsAs("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "10000000000000000\r\na", HttpParseError::Malformed));
}

void TestExactBounds() {
  using namespace rateguard::supervisor;

  const std::string base = "HTTP/1.1 200 OK\r\nX: ";
  const std::string suffix = "\r\n\r\n";
  CHECK(base.size() + (kUnixHttpMaxHeaderBytes - base.size() - suffix.size()) +
            suffix.size() == kUnixHttpMaxHeaderBytes);
  const std::string exact_header =
      base + std::string(kUnixHttpMaxHeaderBytes - base.size() - suffix.size(),
                         'a') + suffix;
  CHECK(ParseHttpResponse(Bytes(exact_header)).index() == 0);
  const std::string over_header = "HTTP/1.1 200 OK\r\nX: " +
      std::string(kUnixHttpMaxHeaderBytes, 'a') + suffix;
  CHECK(FailsAs(over_header, HttpParseError::TooLarge));

  std::string exact_fields = "HTTP/1.1 200 OK\r\n";
  for (std::size_t i = 0; i < kUnixHttpMaxHeaderFields; ++i)
    exact_fields += "X-" + std::to_string(i) + ": a\r\n";
  exact_fields += "\r\n";
  CHECK(ParseHttpResponse(Bytes(exact_fields)).index() == 0);
  std::string over_fields = "HTTP/1.1 200 OK\r\n";
  for (std::size_t i = 0; i <= kUnixHttpMaxHeaderFields; ++i)
    over_fields += "X-" + std::to_string(i) + ": a\r\n";
  over_fields += "\r\n";
  CHECK(FailsAs(over_fields, HttpParseError::TooLarge));

  const std::string body_header = "HTTP/1.1 200 OK\r\nContent-Length: " +
      std::to_string(kUnixHttpMaxDecodedBodyBytes) + "\r\n\r\n";
  const auto exact_body = body_header +
      std::string(kUnixHttpMaxDecodedBodyBytes, 'b');
  CHECK(ParseHttpResponse(Bytes(exact_body)).index() == 0);
  const std::string body_over = "HTTP/1.1 200 OK\r\nContent-Length: " +
      std::to_string(kUnixHttpMaxDecodedBodyBytes + 1) + "\r\n\r\n";
  CHECK(FailsAs(body_over, HttpParseError::TooLarge));

  std::string exact_chunks =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  for (std::size_t i = 0; i < kUnixHttpMaxChunks; ++i)
    exact_chunks += "1\r\na\r\n";
  exact_chunks += "0\r\n\r\n";
  CHECK(ParseHttpResponse(Bytes(exact_chunks)).index() == 0);
  std::string chunks_over =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  for (std::size_t i = 0; i <= kUnixHttpMaxChunks; ++i)
    chunks_over += "1\r\na\r\n";
  chunks_over += "0\r\n\r\n";
  CHECK(FailsAs(chunks_over, HttpParseError::TooLarge));

  std::string exact_chunk_line =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  exact_chunk_line += std::string(kUnixHttpMaxChunkLineBytes - 1, '0');
  exact_chunk_line += "1\r\na\r\n0\r\n\r\n";
  CHECK(ParseHttpResponse(Bytes(exact_chunk_line)).index() == 0);
  std::string over_chunk_line =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  over_chunk_line += std::string(kUnixHttpMaxChunkLineBytes, '0');
  over_chunk_line += "1\r\na\r\n0\r\n\r\n";
  CHECK(FailsAs(over_chunk_line, HttpParseError::TooLarge));

  CHECK(FailsAs(std::string(kUnixHttpMaxWireResponseBytes + 1, 'x'),
                HttpParseError::TooLarge));
}

void TestTargetGrammar() {
  using namespace rateguard::supervisor;
  CHECK(IsValidOriginFormTarget("/version"));
  CHECK(IsValidOriginFormTarget("/v1.57/containers/" + std::string(64, 'a') +
                                "/json"));
  CHECK(IsValidOriginFormTarget("/v1.57/containers/id/stop?signal=SIGTERM&t=1"));
  CHECK(IsValidOriginFormTarget("/" + std::string(kUnixHttpMaxTargetBytes - 1, 'a')));
  CHECK(!IsValidOriginFormTarget(""));
  CHECK(!IsValidOriginFormTarget("relative/path"));
  CHECK(!IsValidOriginFormTarget("//authority/path"));
  CHECK(!IsValidOriginFormTarget("/path#fragment"));
  CHECK(!IsValidOriginFormTarget("/path\\segment"));
  CHECK(!IsValidOriginFormTarget("/path\r\nInjected: x"));
  const std::string embedded_nul("/path\0tail", 10);
  CHECK(!IsValidOriginFormTarget(embedded_nul));
  CHECK(!IsValidOriginFormTarget("/" + std::string(kUnixHttpMaxTargetBytes, 'a')));
}

}  // namespace

int main() {
  TestFramingAndStatusOwnership();
  TestAmbiguousOrMalformedFraming();
  TestChunkGrammar();
  TestExactBounds();
  TestTargetGrammar();
  if (failures != 0) {
    std::cerr << failures << " independent HTTP parser assertion(s) failed\n";
    return 1;
  }
  std::cout << "Independent HTTP parser checks passed\n";
  return 0;
}
