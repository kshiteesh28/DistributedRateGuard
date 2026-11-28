#include "supervisor/http1_parser.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr "\n"; ++failures; } } while (false)

std::vector<std::uint8_t> Bytes(std::string_view text) {
  return {text.begin(), text.end()};
}

bool IsError(std::string_view wire,
             rateguard::supervisor::detail::HttpParseError expected) {
  auto input = Bytes(wire);
  const auto result = rateguard::supervisor::detail::ParseHttpResponse(input);
  return std::holds_alternative<rateguard::supervisor::detail::HttpParseError>(result) &&
         std::get<rateguard::supervisor::detail::HttpParseError>(result) == expected;
}

void TestContentLengthAndStatus() {
  using namespace rateguard::supervisor;
  auto input = Bytes("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
  auto result = detail::ParseHttpResponse(input);
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result)) {
    const auto& response = std::get<UnixHttpResponse>(result);
    CHECK(response.status == 200);
    CHECK(std::string(response.body.begin(), response.body.end()) == "abc");
  }
  input = Bytes("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  result = detail::ParseHttpResponse(input);
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result))
    CHECK(std::get<UnixHttpResponse>(result).status == 404);
}

void TestCloseDelimitedAndEmptyStatuses() {
  using namespace rateguard::supervisor;
  auto result = detail::ParseHttpResponse(Bytes("HTTP/1.1 500 Error\r\n\r\nbody"));
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result)) {
    const auto& response = std::get<UnixHttpResponse>(result);
    CHECK(response.status == 500);
    CHECK(std::string(response.body.begin(), response.body.end()) == "body");
  }
  for (const auto status : {204, 304}) {
    const auto wire = "HTTP/1.1 " + std::to_string(status) + " No Content\r\n\r\n";
    result = detail::ParseHttpResponse(Bytes(wire));
    CHECK(std::holds_alternative<UnixHttpResponse>(result));
    if (std::holds_alternative<UnixHttpResponse>(result))
      CHECK(std::get<UnixHttpResponse>(result).body.empty());
  }
  CHECK(IsError("HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
                detail::HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                detail::HttpParseError::Malformed));
}

void TestChunked() {
  using namespace rateguard::supervisor;
  auto result = detail::ParseHttpResponse(Bytes(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"
      "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"));
  CHECK(std::holds_alternative<UnixHttpResponse>(result));
  if (std::holds_alternative<UnixHttpResponse>(result)) {
    const auto& response = std::get<UnixHttpResponse>(result);
    CHECK(std::string(response.body.begin(), response.body.end()) == "abcde");
  }
  CHECK(IsError("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "1;ext=x\r\na\r\n0\r\n\r\n",
                detail::HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "0\r\nX-Trailer: no\r\n\r\n",
                detail::HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "1\r\na\r\n0\r\n\r\nEXTRA",
                detail::HttpParseError::Malformed));
}

void TestMalformedAndAmbiguousFraming() {
  using rateguard::supervisor::detail::HttpParseError;
  CHECK(IsError("", HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\nContent-Length: 0\n\n", HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 100 Continue\r\n\r\n", HttpParseError::Malformed));
  CHECK(IsError("HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n", HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nFolded: yes\r\n invalid\r\nContent-Length: 0\r\n\r\n",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab",
                HttpParseError::Malformed));
  CHECK(IsError("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra",
                HttpParseError::Malformed));
}

void TestBounds() {
  using namespace rateguard::supervisor;
  using detail::HttpParseError;
  std::string long_headers = "HTTP/1.1 200 OK\r\n";
  for (int i = 0; i < 65; ++i) long_headers += "X-A: b\r\n";
  long_headers += "\r\n";
  CHECK(IsError(long_headers, HttpParseError::TooLarge));

  std::string too_many_wire(kUnixHttpMaxWireResponseBytes + 1, 'x');
  CHECK(IsError(too_many_wire, HttpParseError::TooLarge));

  std::string too_long_head(kUnixHttpMaxHeaderBytes, 'x');
  CHECK(IsError(too_long_head, HttpParseError::TooLarge));

  const std::string too_large_body = "HTTP/1.1 200 OK\r\nContent-Length: " +
      std::to_string(kUnixHttpMaxDecodedBodyBytes + 1) + "\r\n\r\n";
  CHECK(IsError(too_large_body, HttpParseError::TooLarge));

  std::string long_chunkline = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  long_chunkline += std::string(kUnixHttpMaxChunkLineBytes + 1, 'a') + "\r\n";
  CHECK(IsError(long_chunkline, HttpParseError::TooLarge));

  std::string many_chunks = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  for (std::size_t i = 0; i <= kUnixHttpMaxChunks; ++i)
    many_chunks += "1\r\na\r\n";
  many_chunks += "0\r\n\r\n";
  CHECK(IsError(many_chunks, HttpParseError::TooLarge));
}

void TestTargetValidation() {
  using rateguard::supervisor::detail::IsValidOriginFormTarget;
  CHECK(IsValidOriginFormTarget("/version"));
  CHECK(IsValidOriginFormTarget("/v1.45/containers/id/json?size=0"));
  CHECK(!IsValidOriginFormTarget(""));
  CHECK(!IsValidOriginFormTarget("version"));
  CHECK(!IsValidOriginFormTarget("//host/path"));
  CHECK(!IsValidOriginFormTarget("/path#fragment"));
  CHECK(!IsValidOriginFormTarget("/path\r\nInjected: yes"));
  CHECK(!IsValidOriginFormTarget("/path\\other"));
  CHECK(!IsValidOriginFormTarget(std::string(2'049, 'a').replace(0, 1, "/")));
}

}  // namespace

int main() {
  TestContentLengthAndStatus();
  TestCloseDelimitedAndEmptyStatuses();
  TestChunked();
  TestMalformedAndAmbiguousFraming();
  TestBounds();
  TestTargetValidation();
  if (failures != 0) {
    std::cerr << failures << " test assertion(s) failed\n";
    return 1;
  }
  std::cout << "HTTP parser contract tests passed\n";
  return 0;
}
