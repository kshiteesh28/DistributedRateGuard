#include "supervisor/http1_parser.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <new>
#include <string>
#include <vector>

namespace {
std::atomic_bool fail_allocations{false};
}

void* operator new(std::size_t size) {
  if (fail_allocations.load(std::memory_order_relaxed)) throw std::bad_alloc();
  if (void* allocation = std::malloc(size == 0 ? 1 : size); allocation != nullptr)
    return allocation;
  throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
  if (fail_allocations.load(std::memory_order_relaxed)) throw std::bad_alloc();
  if (void* allocation = std::malloc(size == 0 ? 1 : size); allocation != nullptr)
    return allocation;
  throw std::bad_alloc();
}

void operator delete(void* allocation) noexcept { std::free(allocation); }
void operator delete[](void* allocation) noexcept { std::free(allocation); }
void operator delete(void* allocation, std::size_t) noexcept { std::free(allocation); }
void operator delete[](void* allocation, std::size_t) noexcept { std::free(allocation); }

int main() {
  const std::string wire =
      "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata";
  const std::vector<std::uint8_t> input(wire.begin(), wire.end());
  fail_allocations.store(true, std::memory_order_relaxed);
  const auto result = rateguard::supervisor::detail::ParseHttpResponse(input);
  fail_allocations.store(false, std::memory_order_relaxed);

  const bool correctly_classified =
      std::holds_alternative<rateguard::supervisor::detail::HttpParseError>(result) &&
      std::get<rateguard::supervisor::detail::HttpParseError>(result) ==
          rateguard::supervisor::detail::HttpParseError::AllocationFailure;
  if (!correctly_classified) {
    std::cerr << "parser did not classify injected allocation failure\n";
    return 1;
  }
  std::cout << "Independent parser allocation-failure check passed\n";
  return 0;
}
