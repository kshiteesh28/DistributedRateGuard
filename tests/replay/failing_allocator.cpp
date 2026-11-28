#include "failing_allocator.h"

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace {
std::atomic<long long> allocation_countdown{-1};

bool ShouldFailAllocation() noexcept {
  long long value = allocation_countdown.load(std::memory_order_relaxed);
  while (value >= 0) {
    if (value == 0) {
      if (allocation_countdown.compare_exchange_weak(
              value, -1, std::memory_order_relaxed))
        return true;
    } else if (allocation_countdown.compare_exchange_weak(
                   value, value - 1, std::memory_order_relaxed)) {
      return false;
    }
  }
  return false;
}
}  // namespace

namespace rateguard::test_support {
void ArmAllocationFailure(long long fail_after) noexcept {
  allocation_countdown.store(fail_after, std::memory_order_relaxed);
}
void DisarmAllocationFailure() noexcept {
  allocation_countdown.store(-1, std::memory_order_relaxed);
}
bool AllocationFailureArmedAtZero() noexcept {
  return allocation_countdown.load(std::memory_order_relaxed) == 0;
}
}  // namespace rateguard::test_support

// Kept out of the fixture translation unit so optimized callers cannot inline
// delete/free into an allocation site and misclassify the matched replacement.
// The frozen build uses separate compilation, with no LTO enabled.
// Test-only global allocation failpoint. All setup and assertions run disarmed.
void* operator new(std::size_t size) {
  if (ShouldFailAllocation()) throw std::bad_alloc();
  if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
  throw std::bad_alloc();
}
void* operator new[](std::size_t size) {
  if (ShouldFailAllocation()) throw std::bad_alloc();
  if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void* operator new(std::size_t size, std::align_val_t alignment) {
  if (ShouldFailAllocation()) throw std::bad_alloc();
  void* p = nullptr;
  if (posix_memalign(&p, static_cast<std::size_t>(alignment), size == 0 ? 1 : size) == 0)
    return p;
  throw std::bad_alloc();
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
  if (ShouldFailAllocation()) throw std::bad_alloc();
  void* p = nullptr;
  if (posix_memalign(&p, static_cast<std::size_t>(alignment), size == 0 ? 1 : size) == 0)
    return p;
  throw std::bad_alloc();
}
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

