#pragma once

// Test-only allocation seam; linked only into the resource fixture executable.
namespace rateguard::test_support {
void ArmAllocationFailure(long long fail_after) noexcept;
void DisarmAllocationFailure() noexcept;
[[nodiscard]] bool AllocationFailureArmedAtZero() noexcept;
}  // namespace rateguard::test_support
