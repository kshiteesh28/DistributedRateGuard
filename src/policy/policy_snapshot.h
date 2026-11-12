#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rateguard::policy {

enum class Mode : std::uint32_t { Strict = 1, Credit = 2 };
enum class PrincipalRole : std::uint32_t { Adapter = 1, Replica = 2, Authority = 3 };

enum class PolicyErrorCode : std::uint8_t {
  InvalidJson,
  InvalidSchema,
  InvalidValue,
  ResourceLimit,
  CryptoFailure,
  EncodingFailure,
};

struct PolicyError {
  PolicyErrorCode code;
  std::string message;
};

template <class T>
using Result = std::variant<T, PolicyError>;

using Id16 = std::array<std::uint8_t, 16>;
using Digest32 = std::array<std::uint8_t, 32>;

struct OperationPolicy {
  std::string operation_id;
  std::uint64_t cost_units{};
};

struct TenantPolicy {
  std::string tenant_id;
  std::uint64_t capacity_units{};
  std::uint64_t rate_units_per_second{};
  std::optional<std::uint64_t> credit_batch_units;
  std::vector<OperationPolicy> operations;

  [[nodiscard]] std::uint64_t initial_balance_subunits() const noexcept {
    return capacity_units * 1'000'000'000ULL;
  }
  [[nodiscard]] const OperationPolicy* FindOperation(std::string_view id) const noexcept;
};

struct ReplicaSlot {
  std::uint32_t slot_id{};
  Id16 incarnation_id{};
};

struct Permission {
  std::string tenant_id;
  std::string operation_id;
  friend bool operator==(const Permission&, const Permission&) = default;
};

struct Principal {
  std::string uri;
  PrincipalRole role{};
  std::optional<std::uint32_t> slot_id;
  std::vector<Permission> permissions;
};

class PolicyLoader;
class CanonicalPolicyCodec;

// Constructed only by PolicyLoader after complete validation. Public accessors
// are read-only; lookup functions never insert or lazily allocate state.
class PolicySnapshot final {
 public:
  [[nodiscard]] Mode mode() const noexcept { return mode_; }
  [[nodiscard]] const Id16& epoch_id() const noexcept { return epoch_id_; }
  [[nodiscard]] const Id16& authority_incarnation() const noexcept { return authority_incarnation_; }
  [[nodiscard]] const Digest32& trust_root_sha256() const noexcept { return trust_root_sha256_; }
  [[nodiscard]] const std::vector<ReplicaSlot>& replica_slots() const noexcept { return replica_slots_; }
  [[nodiscard]] const std::vector<TenantPolicy>& tenants() const noexcept { return tenants_; }
  [[nodiscard]] const std::vector<Principal>& principals() const noexcept { return principals_; }
  [[nodiscard]] const TenantPolicy* FindTenant(std::string_view id) const noexcept;
  [[nodiscard]] const Principal* FindPrincipal(std::string_view uri) const noexcept;
  [[nodiscard]] bool IsAuthorized(std::string_view uri, PrincipalRole role,
                                  std::string_view tenant,
                                  std::string_view operation) const noexcept;

 private:
  friend class PolicyLoader;
  friend class CanonicalPolicyCodec;
  PolicySnapshot(Mode mode, Id16 epoch, Id16 authority, Digest32 trust_root,
                 std::vector<ReplicaSlot> slots,
                 std::vector<TenantPolicy> tenants,
                 std::vector<Principal> principals)
      : mode_(mode), epoch_id_(epoch), authority_incarnation_(authority),
        trust_root_sha256_(trust_root), replica_slots_(std::move(slots)),
        tenants_(std::move(tenants)), principals_(std::move(principals)) {}

  Mode mode_;
  Id16 epoch_id_;
  Id16 authority_incarnation_;
  Digest32 trust_root_sha256_;
  std::vector<ReplicaSlot> replica_slots_;
  std::vector<TenantPolicy> tenants_;
  std::vector<Principal> principals_;
};

}  // namespace rateguard::policy
