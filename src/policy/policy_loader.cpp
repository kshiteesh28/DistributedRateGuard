#include "policy_loader.h"

#include "canonical_codec.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <limits>
#include <new>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace rateguard::policy {
namespace {

using Json = nlohmann::json;
constexpr std::uint64_t kMaxPolicyValue = 1'000'000'000ULL;
constexpr std::size_t kMaxDiagnosticBytes = 256;

struct Failure final {
  PolicyError error;
};

[[noreturn]] void Fail(PolicyErrorCode code, std::string message) {
  if (message.size() > kMaxDiagnosticBytes) message.resize(kMaxDiagnosticBytes);
  throw Failure{{code, std::move(message)}};
}

class InputGuard final : public nlohmann::json_sax<Json> {
 public:
  using string_t = Json::string_t;
  using binary_t = Json::binary_t;
  using number_integer_t = Json::number_integer_t;
  using number_unsigned_t = Json::number_unsigned_t;
  using number_float_t = Json::number_float_t;

  bool null() override { return true; }
  bool boolean(bool) override { return true; }
  bool number_integer(number_integer_t) override { return true; }
  bool number_unsigned(number_unsigned_t) override { return true; }
  // Float tokens are rejected by this lexical guard and reported as
  // InvalidJson. Boolean values remain syntactically valid JSON and are
  // rejected later as InvalidValue when an integer field requires a string.
  bool number_float(number_float_t, const string_t&) override {
    return Reject("JSON floating-point numbers are not permitted");
  }
  bool string(string_t&) override { return true; }
  bool binary(binary_t&) override { return Reject("binary value is not valid policy JSON"); }
  bool start_object(std::size_t) override {
    if (frames_.size() >= PolicyLoader::kMaxJsonDepth) return Reject("JSON nesting exceeds depth 32");
    frames_.push_back(Frame{true, {}});
    return true;
  }
  bool key(string_t& value) override {
    if (frames_.empty() || !frames_.back().object) return Reject("object key outside object");
    if (!frames_.back().keys.insert(value).second) return Reject("duplicate JSON object key");
    return true;
  }
  bool end_object() override {
    if (frames_.empty() || !frames_.back().object) return Reject("mismatched object terminator");
    frames_.pop_back();
    return true;
  }
  bool start_array(std::size_t) override {
    if (frames_.size() >= PolicyLoader::kMaxJsonDepth) return Reject("JSON nesting exceeds depth 32");
    frames_.push_back(Frame{false, {}});
    return true;
  }
  bool end_array() override {
    if (frames_.empty() || frames_.back().object) return Reject("mismatched array terminator");
    frames_.pop_back();
    return true;
  }
  bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception& error) override {
    (void)error;
    if (error_.empty()) error_ = "invalid JSON syntax";
    return false;
  }
  [[nodiscard]] const std::string& error() const noexcept { return error_; }

 private:
  struct Frame {
    bool object;
    std::unordered_set<std::string> keys;
  };
  bool Reject(std::string message) {
    if (error_.empty()) error_ = std::move(message);
    return false;
  }
  std::vector<Frame> frames_;
  std::string error_;
};

void CheckKeys(const Json& value, std::string_view context,
               std::initializer_list<std::string_view> required,
               std::initializer_list<std::string_view> optional = {}) {
  if (!value.is_object()) Fail(PolicyErrorCode::InvalidSchema, std::string(context) + " must be an object");
  for (const auto& item : value.items()) {
    const std::string_view key = item.key();
    if (std::find(required.begin(), required.end(), key) == required.end() &&
        std::find(optional.begin(), optional.end(), key) == optional.end())
      Fail(PolicyErrorCode::InvalidSchema, std::string(context) + " has unknown field");
  }
  for (std::string_view key : required) {
    if (!value.contains(std::string(key)))
      Fail(PolicyErrorCode::InvalidSchema, std::string(context) + " missing field " + std::string(key));
  }
}

const Json& Required(const Json& object, const char* key, std::string_view context) {
  const auto it = object.find(key);
  if (it == object.end()) Fail(PolicyErrorCode::InvalidSchema,
                               std::string(context) + " missing field " + key);
  return *it;
}

std::string StringValue(const Json& value, std::string_view context) {
  if (!value.is_string()) Fail(PolicyErrorCode::InvalidValue, std::string(context) + " must be a string");
  return value.get<std::string>();
}

std::uint32_t JsonU32(const Json& value, std::string_view context) {
  if (value.is_number_unsigned()) {
    const auto number = value.get<std::uint64_t>();
    if (number <= std::numeric_limits<std::uint32_t>::max()) return static_cast<std::uint32_t>(number);
  } else if (value.is_number_integer() && !value.is_number_float()) {
    const auto number = value.get<std::int64_t>();
    if (number >= 0 && static_cast<std::uint64_t>(number) <= std::numeric_limits<std::uint32_t>::max())
      return static_cast<std::uint32_t>(number);
  }
  Fail(PolicyErrorCode::InvalidValue, std::string(context) + " must be a nonnegative JSON uint32 integer");
}

std::uint64_t DecimalU64(const Json& value, std::string_view context) {
  if (!value.is_string()) Fail(PolicyErrorCode::InvalidValue, std::string(context) + " must be a decimal string");
  const std::string text = value.get<std::string>();
  if (text.empty() || (text.size() > 1 && text.front() == '0'))
    Fail(PolicyErrorCode::InvalidValue, std::string(context) + " is not canonical decimal uint64");
  for (unsigned char c : text) {
    if (c < '0' || c > '9')
      Fail(PolicyErrorCode::InvalidValue, std::string(context) + " is not canonical decimal uint64");
  }
  std::uint64_t result = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    Fail(PolicyErrorCode::InvalidValue, std::string(context) + " is outside uint64 range");
  return result;
}

bool ValidIdentifier(std::string_view value) {
  if (value.empty() || value.size() > PolicyLoader::kMaxIdentifierBytes) return false;
  for (unsigned char c : value) {
    const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    if (!alnum && c != '_' && c != '.' && c != '-') return false;
  }
  return true;
}

template <std::size_t N>
std::array<std::uint8_t, N> LowerHex(const Json& value, std::string_view context) {
  const std::string hex = StringValue(value, context);
  if (hex.size() != N * 2) Fail(PolicyErrorCode::InvalidValue, std::string(context) + " has incorrect hex width");
  std::array<std::uint8_t, N> bytes{};
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < N; ++i) {
    const int high = nibble(hex[i * 2]);
    const int low = nibble(hex[i * 2 + 1]);
    if (high < 0 || low < 0)
      Fail(PolicyErrorCode::InvalidValue, std::string(context) + " must be lowercase hexadecimal");
    bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return bytes;
}

std::string Hex(const Id16& value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.resize(value.size() * 2);
  for (std::size_t i = 0; i < value.size(); ++i) {
    result[2 * i] = digits[value[i] >> 4];
    result[2 * i + 1] = digits[value[i] & 0x0f];
  }
  return result;
}

void ValidateIdentifier(const std::string& id, std::string_view context) {
  if (!ValidIdentifier(id)) Fail(PolicyErrorCode::InvalidValue,
                                 std::string(context) + " must match 1..128 ASCII [A-Za-z0-9_.-]");
}

void RequireArray(const Json& value, std::string_view context) {
  if (!value.is_array()) Fail(PolicyErrorCode::InvalidSchema, std::string(context) + " must be an array");
}

bool PermissionLess(const Permission& a, const Permission& b) {
  return a.tenant_id < b.tenant_id ||
         (a.tenant_id == b.tenant_id && a.operation_id < b.operation_id);
}

const TenantPolicy* FindTenantIn(const std::vector<TenantPolicy>& tenants, std::string_view id) {
  const auto it = std::lower_bound(tenants.begin(), tenants.end(), id,
      [](const TenantPolicy& tenant, std::string_view key) { return std::string_view(tenant.tenant_id) < key; });
  return it != tenants.end() && std::string_view(it->tenant_id) == id ? &*it : nullptr;
}

const ReplicaSlot* FindSlotIn(const std::vector<ReplicaSlot>& slots, std::uint32_t id) {
  const auto it = std::lower_bound(slots.begin(), slots.end(), id,
      [](const ReplicaSlot& slot, std::uint32_t key) { return slot.slot_id < key; });
  return it != slots.end() && it->slot_id == id ? &*it : nullptr;
}

}  // namespace

const OperationPolicy* TenantPolicy::FindOperation(std::string_view id) const noexcept {
  const auto it = std::lower_bound(operations.begin(), operations.end(), id,
      [](const OperationPolicy& operation, std::string_view key) { return std::string_view(operation.operation_id) < key; });
  return it != operations.end() && std::string_view(it->operation_id) == id ? &*it : nullptr;
}

const TenantPolicy* PolicySnapshot::FindTenant(std::string_view id) const noexcept {
  return FindTenantIn(tenants_, id);
}

const Principal* PolicySnapshot::FindPrincipal(std::string_view uri) const noexcept {
  const auto it = std::lower_bound(principals_.begin(), principals_.end(), uri,
      [](const Principal& principal, std::string_view key) { return std::string_view(principal.uri) < key; });
  return it != principals_.end() && std::string_view(it->uri) == uri ? &*it : nullptr;
}

bool PolicySnapshot::IsAuthorized(std::string_view uri, PrincipalRole role,
                                  std::string_view tenant,
                                  std::string_view operation) const noexcept {
  const Principal* principal = FindPrincipal(uri);
  if (principal == nullptr || principal->role != role ||
      (role != PrincipalRole::Adapter && role != PrincipalRole::Replica)) return false;
  const auto it = std::lower_bound(principal->permissions.begin(), principal->permissions.end(),
      std::pair<std::string_view, std::string_view>{tenant, operation},
      [](const Permission& item, const auto& key) {
        return std::string_view(item.tenant_id) < key.first ||
               (std::string_view(item.tenant_id) == key.first &&
                std::string_view(item.operation_id) < key.second);
      });
  return it != principal->permissions.end() && std::string_view(it->tenant_id) == tenant &&
         std::string_view(it->operation_id) == operation;
}

Result<std::shared_ptr<const PolicySnapshot>> PolicyLoader::Load(std::string_view input) {
  try {
    if (input.empty() || input.size() > kMaxJsonBytes)
      Fail(PolicyErrorCode::ResourceLimit, "policy JSON must be 1..64 MiB");

    InputGuard guard;
    if (!Json::sax_parse(input.begin(), input.end(), &guard))
      Fail(PolicyErrorCode::InvalidJson, guard.error().empty() ? "invalid JSON syntax" : guard.error());
    Json root = Json::parse(input.begin(), input.end(), nullptr, false);
    if (root.is_discarded()) Fail(PolicyErrorCode::InvalidJson, "policy JSON parse failed");
    CheckKeys(root, "root", {"schema_version", "mode", "epoch_id", "authority_incarnation",
                              "trust_root_sha256", "replica_slots", "tenants", "principals"});
    if (JsonU32(Required(root, "schema_version", "root"), "schema_version") != 1)
      Fail(PolicyErrorCode::InvalidSchema, "unsupported policy schema_version");

    const std::string mode_text = StringValue(Required(root, "mode", "root"), "mode");
    Mode mode;
    if (mode_text == "strict") mode = Mode::Strict;
    else if (mode_text == "credit") mode = Mode::Credit;
    else Fail(PolicyErrorCode::InvalidValue, "mode must be strict or credit");
    const Id16 epoch = LowerHex<16>(Required(root, "epoch_id", "root"), "epoch_id");
    const Id16 authority = LowerHex<16>(Required(root, "authority_incarnation", "root"), "authority_incarnation");
    const Digest32 trust_fingerprint = LowerHex<32>(Required(root, "trust_root_sha256", "root"), "trust_root_sha256");
    const Json& slot_rows = Required(root, "replica_slots", "root");
    RequireArray(slot_rows, "replica_slots");
    if (slot_rows.empty() || slot_rows.size() > kMaxSlots)
      Fail(PolicyErrorCode::ResourceLimit, "replica_slots must contain 1..8 entries");
    std::vector<ReplicaSlot> slots;
    slots.reserve(slot_rows.size());
    for (const Json& row : slot_rows) {
      CheckKeys(row, "replica slot", {"slot_id", "incarnation_id"});
      slots.push_back({JsonU32(Required(row, "slot_id", "replica slot"), "slot_id"),
                       LowerHex<16>(Required(row, "incarnation_id", "replica slot"), "incarnation_id")});
    }
    std::sort(slots.begin(), slots.end(), [](const auto& a, const auto& b) { return a.slot_id < b.slot_id; });
    if (std::adjacent_find(slots.begin(), slots.end(), [](const auto& a, const auto& b) {
          return a.slot_id == b.slot_id;
        }) != slots.end())
      Fail(PolicyErrorCode::InvalidValue, "duplicate replica slot_id");

    const Json& tenant_rows = Required(root, "tenants", "root");
    RequireArray(tenant_rows, "tenants");
    if (tenant_rows.empty() || tenant_rows.size() > kMaxTenants)
      Fail(PolicyErrorCode::ResourceLimit, "tenants must contain 1..10,000 entries");
    std::vector<TenantPolicy> tenants;
    tenants.reserve(tenant_rows.size());
    std::size_t total_operations = 0;
    for (const Json& row : tenant_rows) {
      CheckKeys(row, "tenant", {"tenant_id", "capacity_units", "rate_units_per_second", "operations"},
                {"credit_batch_units"});
      TenantPolicy tenant;
      tenant.tenant_id = StringValue(Required(row, "tenant_id", "tenant"), "tenant_id");
      ValidateIdentifier(tenant.tenant_id, "tenant_id");
      tenant.capacity_units = DecimalU64(Required(row, "capacity_units", "tenant"), "capacity_units");
      tenant.rate_units_per_second = DecimalU64(Required(row, "rate_units_per_second", "tenant"), "rate_units_per_second");
      if (tenant.capacity_units == 0 || tenant.capacity_units > kMaxPolicyValue ||
          tenant.rate_units_per_second == 0 || tenant.rate_units_per_second > kMaxPolicyValue)
        Fail(PolicyErrorCode::InvalidValue, "capacity_units and rate_units_per_second must be in 1..10^9");
      if (mode == Mode::Credit) {
        tenant.credit_batch_units = DecimalU64(Required(row, "credit_batch_units", "credit tenant"), "credit_batch_units");
        if (*tenant.credit_batch_units == 0 || *tenant.credit_batch_units > tenant.capacity_units)
          Fail(PolicyErrorCode::InvalidValue, "credit_batch_units must be in 1..capacity_units");
      } else if (row.contains("credit_batch_units")) {
        Fail(PolicyErrorCode::InvalidSchema, "strict tenant must omit credit_batch_units");
      }
      const Json& operation_rows = Required(row, "operations", "tenant");
      RequireArray(operation_rows, "tenant.operations");
      if (operation_rows.empty() || operation_rows.size() > kMaxOperationsPerTenant)
        Fail(PolicyErrorCode::ResourceLimit, "each tenant must have 1..64 operations");
      if (operation_rows.size() > kMaxOperationsTotal - total_operations)
        Fail(PolicyErrorCode::ResourceLimit, "operation count exceeds 100,000");
      total_operations += operation_rows.size();
      tenant.operations.reserve(operation_rows.size());
      for (const Json& op_row : operation_rows) {
        CheckKeys(op_row, "operation", {"operation_id", "cost_units"});
        OperationPolicy operation;
        operation.operation_id = StringValue(Required(op_row, "operation_id", "operation"), "operation_id");
        ValidateIdentifier(operation.operation_id, "operation_id");
        operation.cost_units = DecimalU64(Required(op_row, "cost_units", "operation"), "cost_units");
        if (operation.cost_units == 0 || operation.cost_units > tenant.capacity_units)
          Fail(PolicyErrorCode::InvalidValue, "operation cost must be in 1..capacity_units");
        tenant.operations.push_back(std::move(operation));
      }
      std::sort(tenant.operations.begin(), tenant.operations.end(), [](const auto& a, const auto& b) {
        return a.operation_id < b.operation_id;
      });
      if (std::adjacent_find(tenant.operations.begin(), tenant.operations.end(), [](const auto& a, const auto& b) {
            return a.operation_id == b.operation_id;
          }) != tenant.operations.end())
        Fail(PolicyErrorCode::InvalidValue, "duplicate operation_id within tenant");
      if (tenant.credit_batch_units) {
        const auto maximum_cost = std::max_element(tenant.operations.begin(), tenant.operations.end(),
            [](const auto& a, const auto& b) { return a.cost_units < b.cost_units; })->cost_units;
        if (*tenant.credit_batch_units < maximum_cost)
          Fail(PolicyErrorCode::InvalidValue, "credit_batch_units must cover the maximum operation cost");
      }
      tenants.push_back(std::move(tenant));
    }
    std::sort(tenants.begin(), tenants.end(), [](const auto& a, const auto& b) { return a.tenant_id < b.tenant_id; });
    if (std::adjacent_find(tenants.begin(), tenants.end(), [](const auto& a, const auto& b) {
          return a.tenant_id == b.tenant_id;
        }) != tenants.end())
      Fail(PolicyErrorCode::InvalidValue, "duplicate tenant_id");

    const Json& principal_rows = Required(root, "principals", "root");
    RequireArray(principal_rows, "principals");
    if (principal_rows.empty() || principal_rows.size() > kMaxPrincipals)
      Fail(PolicyErrorCode::ResourceLimit, "principals must contain 1..10,000 entries");
    std::vector<Principal> principals;
    principals.reserve(principal_rows.size());
    std::size_t total_permissions = 0;
    std::size_t adapter_count = 0;
    std::size_t authority_count = 0;
    std::set<std::uint32_t> replica_principals;
    for (const Json& row : principal_rows) {
      CheckKeys(row, "principal", {"uri", "role", "permissions"}, {"slot_id"});
      Principal principal;
      principal.uri = StringValue(Required(row, "uri", "principal"), "principal.uri");
      if (principal.uri.empty() || principal.uri.size() > kMaxPrincipalUriBytes ||
          std::any_of(principal.uri.begin(), principal.uri.end(), [](unsigned char c) { return c == 0 || c > 0x7f; }))
        Fail(PolicyErrorCode::InvalidValue, "principal URI must be 1..256 ASCII bytes");
      const std::string role = StringValue(Required(row, "role", "principal"), "principal.role");
      if (role == "adapter") principal.role = PrincipalRole::Adapter;
      else if (role == "replica") principal.role = PrincipalRole::Replica;
      else if (role == "authority") principal.role = PrincipalRole::Authority;
      else Fail(PolicyErrorCode::InvalidValue, "principal role must be adapter, replica, or authority");
      if (principal.role == PrincipalRole::Replica) {
        principal.slot_id = JsonU32(Required(row, "slot_id", "replica principal"), "principal.slot_id");
      } else if (row.contains("slot_id")) {
        Fail(PolicyErrorCode::InvalidSchema, "only replica principals may specify slot_id");
      }
      const Json& permission_rows = Required(row, "permissions", "principal");
      RequireArray(permission_rows, "principal.permissions");
      if (permission_rows.size() > kMaxPermissionPairs - total_permissions)
        Fail(PolicyErrorCode::ResourceLimit, "permission pair count exceeds 100,000");
      total_permissions += permission_rows.size();
      principal.permissions.reserve(permission_rows.size());
      for (const Json& pair : permission_rows) {
        CheckKeys(pair, "permission", {"tenant_id", "operation_id"});
        Permission permission{StringValue(Required(pair, "tenant_id", "permission"), "permission.tenant_id"),
                              StringValue(Required(pair, "operation_id", "permission"), "permission.operation_id")};
        ValidateIdentifier(permission.tenant_id, "permission.tenant_id");
        ValidateIdentifier(permission.operation_id, "permission.operation_id");
        principal.permissions.push_back(std::move(permission));
      }
      std::sort(principal.permissions.begin(), principal.permissions.end(), PermissionLess);
      if (std::adjacent_find(principal.permissions.begin(), principal.permissions.end()) != principal.permissions.end())
        Fail(PolicyErrorCode::InvalidValue, "duplicate permission pair for principal");
      if (principal.role == PrincipalRole::Adapter) ++adapter_count;
      if (principal.role == PrincipalRole::Authority) {
        ++authority_count;
        if (!principal.permissions.empty())
          Fail(PolicyErrorCode::InvalidValue, "authority principal permissions must be empty");
        const std::string expected = "spiffe://rateguard.local/authority/" + Hex(authority);
        if (principal.uri != expected)
          Fail(PolicyErrorCode::InvalidValue, "authority principal URI does not match authority_incarnation");
      }
      if (principal.role == PrincipalRole::Replica) {
        const auto slot_id = *principal.slot_id;
        const ReplicaSlot* slot = FindSlotIn(slots, slot_id);
        if (slot == nullptr) Fail(PolicyErrorCode::InvalidValue, "replica principal references an unknown slot");
        const std::string expected = "spiffe://rateguard.local/replica/" + std::to_string(slot_id) + "/" + Hex(slot->incarnation_id);
        if (principal.uri != expected)
          Fail(PolicyErrorCode::InvalidValue, "replica URI, slot_id, and incarnation_id must agree");
        if (!replica_principals.insert(slot_id).second)
          Fail(PolicyErrorCode::InvalidValue, "duplicate replica principal for slot_id");
      }
      if (principal.role == PrincipalRole::Adapter) {
        constexpr std::string_view prefix = "spiffe://rateguard.local/adapter/";
        if (!principal.uri.starts_with(prefix) ||
            !ValidIdentifier(std::string_view(principal.uri).substr(prefix.size())) ||
            principal.uri != std::string(prefix) + std::string(std::string_view(principal.uri).substr(prefix.size())))
          Fail(PolicyErrorCode::InvalidValue, "adapter principal URI must use the exact A-02 identifier form");
      }
      principals.push_back(std::move(principal));
    }
    std::sort(principals.begin(), principals.end(), [](const auto& a, const auto& b) { return a.uri < b.uri; });
    if (std::adjacent_find(principals.begin(), principals.end(), [](const auto& a, const auto& b) {
          return a.uri == b.uri;
        }) != principals.end())
      Fail(PolicyErrorCode::InvalidValue, "duplicate principal URI");
    if (adapter_count == 0 || authority_count != 1)
      Fail(PolicyErrorCode::InvalidValue, "require at least one adapter and exactly one authority principal");
    if (replica_principals.size() != slots.size())
      Fail(PolicyErrorCode::InvalidValue, "require exactly one replica principal for every registered slot");

    for (const Principal& principal : principals) {
      for (const Permission& permission : principal.permissions) {
        const TenantPolicy* tenant = FindTenantIn(tenants, permission.tenant_id);
        if (tenant == nullptr || tenant->FindOperation(permission.operation_id) == nullptr)
          Fail(PolicyErrorCode::InvalidValue, "permission references an unknown tenant/operation pair");
      }
    }

    auto snapshot = std::shared_ptr<const PolicySnapshot>(new PolicySnapshot(
        mode, epoch, authority, trust_fingerprint, std::move(slots), std::move(tenants), std::move(principals)));
    auto canonical = CanonicalPolicyCodec::Encode(*snapshot);
    if (std::holds_alternative<PolicyError>(canonical)) return std::get<PolicyError>(std::move(canonical));
    return snapshot;
  } catch (const Failure& failure) {
    return failure.error;
  } catch (const std::bad_alloc&) {
    return PolicyError{PolicyErrorCode::ResourceLimit, "insufficient memory to validate bounded policy"};
  } catch (const std::exception& exception) {
    (void)exception;
    return PolicyError{PolicyErrorCode::InvalidJson, "policy load failed"};
  }
}

}  // namespace rateguard::policy
