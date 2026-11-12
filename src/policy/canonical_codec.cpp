#include "canonical_codec.h"

#include <openssl/evp.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <new>
#include <string_view>
#include <utility>

namespace rateguard::policy {
namespace {

constexpr std::size_t kMaxCanonicalBytes = 64U * 1024U * 1024U;

class Writer {
 public:
  bool U8(std::uint8_t value) { return Append(&value, 1); }
  bool U32(std::uint32_t value) {
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value >> 24),
        static_cast<std::uint8_t>(value >> 16),
        static_cast<std::uint8_t>(value >> 8),
        static_cast<std::uint8_t>(value)};
    return Append(bytes, sizeof(bytes));
  }
  bool U64(std::uint64_t value) {
    std::uint8_t bytes[8];
    for (int i = 7; i >= 0; --i) {
      bytes[i] = static_cast<std::uint8_t>(value);
      value >>= 8;
    }
    return Append(bytes, sizeof(bytes));
  }
  bool Raw(const std::uint8_t* data, std::size_t size) { return Append(data, size); }
  bool String(std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) return false;
    return U32(static_cast<std::uint32_t>(value.size())) &&
           Append(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
  }
  std::vector<std::uint8_t> Take() && { return std::move(bytes_); }

 private:
  bool Append(const std::uint8_t* data, std::size_t size) {
    if (size > kMaxCanonicalBytes - bytes_.size()) return false;
    bytes_.insert(bytes_.end(), data, data + size);
    return true;
  }

  std::vector<std::uint8_t> bytes_;
};

PolicyError EncodingError(std::string message) {
  return {PolicyErrorCode::EncodingFailure, std::move(message)};
}

std::uint32_t TenantIndex(const PolicySnapshot& snapshot, std::string_view id) {
  const auto& tenants = snapshot.tenants();
  const auto found = std::lower_bound(tenants.begin(), tenants.end(), id,
      [](const TenantPolicy& item, std::string_view value) { return std::string_view(item.tenant_id) < value; });
  if (found == tenants.end() || std::string_view(found->tenant_id) != id)
    return std::numeric_limits<std::uint32_t>::max();
  return static_cast<std::uint32_t>(std::distance(tenants.begin(), found));
}

std::uint32_t OperationIndex(const TenantPolicy& tenant, std::string_view id) {
  const auto found = std::lower_bound(tenant.operations.begin(), tenant.operations.end(), id,
      [](const OperationPolicy& item, std::string_view value) { return std::string_view(item.operation_id) < value; });
  if (found == tenant.operations.end() || std::string_view(found->operation_id) != id)
    return std::numeric_limits<std::uint32_t>::max();
  return static_cast<std::uint32_t>(std::distance(tenant.operations.begin(), found));
}

}  // namespace

Result<std::vector<std::uint8_t>> CanonicalPolicyCodec::Encode(
    const PolicySnapshot& snapshot) try {
  Writer out;
  const std::uint32_t mode = snapshot.mode() == Mode::Strict ? 1U : 2U;
  if (!out.U32(1) || !out.U32(mode) ||
      !out.Raw(snapshot.epoch_id().data(), snapshot.epoch_id().size()) ||
      !out.Raw(snapshot.authority_incarnation().data(), snapshot.authority_incarnation().size()) ||
      !out.Raw(snapshot.trust_root_sha256().data(), snapshot.trust_root_sha256().size()) ||
      !out.U32(static_cast<std::uint32_t>(snapshot.replica_slots().size())))
    return EncodingError("canonical policy exceeds output limit or count width");

  for (const auto& slot : snapshot.replica_slots()) {
    if (!out.U32(slot.slot_id) || !out.Raw(slot.incarnation_id.data(), slot.incarnation_id.size()))
      return EncodingError("canonical policy exceeds output limit while encoding slots");
  }
  if (!out.U32(static_cast<std::uint32_t>(snapshot.tenants().size())))
    return EncodingError("canonical policy exceeds output limit while encoding tenants");
  for (const auto& tenant : snapshot.tenants()) {
    if (!out.String(tenant.tenant_id) || !out.U64(tenant.capacity_units) ||
        !out.U64(tenant.rate_units_per_second))
      return EncodingError("canonical policy exceeds output limit while encoding tenant");
    if (tenant.credit_batch_units) {
      if (!out.U8(1) || !out.U64(*tenant.credit_batch_units))
        return EncodingError("canonical policy exceeds output limit while encoding credit batch");
    } else if (!out.U8(0)) {
      return EncodingError("canonical policy exceeds output limit while encoding strict mode");
    }
    if (!out.U32(static_cast<std::uint32_t>(tenant.operations.size())))
      return EncodingError("canonical policy exceeds output limit while encoding operation count");
    for (const auto& operation : tenant.operations) {
      if (!out.String(operation.operation_id) || !out.U64(operation.cost_units))
        return EncodingError("canonical policy exceeds output limit while encoding operation");
    }
  }
  if (!out.U32(static_cast<std::uint32_t>(snapshot.principals().size())))
    return EncodingError("canonical policy exceeds output limit while encoding principal count");
  for (const auto& principal : snapshot.principals()) {
    if (!out.String(principal.uri) || !out.U32(static_cast<std::uint32_t>(principal.role)))
      return EncodingError("canonical policy exceeds output limit while encoding principal");
    if (principal.role == PrincipalRole::Replica &&
        (!principal.slot_id || !out.U32(*principal.slot_id)))
      return EncodingError("replica principal has no validated slot");
    if (!out.U32(static_cast<std::uint32_t>(principal.permissions.size())))
      return EncodingError("canonical policy exceeds output limit while encoding permissions");
    for (const auto& permission : principal.permissions) {
      const auto tenant_index = TenantIndex(snapshot, permission.tenant_id);
      if (tenant_index >= snapshot.tenants().size())
        return EncodingError("validated permission lost its tenant reference");
      const auto& tenant = snapshot.tenants()[tenant_index];
      const auto operation_index = OperationIndex(tenant, permission.operation_id);
      if (operation_index >= tenant.operations.size())
        return EncodingError("validated permission lost its operation reference");
      if (!out.U32(tenant_index) || !out.U32(operation_index))
        return EncodingError("canonical policy exceeds output limit while encoding permission");
    }
  }
  return std::move(out).Take();
} catch (const std::bad_alloc&) {
  return PolicyError{PolicyErrorCode::ResourceLimit, "insufficient memory for bounded canonical encoding"};
} catch (const std::exception&) {
  return EncodingError("canonical encoding failed");
}

Result<Digest32> CanonicalPolicyCodec::Digest(const PolicySnapshot& snapshot) {
  auto encoded = Encode(snapshot);
  if (const auto* error = std::get_if<PolicyError>(&encoded)) return *error;
  const auto& bytes = std::get<std::vector<std::uint8_t>>(encoded);
  Digest32 digest{};
  unsigned int length = 0;
  if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 ||
      length != digest.size())
    return PolicyError{PolicyErrorCode::CryptoFailure, "SHA-256 computation failed"};
  return digest;
}

}  // namespace rateguard::policy
