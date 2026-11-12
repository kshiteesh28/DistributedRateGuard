#include "../src/policy/canonical_codec.h"
#include "../src/policy/policy_loader.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {
using nlohmann::json;
using namespace rateguard::policy;
int failures = 0;

void Check(bool condition, std::string_view name) {
  if (!condition) {
    std::cerr << "FAIL: " << name << '\n';
    ++failures;
  }
}

std::string ReadText(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return {};
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string ReadHex(const std::string& path) {
  const std::string text = ReadText(path);
  std::string output;
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::string compact;
  for (unsigned char c : text)
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') compact.push_back(static_cast<char>(c));
  if (compact.empty() || compact.size() % 2 != 0) return {};
  output.reserve(compact.size() / 2);
  for (std::size_t i = 0; i < compact.size(); i += 2) {
    const int high = digit(compact[i]);
    const int low = digit(compact[i + 1]);
    if (high < 0 || low < 0) return {};
    output.push_back(static_cast<char>((high << 4) | low));
  }
  return output;
}

std::string Hex(const std::uint8_t* bytes, std::size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(size * 2, '0');
  for (std::size_t i = 0; i < size; ++i) {
    result[2 * i] = digits[bytes[i] >> 4];
    result[2 * i + 1] = digits[bytes[i] & 0x0f];
  }
  return result;
}

bool Rejected(std::string_view input) {
  return std::holds_alternative<PolicyError>(PolicyLoader::Load(input));
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: policy_test <repository-root>\n";
    return 2;
  }
  const std::string root = argv[1];
  const std::string json_path = root + "/tests/fixtures/policy_v1.json";
  const std::string expected_path = root + "/tests/fixtures/policy_v1.canonical.hex";
  const std::string input = ReadText(json_path);
  Check(!input.empty(), "read canonical policy fixture");

  auto loaded = PolicyLoader::Load(input);
  if (const auto* error = std::get_if<PolicyError>(&loaded)) {
    std::cerr << "fixture load failed: " << error->message << '\n';
    return 1;
  }
  const auto snapshot = std::get<std::shared_ptr<const PolicySnapshot>>(loaded);
  Check(snapshot->mode() == Mode::Credit, "mode loaded");
  Check(snapshot->tenants().size() == 2 && snapshot->tenants()[0].tenant_id == "alpha" &&
        snapshot->tenants()[1].tenant_id == "zeta", "tenant table sorted");
  Check(snapshot->replica_slots().size() == 2 && snapshot->replica_slots()[0].slot_id == 2 &&
        snapshot->replica_slots()[1].slot_id == 7, "arbitrary slot IDs sorted numerically");
  const TenantPolicy* alpha = snapshot->FindTenant("alpha");
  Check(alpha != nullptr && alpha->capacity_units == 100 && alpha->rate_units_per_second == 10 &&
        alpha->credit_batch_units == 8 && alpha->initial_balance_subunits() == 100'000'000'000ULL,
        "validated tenant fields and full-B initial balance");
  Check(alpha != nullptr && alpha->FindOperation("read") != nullptr &&
        alpha->FindOperation("missing") == nullptr, "operation lookup is read-only");
  Check(snapshot->FindTenant("unconfigured") == nullptr, "unknown tenant lookup does not insert");
  const std::string adapter = "spiffe://rateguard.local/adapter/ingress1";
  Check(snapshot->IsAuthorized(adapter, PrincipalRole::Adapter, "alpha", "read"),
        "registered adapter permission resolves");
  Check(!snapshot->IsAuthorized(adapter, PrincipalRole::Adapter, "alpha", "write"),
        "unlisted operation is unauthorized");
  Check(!snapshot->IsAuthorized(adapter, PrincipalRole::Replica, "alpha", "read"),
        "principal role is part of authorization");

  auto encoded = CanonicalPolicyCodec::Encode(*snapshot);
  Check(std::holds_alternative<std::vector<std::uint8_t>>(encoded), "encode succeeds");
  if (const auto* bytes = std::get_if<std::vector<std::uint8_t>>(&encoded)) {
    const std::string expected_bytes = ReadHex(expected_path);
    const std::string actual_bytes(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    Check(expected_bytes.size() == 580, "independent canonical fixture is 580 bytes");
    Check(actual_bytes == expected_bytes, "canonical bytes match independent Python oracle exactly");
  }
  auto digest = CanonicalPolicyCodec::Digest(*snapshot);
  Check(std::holds_alternative<Digest32>(digest), "SHA-256 digest succeeds");
  if (const auto* hash = std::get_if<Digest32>(&digest))
    Check(Hex(hash->data(), hash->size()) ==
          "0fa75c3373b71fc7c21ce0417258ea6545986d884c69c16f2ee8d6d9fefe00ff",
          "SHA-256 matches independent Python oracle");

  json shuffled = json::parse(input);
  std::reverse(shuffled["replica_slots"].begin(), shuffled["replica_slots"].end());
  std::reverse(shuffled["tenants"].begin(), shuffled["tenants"].end());
  std::reverse(shuffled["principals"].begin(), shuffled["principals"].end());
  for (auto& tenant : shuffled["tenants"])
    std::reverse(tenant["operations"].begin(), tenant["operations"].end());
  for (auto& principal : shuffled["principals"])
    std::reverse(principal["permissions"].begin(), principal["permissions"].end());
  auto shuffled_result = PolicyLoader::Load(shuffled.dump());
  Check(std::holds_alternative<std::shared_ptr<const PolicySnapshot>>(shuffled_result),
        "input table order variation accepted");
  if (const auto* reordered = std::get_if<std::shared_ptr<const PolicySnapshot>>(&shuffled_result)) {
    auto reordered_digest = CanonicalPolicyCodec::Digest(**reordered);
    if (const auto* reordered_hash = std::get_if<Digest32>(&reordered_digest)) {
      if (const auto* original_hash = std::get_if<Digest32>(&digest))
        Check(*reordered_hash == *original_hash, "input order normalizes to identical digest");
      else
        Check(false, "original digest available for order comparison");
    } else {
      Check(false, "reordered digest succeeds");
    }
  }

  Check(Rejected("{\"schema_version\":1,\"schema_version\":1}"), "duplicate object keys rejected");
  json invalid = json::parse(input);
  invalid["unexpected"] = true;
  Check(Rejected(invalid.dump()), "unknown field rejected");
  invalid = json::parse(input);
  invalid["schema_version"] = 1.0;
  Check(Rejected(invalid.dump()), "floating-point schema version rejected");
  invalid = json::parse(input);
  invalid["tenants"][0]["credit_batch_units"] = "4";
  Check(Rejected(invalid.dump()), "Q below maximum operation cost rejected");
  invalid = json::parse(input);
  invalid["tenants"][0]["operations"].push_back(invalid["tenants"][0]["operations"][0]);
  Check(Rejected(invalid.dump()), "duplicate operation ID rejected");
  invalid = json::parse(input);
  invalid["principals"][0]["slot_id"] = 8;
  Check(Rejected(invalid.dump()), "URI/slot membership mismatch rejected");
  invalid = json::parse(input);
  invalid["principals"][1]["permissions"][0]["tenant_id"] = "unknown";
  Check(Rejected(invalid.dump()), "unknown authorization reference rejected");
  invalid = json::parse(input);
  invalid["epoch_id"] = "000102030405060708090A0b0c0d0e0f";
  Check(Rejected(invalid.dump()), "non-lowercase epoch hex rejected");
  invalid = json::parse(input);
  invalid["mode"] = "strict";
  for (auto& tenant : invalid["tenants"]) tenant.erase("credit_batch_units");
  auto strict = PolicyLoader::Load(invalid.dump());
  Check(std::holds_alternative<std::shared_ptr<const PolicySnapshot>>(strict),
        "strict mode omits per-tenant credit Q");

  std::string deeply_nested;
  for (int i = 0; i < 33; ++i) deeply_nested.push_back('[');
  deeply_nested.append(33, ']');
  Check(Rejected(deeply_nested), "JSON nesting beyond 32 containers rejected");

  if (failures != 0) return 1;
  std::cout << "policy loader and canonical codec checks passed\n";
  return 0;
}
