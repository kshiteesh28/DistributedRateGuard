#include "src/policy/canonical_codec.h"
#include "src/policy/policy_loader.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace {
using nlohmann::json;

std::string Hex(const std::uint8_t* bytes, std::size_t size) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(size * 2, '0');
  for (std::size_t i = 0; i < size; ++i) {
    result[2 * i] = digits[bytes[i] >> 4];
    result[2 * i + 1] = digits[bytes[i] & 0x0f];
  }
  return result;
}

const char* CodeName(rateguard::policy::PolicyErrorCode code) {
  using rateguard::policy::PolicyErrorCode;
  switch (code) {
    case PolicyErrorCode::InvalidJson: return "invalid_json";
    case PolicyErrorCode::InvalidSchema: return "invalid_schema";
    case PolicyErrorCode::InvalidValue: return "invalid_value";
    case PolicyErrorCode::ResourceLimit: return "resource_limit";
    case PolicyErrorCode::CryptoFailure: return "crypto_failure";
    case PolicyErrorCode::EncodingFailure: return "encoding_failure";
  }
  return "unknown";
}

int Error(rateguard::policy::PolicyError error) {
  json output{{"status", "error"}, {"code", CodeName(error.code)},
              {"message", std::move(error.message)}};
  std::cout << output.dump() << '\n';
  return 2;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: policy_driver <policy-json-path>\n";
    return 64;
  }
  try {
    const std::filesystem::path path(argv[1]);
    const auto size = std::filesystem::file_size(path);
    if (size == 0 || size > rateguard::policy::PolicyLoader::kMaxJsonBytes)
      return Error({rateguard::policy::PolicyErrorCode::ResourceLimit,
                    "policy JSON must be 1..64 MiB"});
    std::ifstream input(path, std::ios::binary);
    if (!input) return Error({rateguard::policy::PolicyErrorCode::InvalidJson,
                              "unable to read policy JSON"});
    const std::string bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    auto loaded = rateguard::policy::PolicyLoader::Load(bytes);
    if (const auto* error = std::get_if<rateguard::policy::PolicyError>(&loaded)) return Error(*error);
    const auto& snapshot = *std::get<std::shared_ptr<const rateguard::policy::PolicySnapshot>>(loaded);

    auto encoded = rateguard::policy::CanonicalPolicyCodec::Encode(snapshot);
    if (const auto* error = std::get_if<rateguard::policy::PolicyError>(&encoded)) return Error(*error);
    const auto& canonical = std::get<std::vector<std::uint8_t>>(encoded);
    auto digest = rateguard::policy::CanonicalPolicyCodec::Digest(snapshot);
    if (const auto* error = std::get_if<rateguard::policy::PolicyError>(&digest)) return Error(*error);
    const auto& sha = std::get<rateguard::policy::Digest32>(digest);

    json output{{"status", "ok"}, {"canonical_hex", Hex(canonical.data(), canonical.size())},
                {"sha256", Hex(sha.data(), sha.size())}};
    std::cout << output.dump() << '\n';
    return 0;
  } catch (const std::exception&) {
    return Error({rateguard::policy::PolicyErrorCode::InvalidJson,
                  "policy driver failed"});
  }
}
