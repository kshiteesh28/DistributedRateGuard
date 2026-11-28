#include "supervisor/epoch_artifact_layout.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

namespace layout = rateguard::supervisor::epoch_layout_v1;
using rateguard::supervisor::EpochId;

namespace {

int failures = 0;

void Check(bool condition, std::string_view label) {
  if (!condition) {
    ++failures;
    std::cerr << "FAIL: " << label << '\n';
  }
}

void RoundTrip(const EpochId& id, std::string_view expected) {
  const auto encoded = layout::FormatEpochDirectoryName(id);
  const auto* name = std::get_if<std::string>(&encoded);
  Check(name != nullptr, "format accepted nonzero ID");
  if (name == nullptr) return;
  Check(*name == expected, "format canonical expected spelling");
  const auto parsed = layout::ParseEpochDirectoryName(*name);
  Check(parsed.has_value(), "parse formatted name");
  if (parsed) Check(*parsed == id, "round trip preserves all bytes");
}

void TestNames() {
  constexpr std::array<std::pair<std::string_view, std::string_view>, 7> kNames{{
      {"epoch-", layout::kEpochDirectoryPrefix},
      {"intent.json", layout::kIntentFileName},
      {"intent.tmp", layout::kIntentTemporaryFileName},
      {"manifest-store", layout::kManifestStoreDirectoryName},
      {"owner.lock", layout::kManifestStoreLockFileName},
      {"manifest.json", layout::kManifestFileName},
      {"manifest.tmp", layout::kManifestTemporaryFileName},
  }};
  for (const auto& [expected, actual] : kNames)
    Check(expected == actual, "shared v1 artifact name constant");
}

void TestRoundTrips() {
  EpochId zero_first{};
  zero_first[15] = 1;
  RoundTrip(zero_first, "epoch-00000000000000000000000000000001");

  EpochId all_ff{};
  all_ff.fill(0xff);
  RoundTrip(all_ff, "epoch-ffffffffffffffffffffffffffffffff");

  EpochId alternating{};
  for (std::size_t i = 0; i < alternating.size(); ++i)
    alternating[i] = i % 2 == 0 ? 0x0a : 0xb0;
  RoundTrip(alternating, "epoch-0ab00ab00ab00ab00ab00ab00ab00ab0");

  EpochId max_first{};
  max_first[0] = 0x80;
  max_first[15] = 0x01;
  RoundTrip(max_first, "epoch-80000000000000000000000000000001");
}

void TestRejectedNames() {
  constexpr std::string_view kValid = "epoch-00000000000000000000000000000001";
  Check(layout::ParseEpochDirectoryName(kValid).has_value(), "canonical sample parses");
  Check(!layout::ParseEpochDirectoryName("epoch-00000000000000000000000000000000"),
        "all-zero ID rejected");
  Check(!layout::ParseEpochDirectoryName("Epoch-00000000000000000000000000000001"),
        "uppercase prefix rejected");
  Check(!layout::ParseEpochDirectoryName("epoch-0000000000000000000000000000000A"),
        "uppercase hex rejected");
  Check(!layout::ParseEpochDirectoryName("epoch-0000000000000000000000000000000g"),
        "non-hex character rejected");
  Check(!layout::ParseEpochDirectoryName("epoch-0000000000000000000000000000001"),
        "short name rejected");
  Check(!layout::ParseEpochDirectoryName("epoch-000000000000000000000000000000001"),
        "long name rejected");
  Check(!layout::ParseEpochDirectoryName("xepoch-00000000000000000000000000000001"),
        "noncanonical prefix rejected");
  Check(!layout::ParseEpochDirectoryName("epoch_00000000000000000000000000000001"),
        "alternate separator rejected");

  const EpochId all_zero{};
  const auto formatted_zero = layout::FormatEpochDirectoryName(all_zero);
  const auto* error = std::get_if<layout::LayoutError>(&formatted_zero);
  Check(error != nullptr && *error == layout::LayoutError::ZeroEpochId,
        "format rejects zero ID with typed error");
}

}  // namespace

int main() {
  TestNames();
  TestRoundTrips();
  TestRejectedNames();
  if (failures != 0) return 1;
  std::cout << "epoch artifact layout checks passed\n";
  return 0;
}
