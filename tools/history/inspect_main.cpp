// Offline structural inspector for RGHIST01 binary history files.
//
// CLI-specific trusted plan JSON (all keys required, no other keys):
// {
//   "schema_version": 1,
//   "epoch_id": "<32 lowercase hex chars>",
//   "policy_digest": "<64 lowercase hex chars>",
//   "budget_bytes": "<canonical positive decimal uint64>",
//   "producers": [
//     {"producer_owner": 1, "producer_index": 0, "event_capacity": "1"}
//   ]
// }
// `producer_owner` is numeric 1..5; `producer_index` is uint32 JSON integer. All u64
// values are canonical decimal strings to avoid JSON float rounding. The CLI
// accepts at most 1 MiB of plan JSON; the producer count is additionally
// bounded by the plan's fixed-width history budget. This is an offline tool
// input limit, not a product/runtime limit. A structurally complete history
// is not a quota-safety verdict: output always reports UNKNOWN for safety.

#include "tools/history/history_reader.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using Json = nlohmann::json;
using namespace rateguard::events;

constexpr std::size_t kMaxPlanJsonBytes = 1U * 1024U * 1024U;
constexpr std::size_t kMaxJsonDepth = 8;
constexpr std::uint64_t kMaxRunBytes = kMaxRunBudgetBytes;

struct CliFailure final {
  std::string code;
  int exit_code;
};

[[noreturn]] void Fail(std::string_view code, int exit_code = 2) {
  throw CliFailure{std::string(code), exit_code};
}

Json ErrorJson(std::string_view code) {
  return Json{{"result_schema_version", 1}, {"status", "error"},
              {"error", code}, {"safety_verdict", "UNKNOWN"}};
}

void EmitError(std::string_view code) noexcept {
  try {
    std::cout << ErrorJson(code).dump() << '\n';
  } catch (...) {
    // The normal path uses only a fixed, small JSON object. This fallback
    // avoids writing exception detail or input data to diagnostics.
    std::cout << "{\"result_schema_version\":1,\"status\":\"error\","
                 "\"error\":\"output_failure\",\"safety_verdict\":\"UNKNOWN\"}\n";
  }
}

class DuplicateKeyAndFloatGuard final : public nlohmann::json_sax<Json> {
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
  bool number_float(number_float_t, const string_t&) override {
    return Reject("json_float");
  }
  bool string(string_t&) override { return true; }
  bool binary(binary_t&) override { return Reject("json_binary"); }
  bool start_object(std::size_t) override {
    if (frames_.size() >= kMaxJsonDepth) return Reject("json_depth_limit");
    frames_.push_back(Frame{true, {}});
    return true;
  }
  bool key(string_t& value) override {
    if (frames_.empty() || !frames_.back().is_object) return Reject("json_invalid_key");
    if (!frames_.back().keys.insert(value).second) return Reject("json_duplicate_key");
    return true;
  }
  bool end_object() override {
    if (frames_.empty() || !frames_.back().is_object) return Reject("json_invalid_object");
    frames_.pop_back();
    return true;
  }
  bool start_array(std::size_t) override {
    if (frames_.size() >= kMaxJsonDepth) return Reject("json_depth_limit");
    frames_.push_back(Frame{false, {}});
    return true;
  }
  bool end_array() override {
    if (frames_.empty() || frames_.back().is_object) return Reject("json_invalid_array");
    frames_.pop_back();
    return true;
  }
  bool parse_error(std::size_t, const std::string&,
                   const nlohmann::detail::exception&) override {
    if (error_.empty()) error_ = "json_syntax";
    return false;
  }
  [[nodiscard]] std::string_view error() const noexcept { return error_; }

 private:
  struct Frame final {
    bool is_object;
    std::set<std::string, std::less<>> keys;
  };
  bool Reject(std::string_view code) {
    if (error_.empty()) error_ = code;
    return false;
  }
  std::vector<Frame> frames_;
  std::string_view error_;
};

std::string ReadBoundedPlanFile(const std::filesystem::path& path) {
  std::error_code ec;
  const auto status = std::filesystem::status(path, ec);
  if (ec || !std::filesystem::is_regular_file(status)) Fail("plan_file_unavailable");
  const auto bytes = std::filesystem::file_size(path, ec);
  if (ec) Fail("plan_file_unavailable");
  if (bytes > kMaxPlanJsonBytes) Fail("plan_too_large");

  std::ifstream input(path, std::ios::binary);
  if (!input) Fail("plan_file_unavailable");
  std::string text(static_cast<std::size_t>(bytes), '\0');
  if (bytes != 0) {
    input.read(text.data(), static_cast<std::streamsize>(bytes));
    if (input.gcount() != static_cast<std::streamsize>(bytes)) Fail("plan_read_failure");
  }
  char extra{};
  if (input.get(extra)) Fail("plan_changed_during_read");
  if (input.bad()) Fail("plan_read_failure");
  return text;
}

void CheckKeys(const Json& object, std::initializer_list<std::string_view> required) {
  if (!object.is_object()) Fail("plan_schema_invalid");
  for (const auto& item : object.items()) {
    if (std::find(required.begin(), required.end(), std::string_view(item.key())) == required.end())
      Fail("plan_unknown_key");
  }
  for (const auto key : required) {
    if (!object.contains(std::string(key))) Fail("plan_missing_key");
  }
}

std::uint32_t JsonU32(const Json& value) {
  if (value.is_number_unsigned()) {
    const auto number = value.get<std::uint64_t>();
    if (number <= std::numeric_limits<std::uint32_t>::max())
      return static_cast<std::uint32_t>(number);
  } else if (value.is_number_integer()) {
    const auto number = value.get<std::int64_t>();
    if (number >= 0 && static_cast<std::uint64_t>(number) <=
        std::numeric_limits<std::uint32_t>::max())
      return static_cast<std::uint32_t>(number);
  }
  Fail("plan_integer_invalid");
}

std::uint64_t DecimalU64(const Json& value, bool positive) {
  if (!value.is_string()) Fail("plan_u64_must_be_decimal_string");
  const auto text = value.get<std::string>();
  if (text.empty() || (text.size() > 1 && text.front() == '0'))
    Fail("plan_decimal_noncanonical");
  for (const unsigned char c : text) {
    if (c < '0' || c > '9') Fail("plan_decimal_noncanonical");
  }
  std::uint64_t parsed_value = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), parsed_value, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    Fail("plan_u64_out_of_range");
  if (positive && parsed_value == 0) Fail("plan_value_must_be_positive");
  return parsed_value;
}

template <std::size_t N>
std::array<std::uint8_t, N> LowerHex(const Json& value) {
  if (!value.is_string()) Fail("plan_hex_must_be_string");
  const auto hex = value.get<std::string>();
  if (hex.size() != N * 2) Fail("plan_hex_width_invalid");
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  std::array<std::uint8_t, N> result{};
  for (std::size_t i = 0; i < N; ++i) {
    const auto high = nibble(hex[2 * i]);
    const auto low = nibble(hex[2 * i + 1]);
    if (high < 0 || low < 0) Fail("plan_hex_not_lowercase");
    result[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return result;
}

std::uint64_t PlanExtent(const std::vector<ProducerSpec>& producers) {
  constexpr std::uint64_t kHeader = 80;
  constexpr std::uint64_t kTerminal = 17;
  constexpr std::uint64_t kProducerEnvelope = 13;
  constexpr std::uint64_t kSlot = 51;
  constexpr std::uint64_t kProducerSeal = 26;
  std::uint64_t total = kHeader + kTerminal;
  for (const auto& producer : producers) {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    if (total > maximum - kProducerEnvelope - kProducerSeal)
      Fail("plan_extent_overflow");
    const auto remaining = maximum - total - kProducerEnvelope - kProducerSeal;
    if (producer.event_capacity > remaining / kSlot) Fail("plan_extent_overflow");
    total += kProducerEnvelope + producer.event_capacity * kSlot + kProducerSeal;
  }
  return total;
}

RunPlan ParsePlan(std::string_view source) {
  DuplicateKeyAndFloatGuard guard;
  if (!Json::sax_parse(source.begin(), source.end(), &guard))
    Fail(guard.error().empty() ? std::string_view("plan_json_invalid") : guard.error());
  const auto json = Json::parse(source);
  CheckKeys(json, {"schema_version", "epoch_id", "policy_digest", "budget_bytes", "producers"});
  if (JsonU32(json.at("schema_version")) != 1) Fail("plan_schema_version_unsupported");

  RunPlan plan;
  plan.epoch_id = LowerHex<16>(json.at("epoch_id"));
  plan.policy_digest = LowerHex<32>(json.at("policy_digest"));
  plan.budget_bytes = DecimalU64(json.at("budget_bytes"), true);
  if (plan.budget_bytes > kMaxRunBytes) Fail("plan_budget_exceeds_cap");

  const auto& producers = json.at("producers");
  if (!producers.is_array() || producers.empty()) Fail("plan_producers_invalid");
  if (plan.budget_bytes < 97 || producers.size() > (plan.budget_bytes - 97) / 90)
    Fail("plan_producer_count_exceeds_budget");

  std::set<std::pair<std::uint8_t, std::uint32_t>> seen;
  plan.producers.reserve(producers.size());
  for (const auto& item : producers) {
    CheckKeys(item, {"producer_owner", "producer_index", "event_capacity"});
    const auto owner_value = JsonU32(item.at("producer_owner"));
    if (owner_value < 1 || owner_value > 5) Fail("plan_owner_invalid");
    const auto index = JsonU32(item.at("producer_index"));
    const auto capacity = DecimalU64(item.at("event_capacity"), true);
    if (capacity > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
      Fail("plan_capacity_out_of_range");
    const auto owner = static_cast<std::uint8_t>(owner_value);
    if (!seen.emplace(owner, index).second) Fail("plan_duplicate_producer");
    plan.producers.push_back(ProducerSpec{static_cast<ProducerOwner>(owner), index, capacity});
  }

  const auto expected_bytes = PlanExtent(plan.producers);
  if (expected_bytes >= kMaxRunBytes) Fail("plan_extent_exceeds_cap");
  if (expected_bytes > plan.budget_bytes) Fail("plan_budget_below_extent");
  return plan;
}

std::uint64_t FileSize(const std::filesystem::path& path, std::string_view error) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(std::filesystem::status(path, ec)) || ec)
    Fail(error);
  const auto bytes = std::filesystem::file_size(path, ec);
  if (ec) Fail(error);
  return bytes;
}

std::string_view ReadErrorName(history::ReadError error) noexcept {
  switch (error) {
    case history::ReadError::BadPlan: return "history_bad_plan";
    case history::ReadError::BadHeader: return "history_bad_header";
    case history::ReadError::BadEncoding: return "history_bad_encoding";
    case history::ReadError::IncompleteEvidence: return "history_incomplete";
    case history::ReadError::ReadFailure: return "history_read_failure";
  }
  return "history_read_failure";
}

int Run(const std::filesystem::path& plan_path,
        const std::filesystem::path& history_path) {
  const auto plan_text = ReadBoundedPlanFile(plan_path);
  const auto plan = ParsePlan(plan_text);
  const auto expected_bytes = PlanExtent(plan.producers);
  const auto history_bytes = FileSize(history_path, "history_file_unavailable");
  if (history_bytes != expected_bytes) Fail("history_size_mismatch");

  std::ifstream history_input(history_path, std::ios::binary);
  if (!history_input) Fail("history_file_unavailable");
  auto parsed = history::ReadStrictHistory(history_input, plan);
  if (const auto* error = std::get_if<history::ReadError>(&parsed))
    Fail(ReadErrorName(*error));
  const auto& snapshot = std::get<EventSnapshotV1>(parsed);
  const auto report = validation::ValidateHistorySnapshot(snapshot, plan);
  if (!report.complete()) Fail("history_incomplete");

  const Json result{
      {"result_schema_version", 1},
      {"history_schema_version", snapshot.schema_version},
      {"status", "structurally_complete"},
      {"safety_verdict", "UNKNOWN"},
      {"event_count", std::to_string(report.published_events)},
      {"history_bytes", std::to_string(report.snapshot_bytes)},
      {"budget_bytes", std::to_string(snapshot.budget_bytes)},
  };
  std::cout << result.dump() << '\n';
  return std::cout ? 0 : 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    EmitError("usage");
    return 64;
  }
  try {
    return Run(argv[1], argv[2]);
  } catch (const CliFailure& failure) {
    EmitError(failure.code);
    return failure.exit_code;
  } catch (...) {
    EmitError("internal_error");
    return 2;
  }
}
