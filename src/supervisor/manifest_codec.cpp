#include "supervisor/manifest_codec.h"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <charconv>
#include <initializer_list>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <vector>

namespace rateguard::supervisor {
namespace {

using Json = nlohmann::json;
constexpr std::size_t kMaxJsonDepth = 6;
constexpr std::uint32_t kNanosPerSecond = 1'000'000'000U;
constexpr std::int32_t kClockMonotonic = 1;

struct Failure final { ManifestCodecError error; };
[[noreturn]] void Fail(ManifestCodecError error) { throw Failure{error}; }

bool AllZero(const auto& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b == 0; });
}

class StrictJsonGuard final : public nlohmann::json_sax<Json> {
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
  bool number_float(number_float_t, const string_t&) override { return Reject(ManifestCodecError::InvalidJson); }
  bool string(string_t&) override { return true; }
  bool binary(binary_t&) override { return Reject(ManifestCodecError::InvalidJson); }
  bool start_object(std::size_t) override {
    if (frames_.size() >= kMaxJsonDepth) return Reject(ManifestCodecError::InvalidJson);
    frames_.push_back(Frame{true, {}}); return true;
  }
  bool key(string_t& value) override {
    if (frames_.empty() || !frames_.back().object) return Reject(ManifestCodecError::InvalidJson);
    if (!frames_.back().keys.insert(value).second) return Reject(ManifestCodecError::DuplicateKey);
    return true;
  }
  bool end_object() override {
    if (frames_.empty() || !frames_.back().object) return Reject(ManifestCodecError::InvalidJson);
    frames_.pop_back(); return true;
  }
  bool start_array(std::size_t) override {
    if (frames_.size() >= kMaxJsonDepth) return Reject(ManifestCodecError::InvalidJson);
    frames_.push_back(Frame{false, {}}); return true;
  }
  bool end_array() override {
    if (frames_.empty() || frames_.back().object) return Reject(ManifestCodecError::InvalidJson);
    frames_.pop_back(); return true;
  }
  bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) override {
    if (!error_) error_ = ManifestCodecError::InvalidJson;
    return false;
  }
  [[nodiscard]] ManifestCodecError error() const noexcept {
    return error_.value_or(ManifestCodecError::InvalidJson);
  }
  [[nodiscard]] bool has_error() const noexcept { return error_.has_value(); }
 private:
  struct Frame { bool object; std::set<std::string, std::less<>> keys; };
  bool Reject(ManifestCodecError error) {
    if (!error_) error_ = error;
    return false;
  }
  std::vector<Frame> frames_;
  std::optional<ManifestCodecError> error_;
};

void CheckKeys(const Json& value, std::initializer_list<std::string_view> keys) {
  if (!value.is_object()) Fail(ManifestCodecError::InvalidValue);
  for (const auto& item : value.items()) {
    if (std::find(keys.begin(), keys.end(), std::string_view(item.key())) == keys.end())
      Fail(ManifestCodecError::UnknownKey);
  }
  for (const auto key : keys) if (!value.contains(std::string(key))) Fail(ManifestCodecError::MissingKey);
}

std::string Hex(const auto& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    result[2 * i] = digits[bytes[i] >> 4];
    result[2 * i + 1] = digits[bytes[i] & 0x0f];
  }
  return result;
}

template <std::size_t N>
std::array<std::uint8_t, N> ParseHex(const Json& value) {
  if (!value.is_string()) Fail(ManifestCodecError::InvalidValue);
  const auto text = value.get<std::string>();
  if (text.size() != N * 2) Fail(ManifestCodecError::InvalidValue);
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  std::array<std::uint8_t, N> out{};
  for (std::size_t i = 0; i < N; ++i) {
    const int hi = nibble(text[2 * i]), lo = nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) Fail(ManifestCodecError::InvalidValue);
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return out;
}

std::string U64(std::uint64_t value) { return std::to_string(value); }
std::string I64(std::int64_t value) { return std::to_string(value); }

std::uint64_t ParseU64(const Json& value) {
  if (!value.is_string()) Fail(ManifestCodecError::InvalidValue);
  const auto text = value.get<std::string>();
  if (text.empty() || (text.size() > 1 && text.front() == '0')) Fail(ManifestCodecError::InvalidValue);
  for (unsigned char c : text) if (c < '0' || c > '9') Fail(ManifestCodecError::InvalidValue);
  std::uint64_t out{};
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) Fail(ManifestCodecError::InvalidValue);
  return out;
}

std::int64_t ParseI64(const Json& value) {
  if (!value.is_string()) Fail(ManifestCodecError::InvalidValue);
  const auto text = value.get<std::string>();
  if (text.empty() || text == "-0" || (text.size() > 1 && text[0] == '0') ||
      (text.size() > 2 && text[0] == '-' && text[1] == '0')) Fail(ManifestCodecError::InvalidValue);
  const std::size_t start = text.front() == '-' ? 1 : 0;
  if (start == text.size()) Fail(ManifestCodecError::InvalidValue);
  for (std::size_t i = start; i < text.size(); ++i)
    if (text[i] < '0' || text[i] > '9') Fail(ManifestCodecError::InvalidValue);
  std::int64_t out{};
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) Fail(ManifestCodecError::InvalidValue);
  return out;
}

std::uint32_t U32(const Json& value) {
  if (value.is_number_unsigned()) {
    const auto n = value.get<std::uint64_t>();
    if (n <= std::numeric_limits<std::uint32_t>::max()) return static_cast<std::uint32_t>(n);
  } else if (value.is_number_integer()) {
    const auto n = value.get<std::int64_t>();
    if (n >= 0 && static_cast<std::uint64_t>(n) <= std::numeric_limits<std::uint32_t>::max())
      return static_cast<std::uint32_t>(n);
  }
  Fail(ManifestCodecError::InvalidValue);
}

std::int32_t I32(const Json& value) {
  if (value.is_number_unsigned()) {
    const auto n = value.get<std::uint64_t>();
    if (n <= static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max()))
      return static_cast<std::int32_t>(n);
  } else if (value.is_number_integer()) {
    const auto n = value.get<std::int64_t>();
    if (n >= std::numeric_limits<std::int32_t>::min() && n <= std::numeric_limits<std::int32_t>::max())
      return static_cast<std::int32_t>(n);
  }
  Fail(ManifestCodecError::InvalidValue);
}

const char* RoleName(ParticipantRole role) {
  switch (role) {
    case ParticipantRole::Authority: return "AUTHORITY";
    case ParticipantRole::Replica: return "REPLICA";
    case ParticipantRole::Adapter: return "ADAPTER";
    case ParticipantRole::Witness: return "WITNESS";
  }
  Fail(ManifestCodecError::InvalidValue);
}
ParticipantRole ParseRole(const Json& value) {
  if (!value.is_string()) Fail(ManifestCodecError::InvalidValue);
  const auto role = value.get<std::string>();
  if (role == "AUTHORITY") return ParticipantRole::Authority;
  if (role == "REPLICA") return ParticipantRole::Replica;
  if (role == "ADAPTER") return ParticipantRole::Adapter;
  if (role == "WITNESS") return ParticipantRole::Witness;
  Fail(ManifestCodecError::InvalidValue);
}

const char* PhaseName(ManifestPhase phase) {
  switch (phase) {
    case ManifestPhase::Prepared: return "PREPARED";
    case ManifestPhase::Active: return "ACTIVE";
    case ManifestPhase::Draining: return "DRAINING";
    case ManifestPhase::Closed: return "CLOSED";
  }
  Fail(ManifestCodecError::InvalidValue);
}
ManifestPhase ParsePhase(const Json& value) {
  if (!value.is_string()) Fail(ManifestCodecError::InvalidValue);
  const auto phase = value.get<std::string>();
  if (phase == "PREPARED") return ManifestPhase::Prepared;
  if (phase == "ACTIVE") return ManifestPhase::Active;
  if (phase == "DRAINING") return ManifestPhase::Draining;
  if (phase == "CLOSED") return ManifestPhase::Closed;
  Fail(ManifestCodecError::InvalidValue);
}

Json ClockJson(const platform::ClockIdentity& c) {
  return Json{{"boot_uuid", Hex(c.boot_uuid)},
              {"boottime_offset_nanoseconds", c.boottime_offset_nanoseconds},
              {"boottime_offset_seconds", I64(c.boottime_offset_seconds)},
              {"clock_id", c.clock_id},
              {"monotonic_offset_nanoseconds", c.monotonic_offset_nanoseconds},
              {"monotonic_offset_seconds", I64(c.monotonic_offset_seconds)},
              {"namespace_device", U64(c.namespace_device)},
              {"namespace_inode", U64(c.namespace_inode)}};
}
platform::ClockIdentity ParseClock(const Json& j) {
  CheckKeys(j, {"boot_uuid", "boottime_offset_nanoseconds", "boottime_offset_seconds", "clock_id",
                "monotonic_offset_nanoseconds", "monotonic_offset_seconds", "namespace_device", "namespace_inode"});
  platform::ClockIdentity c{};
  c.boot_uuid = ParseHex<16>(j.at("boot_uuid"));
  c.namespace_device = ParseU64(j.at("namespace_device"));
  c.namespace_inode = ParseU64(j.at("namespace_inode"));
  c.monotonic_offset_seconds = ParseI64(j.at("monotonic_offset_seconds"));
  c.monotonic_offset_nanoseconds = U32(j.at("monotonic_offset_nanoseconds"));
  c.boottime_offset_seconds = ParseI64(j.at("boottime_offset_seconds"));
  c.boottime_offset_nanoseconds = U32(j.at("boottime_offset_nanoseconds"));
  c.clock_id = I32(j.at("clock_id"));
  if (AllZero(c.boot_uuid) || c.namespace_device == 0 || c.namespace_inode == 0 ||
      c.clock_id != kClockMonotonic || c.monotonic_offset_nanoseconds >= kNanosPerSecond ||
      c.boottime_offset_nanoseconds >= kNanosPerSecond) Fail(ManifestCodecError::InvalidValue);
  return c;
}

Json ParticipantJson(const Participant& p) {
  return Json{{"clock_identity", ClockJson(p.clock_identity)},
              {"incarnation", Hex(p.incarnation)},
              {"participant_id", p.participant_id},
              {"process", Json{{"container_id", p.process.container_id},
                               {"pid", U64(p.process.pid)},
                               {"pid_start_ticks", U64(p.process.pid_start_ticks)}}},
              {"role", RoleName(p.role)},
              {"slot_id", p.slot_id}};
}
Participant ParseParticipant(const Json& j) {
  CheckKeys(j, {"clock_identity", "incarnation", "participant_id", "process", "role", "slot_id"});
  Participant p{};
  p.role = ParseRole(j.at("role"));
  p.slot_id = U32(j.at("slot_id"));
  if (!j.at("participant_id").is_string()) Fail(ManifestCodecError::InvalidValue);
  p.participant_id = j.at("participant_id").get<std::string>();
  p.incarnation = ParseHex<16>(j.at("incarnation"));
  CheckKeys(j.at("process"), {"container_id", "pid", "pid_start_ticks"});
  const auto& proc = j.at("process");
  if (!proc.at("container_id").is_string()) Fail(ManifestCodecError::InvalidValue);
  p.process.container_id = proc.at("container_id").get<std::string>();
  p.process.pid = ParseU64(proc.at("pid"));
  p.process.pid_start_ticks = ParseU64(proc.at("pid_start_ticks"));
  p.clock_identity = ParseClock(j.at("clock_identity"));
  return p;
}

Json PayloadJson(const ManifestV1& m) {
  if (m.generation == 0 || AllZero(m.transition_operation_id)) Fail(ManifestCodecError::InvalidValue);
  if (m.candidate.participants.size() > kMaxParticipants || ValidateEpochCandidate(m.candidate))
    Fail(ManifestCodecError::InvalidValue);
  const auto& c = m.candidate.clock_identity;
  if (AllZero(c.boot_uuid) || c.namespace_device == 0 || c.namespace_inode == 0 || c.clock_id != kClockMonotonic ||
      c.monotonic_offset_nanoseconds >= kNanosPerSecond || c.boottime_offset_nanoseconds >= kNanosPerSecond)
    Fail(ManifestCodecError::InvalidValue);
  std::vector<Participant> participants = m.candidate.participants;
  std::sort(participants.begin(), participants.end(), [](const Participant& a, const Participant& b) {
    if (a.role != b.role) return static_cast<std::uint8_t>(a.role) < static_cast<std::uint8_t>(b.role);
    if (a.participant_id != b.participant_id) return a.participant_id < b.participant_id;
    return a.slot_id < b.slot_id;
  });
  Json participant_json = Json::array();
  for (const auto& p : participants) participant_json.push_back(ParticipantJson(p));
  return Json{{"authority_incarnation", Hex(m.candidate.authority_incarnation)},
              {"clock_identity", ClockJson(c)},
              {"epoch_id", Hex(m.candidate.epoch_id)},
              {"generation", U64(m.generation)},
              {"participants", std::move(participant_json)},
              {"phase", PhaseName(m.phase)},
              {"policy_digest", Hex(m.candidate.policy_digest)},
              {"schema_version", 1},
              {"transition_operation_id", Hex(m.transition_operation_id)}};
}

std::array<std::uint8_t, 32> Sha256(std::string_view data) {
  std::array<std::uint8_t, 32> digest{};
  unsigned int length = 0;
  if (EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 || length != digest.size())
    Fail(ManifestCodecError::DigestFailure);
  return digest;
}

Json ParseJson(std::string_view input) {
  StrictJsonGuard guard;
  if (!Json::sax_parse(input.begin(), input.end(), &guard)) Fail(guard.error());
  try { return Json::parse(input); }
  catch (...) { Fail(ManifestCodecError::InvalidJson); }
}

ManifestV1 ParsePayload(const Json& j) {
  CheckKeys(j, {"authority_incarnation", "clock_identity", "epoch_id", "generation", "participants",
                "phase", "policy_digest", "schema_version", "transition_operation_id"});
  const auto& schema = j.at("schema_version");
  const bool schema_one = schema.is_number_unsigned() ? schema.get<std::uint64_t>() == 1
      : schema.is_number_integer() && schema.get<std::int64_t>() == 1;
  if (!schema_one) Fail(ManifestCodecError::UnsupportedSchema);
  ManifestV1 m;
  m.candidate.epoch_id = ParseHex<16>(j.at("epoch_id"));
  m.candidate.authority_incarnation = ParseHex<16>(j.at("authority_incarnation"));
  m.candidate.policy_digest = ParseHex<32>(j.at("policy_digest"));
  m.candidate.clock_identity = ParseClock(j.at("clock_identity"));
  m.phase = ParsePhase(j.at("phase"));
  m.generation = ParseU64(j.at("generation"));
  m.transition_operation_id = ParseHex<16>(j.at("transition_operation_id"));
  if (m.generation == 0 || AllZero(m.transition_operation_id)) Fail(ManifestCodecError::InvalidValue);
  const auto& ps = j.at("participants");
  if (!ps.is_array() || ps.empty() || ps.size() > kMaxParticipants) Fail(ManifestCodecError::InvalidValue);
  m.candidate.participants.reserve(ps.size());
  for (const auto& item : ps) m.candidate.participants.push_back(ParseParticipant(item));
  if (ValidateEpochCandidate(m.candidate)) Fail(ManifestCodecError::InvalidValue);
  return m;
}

}  // namespace

ManifestEncodeResult EncodeManifestV1(const ManifestV1& manifest) noexcept {
  try {
    const auto payload = PayloadJson(manifest).dump(-1, ' ', false, Json::error_handler_t::strict);
    if (payload.size() > kMaxManifestBytes) return ManifestCodecError::TooLarge;
    const auto digest = Sha256(payload);
    const Json envelope{{"manifest", Json::parse(payload)}, {"sha256", Hex(digest)}};
    auto encoded = envelope.dump(-1, ' ', false, Json::error_handler_t::strict);
    if (encoded.size() > kMaxManifestBytes) return ManifestCodecError::TooLarge;
    return encoded;
  } catch (const Failure& f) { return f.error; }
    catch (...) { return ManifestCodecError::AllocationFailure; }
}

ManifestDecodeResult DecodeManifestV1(std::string_view envelope) noexcept {
  if (envelope.size() > kMaxManifestBytes) return ManifestCodecError::TooLarge;
  try {
    const auto root = ParseJson(envelope);
    CheckKeys(root, {"manifest", "sha256"});
    const auto& digest_field = root.at("sha256");
    if (!digest_field.is_string()) return ManifestCodecError::InvalidValue;
    const auto expected = ParseHex<32>(digest_field);
    const auto manifest = ParsePayload(root.at("manifest"));
    const auto payload_text = PayloadJson(manifest).dump(-1, ' ', false, Json::error_handler_t::strict);
    if (Sha256(payload_text) != expected) return ManifestCodecError::DigestMismatch;
    const auto canonical = EncodeManifestV1(manifest);
    if (const auto* error = std::get_if<ManifestCodecError>(&canonical)) return *error;
    if (std::get<std::string>(canonical) != envelope) return ManifestCodecError::NonCanonical;
    return manifest;
  } catch (const Failure& f) { return f.error; }
    catch (...) { return ManifestCodecError::AllocationFailure; }
}

ManifestDigestResult ManifestDigestV1(const ManifestV1& manifest) noexcept {
  try {
    const auto payload = PayloadJson(manifest).dump(-1, ' ', false, Json::error_handler_t::strict);
    if (payload.size() > kMaxManifestBytes) return ManifestCodecError::TooLarge;
    return Sha256(payload);
  } catch (const Failure& f) { return f.error; }
    catch (...) { return ManifestCodecError::AllocationFailure; }
}

}  // namespace rateguard::supervisor
