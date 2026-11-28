#include "supervisor/bootstrap_inventory.h"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <charconv>
#include <initializer_list>
#include <limits>
#include <optional>
#include <set>
#include <system_error>

namespace rateguard::supervisor {

struct BootstrapCodecAccess {
  static BootstrapInventory Make(std::array<std::uint8_t, 16> domain, std::uint64_t revision,
                                 EpochId epoch, IncarnationId authority, PolicyDigest digest,
                                 platform::ClockIdentity clock,
                                 std::shared_ptr<const std::vector<BootstrapRecord>> records,
                                 bool recovery, BootstrapError reason) noexcept {
    return BootstrapInventory(domain, revision, epoch, authority, digest, clock,
                              std::move(records), recovery, reason);
  }
};

namespace {
using Json = nlohmann::json;
constexpr std::uint32_t kNanosPerSecond = 1'000'000'000U;
constexpr std::int32_t kClockMonotonic = 1;
constexpr std::size_t kMaxDepth = 6;

struct Failure { BootstrapError error; };
[[noreturn]] void Fail(BootstrapError error) { throw Failure{error}; }

bool AllZero(const auto& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) { return byte == 0; });
}

bool ValidClock(const platform::ClockIdentity& c) noexcept {
  return !AllZero(c.boot_uuid) && c.namespace_device != 0 && c.namespace_inode != 0 &&
      c.clock_id == kClockMonotonic && c.monotonic_offset_nanoseconds < kNanosPerSecond &&
      c.boottime_offset_nanoseconds < kNanosPerSecond;
}

bool ValidParticipantId(std::string_view id) noexcept {
  if (id.empty() || id.size() > 64) return false;
  for (unsigned char c : id)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  return true;
}

bool ValidContainerId(std::string_view id) noexcept {
  if (id.size() != 64) return false;
  for (unsigned char c : id)
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}

bool PlannedRosterValid(const BootstrapPlan& plan) {
  if (AllZero(plan.domain_id) || AllZero(plan.epoch_id) || AllZero(plan.authority_incarnation) || AllZero(plan.policy_digest) ||
      !ValidClock(plan.expected_clock_identity) || plan.participants.empty() ||
      plan.participants.size() > kMaxParticipants) return false;
  std::size_t authorities = 0, replicas = 0, adapters = 0, witnesses = 0;
  std::set<std::pair<std::uint8_t, std::string>> ids;
  std::set<std::string> containers;
  std::set<std::uint32_t> replica_slots;
  for (const auto& p : plan.participants) {
    if (!ValidParticipantId(p.participant_id) || !ValidContainerId(p.container_id) ||
        AllZero(p.incarnation) || !ids.emplace(static_cast<std::uint8_t>(p.role), p.participant_id).second ||
        !containers.insert(p.container_id).second) return false;
    switch (p.role) {
      case ParticipantRole::Authority:
        ++authorities;
        if (p.slot_id != 0 || p.incarnation != plan.authority_incarnation) return false;
        break;
      case ParticipantRole::Replica:
        ++replicas;
        if (!replica_slots.insert(p.slot_id).second) return false;
        break;
      case ParticipantRole::Adapter:
        ++adapters;
        if (p.slot_id != 0) return false;
        break;
      case ParticipantRole::Witness:
        ++witnesses;
        if (p.slot_id != 0) return false;
        break;
      default: return false;
    }
  }
  return authorities == 1 && witnesses == 1 && adapters > 0 && replicas > 0 && replicas <= kMaxReplicaSlots;
}

bool ValidBootstrapError(BootstrapError error) noexcept {
  return static_cast<std::uint8_t>(error) <= static_cast<std::uint8_t>(BootstrapError::RevisionExhausted);
}

class JsonGuard final : public nlohmann::json_sax<Json> {
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
  bool number_float(number_float_t, const string_t&) override { return Reject(BootstrapError::InvalidEncoding); }
  bool string(string_t&) override { return true; }
  bool binary(binary_t&) override { return Reject(BootstrapError::InvalidEncoding); }
  bool start_object(std::size_t) override {
    if (stack_.size() >= kMaxDepth) return Reject(BootstrapError::InvalidEncoding);
    stack_.push_back(Frame{true, {}}); return true;
  }
  bool key(string_t& key) override {
    if (stack_.empty() || !stack_.back().object) return Reject(BootstrapError::InvalidEncoding);
    if (!stack_.back().keys.insert(key).second) return Reject(BootstrapError::DuplicateKey);
    return true;
  }
  bool end_object() override {
    if (stack_.empty() || !stack_.back().object) return Reject(BootstrapError::InvalidEncoding);
    stack_.pop_back(); return true;
  }
  bool start_array(std::size_t) override {
    if (stack_.size() >= kMaxDepth) return Reject(BootstrapError::InvalidEncoding);
    stack_.push_back(Frame{false, {}}); return true;
  }
  bool end_array() override {
    if (stack_.empty() || stack_.back().object) return Reject(BootstrapError::InvalidEncoding);
    stack_.pop_back(); return true;
  }
  bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) override {
    if (!error_) error_ = BootstrapError::InvalidEncoding;
    return false;
  }
  [[nodiscard]] BootstrapError error() const noexcept { return error_.value_or(BootstrapError::InvalidEncoding); }
 private:
  struct Frame { bool object; std::set<std::string, std::less<>> keys; };
  bool Reject(BootstrapError e) { if (!error_) error_ = e; return false; }
  std::vector<Frame> stack_;
  std::optional<BootstrapError> error_;
};

void CheckKeys(const Json& value, std::initializer_list<std::string_view> required) {
  if (!value.is_object()) Fail(BootstrapError::InvalidEncoding);
  for (const auto& item : value.items())
    if (std::find(required.begin(), required.end(), std::string_view(item.key())) == required.end())
      Fail(BootstrapError::UnknownKey);
  for (auto key : required) if (!value.contains(std::string(key))) Fail(BootstrapError::MissingKey);
}

std::string Hex(const auto& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(bytes.size() * 2, '0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    result[2 * i] = digits[bytes[i] >> 4]; result[2 * i + 1] = digits[bytes[i] & 15];
  }
  return result;
}

template <std::size_t N> std::array<std::uint8_t, N> ParseHex(const Json& value) {
  if (!value.is_string()) Fail(BootstrapError::InvalidEncoding);
  const auto text = value.get<std::string>();
  if (text.size() != N * 2) Fail(BootstrapError::InvalidEncoding);
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  std::array<std::uint8_t, N> result{};
  for (std::size_t i = 0; i < N; ++i) {
    int hi = nibble(text[2 * i]), lo = nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) Fail(BootstrapError::InvalidEncoding);
    result[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return result;
}

std::string U64(std::uint64_t value) { return std::to_string(value); }
std::string I64(std::int64_t value) { return std::to_string(value); }
std::uint64_t ParseU64(const Json& value) {
  if (!value.is_string()) Fail(BootstrapError::InvalidEncoding);
  const auto text = value.get<std::string>();
  if (text.empty() || (text.size() > 1 && text.front() == '0')) Fail(BootstrapError::InvalidEncoding);
  for (unsigned char c : text) if (c < '0' || c > '9') Fail(BootstrapError::InvalidEncoding);
  std::uint64_t out{};
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) Fail(BootstrapError::InvalidEncoding);
  return out;
}
std::int64_t ParseI64(const Json& value) {
  if (!value.is_string()) Fail(BootstrapError::InvalidEncoding);
  const auto text = value.get<std::string>();
  if (text.empty() || text == "-0" || (text.size() > 1 && text[0] == '0') ||
      (text.size() > 2 && text[0] == '-' && text[1] == '0')) Fail(BootstrapError::InvalidEncoding);
  const std::size_t begin = text.front() == '-' ? 1 : 0;
  if (begin == text.size()) Fail(BootstrapError::InvalidEncoding);
  for (std::size_t i = begin; i < text.size(); ++i)
    if (text[i] < '0' || text[i] > '9') Fail(BootstrapError::InvalidEncoding);
  std::int64_t out{};
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) Fail(BootstrapError::InvalidEncoding);
  return out;
}
std::uint32_t U32(const Json& value) {
  std::uint64_t n{};
  if (value.is_number_unsigned()) n = value.get<std::uint64_t>();
  else if (value.is_number_integer()) {
    const auto signed_n = value.get<std::int64_t>();
    if (signed_n < 0) Fail(BootstrapError::InvalidEncoding);
    n = static_cast<std::uint64_t>(signed_n);
  } else Fail(BootstrapError::InvalidEncoding);
  if (n > std::numeric_limits<std::uint32_t>::max()) Fail(BootstrapError::InvalidEncoding);
  return static_cast<std::uint32_t>(n);
}
std::int32_t I32(const Json& value) {
  std::int64_t n{};
  if (value.is_number_unsigned()) {
    const auto u = value.get<std::uint64_t>();
    if (u > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) Fail(BootstrapError::InvalidEncoding);
    n = static_cast<std::int64_t>(u);
  } else if (value.is_number_integer()) n = value.get<std::int64_t>();
  else Fail(BootstrapError::InvalidEncoding);
  if (n < std::numeric_limits<std::int32_t>::min() || n > std::numeric_limits<std::int32_t>::max())
    Fail(BootstrapError::InvalidEncoding);
  return static_cast<std::int32_t>(n);
}

const char* RoleName(ParticipantRole role) {
  switch (role) {
    case ParticipantRole::Authority: return "AUTHORITY";
    case ParticipantRole::Replica: return "REPLICA";
    case ParticipantRole::Adapter: return "ADAPTER";
    case ParticipantRole::Witness: return "WITNESS";
  }
  Fail(BootstrapError::InvalidEncoding);
}
ParticipantRole ParseRole(const Json& value) {
  if (!value.is_string()) Fail(BootstrapError::InvalidEncoding);
  const auto role = value.get<std::string>();
  if (role == "AUTHORITY") return ParticipantRole::Authority;
  if (role == "REPLICA") return ParticipantRole::Replica;
  if (role == "ADAPTER") return ParticipantRole::Adapter;
  if (role == "WITNESS") return ParticipantRole::Witness;
  Fail(BootstrapError::InvalidEncoding);
}

Json ClockJson(const platform::ClockIdentity& c) {
  return Json{{"boot_uuid", Hex(c.boot_uuid)}, {"boottime_offset_nanoseconds", c.boottime_offset_nanoseconds},
      {"boottime_offset_seconds", I64(c.boottime_offset_seconds)}, {"clock_id", c.clock_id},
      {"monotonic_offset_nanoseconds", c.monotonic_offset_nanoseconds},
      {"monotonic_offset_seconds", I64(c.monotonic_offset_seconds)},
      {"namespace_device", U64(c.namespace_device)}, {"namespace_inode", U64(c.namespace_inode)}};
}
platform::ClockIdentity ParseClock(const Json& j) {
  CheckKeys(j, {"boot_uuid", "boottime_offset_nanoseconds", "boottime_offset_seconds", "clock_id",
      "monotonic_offset_nanoseconds", "monotonic_offset_seconds", "namespace_device", "namespace_inode"});
  platform::ClockIdentity c{};
  c.boot_uuid = ParseHex<16>(j.at("boot_uuid")); c.namespace_device = ParseU64(j.at("namespace_device"));
  c.namespace_inode = ParseU64(j.at("namespace_inode"));
  c.monotonic_offset_seconds = ParseI64(j.at("monotonic_offset_seconds"));
  c.monotonic_offset_nanoseconds = U32(j.at("monotonic_offset_nanoseconds"));
  c.boottime_offset_seconds = ParseI64(j.at("boottime_offset_seconds"));
  c.boottime_offset_nanoseconds = U32(j.at("boottime_offset_nanoseconds")); c.clock_id = I32(j.at("clock_id"));
  if (!ValidClock(c)) Fail(BootstrapError::InvalidEncoding);
  return c;
}

Json RecordJson(const BootstrapRecord& r) {
  Json process = nullptr;
  Json clock = nullptr;
  if (r.identity_recorded) {
    process = Json{{"pid", U64(r.pid)}, {"pid_start_ticks", U64(r.pid_start_ticks)}};
    clock = ClockJson(r.clock_identity);
  }
  return Json{{"clock_identity", std::move(clock)}, {"container_id", r.planned.container_id},
      {"identity_recorded", r.identity_recorded}, {"incarnation", Hex(r.planned.incarnation)},
      {"participant_id", r.planned.participant_id}, {"process", std::move(process)},
      {"role", RoleName(r.planned.role)}, {"slot_id", r.planned.slot_id}};
}

Json PayloadJson(const BootstrapInventory& i) {
  Json rows = Json::array();
  for (const auto& record : i.records()) rows.push_back(RecordJson(record));
  return Json{{"authority_incarnation", Hex(i.authority_incarnation())},
      {"domain_id", Hex(i.domain_id())},
      {"epoch_id", Hex(i.epoch_id())}, {"expected_clock_identity", ClockJson(i.expected_clock_identity())},
      {"participants", std::move(rows)}, {"policy_digest", Hex(i.policy_digest())},
      {"recovery_reason", static_cast<std::uint8_t>(i.recovery_reason())},
      {"recovery_required", i.recovery_required()}, {"revision", U64(i.revision())}, {"schema_version", 1}};
}

std::array<std::uint8_t, 32> Sha256(std::string_view text) {
  std::array<std::uint8_t, 32> out{}; unsigned int length = 0;
  if (EVP_Digest(text.data(), text.size(), out.data(), &length, EVP_sha256(), nullptr) != 1 || length != out.size())
    Fail(BootstrapError::DigestFailure);
  return out;
}

Json ParseJson(std::string_view text) {
  JsonGuard guard;
  if (!Json::sax_parse(text.begin(), text.end(), &guard)) Fail(guard.error());
  try { return Json::parse(text); } catch (...) { Fail(BootstrapError::InvalidEncoding); }
}

BootstrapInventory ParsePayload(const Json& j) {
  CheckKeys(j, {"authority_incarnation", "domain_id", "epoch_id", "expected_clock_identity", "participants", "policy_digest",
      "recovery_reason", "recovery_required", "revision", "schema_version"});
  const auto& version = j.at("schema_version");
  bool v1 = version.is_number_unsigned() ? version.get<std::uint64_t>() == 1
      : version.is_number_integer() && version.get<std::int64_t>() == 1;
  if (!v1) Fail(BootstrapError::UnsupportedSchema);
  const auto& recovery = j.at("recovery_required");
  if (!recovery.is_boolean()) Fail(BootstrapError::InvalidEncoding);
  const auto reason_num = U32(j.at("recovery_reason"));
  if (reason_num > static_cast<std::uint32_t>(BootstrapError::RevisionExhausted)) Fail(BootstrapError::InvalidEncoding);
  const auto reason = static_cast<BootstrapError>(reason_num);
  const bool is_recovery = recovery.get<bool>();
  if (is_recovery != (reason != BootstrapError::None)) Fail(BootstrapError::InvalidEncoding);
  const auto& ps = j.at("participants");
  if (!ps.is_array() || ps.empty() || ps.size() > kMaxParticipants) Fail(BootstrapError::InvalidEncoding);
  BootstrapPlan plan;
  plan.domain_id = ParseHex<16>(j.at("domain_id"));
  plan.epoch_id = ParseHex<16>(j.at("epoch_id"));
  plan.authority_incarnation = ParseHex<16>(j.at("authority_incarnation"));
  plan.policy_digest = ParseHex<32>(j.at("policy_digest"));
  plan.expected_clock_identity = ParseClock(j.at("expected_clock_identity"));
  std::vector<BootstrapRecord> records;
  records.reserve(ps.size());
  for (const auto& p : ps) {
    CheckKeys(p, {"clock_identity", "container_id", "identity_recorded", "incarnation", "participant_id", "process", "role", "slot_id"});
    PlannedParticipant planned;
    planned.role = ParseRole(p.at("role")); planned.slot_id = U32(p.at("slot_id"));
    if (!p.at("participant_id").is_string() || !p.at("container_id").is_string()) Fail(BootstrapError::InvalidEncoding);
    planned.participant_id = p.at("participant_id").get<std::string>();
    planned.container_id = p.at("container_id").get<std::string>();
    planned.incarnation = ParseHex<16>(p.at("incarnation"));
    const auto& recorded = p.at("identity_recorded");
    if (!recorded.is_boolean()) Fail(BootstrapError::InvalidEncoding);
    const bool has_identity = recorded.get<bool>();
    BootstrapRecord record{planned, 0, 0, has_identity, {}};
    if (has_identity) {
      CheckKeys(p.at("process"), {"pid", "pid_start_ticks"});
      record.pid = ParseU64(p.at("process").at("pid"));
      record.pid_start_ticks = ParseU64(p.at("process").at("pid_start_ticks"));
      record.clock_identity = ParseClock(p.at("clock_identity"));
    } else if (!p.at("process").is_null() || !p.at("clock_identity").is_null()) {
      Fail(BootstrapError::InvalidEncoding);
    }
    plan.participants.push_back(planned);
    records.push_back(std::move(record));
  }
  if (!PlannedRosterValid(plan)) Fail(BootstrapError::InvalidEncoding);
  std::sort(records.begin(), records.end(), [](const auto& a, const auto& b) {
    if (a.planned.role != b.planned.role) return static_cast<std::uint8_t>(a.planned.role) < static_cast<std::uint8_t>(b.planned.role);
    if (a.planned.participant_id != b.planned.participant_id) return a.planned.participant_id < b.planned.participant_id;
    return a.planned.slot_id < b.planned.slot_id;
  });
  const auto revision = ParseU64(j.at("revision"));
  if (revision == 0) Fail(BootstrapError::InvalidEncoding);
  BootstrapInventory inventory = BootstrapCodecAccess::Make(plan.domain_id, revision, plan.epoch_id, plan.authority_incarnation,
      plan.policy_digest, plan.expected_clock_identity,
      std::make_shared<const std::vector<BootstrapRecord>>(std::move(records)), is_recovery, reason);
  // Check every recorded identity against its exact plan and ensure process IDs are unique.
  for (std::size_t n = 0; n < inventory.records().size(); ++n) {
    const auto& r = inventory.records()[n];
    if (!r.identity_recorded) continue;
    if (r.pid == 0 || r.pid_start_ticks == 0 || !(r.clock_identity == inventory.expected_clock_identity()))
      Fail(BootstrapError::InvalidEncoding);
    for (std::size_t k = 0; k < n; ++k)
      if (inventory.records()[k].identity_recorded && inventory.records()[k].pid == r.pid)
        Fail(BootstrapError::InvalidEncoding);
  }
  if (is_recovery && reason == BootstrapError::None) Fail(BootstrapError::InvalidEncoding);
  return inventory;
}
}  // namespace

std::variant<BootstrapInventory, BootstrapError> BootstrapInventory::Create(const BootstrapPlan& plan) noexcept {
  try {
    if (plan.participants.size() > kMaxParticipants) return BootstrapError::TooManyParticipants;
    if (!PlannedRosterValid(plan)) return BootstrapError::InvalidPlan;
    std::vector<BootstrapRecord> records;
    records.reserve(plan.participants.size());
    for (const auto& participant : plan.participants) records.push_back(BootstrapRecord{participant, 0, 0, false, {}});
    std::sort(records.begin(), records.end(), [](const auto& a, const auto& b) {
      if (a.planned.role != b.planned.role) return static_cast<std::uint8_t>(a.planned.role) < static_cast<std::uint8_t>(b.planned.role);
      if (a.planned.participant_id != b.planned.participant_id) return a.planned.participant_id < b.planned.participant_id;
      return a.planned.slot_id < b.planned.slot_id;
    });
    BootstrapInventory result(plan.domain_id, 1, plan.epoch_id, plan.authority_incarnation, plan.policy_digest,
        plan.expected_clock_identity,
        std::make_shared<const std::vector<BootstrapRecord>>(std::move(records)), false, BootstrapError::None);
    const auto encoded = EncodeBootstrapInventoryV1(result);
    if (const auto* error = std::get_if<BootstrapError>(&encoded)) return *error;
    return result;
  } catch (...) { return BootstrapError::AllocationFailure; }
}

std::size_t BootstrapInventory::recorded_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(records_->begin(), records_->end(), [](const auto& r) { return r.identity_recorded; }));
}

BootstrapTransition BootstrapInventory::RecordIdentity(const ObservedBootstrapIdentity& observed) const noexcept {
  try {
    auto records = *records_;
    auto fail = [&](BootstrapError error) {
      if (recovery_required_) return BootstrapTransition{*this, BootstrapError::RecoveryRequired};
      if (revision_ == std::numeric_limits<std::uint64_t>::max())
        return BootstrapTransition{BootstrapInventory(domain_id_, revision_, epoch_id_, authority_incarnation_, policy_digest_,
            expected_clock_identity_, records_, true, BootstrapError::RevisionExhausted), BootstrapError::RevisionExhausted};
      return BootstrapTransition{BootstrapInventory(domain_id_, revision_ + 1, epoch_id_, authority_incarnation_, policy_digest_,
          expected_clock_identity_, records_, true, error), error};
    };
    if (recovery_required_) return BootstrapTransition{*this, BootstrapError::RecoveryRequired};
    const auto it = std::find_if(records.begin(), records.end(), [&](const auto& r) {
      return r.planned.role == observed.participant.role && r.planned.participant_id == observed.participant.participant_id;
    });
    if (it == records.end()) return fail(BootstrapError::IdentityNotInPlan);
    if (!(it->planned == observed.participant) || observed.pid == 0 || observed.pid_start_ticks == 0 ||
        !(observed.clock_identity == expected_clock_identity_) || !ValidClock(observed.clock_identity))
      return fail(BootstrapError::IdentityMismatch);
    if (it->identity_recorded) {
      const bool same = it->pid == observed.pid && it->pid_start_ticks == observed.pid_start_ticks &&
          it->clock_identity == observed.clock_identity;
      if (same) return BootstrapTransition{*this, BootstrapError::None};
      return fail(BootstrapError::IdentityMismatch);
    }
    for (const auto& record : records) {
      if (&record != &*it && record.identity_recorded && record.pid == observed.pid)
        return fail(BootstrapError::DuplicateProcessIdentity);
    }
    it->pid = observed.pid;
    it->pid_start_ticks = observed.pid_start_ticks;
    it->clock_identity = observed.clock_identity;
    it->identity_recorded = true;
    if (revision_ == std::numeric_limits<std::uint64_t>::max())
      return fail(BootstrapError::RevisionExhausted);
    return BootstrapTransition{BootstrapInventory(domain_id_, revision_ + 1, epoch_id_, authority_incarnation_, policy_digest_,
        expected_clock_identity_, std::make_shared<const std::vector<BootstrapRecord>>(std::move(records)),
        false, BootstrapError::None), BootstrapError::None};
  } catch (...) {
    return BootstrapTransition{RequireRecovery(BootstrapError::AllocationFailure), BootstrapError::AllocationFailure};
  }
}

BootstrapInventory BootstrapInventory::RequireRecovery(BootstrapError reason) const noexcept {
  if (recovery_required_) return *this;
  if (!ValidBootstrapError(reason) || reason == BootstrapError::None) reason = BootstrapError::InvalidPlan;
  if (revision_ == std::numeric_limits<std::uint64_t>::max())
    return BootstrapInventory(domain_id_, revision_, epoch_id_, authority_incarnation_, policy_digest_,
        expected_clock_identity_, records_, true, BootstrapError::RevisionExhausted);
  return BootstrapInventory(domain_id_, revision_ + 1, epoch_id_, authority_incarnation_, policy_digest_, expected_clock_identity_,
      records_, true, reason);
}

std::variant<EpochCandidate, BootstrapError> BootstrapInventory::ReadyCandidate() const noexcept {
  try {
    if (recovery_required_) return BootstrapError::RecoveryRequired;
    if (revision_ == std::numeric_limits<std::uint64_t>::max()) return BootstrapError::RevisionExhausted;
    if (recorded_count() != records_->size()) return BootstrapError::IncompleteRoster;
    EpochCandidate candidate{epoch_id_, authority_incarnation_, policy_digest_, expected_clock_identity_, {}};
    candidate.participants.reserve(records_->size());
    for (const auto& record : *records_) {
      if (!record.identity_recorded) return BootstrapError::IncompleteRoster;
      candidate.participants.push_back(Participant{record.planned.role, record.planned.slot_id,
          record.planned.participant_id, record.planned.incarnation,
          ProcessIdentity{record.planned.container_id, record.pid, record.pid_start_ticks}, record.clock_identity});
    }
    if (ValidateEpochCandidate(candidate)) return BootstrapError::IdentityMismatch;
    return candidate;
  } catch (...) { return BootstrapError::AllocationFailure; }
}

BootstrapEncodeResult EncodeBootstrapInventoryV1(const BootstrapInventory& inventory) noexcept {
  try {
    const auto payload = PayloadJson(inventory).dump(-1, ' ', false, Json::error_handler_t::strict);
    if (payload.size() > kMaxBootstrapBytes) return BootstrapError::TooLarge;
    const auto digest = Sha256(payload);
    Json envelope{{"inventory", Json::parse(payload)}, {"sha256", Hex(digest)}};
    auto encoded = envelope.dump(-1, ' ', false, Json::error_handler_t::strict);
    if (encoded.size() > kMaxBootstrapBytes) return BootstrapError::TooLarge;
    return encoded;
  } catch (const Failure& e) { return e.error; }
    catch (...) { return BootstrapError::AllocationFailure; }
}

BootstrapDecodeResult DecodeBootstrapInventoryV1(std::string_view envelope) noexcept {
  if (envelope.size() > kMaxBootstrapBytes) return BootstrapError::TooLarge;
  try {
    const auto root = ParseJson(envelope);
    CheckKeys(root, {"inventory", "sha256"});
    const auto expected = ParseHex<32>(root.at("sha256"));
    auto inventory = ParsePayload(root.at("inventory"));
    const auto payload = PayloadJson(inventory).dump(-1, ' ', false, Json::error_handler_t::strict);
    if (Sha256(payload) != expected) return BootstrapError::DigestMismatch;
    const auto canonical = EncodeBootstrapInventoryV1(inventory);
    if (const auto* error = std::get_if<BootstrapError>(&canonical)) return *error;
    if (std::get<std::string>(canonical) != envelope) return BootstrapError::NonCanonical;
    return inventory;
  } catch (const Failure& e) { return e.error; }
    catch (...) { return BootstrapError::AllocationFailure; }
}

BootstrapDigestResult BootstrapDigestV1(const BootstrapInventory& inventory) noexcept {
  try {
    const auto payload = PayloadJson(inventory).dump(-1, ' ', false, Json::error_handler_t::strict);
    if (payload.size() > kMaxBootstrapBytes) return BootstrapError::TooLarge;
    return Sha256(payload);
  } catch (const Failure& e) { return e.error; }
    catch (...) { return BootstrapError::AllocationFailure; }
}

}  // namespace rateguard::supervisor
