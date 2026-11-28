#include "supervisor/docker_process_controller.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <set>
#include <string_view>
#include <vector>

namespace rateguard::supervisor {
namespace {

using Json = nlohmann::json;

constexpr std::uint64_t kFactoryVersionTimeoutNanos = 5'000'000'000ULL;
// Docker Engine added the stop endpoint's `signal` query at API v1.42.
// Primary source: https://docs.docker.com/reference/api/version-history/#v142-api-changes
constexpr std::uint32_t kDockerStopSignalApiMajor = 1;
constexpr std::uint32_t kDockerStopSignalApiMinor = 42;

bool AllZero(const auto& value) noexcept {
  return std::all_of(value.begin(), value.end(), [](std::uint8_t byte) { return byte == 0; });
}

bool CanonicalHexId(std::string_view value, std::size_t expected_bytes) noexcept {
  if (expected_bytes > std::numeric_limits<std::size_t>::max() / 2 ||
      value.size() != expected_bytes * 2) return false;
  return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
  });
}

template <std::size_t N>
std::string Hex(const std::array<std::uint8_t, N>& value) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string result;
  result.reserve(N * 2);
  for (const auto byte : value) {
    result.push_back(kHex[(byte >> 4U) & 0x0fU]);
    result.push_back(kHex[byte & 0x0fU]);
  }
  return result;
}

std::string RoleName(ParticipantRole role) {
  switch (role) {
    case ParticipantRole::Authority: return "authority";
    case ParticipantRole::Replica: return "replica";
    case ParticipantRole::Adapter: return "adapter";
    case ParticipantRole::Witness: return "witness";
  }
  return {};
}

std::string SlotText(std::uint32_t slot) {
  std::array<char, 10> buffer{};
  const auto [end, error] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), slot);
  if (error != std::errc{}) return {};
  return std::string(buffer.data(), end);
}

bool ValidParticipantId(std::string_view value) noexcept {
  return !value.empty() && value.size() <= 64 &&
      std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
      });
}

bool ValidBinding(const DockerTargetBinding& binding) noexcept {
  if (AllZero(binding.domain_id) || AllZero(binding.epoch_id) ||
      AllZero(binding.authority_incarnation) || AllZero(binding.policy_digest) ||
      AllZero(binding.incarnation) || !ValidParticipantId(binding.participant_id) ||
      !CanonicalHexId(binding.container_id, 32)) return false;

  switch (binding.role) {
    case ParticipantRole::Authority:
      return binding.slot_id == 0 && binding.incarnation == binding.authority_incarnation;
    case ParticipantRole::Replica:
      return true;
    case ParticipantRole::Adapter:
    case ParticipantRole::Witness:
      return binding.slot_id == 0;
  }
  return false;
}

const DockerTargetBinding& BindingOf(const RecoveryContainerTarget& target) noexcept {
  return std::visit([](const auto& item) -> const DockerTargetBinding& { return item.binding; }, target);
}

const ObservedContainerTarget* ObservedTarget(const RecoveryContainerTarget& target) noexcept {
  return std::get_if<ObservedContainerTarget>(&target);
}

bool HasExpectedLabelValues(const Json& labels, const DockerTargetBinding& binding) {
  if (!labels.is_object()) return false;
  const std::array<std::pair<const char*, std::string>, 8> expected{{
      {"io.rateguard.domain", Hex(binding.domain_id)},
      {"io.rateguard.epoch", Hex(binding.epoch_id)},
      {"io.rateguard.authority", Hex(binding.authority_incarnation)},
      {"io.rateguard.policy", Hex(binding.policy_digest)},
      {"io.rateguard.role", RoleName(binding.role)},
      {"io.rateguard.slot", SlotText(binding.slot_id)},
      {"io.rateguard.participant", binding.participant_id},
      {"io.rateguard.incarnation", Hex(binding.incarnation)},
  }};

  for (const auto& [key, expected_value] : expected) {
    const auto it = labels.find(key);
    if (it == labels.end() || !it->is_string() || it->get_ref<const std::string&>() != expected_value)
      return false;
  }
  return true;
}

// A first SAX pass rejects duplicate keys and bounds nesting, object fields,
// nodes and individual decoded strings before DOM allocation.
class BoundedJsonSax final : public Json::json_sax_t {
 public:
  bool null() override { return CountNode(); }
  bool boolean(bool) override { return CountNode(); }
  bool number_integer(number_integer_t) override { return CountNode(); }
  bool number_unsigned(number_unsigned_t) override { return CountNode(); }
  bool number_float(number_float_t, const string_t&) override { return CountNode(); }
  bool binary(binary_t&) override { return false; }

  bool string(string_t& value) override {
    return CountNode() && CountString(value);
  }

  bool start_object(std::size_t) override {
    if (!CountNode() || stack_.size() >= kDockerMaxJsonDepth) return Fail();
    try {
      stack_.push_back(Frame{true, 0, {}});
      return true;
    } catch (...) {
      return Fail();
    }
  }

  bool key(string_t& value) override {
    if (stack_.empty() || !stack_.back().is_object ||
        stack_.back().field_count >= kDockerMaxJsonFields || !CountString(value)) return Fail();
    try {
      auto& frame = stack_.back();
      ++frame.field_count;
      return frame.keys.insert(value).second || Fail();
    } catch (...) {
      return Fail();
    }
  }

  bool end_object() override {
    if (stack_.empty() || !stack_.back().is_object) return Fail();
    stack_.pop_back();
    return true;
  }

  bool start_array(std::size_t) override {
    if (!CountNode() || stack_.size() >= kDockerMaxJsonDepth) return Fail();
    try {
      stack_.push_back(Frame{false, 0, {}});
      return true;
    } catch (...) {
      return Fail();
    }
  }

  bool end_array() override {
    if (stack_.empty() || stack_.back().is_object) return Fail();
    stack_.pop_back();
    return true;
  }

  bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) override {
    return Fail();
  }

  [[nodiscard]] bool ok() const noexcept { return ok_; }

 private:
  struct Frame final {
    bool is_object{};
    std::size_t field_count{};
    std::set<std::string> keys;
  };

  bool CountNode() noexcept {
    if (++nodes_ > kDockerMaxJsonNodes) return Fail();
    return true;
  }

  bool CountString(const string_t& value) noexcept {
    if (value.size() > kDockerMaxJsonStringBytes) return Fail();
    return true;
  }

  bool Fail() noexcept {
    ok_ = false;
    return false;
  }

  std::size_t nodes_{};
  bool ok_{true};
  std::vector<Frame> stack_;
};

bool ParseBoundedJson(std::string_view bytes, Json& output) noexcept {
  if (bytes.empty() || bytes.size() > kDockerMaxInspectBodyBytes) return false;
  try {
    BoundedJsonSax checker;
    if (!Json::sax_parse(bytes.begin(), bytes.end(), &checker, Json::input_format_t::json,
                         true, true) || !checker.ok()) return false;
    output = Json::parse(bytes.begin(), bytes.end(), nullptr, true, false);
    return !output.is_discarded();
  } catch (...) {
    return false;
  }
}

const Json* Member(const Json& object, const char* key) noexcept {
  if (!object.is_object()) return nullptr;
  const auto it = object.find(key);
  return it == object.end() ? nullptr : &*it;
}

bool ReadString(const Json* value, std::string& result) {
  if (value == nullptr || !value->is_string()) return false;
  result = value->get<std::string>();
  return result.size() <= kDockerMaxJsonStringBytes;
}

bool ReadBool(const Json* value, bool& result) noexcept {
  if (value == nullptr || !value->is_boolean()) return false;
  result = value->get<bool>();
  return true;
}

bool ReadU64(const Json* value, std::uint64_t& result) noexcept {
  if (value == nullptr || !value->is_number_integer()) return false;
  try {
    if (value->is_number_unsigned()) {
      result = value->get<std::uint64_t>();
    } else {
      const auto signed_value = value->get<std::int64_t>();
      if (signed_value < 0) return false;
      result = static_cast<std::uint64_t>(signed_value);
    }
    return true;
  } catch (...) {
    return false;
  }
}

DockerContainerState ParseState(std::string_view value) noexcept {
  if (value == "created") return DockerContainerState::Created;
  if (value == "running") return DockerContainerState::Running;
  if (value == "paused") return DockerContainerState::Paused;
  if (value == "restarting") return DockerContainerState::Restarting;
  if (value == "removing") return DockerContainerState::Removing;
  if (value == "exited") return DockerContainerState::Exited;
  if (value == "dead") return DockerContainerState::Dead;
  return DockerContainerState::Unknown;
}

struct ParsedContainer final {
  bool json_valid{};
  bool exact_id{};
  bool labels_match{};
  bool restart_policy_field_valid{};
  bool required_state_fields_valid{};
  bool restart_policy_disabled{};
  DockerContainerState state{DockerContainerState::Unknown};
  bool running{};
  bool restarting{};
  std::uint64_t pid{};
};

ParsedContainer ParseContainer(std::string_view body, const DockerTargetBinding& binding) noexcept {
  ParsedContainer parsed;
  Json root;
  if (!ParseBoundedJson(body, root) || !root.is_object()) return parsed;
  parsed.json_valid = true;

  try {
    std::string id;
    parsed.exact_id = ReadString(Member(root, "Id"), id) && id == binding.container_id;

    const Json* config = Member(root, "Config");
    const Json* labels = config == nullptr ? nullptr : Member(*config, "Labels");
    parsed.labels_match = labels != nullptr && HasExpectedLabelValues(*labels, binding);

    const Json* host_config = Member(root, "HostConfig");
    const Json* restart = host_config == nullptr ? nullptr : Member(*host_config, "RestartPolicy");
    std::string restart_name;
    parsed.restart_policy_field_valid = ReadString(
        restart == nullptr ? nullptr : Member(*restart, "Name"), restart_name);
    parsed.restart_policy_disabled = parsed.restart_policy_field_valid && restart_name == "no";

    const Json* state = Member(root, "State");
    std::string status;
    bool running = false;
    bool restarting = false;
    std::uint64_t pid = 0;
    const bool valid_status = ReadString(state == nullptr ? nullptr : Member(*state, "Status"), status);
    const bool valid_running = ReadBool(state == nullptr ? nullptr : Member(*state, "Running"), running);
    const bool valid_restarting = ReadBool(state == nullptr ? nullptr : Member(*state, "Restarting"), restarting);
    const bool valid_pid = ReadU64(state == nullptr ? nullptr : Member(*state, "Pid"), pid);
    parsed.required_state_fields_valid = valid_status && valid_running && valid_restarting && valid_pid;
    if (valid_status) parsed.state = ParseState(status);
    parsed.running = running;
    parsed.restarting = restarting;
    parsed.pid = pid;
  } catch (...) {
    return ParsedContainer{};
  }
  return parsed;
}

struct Version final {
  std::uint32_t major{};
  std::uint32_t minor{};
};

bool ParseVersion(std::string_view value, Version& out) noexcept {
  if (value.empty() || value.size() > 24) return false;
  const std::size_t dot = value.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 >= value.size() ||
      value.find('.', dot + 1) != std::string_view::npos) return false;
  auto parse_part = [](std::string_view part, std::uint32_t& result) noexcept {
    if (part.empty() || (part.size() > 1 && part.front() == '0')) return false;
    std::uint32_t number = 0;
    const auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), number);
    if (error != std::errc{} || end != part.data() + part.size()) return false;
    result = number;
    return true;
  };
  return parse_part(value.substr(0, dot), out.major) &&
      parse_part(value.substr(dot + 1), out.minor);
}

bool Less(Version a, Version b) noexcept {
  return a.major < b.major || (a.major == b.major && a.minor < b.minor);
}

bool IsAtLeastStopSignalFloor(Version value) noexcept {
  const Version floor{kDockerStopSignalApiMajor, kDockerStopSignalApiMinor};
  return !Less(value, floor);
}

DockerControllerFailure Failure(DockerControllerErrorCode code, bool sent = false) noexcept {
  return DockerControllerFailure{code, sent};
}

DockerControllerErrorCode MapHttpFailure(UnixHttpFailureReason reason) noexcept {
  switch (reason) {
    case UnixHttpFailureReason::InvalidTarget: return DockerControllerErrorCode::HttpProtocolError;
    case UnixHttpFailureReason::InvalidDeadline: return DockerControllerErrorCode::InvalidDeadline;
    case UnixHttpFailureReason::NotConfigured:
    case UnixHttpFailureReason::PeerCredentialMismatch:
    case UnixHttpFailureReason::SocketFailure: return DockerControllerErrorCode::TransportUnavailable;
    case UnixHttpFailureReason::UnsupportedPlatform: return DockerControllerErrorCode::UnsupportedPlatform;
    case UnixHttpFailureReason::Overloaded: return DockerControllerErrorCode::TransportUnavailable;
    case UnixHttpFailureReason::Cancelled: return DockerControllerErrorCode::Cancelled;
    case UnixHttpFailureReason::DeadlineExpired: return DockerControllerErrorCode::TimedOut;
    case UnixHttpFailureReason::ClockFailure: return DockerControllerErrorCode::ClockUnavailable;
    case UnixHttpFailureReason::ProtocolError: return DockerControllerErrorCode::HttpProtocolError;
    case UnixHttpFailureReason::ResponseTooLarge: return DockerControllerErrorCode::ResponseTooLarge;
    case UnixHttpFailureReason::AllocationFailure: return DockerControllerErrorCode::AllocationFailure;
  }
  return DockerControllerErrorCode::TransportUnavailable;
}

bool ParseVersionRange(std::string_view body, Version& minimum, Version& maximum) noexcept {
  try {
    Json root;
    if (!ParseBoundedJson(body, root) || !root.is_object()) return false;
    std::string api;
    std::string min_api;
    if (!ReadString(Member(root, "ApiVersion"), api) ||
        !ReadString(Member(root, "MinAPIVersion"), min_api)) return false;
    return ParseVersion(min_api, minimum) && ParseVersion(api, maximum) && !Less(maximum, minimum);
  } catch (...) {
    return false;
  }
}

bool ValidateDeadline(platform::IClock& clock, ControllerDeadline deadline,
                      const std::atomic_bool& cancelled,
                      bool in_flight,
                      DockerControllerErrorCode& error) noexcept {
  if (cancelled.load(std::memory_order_relaxed)) {
    error = DockerControllerErrorCode::Cancelled;
    return false;
  }
  try {
    if (!clock.Healthy()) {
      error = DockerControllerErrorCode::ClockUnavailable;
      return false;
    }
    const auto now_result = clock.Now();
    const auto* now = std::get_if<platform::MonoNanos>(&now_result);
    if (now == nullptr) {
      error = DockerControllerErrorCode::ClockUnavailable;
      return false;
    }
    if (cancelled.load(std::memory_order_relaxed)) {
      error = DockerControllerErrorCode::Cancelled;
      return false;
    }
    if (deadline.at.value <= now->value) {
      error = in_flight ? DockerControllerErrorCode::TimedOut
                        : DockerControllerErrorCode::InvalidDeadline;
      return false;
    }
    if (deadline.at.value - now->value > kDockerMaxOperationTimeoutNanos) {
      error = DockerControllerErrorCode::InvalidDeadline;
      return false;
    }
    error = DockerControllerErrorCode::InvalidDeadline;
    return true;
  } catch (...) {
    error = DockerControllerErrorCode::ClockUnavailable;
    return false;
  }
}

DockerControllerFailure InspectTransportFailure(const UnixHttpFailure& failure) noexcept {
  return Failure(MapHttpFailure(failure.reason), false);
}

std::string InspectPath(std::string_view version, std::string_view container_id) {
  std::string path;
  path.reserve(version.size() + container_id.size() + 24);
  path.append("/v").append(version).append("/containers/").append(container_id).append("/json");
  return path;
}

std::string StopPath(std::string_view version, std::string_view container_id) {
  std::string path;
  path.reserve(version.size() + container_id.size() + 56);
  path.append("/v").append(version).append("/containers/").append(container_id)
      .append("/stop?signal=SIGTERM&t=").append(std::to_string(kDockerStopGraceSeconds));
  return path;
}

std::string_view BodyView(const std::vector<std::uint8_t>& body) noexcept {
  if (body.empty()) return {};
  return {reinterpret_cast<const char*>(body.data()), body.size()};
}

class DockerProcessController final : public IRecoveryProcessController {
 public:
  DockerProcessController(std::string api_version, platform::IClock& clock,
                          std::unique_ptr<IUnixHttpTransport> transport,
                          std::unique_ptr<platform::IRecordedProcessProbe> process_probe)
      : api_version_(std::move(api_version)), clock_(clock), transport_(std::move(transport)),
        process_probe_(std::move(process_probe)) {}

  DockerInspectResult Inspect(const RecoveryContainerTarget& target, ControllerDeadline deadline,
                              const std::atomic_bool& cancel_requested) noexcept override {
    if (!ValidateRecoveryContainerTarget(target))
      return Failure(DockerControllerErrorCode::InvalidTarget);
    DockerControllerErrorCode deadline_error{};
    if (!ValidateDeadline(clock_, deadline, cancel_requested, false, deadline_error))
      return Failure(deadline_error);
    try {
      auto finish = [&](DockerInspectResult result) -> DockerInspectResult {
        DockerControllerErrorCode final_error{};
        if (!ValidateDeadline(clock_, deadline, cancel_requested, true, final_error))
          return Failure(final_error);
        return result;
      };
      const auto& binding = BindingOf(target);
      const std::string path = InspectPath(api_version_, binding.container_id);
      const auto response_result = transport_->RoundTrip(
          UnixHttpMethod::Get, path, deadline.at, cancel_requested);
      if (const auto* failure = std::get_if<UnixHttpFailure>(&response_result))
        return InspectTransportFailure(*failure);
      DockerControllerErrorCode after_http_error{};
      if (!ValidateDeadline(clock_, deadline, cancel_requested, true, after_http_error))
        return Failure(after_http_error);
      const auto& response = std::get<UnixHttpResponse>(response_result);
      if (response.status == 404) {
        return finish(Unknown(DockerObservationReason::NotFound, binding.container_id));
      }
      if (response.status != 200) return finish(Failure(DockerControllerErrorCode::HttpProtocolError));
      if (response.body.size() > kDockerMaxInspectBodyBytes)
        return finish(Failure(DockerControllerErrorCode::ResponseTooLarge));

      const auto parsed = ParseContainer(
          BodyView(response.body), binding);
      if (!parsed.json_valid)
        return finish(Unknown(DockerObservationReason::MalformedResponse, binding.container_id));
      if (!parsed.exact_id)
        return finish(Unknown(DockerObservationReason::MissingIdentity, binding.container_id));
      if (!parsed.labels_match)
        return finish(Unknown(DockerObservationReason::LabelMismatch, binding.container_id));
      if (!parsed.restart_policy_field_valid)
        return finish(Unknown(DockerObservationReason::MalformedResponse, binding.container_id, true));
      if (!parsed.required_state_fields_valid)
        return finish(Unknown(DockerObservationReason::MalformedResponse, binding.container_id, true));

      DockerContainerObservation observation;
      observation.exact_container_id = binding.container_id;
      observation.state = parsed.state;
      observation.labels_match = true;
      observation.restart_policy_disabled = parsed.restart_policy_disabled;
      observation.running = parsed.running;
      observation.restarting = parsed.restarting;
      observation.engine_pid = parsed.pid;

      if (parsed.state == DockerContainerState::Running && parsed.running &&
          !parsed.restarting && parsed.pid > 0) {
        if (const auto* observed = ObservedTarget(target)) {
          if (parsed.pid != observed->host_pid)
            return finish(Unknown(DockerObservationReason::ProcessIdentityMismatch,
                                  binding.container_id, true));
          const platform::RecordedLinuxProcess recorded{
              observed->host_pid, observed->pid_start_ticks, observed->clock_identity};
          const auto probe_result = process_probe_->Check(recorded, deadline.at, cancel_requested);
          if (const auto* probe = std::get_if<platform::LinuxProcessObservation>(&probe_result)) {
            observation.process_evidence = *probe;
            if (probe->disposition == platform::LinuxProcessDisposition::LiveIdentityMatched) {
              observation.disposition = DockerObservationDisposition::MatchedRunning;
              observation.reason = DockerObservationReason::None;
              return finish(std::move(observation));
            }
            observation.reason = probe->disposition == platform::LinuxProcessDisposition::MatchedZombie
                ? DockerObservationReason::ProcessStillPresent
                : MapProcessReason(probe->reason);
            if (observation.reason == DockerObservationReason::None)
              observation.reason = DockerObservationReason::ProcessAbsenceUnverified;
          } else {
            const auto& failure = std::get<platform::LinuxProcessProbeFailure>(probe_result);
            observation.reason = MapProcessReason(failure.reason);
          }
          observation.disposition = DockerObservationDisposition::Unknown;
          return finish(std::move(observation));
        }
        observation.disposition = DockerObservationDisposition::MatchedRunning;
        observation.reason = DockerObservationReason::None;
        return finish(std::move(observation));
      }

      if (parsed.state == DockerContainerState::Exited && !parsed.running &&
          !parsed.restarting && parsed.pid == 0 && parsed.restart_policy_disabled) {
        if (const auto* observed = ObservedTarget(target)) {
          const platform::RecordedLinuxProcess recorded{
              observed->host_pid, observed->pid_start_ticks, observed->clock_identity};
          const auto probe_result = process_probe_->Check(recorded, deadline.at, cancel_requested);
          if (const auto* probe = std::get_if<platform::LinuxProcessObservation>(&probe_result)) {
            observation.process_evidence = *probe;
            if (probe->disposition == platform::LinuxProcessDisposition::RecordedProcessAbsent) {
              observation.disposition = DockerObservationDisposition::MatchedExited;
              observation.reason = DockerObservationReason::None;
              observation.exit_evidence_scope = DockerExitEvidenceScope::RuntimeAndRecordedProcessAbsent;
              return finish(std::move(observation));
            }
            observation.reason =
                (probe->disposition == platform::LinuxProcessDisposition::MatchedZombie ||
                 probe->disposition == platform::LinuxProcessDisposition::LiveIdentityMatched)
                    ? DockerObservationReason::ProcessStillPresent
                    : MapProcessReason(probe->reason);
            if (observation.reason == DockerObservationReason::None)
              observation.reason = DockerObservationReason::ProcessAbsenceUnverified;
          } else {
            const auto& failure = std::get<platform::LinuxProcessProbeFailure>(probe_result);
            observation.reason = MapProcessReason(failure.reason);
          }
          observation.disposition = DockerObservationDisposition::Unknown;
          return finish(std::move(observation));
        }
        observation.disposition = DockerObservationDisposition::MatchedExited;
        observation.reason = DockerObservationReason::None;
        observation.exit_evidence_scope = DockerExitEvidenceScope::RuntimeOnlyPendingTarget;
        return finish(std::move(observation));
      }

      observation.disposition = DockerObservationDisposition::Unknown;
      if (!parsed.restart_policy_disabled)
        observation.reason = DockerObservationReason::RestartPolicyUnexpected;
      else if (parsed.state == DockerContainerState::Exited &&
               (parsed.running || parsed.restarting || parsed.pid != 0))
        observation.reason = DockerObservationReason::ProcessStillPresent;
      else
        observation.reason = DockerObservationReason::ContainerNotTerminal;
      return finish(std::move(observation));
    } catch (...) {
      return Failure(DockerControllerErrorCode::AllocationFailure);
    }
  }

  DockerStopResult RequestStop(const RecoveryContainerTarget& target,
                               const OperationId& operation_id,
                               ControllerDeadline deadline,
                               const std::atomic_bool& cancel_requested) noexcept override {
    if (!ValidateRecoveryContainerTarget(target))
      return Failure(DockerControllerErrorCode::InvalidTarget);
    if (AllZero(operation_id)) return Failure(DockerControllerErrorCode::InvalidOperationId);
    DockerControllerErrorCode deadline_error{};
    if (!ValidateDeadline(clock_, deadline, cancel_requested, false, deadline_error))
      return Failure(deadline_error);

    bool stop_request_possibly_sent = false;
    try {
      const auto& binding = BindingOf(target);
      const std::string inspect_path = InspectPath(api_version_, binding.container_id);
      const auto inspect_result = transport_->RoundTrip(
          UnixHttpMethod::Get, inspect_path, deadline.at, cancel_requested);
      if (const auto* failure = std::get_if<UnixHttpFailure>(&inspect_result))
        return Failure(MapHttpFailure(failure->reason), false);
      const auto& inspect_response = std::get<UnixHttpResponse>(inspect_result);
      if (inspect_response.status != 200) {
        return Failure(inspect_response.status == 404
                           ? DockerControllerErrorCode::IdentityMismatch
                           : DockerControllerErrorCode::HttpProtocolError,
                       false);
      }
      if (inspect_response.body.size() > kDockerMaxInspectBodyBytes)
        return Failure(DockerControllerErrorCode::ResponseTooLarge, false);
      DockerControllerErrorCode after_preflight_error{};
      if (!ValidateDeadline(clock_, deadline, cancel_requested, true, after_preflight_error))
        return Failure(after_preflight_error, false);

      ParsedContainer parsed = ParseContainer(BodyView(inspect_response.body), binding);
      DockerControllerErrorCode after_parse_error{};
      if (!ValidateDeadline(clock_, deadline, cancel_requested, true, after_parse_error))
        return Failure(after_parse_error, false);
      if (!parsed.json_valid) return Failure(DockerControllerErrorCode::InvalidJson, false);
      if (!parsed.exact_id || !parsed.labels_match)
        return Failure(DockerControllerErrorCode::IdentityMismatch, false);

      const std::string stop_path = StopPath(api_version_, binding.container_id);
      DockerControllerErrorCode before_stop_error{};
      if (!ValidateDeadline(clock_, deadline, cancel_requested, true, before_stop_error))
        return Failure(before_stop_error, false);
      const auto stop_result = transport_->RoundTrip(
          UnixHttpMethod::Post, stop_path, deadline.at, cancel_requested);
      if (const auto* failure = std::get_if<UnixHttpFailure>(&stop_result)) {
        stop_request_possibly_sent = failure->request_possibly_sent;
        return Failure(MapHttpFailure(failure->reason), failure->request_possibly_sent);
      }
      stop_request_possibly_sent = true;
      const auto& stop_response = std::get<UnixHttpResponse>(stop_result);
      const auto status = stop_response.status;
      DockerControllerErrorCode final_error{};
      if (!ValidateDeadline(clock_, deadline, cancel_requested, true, final_error))
        return Failure(final_error, true);
      if (status == 204 && stop_response.body.empty())
        return DockerStopAcknowledgement{operation_id, DockerStopAcknowledgement::Kind::Accepted};
      if (status == 304 && stop_response.body.empty())
        return DockerStopAcknowledgement{operation_id, DockerStopAcknowledgement::Kind::AlreadyStopped};
      return Failure(status == 404 ? DockerControllerErrorCode::IdentityMismatch
                                  : DockerControllerErrorCode::HttpProtocolError,
                     true);
    } catch (...) {
      return Failure(DockerControllerErrorCode::AllocationFailure, stop_request_possibly_sent);
    }
  }

 private:
  DockerInspectResult Unknown(DockerObservationReason reason, const std::string& id,
                              bool labels_match = false) const {
    DockerContainerObservation observation;
    observation.disposition = DockerObservationDisposition::Unknown;
    observation.reason = reason;
    observation.exact_container_id = id;
    observation.labels_match = labels_match;
    return observation;
  }

  static DockerObservationReason MapProcessReason(platform::LinuxProcessReason reason) noexcept {
    switch (reason) {
      case platform::LinuxProcessReason::None: return DockerObservationReason::None;
      case platform::LinuxProcessReason::PidReused:
      case platform::LinuxProcessReason::MalformedStat:
      case platform::LinuxProcessReason::InvalidRecordedIdentity:
        return DockerObservationReason::ProcessIdentityMismatch;
      case platform::LinuxProcessReason::BootMismatch:
        return DockerObservationReason::HostBootMismatch;
      case platform::LinuxProcessReason::PidNamespaceMismatch:
        return DockerObservationReason::PidNamespaceMismatch;
      case platform::LinuxProcessReason::TimeNamespaceMismatch:
      case platform::LinuxProcessReason::ClockIdentityMismatch:
        return DockerObservationReason::TimeNamespaceMismatch;
      case platform::LinuxProcessReason::PermissionDenied:
      case platform::LinuxProcessReason::ProcUnavailable:
      case platform::LinuxProcessReason::UnsupportedPlatform:
      case platform::LinuxProcessReason::DeadlineExpired:
      case platform::LinuxProcessReason::Cancelled:
      case platform::LinuxProcessReason::ResourceLimit:
      case platform::LinuxProcessReason::AllocationFailure:
        return DockerObservationReason::ProcessAbsenceUnverified;
    }
    return DockerObservationReason::ProcessAbsenceUnverified;
  }

  std::string api_version_;
  platform::IClock& clock_;
  std::unique_ptr<IUnixHttpTransport> transport_;
  std::unique_ptr<platform::IRecordedProcessProbe> process_probe_;
};

DockerControllerErrorCode MapFactoryHttpFailure(const UnixHttpFailure& failure) noexcept {
  return MapHttpFailure(failure.reason);
}

[[maybe_unused]] DockerControllerErrorCode MapProcessFactoryReason(
    platform::LinuxProcessReason reason) noexcept {
  switch (reason) {
    case platform::LinuxProcessReason::UnsupportedPlatform:
      return DockerControllerErrorCode::UnsupportedPlatform;
    case platform::LinuxProcessReason::DeadlineExpired:
      return DockerControllerErrorCode::TimedOut;
    case platform::LinuxProcessReason::Cancelled:
      return DockerControllerErrorCode::Cancelled;
    case platform::LinuxProcessReason::AllocationFailure:
      return DockerControllerErrorCode::AllocationFailure;
    case platform::LinuxProcessReason::None:
    case platform::LinuxProcessReason::InvalidRecordedIdentity:
    case platform::LinuxProcessReason::ProcUnavailable:
    case platform::LinuxProcessReason::PermissionDenied:
    case platform::LinuxProcessReason::MalformedStat:
    case platform::LinuxProcessReason::PidReused:
    case platform::LinuxProcessReason::BootMismatch:
    case platform::LinuxProcessReason::PidNamespaceMismatch:
    case platform::LinuxProcessReason::TimeNamespaceMismatch:
    case platform::LinuxProcessReason::ClockIdentityMismatch:
    case platform::LinuxProcessReason::ResourceLimit:
      return DockerControllerErrorCode::TransportUnavailable;
  }
  return DockerControllerErrorCode::TransportUnavailable;
}

}  // namespace

bool ValidateRecoveryContainerTarget(const RecoveryContainerTarget& target) noexcept {
  try {
    const auto& binding = BindingOf(target);
    if (!ValidBinding(binding)) return false;
    if (const auto* observed = ObservedTarget(target)) {
      if (observed->host_pid == 0 || observed->pid_start_ticks == 0) return false;
      if (observed->clock_identity.clock_id != 1 ||
          AllZero(observed->clock_identity.boot_uuid) ||
          observed->clock_identity.namespace_device == 0 ||
          observed->clock_identity.namespace_inode == 0 ||
          observed->clock_identity.monotonic_offset_nanoseconds >= 1'000'000'000U ||
          observed->clock_identity.boottime_offset_nanoseconds >= 1'000'000'000U) return false;
    }
    return true;
  } catch (...) {
    return false;
  }
}

DockerDeadlineResult MakeDockerDeadline(platform::IClock& clock,
                                         std::uint64_t timeout_nanos) noexcept {
  if (timeout_nanos == 0 || timeout_nanos > kDockerMaxOperationTimeoutNanos)
    return DockerControllerErrorCode::InvalidDeadline;
  try {
    if (!clock.Healthy()) return DockerControllerErrorCode::ClockUnavailable;
    const auto now_result = clock.Now();
    const auto* now = std::get_if<platform::MonoNanos>(&now_result);
    if (now == nullptr) return DockerControllerErrorCode::ClockUnavailable;
    if (!clock.Healthy()) return DockerControllerErrorCode::ClockUnavailable;
    if (now->value > std::numeric_limits<std::uint64_t>::max() - timeout_nanos)
      return DockerControllerErrorCode::InvalidDeadline;
    return ControllerDeadline{platform::MonoNanos{now->value + timeout_nanos}};
  } catch (...) {
    return DockerControllerErrorCode::ClockUnavailable;
  }
}

DockerDeadlineResult MakeDefaultInspectDeadline(platform::IClock& clock) noexcept {
  return MakeDockerDeadline(clock, kDockerInspectDefaultTimeoutNanos);
}

DockerDeadlineResult MakeDefaultStopDeadline(platform::IClock& clock) noexcept {
  return MakeDockerDeadline(clock, kDockerStopDefaultTimeoutNanos);
}

DockerProcessControllerCreateResult CreateDockerProcessController(
    const DockerProcessControllerConfig& config, platform::IClock& clock,
    std::unique_ptr<IUnixHttpTransport> transport,
    std::unique_ptr<platform::IRecordedProcessProbe> process_probe) noexcept {
  if (!transport || !process_probe || config.engine_api_version.empty() ||
      config.engine_api_version.size() > 24 || config.unix_socket_path.empty() ||
      config.unix_socket_path.size() > kUnixHttpNativeSocketPathMaxBytes ||
      config.unix_socket_path.find('\0') != std::string::npos)
    return Failure(DockerControllerErrorCode::InvalidTarget);

  Version selected{};
  if (!ParseVersion(config.engine_api_version, selected) || !IsAtLeastStopSignalFloor(selected))
    return Failure(DockerControllerErrorCode::EngineVersionMismatch);

  const auto deadline_result = MakeDockerDeadline(clock, kFactoryVersionTimeoutNanos);
  if (const auto* error = std::get_if<DockerControllerErrorCode>(&deadline_result))
    return Failure(*error);
  const auto deadline = std::get<ControllerDeadline>(deadline_result);
  const std::atomic_bool not_cancelled{false};

  try {
    const auto version_response = transport->RoundTrip(
        UnixHttpMethod::Get, "/version", deadline.at, not_cancelled);
    if (const auto* failure = std::get_if<UnixHttpFailure>(&version_response))
      return Failure(MapFactoryHttpFailure(*failure), false);
    const auto& response = std::get<UnixHttpResponse>(version_response);
    if (response.status != 200 || response.body.size() > kDockerMaxInspectBodyBytes)
      return Failure(response.body.size() > kDockerMaxInspectBodyBytes
                         ? DockerControllerErrorCode::ResponseTooLarge
                         : DockerControllerErrorCode::EngineVersionMismatch);

    Version minimum{};
    Version maximum{};
    const bool range_valid = ParseVersionRange(BodyView(response.body), minimum, maximum);
    DockerControllerErrorCode after_version_error{};
    if (!ValidateDeadline(clock, deadline, not_cancelled, true, after_version_error))
      return Failure(after_version_error);
    if (!range_valid || Less(selected, minimum) || Less(maximum, selected))
      return Failure(DockerControllerErrorCode::EngineVersionMismatch);

    return std::unique_ptr<IRecoveryProcessController>(new DockerProcessController(
        config.engine_api_version, clock, std::move(transport), std::move(process_probe)));
  } catch (...) {
    return Failure(DockerControllerErrorCode::AllocationFailure);
  }
}

DockerProcessControllerCreateResult CreateLinuxDockerProcessController(
    const DockerProcessControllerConfig& config, platform::IClock& clock) noexcept {
#if defined(__linux__)
  if (config.process_probe.expected_observer_pid_namespace.device == 0 ||
      config.process_probe.expected_observer_pid_namespace.inode == 0)
    return Failure(DockerControllerErrorCode::InvalidTarget);
  try {
    UnixHttpTransportConfig transport_config;
    transport_config.socket_path = config.unix_socket_path;
    transport_config.expected_peer_uid = kDockerRootUid;
    transport_config.expected_socket_owner_uid = kDockerRootUid;
    auto transport_result = CreateUnixHttpTransport(transport_config, clock);
    if (auto* transport_failure = std::get_if<UnixHttpFailure>(&transport_result))
      return Failure(MapHttpFailure(transport_failure->reason));

    auto probe_config = config.process_probe;
    probe_config.proc_root = "/proc";
    auto probe_result = platform::CreateLinuxRecordedProcessProbe(probe_config, clock);
    if (auto* probe_failure = std::get_if<platform::LinuxProcessProbeFailure>(&probe_result)) {
      return Failure(MapProcessFactoryReason(probe_failure->reason));
    }
    auto transport = std::move(std::get<std::unique_ptr<IUnixHttpTransport>>(transport_result));
    auto probe = std::move(std::get<std::unique_ptr<platform::IRecordedProcessProbe>>(probe_result));
    return CreateDockerProcessController(config, clock, std::move(transport), std::move(probe));
  } catch (...) {
    return Failure(DockerControllerErrorCode::AllocationFailure);
  }
#else
  (void)config;
  (void)clock;
  return Failure(DockerControllerErrorCode::UnsupportedPlatform);
#endif
}

}  // namespace rateguard::supervisor
