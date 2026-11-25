#include "supervisor/docker_process_controller.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {
int failures = 0;

#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #expr    \
                << '\n';                                                       \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

using namespace rateguard;
using namespace rateguard::platform;
using namespace rateguard::supervisor;

class FixedClock final : public IClock {
 public:
  explicit FixedClock(std::uint64_t now = 10'000'000'000ULL) : now_(now) {}
  ClockResult<MonoNanos> Now() override { return MonoNanos{now_}; }
  ClockResult<ClockIdentity> Provenance() override { return ClockIdentity{}; }
  bool Healthy() const override { return true; }
 private:
  std::uint64_t now_;
};

struct ScriptStep {
  UnixHttpMethod method{UnixHttpMethod::Get};
  std::string target;
  UnixHttpResult result{UnixHttpFailure{UnixHttpFailureReason::ProtocolError, false}};
};

struct TransportState {
  std::vector<ScriptStep> steps;
  std::vector<UnixHttpMethod> methods;
  std::vector<std::string> targets;
  std::vector<MonoNanos> deadlines;
  std::size_t next_step{};
  bool mismatch{};
};

class ScriptedTransport final : public IUnixHttpTransport {
 public:
  explicit ScriptedTransport(std::shared_ptr<TransportState> state)
      : state_(std::move(state)) {}

  UnixHttpResult RoundTrip(UnixHttpMethod method, std::string_view target,
                           MonoNanos deadline,
                           const std::atomic_bool& cancel_requested) noexcept override {
    try {
      state_->methods.push_back(method);
      state_->targets.emplace_back(target);
      state_->deadlines.push_back(deadline);
      if (cancel_requested.load(std::memory_order_relaxed))
        return UnixHttpFailure{UnixHttpFailureReason::Cancelled, false};
      if (state_->next_step >= state_->steps.size()) {
        state_->mismatch = true;
        return UnixHttpFailure{UnixHttpFailureReason::ProtocolError, false};
      }
      auto step = std::move(state_->steps[state_->next_step++]);
      if (step.method != method || step.target != target) {
        state_->mismatch = true;
        return UnixHttpFailure{UnixHttpFailureReason::ProtocolError, false};
      }
      return std::move(step.result);
    } catch (...) {
      state_->mismatch = true;
      return UnixHttpFailure{UnixHttpFailureReason::AllocationFailure, false};
    }
  }

 private:
  std::shared_ptr<TransportState> state_;
};

struct ProbeState {
  std::vector<LinuxProcessProbeResult> results;
  std::vector<RecordedLinuxProcess> checked;
  std::size_t next_result{};
};

class ScriptedProcessProbe final : public IRecordedProcessProbe {
 public:
  explicit ScriptedProcessProbe(std::shared_ptr<ProbeState> state)
      : state_(std::move(state)) {}
  LinuxProcessProbeResult Check(const RecordedLinuxProcess& recorded,
                                MonoNanos,
                                const std::atomic_bool&) noexcept override {
    try {
      state_->checked.push_back(recorded);
      if (state_->next_result >= state_->results.size()) {
        LinuxProcessObservation unknown{};
        unknown.disposition = LinuxProcessDisposition::Unknown;
        unknown.reason = LinuxProcessReason::ProcUnavailable;
        return unknown;
      }
      return state_->results[state_->next_result++];
    } catch (...) {
      return LinuxProcessProbeFailure{LinuxProcessReason::AllocationFailure};
    }
  }
 private:
  std::shared_ptr<ProbeState> state_;
};

template <class ByteArray>
std::string Hex(const ByteArray& value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(value.size() * 2);
  for (const auto byte : value) {
    result.push_back(digits[(byte >> 4) & 0x0f]);
    result.push_back(digits[byte & 0x0f]);
  }
  return result;
}

template <std::size_t N>
void Fill(std::array<std::uint8_t, N>& bytes, std::uint8_t seed) {
  for (std::size_t i = 0; i < N; ++i)
    bytes[i] = static_cast<std::uint8_t>(seed + i);
}

ClockIdentity TestIdentity() {
  ClockIdentity identity{};
  Fill(identity.boot_uuid, 0x11);
  identity.namespace_device = 7;
  identity.namespace_inode = 9;
  identity.clock_id = 1;
  return identity;
}

DockerTargetBinding TestBinding() {
  DockerTargetBinding binding{};
  Fill(binding.domain_id, 0x10);
  Fill(binding.epoch_id, 0x20);
  Fill(binding.authority_incarnation, 0x30);
  Fill(binding.policy_digest, 0x40);
  binding.role = ParticipantRole::Authority;
  binding.slot_id = 0;
  binding.participant_id = "authority";
  binding.incarnation = binding.authority_incarnation;
  binding.container_id.assign(64, 'a');
  return binding;
}

ObservedContainerTarget Observed(const DockerTargetBinding& binding) {
  return ObservedContainerTarget{binding, 4321, 987654, TestIdentity()};
}

PendingContainerTarget Pending(const DockerTargetBinding& binding) {
  return PendingContainerTarget{binding};
}

std::string RoleText(ParticipantRole role) {
  switch (role) {
    case ParticipantRole::Authority: return "authority";
    case ParticipantRole::Replica: return "replica";
    case ParticipantRole::Adapter: return "adapter";
    case ParticipantRole::Witness: return "witness";
  }
  return "unknown";
}

std::vector<std::pair<std::string, std::string>> Labels(
    const DockerTargetBinding& binding) {
  return {
      {"io.rateguard.domain", Hex(binding.domain_id)},
      {"io.rateguard.epoch", Hex(binding.epoch_id)},
      {"io.rateguard.authority", Hex(binding.authority_incarnation)},
      {"io.rateguard.policy", Hex(binding.policy_digest)},
      {"io.rateguard.role", RoleText(binding.role)},
      {"io.rateguard.slot", std::to_string(binding.slot_id)},
      {"io.rateguard.participant", binding.participant_id},
      {"io.rateguard.incarnation", Hex(binding.incarnation)},
  };
}

std::string InspectJson(
    const DockerTargetBinding& binding,
    std::string_view status = "running", bool running = true,
    bool restarting = false, std::uint64_t pid = 4321,
    std::string_view restart_policy = "no",
    std::optional<std::pair<std::string, std::string>> override_label = std::nullopt,
    std::string_view id_override = {}) {
  auto labels = Labels(binding);
  if (override_label) {
    for (auto& [key, value] : labels)
      if (key == override_label->first) value = override_label->second;
  }
  const std::string& id = id_override.empty() ? binding.container_id
                                               : std::string(id_override);
  std::string json = "{\"Id\":\"" + id + "\",\"Config\":{\"Labels\":{";
  for (std::size_t i = 0; i < labels.size(); ++i) {
    if (i != 0) json += ',';
    json += "\"" + labels[i].first + "\":\"" + labels[i].second + "\"";
  }
  json += "}},\"HostConfig\":{\"RestartPolicy\":{\"Name\":\"";
  json += restart_policy;
  json += "\"}},\"State\":{\"Status\":\"";
  json += status;
  json += "\",\"Running\":";
  json += running ? "true" : "false";
  json += ",\"Restarting\":";
  json += restarting ? "true" : "false";
  json += ",\"Pid\":" + std::to_string(pid) + "}}";
  return json;
}

std::string VersionJson(std::string_view min = "1.42",
                        std::string_view max = "1.57") {
  return "{\"ApiVersion\":\"" + std::string(max) +
         "\",\"MinAPIVersion\":\"" + std::string(min) + "\"}";
}

ScriptStep Http(UnixHttpMethod method, std::string target, std::uint16_t status,
                std::string body = {}) {
  return {method, std::move(target), UnixHttpResponse{
      status, std::vector<std::uint8_t>(body.begin(), body.end())}};
}

ScriptStep TransportFailure(UnixHttpMethod method, std::string target,
                            UnixHttpFailureReason reason, bool sent) {
  return {method, std::move(target), UnixHttpFailure{reason, sent}};
}

struct Fixture {
  std::shared_ptr<FixedClock> clock = std::make_shared<FixedClock>();
  std::shared_ptr<TransportState> transport_state =
      std::make_shared<TransportState>();
  std::shared_ptr<ProbeState> probe_state = std::make_shared<ProbeState>();
  std::unique_ptr<IRecoveryProcessController> controller;
  std::optional<DockerControllerFailure> create_failure;
};

Fixture MakeFixture(std::string selected_api = "1.57",
                    std::string version_body = VersionJson(),
                    std::uint16_t version_status = 200,
                    std::vector<ScriptStep> calls = {},
                    std::vector<LinuxProcessProbeResult> probe_results = {}) {
  Fixture fixture;
  fixture.transport_state->steps.push_back(
      Http(UnixHttpMethod::Get, "/version", version_status,
           std::move(version_body)));
  for (auto& call : calls)
    fixture.transport_state->steps.push_back(std::move(call));
  fixture.probe_state->results = std::move(probe_results);
  DockerProcessControllerConfig config;
  config.unix_socket_path = "/fixture/docker.sock";
  config.engine_api_version = std::move(selected_api);
  config.process_probe.expected_observer_pid_namespace = {3, 4};
  auto transport = std::make_unique<ScriptedTransport>(fixture.transport_state);
  auto probe = std::make_unique<ScriptedProcessProbe>(fixture.probe_state);
  auto result = CreateDockerProcessController(config, *fixture.clock,
                                              std::move(transport),
                                              std::move(probe));
  if (std::holds_alternative<std::unique_ptr<IRecoveryProcessController>>(result))
    fixture.controller = std::move(std::get<std::unique_ptr<IRecoveryProcessController>>(result));
  else
    fixture.create_failure = std::get<DockerControllerFailure>(result);
  return fixture;
}

std::string InspectPath(std::string_view api, std::string_view cid) {
  return "/v" + std::string(api) + "/containers/" + std::string(cid) + "/json";
}

std::string StopPath(std::string_view api, std::string_view cid) {
  return "/v" + std::string(api) + "/containers/" + std::string(cid) +
         "/stop?signal=SIGTERM&t=1";
}

OperationId TestOperation() {
  OperationId id{};
  id[0] = 0x55;
  return id;
}

LinuxProcessObservation AbsentProcess() {
  return {LinuxProcessDisposition::RecordedProcessAbsent,
          LinuxProcessReason::None, 0, 0, std::nullopt,
          LinuxPidNamespaceIdentity{3, 4}};
}

LinuxProcessObservation LiveProcess() {
  return {LinuxProcessDisposition::LiveIdentityMatched,
          LinuxProcessReason::None, 987654, 'S', TestIdentity(),
          LinuxPidNamespaceIdentity{3, 4}};
}

LinuxProcessObservation ZombieProcess() {
  return {LinuxProcessDisposition::MatchedZombie,
          LinuxProcessReason::None, 987654, 'Z', TestIdentity(),
          LinuxPidNamespaceIdentity{3, 4}};
}

void TestFactoryApiCompatibilityFloorAndRange() {
  {
    auto fixture = MakeFixture("1.41", VersionJson("1.20", "1.57"));
    CHECK(!fixture.controller);
    CHECK(fixture.create_failure.has_value());
    if (fixture.create_failure)
      CHECK(fixture.create_failure->code == DockerControllerErrorCode::EngineVersionMismatch);
    CHECK(fixture.transport_state->targets.empty());
  }
  {
    auto fixture = MakeFixture("1.42", VersionJson("1.42", "1.57"));
    CHECK(fixture.controller != nullptr);
    CHECK(!fixture.create_failure.has_value());
  }
  {
    auto fixture = MakeFixture("1.42", VersionJson("1.43", "1.57"));
    CHECK(!fixture.controller);
    CHECK(fixture.create_failure.has_value());
    if (fixture.create_failure)
      CHECK(fixture.create_failure->code == DockerControllerErrorCode::EngineVersionMismatch);
  }
  {
    auto fixture = MakeFixture("1.58", VersionJson("1.42", "1.57"));
    CHECK(!fixture.controller);
    CHECK(fixture.create_failure.has_value());
    if (fixture.create_failure)
      CHECK(fixture.create_failure->code == DockerControllerErrorCode::EngineVersionMismatch);
  }
  {
    auto fixture = MakeFixture("1.57", "{\"ApiVersion\":\"1.x\","
                                      "\"MinAPIVersion\":\"1.42\"}");
    CHECK(!fixture.controller);
    CHECK(fixture.create_failure.has_value());
    if (fixture.create_failure)
      CHECK(fixture.create_failure->code == DockerControllerErrorCode::EngineVersionMismatch);
  }
  {
    auto fixture = MakeFixture("1.57", VersionJson(), 302);
    CHECK(!fixture.controller);
    CHECK(fixture.create_failure.has_value());
    if (fixture.create_failure)
      CHECK(fixture.create_failure->code == DockerControllerErrorCode::EngineVersionMismatch);
  }
}

void TestAllLabelsAndExactFullContainerIdAreBound() {
  const auto binding = TestBinding();
  const auto labels = Labels(binding);
  std::vector<ScriptStep> calls;
  for (const auto& [key, value] : labels) {
    calls.push_back(Http(UnixHttpMethod::Get,
                         InspectPath("1.57", binding.container_id), 200,
                         InspectJson(binding, "running", true, false, 4321, "no",
                                     std::pair{key, value + "x"})));
  }
  calls.push_back(Http(UnixHttpMethod::Get,
                       InspectPath("1.57", binding.container_id), 200,
                       InspectJson(binding, "running", true, false, 4321, "no",
                                   std::nullopt, std::string(64, 'b'))));
  auto fixture = MakeFixture("1.57", VersionJson(), 200, std::move(calls));
  CHECK(fixture.controller != nullptr);
  if (!fixture.controller) return;
  const RecoveryContainerTarget target = Pending(binding);
  std::atomic_bool cancelled{false};
  for (std::size_t i = 0; i < labels.size() + 1; ++i) {
    const auto result = fixture.controller->Inspect(
        target, ControllerDeadline{{15'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerContainerObservation>(result));
    if (std::holds_alternative<DockerContainerObservation>(result)) {
      const auto& observation = std::get<DockerContainerObservation>(result);
      CHECK(observation.disposition == DockerObservationDisposition::Unknown);
      CHECK(observation.reason == (i < labels.size()
          ? DockerObservationReason::LabelMismatch
          : DockerObservationReason::MissingIdentity));
      CHECK(observation.exit_evidence_scope == DockerExitEvidenceScope::None);
    }
  }
  CHECK(!fixture.transport_state->mismatch);
  CHECK(fixture.transport_state->targets.size() == labels.size() + 2);
}

void TestPendingAndObservedExitEvidenceAreDistinct() {
  const auto binding = TestBinding();
  {
    auto fixture = MakeFixture("1.57", VersionJson(), 200,
        {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
              InspectJson(binding, "exited", false, false, 0, "no"))});
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) return;
    std::atomic_bool cancelled{false};
    const RecoveryContainerTarget target = Pending(binding);
    const auto result = fixture.controller->Inspect(
        target, ControllerDeadline{{15'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerContainerObservation>(result));
    if (std::holds_alternative<DockerContainerObservation>(result)) {
      const auto& observation = std::get<DockerContainerObservation>(result);
      CHECK(observation.disposition == DockerObservationDisposition::MatchedExited);
      CHECK(observation.exit_evidence_scope == DockerExitEvidenceScope::RuntimeOnlyPendingTarget);
      CHECK(!observation.process_evidence.has_value());
    }
  }
  for (auto probe_result : {
           LinuxProcessProbeResult{AbsentProcess()},
           LinuxProcessProbeResult{LiveProcess()},
           LinuxProcessProbeResult{ZombieProcess()},
           LinuxProcessProbeResult{LinuxProcessProbeFailure{LinuxProcessReason::PermissionDenied}}}) {
    std::vector<ScriptStep> calls{Http(
        UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
        InspectJson(binding, "exited", false, false, 0, "no"))};
    std::vector<LinuxProcessProbeResult> probes;
    probes.push_back(std::move(probe_result));
    auto fixture = MakeFixture("1.57", VersionJson(), 200, std::move(calls),
                               std::move(probes));
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) continue;
    std::atomic_bool cancelled{false};
    const RecoveryContainerTarget target = Observed(binding);
    const auto result = fixture.controller->Inspect(
        target, ControllerDeadline{{15'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerContainerObservation>(result));
    if (!std::holds_alternative<DockerContainerObservation>(result)) continue;
    const auto& observation = std::get<DockerContainerObservation>(result);
    CHECK(fixture.probe_state->checked.size() == 1);
    if (fixture.probe_state->next_result == 1) {
      const auto& returned = fixture.probe_state->results[0];
      if (std::holds_alternative<LinuxProcessObservation>(returned) &&
          std::get<LinuxProcessObservation>(returned).disposition ==
              LinuxProcessDisposition::RecordedProcessAbsent) {
        CHECK(observation.disposition == DockerObservationDisposition::MatchedExited);
        CHECK(observation.exit_evidence_scope ==
              DockerExitEvidenceScope::RuntimeAndRecordedProcessAbsent);
      } else {
        CHECK(observation.disposition == DockerObservationDisposition::Unknown);
        CHECK(observation.exit_evidence_scope == DockerExitEvidenceScope::None);
      }
    }
  }
}

void TestInspectUnexpectedStatusAndTerminalMismatches() {
  const auto binding = TestBinding();
  const std::vector<ScriptStep> cases = {
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 404,
           "{}"),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 302,
           "{}"),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 500,
           "{}"),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
           "not json"),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
           InspectJson(binding, "dead", false, false, 0, "no")),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
           InspectJson(binding, "exited", false, false, 0, "always")),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
           InspectJson(binding, "exited", false, true, 0, "no")),
      Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
           InspectJson(binding, "exited", true, false, 0, "no")),
  };
  for (std::size_t index = 0; index < cases.size(); ++index) {
    auto call = cases[index];
    auto fixture = MakeFixture("1.57", VersionJson(), 200, {std::move(call)});
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) continue;
    std::atomic_bool cancelled{false};
    const RecoveryContainerTarget target = Pending(binding);
    const auto result = fixture.controller->Inspect(
        target, ControllerDeadline{{15'000'000'000ULL}}, cancelled);
    if (index == 1 || index == 2) {
      CHECK(std::holds_alternative<DockerControllerFailure>(result));
      if (std::holds_alternative<DockerControllerFailure>(result))
        CHECK(std::get<DockerControllerFailure>(result).code ==
              DockerControllerErrorCode::HttpProtocolError);
    } else {
      CHECK(std::holds_alternative<DockerContainerObservation>(result));
      if (std::holds_alternative<DockerContainerObservation>(result))
        CHECK(std::get<DockerContainerObservation>(result).disposition ==
              DockerObservationDisposition::Unknown);
    }
    CHECK(fixture.transport_state->targets.size() == 2);
  }
}

void TestInspectBodyLimitIsTypedFailure() {
  const auto binding = TestBinding();
  std::string body(kDockerMaxInspectBodyBytes + 1, 'x');
  auto fixture = MakeFixture("1.57", VersionJson(), 200,
      {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id),
            200, std::move(body))});
  CHECK(fixture.controller != nullptr);
  if (!fixture.controller) return;
  std::atomic_bool cancelled{false};
  const auto result = fixture.controller->Inspect(
      Pending(binding), ControllerDeadline{{15'000'000'000ULL}}, cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(result));
  if (std::holds_alternative<DockerControllerFailure>(result))
    CHECK(std::get<DockerControllerFailure>(result).code ==
          DockerControllerErrorCode::ResponseTooLarge);
  CHECK(fixture.transport_state->targets.size() == 2);
}

void TestJsonDepthNodeFieldAndStringLimitsFailClosed() {
  const auto binding = TestBinding();
  const auto base = InspectJson(binding);
  std::vector<std::string> malformed_or_over_bound;
  malformed_or_over_bound.push_back("{\"Id\":\"" + binding.container_id +
      "\",\"Config\":{\"Labels\":{}},\"HostConfig\":{},\"State\":{}"
      ",\"x\":" + std::string(kDockerMaxJsonDepth + 2, '[') + "0" +
      std::string(kDockerMaxJsonDepth + 2, ']') + "}");
  std::string fields = base.substr(0, base.size() - 1);
  for (std::size_t i = 0; i < kDockerMaxJsonFields + 1; ++i)
    fields += ",\"x" + std::to_string(i) + "\":0";
  fields += '}';
  malformed_or_over_bound.push_back(std::move(fields));
  std::string many_nodes =
      "{\"Id\":\"" + binding.container_id + "\",\"Config\":{\"Labels\":{}},"
      "\"HostConfig\":{},\"State\":{},\"x\":[";
  for (std::size_t i = 0; i < kDockerMaxJsonNodes + 1; ++i) {
    if (i != 0) many_nodes += ',';
    many_nodes += '0';
  }
  many_nodes += "]}";
  malformed_or_over_bound.push_back(std::move(many_nodes));

  std::string long_string = InspectJson(binding);
  const auto marker = std::string("\"io.rateguard.participant\":\"authority\"");
  const auto position = long_string.find(marker);
  CHECK(position != std::string::npos);
  if (position != std::string::npos)
    long_string.replace(position, marker.size(),
        "\"io.rateguard.participant\":\"" +
            std::string(kDockerMaxJsonStringBytes + 1, 'x') + "\"");
  malformed_or_over_bound.push_back(std::move(long_string));
  auto duplicate_key = InspectJson(binding);
  const auto id_key = std::string("\"Id\":\"") + binding.container_id + "\"";
  const auto id_position = duplicate_key.find(id_key);
  CHECK(id_position != std::string::npos);
  if (id_position != std::string::npos)
    duplicate_key.insert(id_position + id_key.size(), "," + id_key);
  malformed_or_over_bound.push_back(std::move(duplicate_key));
  malformed_or_over_bound.push_back(
      "{\"Id\":42,\"Config\":{\"Labels\":{}},\"HostConfig\":{},\"State\":{}}");

  for (auto& body : malformed_or_over_bound) {
    auto fixture = MakeFixture("1.57", VersionJson(), 200,
        {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id),
              200, std::move(body))});
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) continue;
    std::atomic_bool cancelled{false};
    const RecoveryContainerTarget target = Pending(binding);
    const auto result = fixture.controller->Inspect(
        target, ControllerDeadline{{15'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerContainerObservation>(result));
    if (std::holds_alternative<DockerContainerObservation>(result))
      CHECK(std::get<DockerContainerObservation>(result).disposition ==
            DockerObservationDisposition::Unknown);
  }
}

void TestStopPreflightMismatchNeverPosts() {
  const auto binding = TestBinding();
  auto fixture = MakeFixture("1.57", VersionJson(), 200,
      {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
            InspectJson(binding, "running", true, false, 4321, "no",
                        std::pair{"io.rateguard.policy", "wrong"}))});
  CHECK(fixture.controller != nullptr);
  if (!fixture.controller) return;
  std::atomic_bool cancelled{false};
  auto operation = TestOperation();
  const RecoveryContainerTarget target = Pending(binding);
  const auto result = fixture.controller->RequestStop(
      target, operation, ControllerDeadline{{20'000'000'000ULL}}, cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(result));
  if (std::holds_alternative<DockerControllerFailure>(result)) {
    const auto failure = std::get<DockerControllerFailure>(result);
    CHECK(failure.code == DockerControllerErrorCode::IdentityMismatch);
    CHECK(!failure.stop_request_possibly_sent);
  }
  CHECK(fixture.transport_state->targets.size() == 2);
  CHECK(fixture.transport_state->targets.back() ==
        InspectPath("1.57", binding.container_id));
}

void TestStopPreflightEveryBindingMismatchNeverPosts() {
  const auto binding = TestBinding();
  const auto labels = Labels(binding);
  std::vector<ScriptStep> calls;
  for (const auto& [key, value] : labels) {
    calls.push_back(Http(UnixHttpMethod::Get,
        InspectPath("1.57", binding.container_id), 200,
        InspectJson(binding, "running", true, false, 4321, "no",
                    std::pair{key, value + "-changed"})));
  }
  calls.push_back(Http(UnixHttpMethod::Get,
      InspectPath("1.57", binding.container_id), 200,
      InspectJson(binding, "running", true, false, 4321, "no", std::nullopt,
                  std::string(64, 'b'))));
  auto fixture = MakeFixture("1.57", VersionJson(), 200, std::move(calls));
  CHECK(fixture.controller != nullptr);
  if (!fixture.controller) return;
  std::atomic_bool cancelled{false};
  const RecoveryContainerTarget target = Pending(binding);
  for (std::size_t i = 0; i < labels.size() + 1; ++i) {
    const auto result = fixture.controller->RequestStop(
        target, TestOperation(), ControllerDeadline{{20'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerControllerFailure>(result));
    if (std::holds_alternative<DockerControllerFailure>(result)) {
      const auto failure = std::get<DockerControllerFailure>(result);
      CHECK(failure.code == DockerControllerErrorCode::IdentityMismatch);
      CHECK(!failure.stop_request_possibly_sent);
    }
  }
  CHECK(fixture.transport_state->targets.size() == labels.size() + 2);
  CHECK(std::all_of(fixture.transport_state->methods.begin() + 1,
                    fixture.transport_state->methods.end(),
                    [](UnixHttpMethod method) { return method == UnixHttpMethod::Get; }));
  CHECK(!fixture.transport_state->mismatch);
}

void TestStopAcknowledgementsAreNotExitEvidenceAndNeverRetry() {
  const auto binding = TestBinding();
  for (const auto [status, expected_kind] : {
           std::pair<std::uint16_t, DockerStopAcknowledgement::Kind>{
               204, DockerStopAcknowledgement::Kind::Accepted},
           std::pair<std::uint16_t, DockerStopAcknowledgement::Kind>{
               304, DockerStopAcknowledgement::Kind::AlreadyStopped}}) {
    auto fixture = MakeFixture("1.57", VersionJson(), 200,
        {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
              InspectJson(binding)),
         Http(UnixHttpMethod::Post, StopPath("1.57", binding.container_id), status)});
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) continue;
    std::atomic_bool cancelled{false};
    const auto operation = TestOperation();
    const RecoveryContainerTarget target = Pending(binding);
    const auto result = fixture.controller->RequestStop(
        target, operation, ControllerDeadline{{20'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerStopAcknowledgement>(result));
    if (std::holds_alternative<DockerStopAcknowledgement>(result)) {
      const auto& ack = std::get<DockerStopAcknowledgement>(result);
      CHECK(ack.operation_id == operation);
      CHECK(ack.kind == expected_kind);
    }
    CHECK(fixture.transport_state->targets.size() == 3);
    CHECK(fixture.transport_state->targets[2] == StopPath("1.57", binding.container_id));
    CHECK(!fixture.transport_state->mismatch);
  }
}

void TestStopMayDrainWithBadPidOrRestartButCannotClaimExit() {
  const auto binding = TestBinding();
  auto fixture = MakeFixture("1.57", VersionJson(), 200,
      {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
            InspectJson(binding, "running", true, false, 0, "always")),
       Http(UnixHttpMethod::Post, StopPath("1.57", binding.container_id), 204)});
  CHECK(fixture.controller != nullptr);
  if (!fixture.controller) return;
  std::atomic_bool cancelled{false};
  const RecoveryContainerTarget target = Observed(binding);
  const auto result = fixture.controller->RequestStop(
      target, TestOperation(), ControllerDeadline{{20'000'000'000ULL}}, cancelled);
  CHECK(std::holds_alternative<DockerStopAcknowledgement>(result));
  CHECK(fixture.transport_state->targets.size() == 3);
  CHECK(fixture.transport_state->targets.back() == StopPath("1.57", binding.container_id));
  CHECK(fixture.probe_state->checked.size() <= 1);
  // ACK is a request result only; there is no MatchedExited observation here.
}

void TestStopPostDispatchFailurePreservesUncertaintyAndNoRetry() {
  const auto binding = TestBinding();
  for (const bool sent : {false, true}) {
    auto fixture = MakeFixture("1.57", VersionJson(), 200,
        {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
              InspectJson(binding)),
         TransportFailure(UnixHttpMethod::Post, StopPath("1.57", binding.container_id),
                          UnixHttpFailureReason::DeadlineExpired, sent)});
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) continue;
    std::atomic_bool cancelled{false};
    const RecoveryContainerTarget target = Pending(binding);
    const auto result = fixture.controller->RequestStop(
        target, TestOperation(), ControllerDeadline{{20'000'000'000ULL}}, cancelled);
    CHECK(std::holds_alternative<DockerControllerFailure>(result));
    if (std::holds_alternative<DockerControllerFailure>(result))
      CHECK(std::get<DockerControllerFailure>(result).stop_request_possibly_sent == sent);
    CHECK(fixture.transport_state->targets.size() == 3);
    CHECK(!fixture.transport_state->mismatch);
  }
}

void TestUnexpectedStopHttpResultsRemainUncertainAndDoNotRetry() {
  const auto binding = TestBinding();
  for (const auto& [status, expected_code] : {
           std::pair<std::uint16_t, DockerControllerErrorCode>{
               404, DockerControllerErrorCode::IdentityMismatch},
           std::pair<std::uint16_t, DockerControllerErrorCode>{
               500, DockerControllerErrorCode::HttpProtocolError},
           std::pair<std::uint16_t, DockerControllerErrorCode>{
               200, DockerControllerErrorCode::HttpProtocolError}}) {
    const std::string response_body = status == 200 ? "unexpected" : "";
    auto fixture = MakeFixture("1.57", VersionJson(), 200,
        {Http(UnixHttpMethod::Get, InspectPath("1.57", binding.container_id), 200,
              InspectJson(binding)),
         Http(UnixHttpMethod::Post, StopPath("1.57", binding.container_id),
              status, response_body)});
    CHECK(fixture.controller != nullptr);
    if (!fixture.controller) continue;
    std::atomic_bool cancelled{false};
    const auto result = fixture.controller->RequestStop(
        Pending(binding), TestOperation(), ControllerDeadline{{20'000'000'000ULL}},
        cancelled);
    CHECK(std::holds_alternative<DockerControllerFailure>(result));
    if (std::holds_alternative<DockerControllerFailure>(result)) {
      const auto failure = std::get<DockerControllerFailure>(result);
      CHECK(failure.code == expected_code);
      CHECK(failure.stop_request_possibly_sent);
    }
    CHECK(fixture.transport_state->targets.size() == 3);
    CHECK(fixture.transport_state->methods.back() == UnixHttpMethod::Post);
  }
}

void TestCancelledAndInvalidDeadlinesDoNotCallTransport() {
  const auto binding = TestBinding();
  auto fixture = MakeFixture();
  CHECK(fixture.controller != nullptr);
  if (!fixture.controller) return;
  const auto calls_before = fixture.transport_state->targets.size();
  std::atomic_bool cancelled{true};
  auto result = fixture.controller->Inspect(
      Pending(binding), ControllerDeadline{{15'000'000'000ULL}}, cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(result));
  if (std::holds_alternative<DockerControllerFailure>(result))
    CHECK(std::get<DockerControllerFailure>(result).code ==
          DockerControllerErrorCode::Cancelled);
  CHECK(fixture.transport_state->targets.size() == calls_before);

  cancelled.store(false, std::memory_order_relaxed);
  result = fixture.controller->Inspect(Pending(binding),
                                       ControllerDeadline{{1}}, cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(result));
  if (std::holds_alternative<DockerControllerFailure>(result))
    CHECK(std::get<DockerControllerFailure>(result).code ==
          DockerControllerErrorCode::InvalidDeadline);
  CHECK(fixture.transport_state->targets.size() == calls_before);

  cancelled.store(true, std::memory_order_relaxed);
  const auto stop_result = fixture.controller->RequestStop(
      Pending(binding), TestOperation(),
      ControllerDeadline{{15'000'000'000ULL}}, cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(stop_result));
  if (std::holds_alternative<DockerControllerFailure>(stop_result))
    CHECK(std::get<DockerControllerFailure>(stop_result).code ==
          DockerControllerErrorCode::Cancelled);
  CHECK(fixture.transport_state->targets.size() == calls_before);

  OperationId zero_operation{};
  const auto zero_op_result = fixture.controller->RequestStop(
      Pending(binding), zero_operation,
      ControllerDeadline{{15'000'000'000ULL}}, cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(zero_op_result));
  if (std::holds_alternative<DockerControllerFailure>(zero_op_result))
    CHECK(std::get<DockerControllerFailure>(zero_op_result).code ==
          DockerControllerErrorCode::InvalidOperationId);
  CHECK(fixture.transport_state->targets.size() == calls_before);
}

}  // namespace

int main() {
  TestFactoryApiCompatibilityFloorAndRange();
  TestAllLabelsAndExactFullContainerIdAreBound();
  TestPendingAndObservedExitEvidenceAreDistinct();
  TestInspectUnexpectedStatusAndTerminalMismatches();
  TestInspectBodyLimitIsTypedFailure();
  TestJsonDepthNodeFieldAndStringLimitsFailClosed();
  TestStopPreflightMismatchNeverPosts();
  TestStopPreflightEveryBindingMismatchNeverPosts();
  TestStopAcknowledgementsAreNotExitEvidenceAndNeverRetry();
  TestStopMayDrainWithBadPidOrRestartButCannotClaimExit();
  TestStopPostDispatchFailurePreservesUncertaintyAndNoRetry();
  TestUnexpectedStopHttpResultsRemainUncertainAndDoNotRetry();
  TestCancelledAndInvalidDeadlinesDoNotCallTransport();
  if (failures != 0) {
    std::cerr << failures << " independent Docker controller assertion(s) failed\n";
    return 1;
  }
  std::cout << "Independent Docker controller checks passed\n";
  return 0;
}
