#include "supervisor/docker_process_controller.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace rateguard::supervisor;
using namespace rateguard::platform;

#define CHECK(condition) do { \
  if (!(condition)) { \
    std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
    return false; \
  } \
} while (false)

struct FakeClock final : IClock {
  std::uint64_t now{1'000};
  bool healthy{true};
  bool throw_on_now{};

  ClockResult<MonoNanos> Now() override {
    if (throw_on_now) throw std::runtime_error("clock fake exception");
    if (!healthy) return ClockFailure{
        rateguard::v1::contract::ServiceError{
            rateguard::v1::contract::ErrorCategory::Dependency,
            rateguard::v1::contract::ErrorCode::Unavailable,
            rateguard::v1::contract::RetryDisposition::Never,
            rateguard::v1::contract::Commitment::NotCommitted},
        ClockFailureReason::LatchedFailure};
    return MonoNanos{now};
  }
  ClockResult<ClockIdentity> Provenance() override {
    return ClockFailure{
        rateguard::v1::contract::ServiceError{
            rateguard::v1::contract::ErrorCategory::Dependency,
            rateguard::v1::contract::ErrorCode::Unavailable,
            rateguard::v1::contract::RetryDisposition::Never,
            rateguard::v1::contract::Commitment::NotCommitted},
        ClockFailureReason::LatchedFailure};
  }
  bool Healthy() const override { return healthy; }
};

struct ScriptedTransport final : IUnixHttpTransport {
  struct Call final {
    UnixHttpMethod method{};
    std::string target;
    MonoNanos deadline{};
  };
  std::vector<Call> calls;
  std::shared_ptr<std::vector<Call>> transcript{std::make_shared<std::vector<Call>>()};
  std::vector<UnixHttpResult> results;
  std::function<void(std::size_t)> after_call;
  std::shared_ptr<std::size_t> call_count{std::make_shared<std::size_t>(0)};

  UnixHttpResult RoundTrip(UnixHttpMethod method, std::string_view target,
                           MonoNanos deadline,
                           const std::atomic_bool&) noexcept override {
    try {
      calls.push_back(Call{method, std::string(target), deadline});
      transcript->push_back(Call{method, std::string(target), deadline});
      ++*call_count;
      if (after_call) after_call(calls.size());
      if (results.empty()) return UnixHttpFailure{UnixHttpFailureReason::SocketFailure, false};
      auto result = std::move(results.front());
      results.erase(results.begin());
      return result;
    } catch (...) {
      return UnixHttpFailure{UnixHttpFailureReason::AllocationFailure, false};
    }
  }
};

struct ScriptedProbe final : IRecordedProcessProbe {
  std::vector<LinuxProcessProbeResult> results;
  std::vector<RecordedLinuxProcess> calls;
  std::function<void()> after_check;
  LinuxProcessProbeResult Check(const RecordedLinuxProcess& process, MonoNanos,
                               const std::atomic_bool&) noexcept override {
    try {
      calls.push_back(process);
      if (after_check) after_check();
      if (results.empty()) {
        LinuxProcessObservation result;
        result.disposition = LinuxProcessDisposition::LiveIdentityMatched;
        result.reason = LinuxProcessReason::None;
        result.observed_pid_start_ticks = process.pid_start_ticks;
        result.observed_state = 'S';
        result.observed_clock_identity = process.clock_identity;
        return result;
      }
      auto result = std::move(results.front());
      results.erase(results.begin());
      return result;
    } catch (...) {
      return LinuxProcessProbeFailure{LinuxProcessReason::AllocationFailure};
    }
  }
};

std::string Hex(const auto& value) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  for (const auto byte : value) {
    out.push_back(kHex[(byte >> 4U) & 0x0fU]);
    out.push_back(kHex[byte & 0x0fU]);
  }
  return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t first) {
  std::array<std::uint8_t, N> out{};
  out[0] = first;
  return out;
}

DockerTargetBinding Binding() {
  DockerTargetBinding b;
  b.domain_id = Filled<16>(1);
  b.epoch_id = Filled<16>(2);
  b.authority_incarnation = Filled<16>(3);
  b.policy_digest = Filled<32>(4);
  b.role = ParticipantRole::Adapter;
  b.slot_id = 0;
  b.participant_id = "adapter-1";
  b.incarnation = Filled<16>(5);
  b.container_id = std::string(64, 'a');
  return b;
}

ClockIdentity ClockIdentityFixture() {
  ClockIdentity identity{};
  identity.boot_uuid = Filled<16>(6);
  identity.namespace_device = 12;
  identity.namespace_inode = 34;
  identity.clock_id = 1;
  return identity;
}

RecoveryContainerTarget PendingTarget() { return PendingContainerTarget{Binding()}; }

RecoveryContainerTarget ObservedTargetFixture() {
  return ObservedContainerTarget{Binding(), 1234, 5678, ClockIdentityFixture()};
}

std::string InspectJson(const DockerTargetBinding& b, std::string_view status = "exited",
                       bool running = false, bool restarting = false,
                       std::uint64_t pid = 0, std::string_view restart_policy = "no") {
  return "{\"Id\":\"" + b.container_id + "\",\"Config\":{\"Labels\":{" +
      "\"io.rateguard.domain\":\"" + Hex(b.domain_id) + "\"," +
      "\"io.rateguard.epoch\":\"" + Hex(b.epoch_id) + "\"," +
      "\"io.rateguard.authority\":\"" + Hex(b.authority_incarnation) + "\"," +
      "\"io.rateguard.policy\":\"" + Hex(b.policy_digest) + "\"," +
      "\"io.rateguard.role\":\"adapter\"," +
      "\"io.rateguard.slot\":\"0\"," +
      "\"io.rateguard.participant\":\"" + b.participant_id + "\"," +
      "\"io.rateguard.incarnation\":\"" + Hex(b.incarnation) + "\"}}," +
      "\"HostConfig\":{\"RestartPolicy\":{\"Name\":\"" +
      std::string(restart_policy) + "\"}},\"State\":{\"Status\":\"" +
      std::string(status) + "\",\"Running\":" + (running ? "true" : "false") +
      ",\"Restarting\":" + (restarting ? "true" : "false") +
      ",\"Pid\":" + std::to_string(pid) + "}}";
}

UnixHttpResponse Response(std::uint16_t status, std::string body = {}) {
  return UnixHttpResponse{status, std::vector<std::uint8_t>(body.begin(), body.end())};
}

bool TestTargetValidation() {
  auto pending = PendingTarget();
  CHECK(ValidateRecoveryContainerTarget(pending));
  auto bad = std::get<PendingContainerTarget>(pending);
  bad.binding.container_id[0] = 'A';
  CHECK(!ValidateRecoveryContainerTarget(RecoveryContainerTarget{bad}));
  bad = std::get<PendingContainerTarget>(pending);
  bad.binding.slot_id = 1;
  CHECK(!ValidateRecoveryContainerTarget(RecoveryContainerTarget{bad}));
  auto observed = std::get<ObservedContainerTarget>(ObservedTargetFixture());
  CHECK(ValidateRecoveryContainerTarget(RecoveryContainerTarget{observed}));
  observed.host_pid = 0;
  CHECK(!ValidateRecoveryContainerTarget(RecoveryContainerTarget{observed}));
  return true;
}

bool TestVersionQualification() {
  FakeClock clock;
  auto make = [&](std::string api, std::string body, DockerControllerErrorCode expected,
                  bool should_call_transport) {
    auto transport = std::make_unique<ScriptedTransport>();
    const auto call_count = transport->call_count;
    const auto transcript = transport->transcript;
    auto probe = std::make_unique<ScriptedProbe>();
    DockerProcessControllerConfig config;
    config.unix_socket_path = "/fake/docker.sock";
    config.engine_api_version = std::move(api);
    config.process_probe.expected_observer_pid_namespace = {1, 2};
    transport->results.emplace_back(Response(200, std::move(body)));
    auto result = CreateDockerProcessController(config, clock,
        std::unique_ptr<IUnixHttpTransport>(transport.release()),
        std::unique_ptr<IRecordedProcessProbe>(probe.release()));
    if (should_call_transport) {
      CHECK(*call_count == 1);
      CHECK(transcript->front().method == UnixHttpMethod::Get);
      CHECK(transcript->front().target == "/version");
    }
    else CHECK(*call_count == 0);
    if (std::holds_alternative<std::unique_ptr<IRecoveryProcessController>>(result))
      return expected == DockerControllerErrorCode::InvalidTarget;
    return std::get<DockerControllerFailure>(result).code == expected;
  };

  CHECK(make("1.41", R"({"ApiVersion":"1.51","MinAPIVersion":"1.40"})",
             DockerControllerErrorCode::EngineVersionMismatch, false));
  CHECK(make("1.42", R"({"ApiVersion":"1.51","MinAPIVersion":"1.40"})",
             DockerControllerErrorCode::InvalidTarget, true));
  CHECK(make("1.42", R"({"ApiVersion":"1.51","MinAPIVersion":"1.43"})",
             DockerControllerErrorCode::EngineVersionMismatch, true));
  CHECK(make("1.52", R"({"ApiVersion":"1.51","MinAPIVersion":"1.40"})",
             DockerControllerErrorCode::EngineVersionMismatch, true));
  CHECK(make("01.42", R"({"ApiVersion":"1.51","MinAPIVersion":"1.40"})",
             DockerControllerErrorCode::EngineVersionMismatch, false));
  CHECK(make("1.42", R"({"ApiVersion":"1.51","ApiVersion":"1.52","MinAPIVersion":"1.40"})",
             DockerControllerErrorCode::EngineVersionMismatch, true));

  FakeClock late_clock;
  auto late_transport = std::make_unique<ScriptedTransport>();
  late_transport->results.emplace_back(Response(200, R"({"ApiVersion":"1.51","MinAPIVersion":"1.40"})"));
  late_transport->after_call = [&](std::size_t) {
    late_clock.now += kDockerMaxOperationTimeoutNanos;
  };
  auto late_probe = std::make_unique<ScriptedProbe>();
  DockerProcessControllerConfig late_config;
  late_config.unix_socket_path = "/fake/docker.sock";
  late_config.engine_api_version = "1.42";
  late_config.process_probe.expected_observer_pid_namespace = {1, 2};
  auto late_result = CreateDockerProcessController(late_config, late_clock,
      std::unique_ptr<IUnixHttpTransport>(late_transport.release()),
      std::unique_ptr<IRecordedProcessProbe>(late_probe.release()));
  CHECK(std::get<DockerControllerFailure>(late_result).code == DockerControllerErrorCode::TimedOut);
  return true;
}

struct Harness final {
  FakeClock clock;
  ScriptedTransport* transport{};
  ScriptedProbe* probe{};
  std::unique_ptr<IRecoveryProcessController> controller;

  bool Init() {
    auto t = std::make_unique<ScriptedTransport>();
    auto p = std::make_unique<ScriptedProbe>();
    transport = t.get();
    probe = p.get();
    transport->results.emplace_back(Response(200, R"({"ApiVersion":"1.51","MinAPIVersion":"1.40"})"));
    DockerProcessControllerConfig config;
    config.unix_socket_path = "/fake/docker.sock";
    config.engine_api_version = "1.42";
    config.process_probe.expected_observer_pid_namespace = {1, 2};
    auto result = CreateDockerProcessController(config, clock,
        std::unique_ptr<IUnixHttpTransport>(t.release()),
        std::unique_ptr<IRecordedProcessProbe>(p.release()));
    if (std::holds_alternative<DockerControllerFailure>(result)) return false;
    controller = std::move(std::get<std::unique_ptr<IRecoveryProcessController>>(result));
    return true;
  }

  ControllerDeadline Deadline(std::uint64_t offset = kDockerInspectDefaultTimeoutNanos) const {
    return ControllerDeadline{MonoNanos{clock.now + offset}};
  }
};

bool TestInspectExitEvidence() {
  Harness h;
  CHECK(h.Init());
  std::atomic_bool cancelled{false};
  const auto target = PendingTarget();
  h.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  auto result = h.controller->Inspect(target, h.Deadline(), cancelled);
  CHECK(std::holds_alternative<DockerContainerObservation>(result));
  const auto& pending = std::get<DockerContainerObservation>(result);
  CHECK(pending.disposition == DockerObservationDisposition::MatchedExited);
  CHECK(pending.exit_evidence_scope == DockerExitEvidenceScope::RuntimeOnlyPendingTarget);
  CHECK(h.probe->calls.empty());
  CHECK(h.transport->calls.back().target == "/v1.42/containers/" + Binding().container_id + "/json");

  Harness observed;
  CHECK(observed.Init());
  LinuxProcessObservation absent;
  absent.disposition = LinuxProcessDisposition::RecordedProcessAbsent;
  absent.reason = LinuxProcessReason::None;
  observed.probe->results.emplace_back(absent);
  observed.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  result = observed.controller->Inspect(ObservedTargetFixture(), observed.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).disposition == DockerObservationDisposition::MatchedExited);
  CHECK(std::get<DockerContainerObservation>(result).exit_evidence_scope ==
        DockerExitEvidenceScope::RuntimeAndRecordedProcessAbsent);

  Harness zombie;
  CHECK(zombie.Init());
  LinuxProcessObservation matched_zombie;
  matched_zombie.disposition = LinuxProcessDisposition::MatchedZombie;
  matched_zombie.reason = LinuxProcessReason::None;
  zombie.probe->results.emplace_back(matched_zombie);
  zombie.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  result = zombie.controller->Inspect(ObservedTargetFixture(), zombie.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).disposition == DockerObservationDisposition::Unknown);
  CHECK(std::get<DockerContainerObservation>(result).reason == DockerObservationReason::ProcessStillPresent);

  Harness mismatch;
  CHECK(mismatch.Init());
  mismatch.transport->results.emplace_back(Response(200, InspectJson(Binding(), "exited", false, false, 0, "always")));
  result = mismatch.controller->Inspect(PendingTarget(), mismatch.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).disposition == DockerObservationDisposition::Unknown);
  CHECK(std::get<DockerContainerObservation>(result).reason == DockerObservationReason::RestartPolicyUnexpected);
  return true;
}

bool TestInspectRejectsUntrustedResponses() {
  std::atomic_bool cancelled{false};
  Harness h;
  CHECK(h.Init());
  h.transport->results.emplace_back(Response(404));
  auto result = h.controller->Inspect(PendingTarget(), h.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).reason == DockerObservationReason::NotFound);

  const auto binding = Binding();
  h.transport->results.emplace_back(Response(200,
      "{\"Id\":\"" + binding.container_id + "\",\"Id\":\"" + binding.container_id + "\"}"));
  result = h.controller->Inspect(PendingTarget(), h.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).reason == DockerObservationReason::MalformedResponse);

  std::string nested = "{\"x\":";
  for (std::size_t i = 0; i < kDockerMaxJsonDepth + 2; ++i) nested += "[";
  nested += "0";
  for (std::size_t i = 0; i < kDockerMaxJsonDepth + 2; ++i) nested += "]";
  nested += "}";
  h.transport->results.emplace_back(Response(200, std::move(nested)));
  result = h.controller->Inspect(PendingTarget(), h.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).reason == DockerObservationReason::MalformedResponse);

  h.transport->results.emplace_back(Response(200, InspectJson(binding, "created", false, false, 0, "no")));
  result = h.controller->Inspect(PendingTarget(), h.Deadline(), cancelled);
  CHECK(std::get<DockerContainerObservation>(result).disposition == DockerObservationDisposition::Unknown);
  return true;
}

bool TestStopPreflightAndAcknowledgements() {
  Harness h;
  CHECK(h.Init());
  std::atomic_bool cancelled{false};
  OperationId operation = Filled<16>(7);
  auto bad = Binding();
  std::string bad_json = InspectJson(bad);
  const auto start = bad_json.find("io.rateguard.policy");
  CHECK(start != std::string::npos);
  const auto value = bad_json.find(Hex(bad.policy_digest), start);
  CHECK(value != std::string::npos);
  bad_json.replace(value, Hex(bad.policy_digest).size(), std::string(64, 'f'));
  h.transport->results.emplace_back(Response(200, bad_json));
  auto stopped = h.controller->RequestStop(PendingTarget(), operation, h.Deadline(), cancelled);
  CHECK(std::holds_alternative<DockerControllerFailure>(stopped));
  CHECK(std::get<DockerControllerFailure>(stopped).code == DockerControllerErrorCode::IdentityMismatch);
  CHECK(!std::get<DockerControllerFailure>(stopped).stop_request_possibly_sent);
  CHECK(h.transport->calls.size() == 2);  // Factory /version plus preflight GET only.

  // Policy/state are not prerequisites to stop a logically matched container.
  h.transport->results.emplace_back(Response(200, InspectJson(Binding(), "dead", false, false, 0, "always")));
  h.transport->results.emplace_back(Response(204));
  stopped = h.controller->RequestStop(PendingTarget(), operation, h.Deadline(kDockerStopDefaultTimeoutNanos), cancelled);
  CHECK(std::holds_alternative<DockerStopAcknowledgement>(stopped));
  CHECK(h.transport->calls.back().method == UnixHttpMethod::Post);
  CHECK(h.transport->calls.back().target == "/v1.42/containers/" + Binding().container_id +
        "/stop?signal=SIGTERM&t=1");

  h.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  h.transport->results.emplace_back(Response(304));
  stopped = h.controller->RequestStop(PendingTarget(), operation, h.Deadline(kDockerStopDefaultTimeoutNanos), cancelled);
  CHECK(std::get<DockerStopAcknowledgement>(stopped).kind == DockerStopAcknowledgement::Kind::AlreadyStopped);
  return true;
}

bool TestStopUncertaintyAndDeadlines() {
  Harness h;
  CHECK(h.Init());
  std::atomic_bool cancelled{false};
  const auto operation = Filled<16>(9);
  h.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  h.transport->results.emplace_back(UnixHttpFailure{UnixHttpFailureReason::SocketFailure, true});
  auto result = h.controller->RequestStop(PendingTarget(), operation,
      h.Deadline(kDockerStopDefaultTimeoutNanos), cancelled);
  CHECK(std::get<DockerControllerFailure>(result).stop_request_possibly_sent);

  h.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  h.transport->results.emplace_back(Response(500, "ignored"));
  result = h.controller->RequestStop(PendingTarget(), operation,
      h.Deadline(kDockerStopDefaultTimeoutNanos), cancelled);
  CHECK(std::get<DockerControllerFailure>(result).stop_request_possibly_sent);

  const auto before_calls = h.transport->calls.size();
  result = h.controller->RequestStop(PendingTarget(), operation,
      ControllerDeadline{MonoNanos{h.clock.now}}, cancelled);
  CHECK(std::get<DockerControllerFailure>(result).code == DockerControllerErrorCode::InvalidDeadline);
  CHECK(h.transport->calls.size() == before_calls);

  cancelled.store(true);
  result = h.controller->RequestStop(PendingTarget(), operation, h.Deadline(), cancelled);
  CHECK(std::get<DockerControllerFailure>(result).code == DockerControllerErrorCode::Cancelled);

  auto deadline = MakeDefaultInspectDeadline(h.clock);
  CHECK(std::holds_alternative<ControllerDeadline>(deadline));
  CHECK(std::get<ControllerDeadline>(deadline).at.value == h.clock.now + kDockerInspectDefaultTimeoutNanos);
  CHECK(std::holds_alternative<DockerControllerErrorCode>(MakeDockerDeadline(h.clock, 0)));
  CHECK(std::holds_alternative<DockerControllerErrorCode>(MakeDockerDeadline(
      h.clock, kDockerMaxOperationTimeoutNanos + 1)));
  h.clock.healthy = false;
  CHECK(std::get<DockerControllerErrorCode>(MakeDockerDeadline(h.clock, 1)) ==
        DockerControllerErrorCode::ClockUnavailable);
  h.clock.healthy = true;
  h.clock.throw_on_now = true;
  CHECK(std::get<DockerControllerErrorCode>(MakeDockerDeadline(h.clock, 1)) ==
        DockerControllerErrorCode::ClockUnavailable);
  h.clock.throw_on_now = false;
  Harness throwing_clock;
  CHECK(throwing_clock.Init());
  throwing_clock.clock.throw_on_now = true;
  const std::atomic_bool no_cancel{false};
  const auto inspect_error = throwing_clock.controller->Inspect(
      PendingTarget(), throwing_clock.Deadline(), no_cancel);
  CHECK(std::get<DockerControllerFailure>(inspect_error).code ==
        DockerControllerErrorCode::ClockUnavailable);
  return true;
}

bool TestFinalGateAfterInFlightWork() {
  Harness h;
  CHECK(h.Init());
  std::atomic_bool cancelled{false};
  h.transport->after_call = [&](std::size_t call) {
    if (call == 2) h.clock.now += kDockerInspectDefaultTimeoutNanos + 1;
  };
  h.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  auto result = h.controller->Inspect(PendingTarget(), h.Deadline(), cancelled);
  CHECK(std::get<DockerControllerFailure>(result).code == DockerControllerErrorCode::TimedOut);

  Harness during_probe;
  CHECK(during_probe.Init());
  during_probe.probe->after_check = [&] {
    during_probe.clock.now += kDockerInspectDefaultTimeoutNanos + 1;
  };
  during_probe.transport->results.emplace_back(
      Response(200, InspectJson(Binding(), "running", true, false, 1234)));
  result = during_probe.controller->Inspect(ObservedTargetFixture(), during_probe.Deadline(), cancelled);
  CHECK(std::get<DockerControllerFailure>(result).code == DockerControllerErrorCode::TimedOut);

  Harness cancelled_after_response;
  CHECK(cancelled_after_response.Init());
  std::atomic_bool cancel_after_response{false};
  cancelled_after_response.transport->after_call = [&](std::size_t call) {
    if (call == 2) cancel_after_response.store(true);
  };
  cancelled_after_response.transport->results.emplace_back(
      Response(200, InspectJson(Binding())));
  result = cancelled_after_response.controller->Inspect(
      PendingTarget(), cancelled_after_response.Deadline(), cancel_after_response);
  CHECK(std::get<DockerControllerFailure>(result).code == DockerControllerErrorCode::Cancelled);

  Harness stop;
  CHECK(stop.Init());
  stop.transport->after_call = [&](std::size_t call) {
    if (call == 3) stop.clock.now += kDockerStopDefaultTimeoutNanos + 1;
  };
  stop.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  stop.transport->results.emplace_back(Response(204));
  auto stopped = stop.controller->RequestStop(PendingTarget(), Filled<16>(8),
      stop.Deadline(kDockerStopDefaultTimeoutNanos), cancelled);
  CHECK(std::get<DockerControllerFailure>(stopped).code == DockerControllerErrorCode::TimedOut);
  CHECK(std::get<DockerControllerFailure>(stopped).stop_request_possibly_sent);

  Harness stop_cancelled;
  CHECK(stop_cancelled.Init());
  std::atomic_bool cancel_after_post{false};
  stop_cancelled.transport->after_call = [&](std::size_t call) {
    if (call == 3) cancel_after_post.store(true);
  };
  stop_cancelled.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  stop_cancelled.transport->results.emplace_back(Response(204));
  stopped = stop_cancelled.controller->RequestStop(PendingTarget(), Filled<16>(10),
      stop_cancelled.Deadline(kDockerStopDefaultTimeoutNanos), cancel_after_post);
  CHECK(std::get<DockerControllerFailure>(stopped).code == DockerControllerErrorCode::Cancelled);
  CHECK(std::get<DockerControllerFailure>(stopped).stop_request_possibly_sent);

  Harness unhealthy;
  CHECK(unhealthy.Init());
  unhealthy.transport->results.emplace_back(Response(200, InspectJson(Binding())));
  unhealthy.transport->after_call = [&](std::size_t) { unhealthy.clock.healthy = false; };
  result = unhealthy.controller->Inspect(PendingTarget(), unhealthy.Deadline(), cancelled);
  CHECK(std::get<DockerControllerFailure>(result).code == DockerControllerErrorCode::ClockUnavailable);
  return true;
}

}  // namespace

int main() {
  const bool ok = TestTargetValidation() && TestVersionQualification() &&
      TestInspectExitEvidence() && TestInspectRejectsUntrustedResponses() &&
      TestStopPreflightAndAcknowledgements() && TestStopUncertaintyAndDeadlines() &&
      TestFinalGateAfterInFlightWork();
  if (ok) std::cout << "docker process controller tests passed\n";
  return ok ? 0 : 1;
}
