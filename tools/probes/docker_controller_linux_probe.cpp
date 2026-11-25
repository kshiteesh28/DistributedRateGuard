#include "platform/clock_linux.h"
#include "supervisor/docker_process_controller.h"

#include <nlohmann/json.hpp>

#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <variant>
#include <vector>

namespace {

using Json = nlohmann::json;
using namespace rateguard::platform;
using namespace rateguard::supervisor;

constexpr std::size_t kFixtureMaxBytes = 16 * 1024;
constexpr std::size_t kJsonMaxDepth = 8;
constexpr std::size_t kJsonMaxNodes = 512;
constexpr std::size_t kJsonMaxFields = 64;
constexpr std::size_t kJsonMaxStringBytes = 4096;

struct Checks final {
  bool pending_running{};
  bool observed_running{};
  bool tampered_stop_rejected{};
  bool original_still_running{};
  bool stop_acknowledged{};
  bool observed_exit_proven{};
  bool pending_exit_proven{};
  bool repeat_stop_acknowledged{};

  [[nodiscard]] bool All() const noexcept {
    return pending_running && observed_running && tampered_stop_rejected &&
           original_still_running && stop_acknowledged && observed_exit_proven &&
           pending_exit_proven && repeat_stop_acknowledged;
  }
};

class BoundedSax final : public Json::json_sax_t {
 public:
  bool null() override { return Node(); }
  bool boolean(bool) override { return Node(); }
  bool number_integer(number_integer_t) override { return Node(); }
  bool number_unsigned(number_unsigned_t) override { return Node(); }
  bool number_float(number_float_t, const string_t&) override { return Node(); }
  bool binary(binary_t&) override { return Fail(); }
  bool string(string_t& s) override { return Node() && s.size() <= kJsonMaxStringBytes; }
  bool start_object(std::size_t) override {
    if (!Node() || frames_.size() >= kJsonMaxDepth) return Fail();
    try { frames_.push_back(Frame{true, 0, {}}); return true; }
    catch (...) { return Fail(); }
  }
  bool key(string_t& s) override {
    if (frames_.empty() || !frames_.back().object || s.size() > kJsonMaxStringBytes ||
        frames_.back().fields >= kJsonMaxFields) return Fail();
    try {
      auto& f = frames_.back();
      ++f.fields;
      return f.keys.insert(s).second || Fail();
    } catch (...) { return Fail(); }
  }
  bool end_object() override {
    if (frames_.empty() || !frames_.back().object) return Fail();
    frames_.pop_back(); return true;
  }
  bool start_array(std::size_t) override {
    if (!Node() || frames_.size() >= kJsonMaxDepth) return Fail();
    try { frames_.push_back(Frame{false, 0, {}}); return true; }
    catch (...) { return Fail(); }
  }
  bool end_array() override {
    if (frames_.empty() || frames_.back().object) return Fail();
    frames_.pop_back(); return true;
  }
  bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) override {
    return Fail();
  }
  [[nodiscard]] bool ok() const noexcept { return ok_; }

 private:
  struct Frame { bool object; std::size_t fields; std::set<std::string> keys; };
  bool Node() noexcept { return ++nodes_ <= kJsonMaxNodes || Fail(); }
  bool Fail() noexcept { ok_ = false; return false; }
  std::size_t nodes_{};
  bool ok_{true};
  std::vector<Frame> frames_;
};

bool ReadFixture(std::string_view path, std::string& bytes) noexcept {
  if (path.empty() || path.front() != '/' || path.size() > 4096) return false;
  try {
    const std::string owned_path(path);
    const int fd = ::open(owned_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct FdGuard { int fd; ~FdGuard() { if (fd >= 0) (void)::close(fd); } } guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        static_cast<std::uintmax_t>(st.st_size) > kFixtureMaxBytes) return false;
    bytes.clear();
    bytes.reserve(static_cast<std::size_t>(st.st_size));
    std::array<char, 2048> chunk{};
    for (;;) {
      const auto n = ::read(fd, chunk.data(), chunk.size());
      if (n < 0) { if (errno == EINTR) continue; return false; }
      if (n == 0) break;
      const auto count = static_cast<std::size_t>(n);
      if (count > kFixtureMaxBytes - bytes.size()) return false;
      bytes.append(chunk.data(), count);
    }
    return !bytes.empty();
  } catch (...) { return false; }
}

bool ExactKeys(const Json& value, std::initializer_list<std::string_view> expected) {
  if (!value.is_object() || value.size() != expected.size()) return false;
  for (const auto key : expected) if (!value.contains(key)) return false;
  return true;
}

bool ReadString(const Json& object, const char* key, std::string& out,
                std::size_t max = kJsonMaxStringBytes) {
  const auto it = object.find(key);
  if (it == object.end() || !it->is_string()) return false;
  out = it->get<std::string>();
  return !out.empty() && out.size() <= max;
}

template <class UInt>
bool ReadUnsigned(const Json& object, const char* key, UInt& out) {
  const auto it = object.find(key);
  if (it == object.end() || !(it->is_number_unsigned() || it->is_number_integer())) return false;
  std::uint64_t v{};
  if (it->is_number_unsigned()) {
    v = it->get<std::uint64_t>();
  } else {
    const auto signed_value = it->get<std::int64_t>();
    if (signed_value < 0) return false;
    v = static_cast<std::uint64_t>(signed_value);
  }
  if (v > std::numeric_limits<UInt>::max()) return false;
  out = static_cast<UInt>(v);
  return true;
}

bool ReadSigned(const Json& object, const char* key, std::int64_t& out) {
  const auto it = object.find(key);
  if (it == object.end() || !it->is_number_integer()) return false;
  if (it->is_number_unsigned()) {
    const auto value = it->get<std::uint64_t>();
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return false;
    out = static_cast<std::int64_t>(value);
  } else {
    out = it->get<std::int64_t>();
  }
  return true;
}

bool ValidApiVersion(std::string_view value) noexcept {
  if (value.size() < 3 || value[0] != '1' || value[1] != '.') return false;
  return std::all_of(value.begin() + 2, value.end(), [](unsigned char ch) {
    return ch >= '0' && ch <= '9';
  });
}

template <std::size_t N>
bool ParseHex(const Json& object, const char* key, std::array<std::uint8_t, N>& out) {
  std::string text;
  if (!ReadString(object, key, text, N * 2) || text.size() != N * 2) return false;
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < N; ++i) {
    const int hi = digit(text[2 * i]);
    const int lo = digit(text[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool ParseFixture(const Json& root, std::string& socket, std::string& api,
                  DockerTargetBinding& binding, ObservedContainerTarget& observed,
                  ClockIdentity& clock_id, LinuxPidNamespaceIdentity& observer_ns,
                  OperationId& stop_op) {
  if (!ExactKeys(root, {"schema_version", "socket_path", "api_version", "binding",
                        "recorded_process", "expected_clock_identity",
                        "expected_observer_pid_namespace", "stop_operation_id"})) return false;
  std::uint32_t schema{};
  if (!ReadUnsigned(root, "schema_version", schema) || schema != 1 ||
      !ReadString(root, "socket_path", socket, 107) || socket.front() != '/' ||
      !ReadString(root, "api_version", api, 16) || !ValidApiVersion(api)) return false;

  const auto& b = root.at("binding");
  if (!ExactKeys(b, {"domain_id", "epoch_id", "authority_incarnation", "policy_digest",
                     "role", "slot_id", "participant_id", "incarnation", "container_id"})) return false;
  std::string role;
  if (!ParseHex(b, "domain_id", binding.domain_id) || !ParseHex(b, "epoch_id", binding.epoch_id) ||
      !ParseHex(b, "authority_incarnation", binding.authority_incarnation) ||
      !ParseHex(b, "policy_digest", binding.policy_digest) ||
      !ParseHex(b, "incarnation", binding.incarnation) ||
      !ReadString(b, "role", role, 16) || role != "replica" ||
      !ReadUnsigned(b, "slot_id", binding.slot_id) ||
      !ReadString(b, "participant_id", binding.participant_id, 64) ||
      !ReadString(b, "container_id", binding.container_id, 64)) return false;
  binding.role = ParticipantRole::Replica;

  const auto& p = root.at("recorded_process");
  if (!ExactKeys(p, {"host_pid", "pid_start_ticks"}) ||
      !ReadUnsigned(p, "host_pid", observed.host_pid) || observed.host_pid == 0 ||
      !ReadUnsigned(p, "pid_start_ticks", observed.pid_start_ticks) || observed.pid_start_ticks == 0) return false;
  observed.binding = binding;

  const auto& c = root.at("expected_clock_identity");
  if (!ExactKeys(c, {"boot_uuid", "namespace_device", "namespace_inode",
                     "monotonic_offset_seconds", "monotonic_offset_nanoseconds",
                     "boottime_offset_seconds", "boottime_offset_nanoseconds", "clock_id"}) ||
      !ParseHex(c, "boot_uuid", clock_id.boot_uuid) ||
      !ReadUnsigned(c, "namespace_device", clock_id.namespace_device) ||
      !ReadUnsigned(c, "namespace_inode", clock_id.namespace_inode) ||
      !ReadSigned(c, "monotonic_offset_seconds", clock_id.monotonic_offset_seconds) ||
      !ReadUnsigned(c, "monotonic_offset_nanoseconds", clock_id.monotonic_offset_nanoseconds) ||
      clock_id.monotonic_offset_nanoseconds >= 1'000'000'000U ||
      !ReadSigned(c, "boottime_offset_seconds", clock_id.boottime_offset_seconds) ||
      !ReadUnsigned(c, "boottime_offset_nanoseconds", clock_id.boottime_offset_nanoseconds) ||
      clock_id.boottime_offset_nanoseconds >= 1'000'000'000U ||
      !ReadUnsigned(c, "clock_id", clock_id.clock_id)) return false;

  const auto& n = root.at("expected_observer_pid_namespace");
  if (!ExactKeys(n, {"device", "inode"}) ||
      !ReadUnsigned(n, "device", observer_ns.device) || !ReadUnsigned(n, "inode", observer_ns.inode)) return false;
  if (!ParseHex(root, "stop_operation_id", stop_op)) return false;
  return ValidateRecoveryContainerTarget(RecoveryContainerTarget{observed});
}

bool IsRunning(const DockerInspectResult& result) noexcept {
  const auto* observation = std::get_if<DockerContainerObservation>(&result);
  return observation != nullptr && observation->disposition == DockerObservationDisposition::MatchedRunning;
}

bool IsIdentityMismatchUnsent(const DockerStopResult& result) noexcept {
  const auto* failure = std::get_if<DockerControllerFailure>(&result);
  return failure != nullptr && failure->code == DockerControllerErrorCode::IdentityMismatch &&
         !failure->stop_request_possibly_sent;
}

bool IsStopAck(const DockerStopResult& result, const OperationId& op,
               DockerStopAcknowledgement::Kind kind) noexcept {
  const auto* ack = std::get_if<DockerStopAcknowledgement>(&result);
  return ack != nullptr && ack->operation_id == op && ack->kind == kind;
}

bool IsExited(const DockerInspectResult& result, DockerExitEvidenceScope scope) noexcept {
  const auto* observation = std::get_if<DockerContainerObservation>(&result);
  return observation != nullptr && observation->disposition == DockerObservationDisposition::MatchedExited &&
         observation->exit_evidence_scope == scope;
}

bool InspectObservedUntilExited(IRecoveryProcessController& controller, IClock& clock,
                                const RecoveryContainerTarget& observed,
                                const std::atomic_bool& cancel) {
  const auto deadline_result = MakeDockerDeadline(clock, kDockerInspectDefaultTimeoutNanos);
  const auto* deadline = std::get_if<ControllerDeadline>(&deadline_result);
  if (deadline == nullptr) return false;

  for (;;) {
    if (!clock.Healthy()) return false;
    const auto now_result = clock.Now();
    const auto* now = std::get_if<MonoNanos>(&now_result);
    if (now == nullptr || now->value >= deadline->at.value) return false;

    const auto result = controller.Inspect(observed, *deadline, cancel);
    if (IsExited(result, DockerExitEvidenceScope::RuntimeAndRecordedProcessAbsent)) return true;

    const auto* observation = std::get_if<DockerContainerObservation>(&result);
    if (observation == nullptr || observation->disposition != DockerObservationDisposition::Unknown ||
        (observation->reason != DockerObservationReason::ProcessAbsenceUnverified &&
         observation->reason != DockerObservationReason::ProcessStillPresent &&
         observation->reason != DockerObservationReason::ContainerNotTerminal)) {
      return false;
    }

    const auto after_result = clock.Now();
    const auto* after = std::get_if<MonoNanos>(&after_result);
    if (after == nullptr || after->value >= deadline->at.value) return false;
    const auto remaining = deadline->at.value - after->value;
    constexpr std::uint64_t kPollNanos = 20'000'000ULL;
    const auto sleep_nanos = std::min(remaining, kPollNanos);
    std::this_thread::sleep_for(std::chrono::nanoseconds(sleep_nanos));
  }
}

bool ParseAndRun(const Json& root, Checks& checks, std::string& api_text,
                 std::string& clock_scope) {
  std::string socket, api;
  DockerTargetBinding binding{};
  ObservedContainerTarget observed{};
  ClockIdentity identity{};
  LinuxPidNamespaceIdentity observer_ns{};
  OperationId stop_op{};
  if (!ParseFixture(root, socket, api, binding, observed, identity, observer_ns, stop_op)) return false;

  auto clock_result = CreateLinuxClock(identity);
  auto* clock_ptr = std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&clock_result);
  if (clock_ptr == nullptr || !*clock_ptr) return false;
  auto& clock = **clock_ptr;

  DockerProcessControllerConfig config{};
  config.unix_socket_path = std::move(socket);
  config.engine_api_version = api;
  config.process_probe.expected_observer_pid_namespace = observer_ns;
  config.process_probe.proc_root = "/proc";
  auto created = CreateLinuxDockerProcessController(config, clock);
  auto* controller_ptr = std::get_if<std::unique_ptr<IRecoveryProcessController>>(&created);
  if (controller_ptr == nullptr || !*controller_ptr) return false;
  auto& controller = **controller_ptr;

  const RecoveryContainerTarget pending{PendingContainerTarget{binding}};
  const RecoveryContainerTarget seen{observed};
  std::atomic_bool cancel{false};
  auto inspect = [&](const RecoveryContainerTarget& target) {
    auto d = MakeDefaultInspectDeadline(clock);
    const auto* deadline = std::get_if<ControllerDeadline>(&d);
    if (deadline == nullptr) return DockerInspectResult{DockerControllerFailure{DockerControllerErrorCode::ClockUnavailable, false}};
    return controller.Inspect(target, *deadline, cancel);
  };
  auto stop = [&](const RecoveryContainerTarget& target) {
    auto d = MakeDefaultStopDeadline(clock);
    const auto* deadline = std::get_if<ControllerDeadline>(&d);
    if (deadline == nullptr) return DockerStopResult{DockerControllerFailure{DockerControllerErrorCode::ClockUnavailable, false}};
    return controller.RequestStop(target, stop_op, *deadline, cancel);
  };

  checks.pending_running = IsRunning(inspect(pending));
  checks.observed_running = IsRunning(inspect(seen));

  auto tampered = binding;
  tampered.participant_id[0] = tampered.participant_id[0] == 'a' ? 'b' : 'a';
  checks.tampered_stop_rejected = IsIdentityMismatchUnsent(stop(RecoveryContainerTarget{PendingContainerTarget{tampered}}));
  checks.original_still_running = IsRunning(inspect(pending));

  checks.stop_acknowledged = IsStopAck(stop(pending), stop_op, DockerStopAcknowledgement::Kind::Accepted);
  checks.observed_exit_proven = checks.stop_acknowledged &&
      InspectObservedUntilExited(controller, clock, seen, cancel);
  checks.pending_exit_proven = IsExited(inspect(pending), DockerExitEvidenceScope::RuntimeOnlyPendingTarget);
  checks.repeat_stop_acknowledged = IsStopAck(stop(pending), stop_op, DockerStopAcknowledgement::Kind::AlreadyStopped);

  api_text = api;
  clock_scope = "trusted expected CLOCK_MONOTONIC namespace; host placement is externally qualified";
  return true;
}

void Emit(const Checks& c, std::string_view api, std::string_view clock_scope, bool setup_ok) {
  Json out = {
      {"schema_version", 1},
      {"passed", setup_ok && c.All()},
      {"selected_api_version", api},
      {"clock_scope", clock_scope},
      {"checks", {
          {"pending_running", c.pending_running},
          {"observed_running", c.observed_running},
          {"tampered_stop_rejected_unsent", c.tampered_stop_rejected},
          {"original_still_running", c.original_still_running},
          {"one_stop_acknowledged", c.stop_acknowledged},
          {"observed_runtime_and_process_exit", c.observed_exit_proven},
          {"pending_runtime_exit", c.pending_exit_proven},
          {"repeat_stop_already_stopped", c.repeat_stop_acknowledged}
      }}
  };
  std::cout << out.dump() << '\n';
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3 || std::string_view(argv[1]) != "--fixture") {
    std::cerr << "usage: docker_controller_linux_probe --fixture /absolute/path\n";
    return 2;
  }
  std::string bytes;
  if (!ReadFixture(argv[2], bytes)) {
    std::cerr << "fixture_read_failed\n";
    return 2;
  }
  Json root;
  try {
    BoundedSax sax;
    if (!Json::sax_parse(bytes.begin(), bytes.end(), &sax) || !sax.ok()) {
      std::cerr << "fixture_invalid\n";
      return 2;
    }
    root = Json::parse(bytes);
  } catch (...) {
    std::cerr << "fixture_invalid\n";
    return 2;
  }

  Checks checks{};
  std::string api, scope;
  bool setup_ok = false;
  try { setup_ok = ParseAndRun(root, checks, api, scope); }
  catch (...) { setup_ok = false; }
  if (!setup_ok) {
    Emit(checks, api, scope, false);
    return 2;
  }
  Emit(checks, api, scope, true);
  return checks.All() ? 0 : 1;
}
