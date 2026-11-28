// Include the probe translation unit so this test exercises its real private
// ParseFixture function without launching Docker or adding a public API.
#define RATEGUARD_PROBE_PARSER_TEST
#include "../../probes/docker_controller_linux_probe.cpp"

#include <cstdlib>
#include <iostream>

namespace {
int failures = 0;
#define CHECK(condition) do { \
  if (!(condition)) { \
    std::cerr << "CHECK failed at line " << __LINE__ << ": " #condition "\n"; \
    ++failures; \
  } \
} while (false)

Json ValidFixture() {
  return Json{
      {"schema_version", 1},
      {"socket_path", "/var/run/docker.sock"},
      {"api_version", "1.48"},
      {"binding", {
          {"domain_id", std::string(32, '1')},
          {"epoch_id", std::string(32, '2')},
          {"authority_incarnation", std::string(32, '3')},
          {"policy_digest", std::string(64, '4')},
          {"role", "replica"}, {"slot_id", 7},
          {"participant_id", "fixture-7"},
          {"incarnation", std::string(32, '5')},
          {"container_id", std::string(64, 'a')},
      }},
      {"recorded_process", {{"host_pid", 1234}, {"pid_start_ticks", 42}}},
      {"expected_clock_identity", {
          {"boot_uuid", std::string(32, '6')},
          {"namespace_device", 11}, {"namespace_inode", 22},
          {"monotonic_offset_seconds", 5},
          {"monotonic_offset_nanoseconds", 6},
          {"boottime_offset_seconds", -2},
          {"boottime_offset_nanoseconds", 7}, {"clock_id", 1},
      }},
      {"expected_observer_pid_namespace", {{"device", 33}, {"inode", 44}}},
      {"stop_operation_id", std::string(32, '7')},
  };
}

void TestValidFixtureCarriesClockIdentityIntoObservedTarget() {
  const Json fixture = ValidFixture();
  std::string socket, api;
  DockerTargetBinding binding{};
  ObservedContainerTarget observed{};
  ClockIdentity expected{};
  LinuxPidNamespaceIdentity observer{};
  OperationId stop_op{};

  CHECK(ParseFixture(fixture, socket, api, binding, observed, expected, observer, stop_op));
  CHECK(socket == "/var/run/docker.sock");
  CHECK(api == "1.48");
  CHECK(observed.clock_identity == expected);
  CHECK(observed.binding.domain_id == binding.domain_id);
  CHECK(observed.binding.epoch_id == binding.epoch_id);
  CHECK(observed.binding.authority_incarnation == binding.authority_incarnation);
  CHECK(observed.binding.policy_digest == binding.policy_digest);
  CHECK(observed.binding.role == binding.role);
  CHECK(observed.binding.slot_id == binding.slot_id);
  CHECK(observed.binding.participant_id == binding.participant_id);
  CHECK(observed.binding.incarnation == binding.incarnation);
  CHECK(observed.binding.container_id == binding.container_id);
  CHECK(observer.device == 33 && observer.inode == 44);
  CHECK(stop_op[0] == 0x77);
}

void TestMissingOrInvalidClockIdentityIsRejected() {
  for (const auto& malformed : {"missing_object", "missing_clock_id", "bad_clock_id",
                                "nanoseconds_overflow", "zero_namespace", "zero_boot",
                                "string_signed_offset"}) {
    Json fixture = ValidFixture();
    if (malformed == std::string_view("missing_object")) {
      fixture.erase("expected_clock_identity");
    } else if (malformed == std::string_view("missing_clock_id")) {
      fixture["expected_clock_identity"].erase("clock_id");
    } else if (malformed == std::string_view("bad_clock_id")) {
      fixture["expected_clock_identity"]["clock_id"] = 0;
    } else if (malformed == std::string_view("nanoseconds_overflow")) {
      fixture["expected_clock_identity"]["monotonic_offset_nanoseconds"] = 1'000'000'000U;
    } else if (malformed == std::string_view("zero_namespace")) {
      fixture["expected_clock_identity"]["namespace_inode"] = 0;
    } else if (malformed == std::string_view("zero_boot")) {
      fixture["expected_clock_identity"]["boot_uuid"] = std::string(32, '0');
    } else {
      fixture["expected_clock_identity"]["monotonic_offset_seconds"] = "5";
    }
    std::string socket, api;
    DockerTargetBinding binding{};
    ObservedContainerTarget observed{};
    ClockIdentity expected{};
    LinuxPidNamespaceIdentity observer{};
    OperationId stop_op{};
    CHECK(!ParseFixture(fixture, socket, api, binding, observed, expected, observer, stop_op));
  }
}
}  // namespace

int main() {
  TestValidFixtureCarriesClockIdentityIntoObservedTarget();
  TestMissingOrInvalidClockIdentityIsRejected();
  if (failures != 0) return EXIT_FAILURE;
  std::cout << "Docker probe fixture parser checks passed\n";
  return EXIT_SUCCESS;
}
