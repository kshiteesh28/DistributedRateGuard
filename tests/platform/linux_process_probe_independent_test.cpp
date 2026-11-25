#include "platform/linux_pidfd_helper.h"
#include "platform/linux_proc_stat_parser.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

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

using namespace rateguard::platform;
using namespace rateguard::platform::detail;

std::string StatLine(std::uint64_t pid, std::string_view command,
                     std::string_view state, std::string_view start_ticks) {
  std::string line = std::to_string(pid) + " (" + std::string(command) + ") " +
                     std::string(state);
  for (int i = 0; i < 18; ++i) line += " 0";
  line += " " + std::string(start_ticks) + " 0 0 0\n";
  return line;
}

void TestProcStatFieldParsing() {
  const auto valid = ParseLinuxProcStat(StatLine(4321, "worker with ) in name", "S", "987654"));
  CHECK(std::holds_alternative<ParsedProcStat>(valid));
  if (std::holds_alternative<ParsedProcStat>(valid)) {
    const auto& parsed = std::get<ParsedProcStat>(valid);
    CHECK(parsed.pid == 4321);
    CHECK(parsed.state == 'S');
    CHECK(parsed.start_ticks == 987654);
  }

  const auto no_newline = StatLine(7, "x", "R", "1");
  CHECK(std::holds_alternative<ParsedProcStat>(ParseLinuxProcStat(
      std::string_view(no_newline).substr(0, no_newline.size() - 1))));
  CHECK(std::holds_alternative<ParsedProcStat>(
      ParseLinuxProcStat(StatLine(8, "cmd ) )", "Z", "2"))));

  CHECK(std::holds_alternative<ProcStatParseError>(ParseLinuxProcStat("")));
  CHECK(std::holds_alternative<ProcStatParseError>(ParseLinuxProcStat("1 (cmd)")));
  CHECK(std::holds_alternative<ProcStatParseError>(
      ParseLinuxProcStat(StatLine(0, "zero", "S", "1"))));
  CHECK(std::holds_alternative<ProcStatParseError>(
      ParseLinuxProcStat(StatLine(1, "missing start", "S", ""))));
  CHECK(std::holds_alternative<ProcStatParseError>(
      ParseLinuxProcStat(StatLine(1, "bad state", "?", "1"))));
  CHECK(std::holds_alternative<ProcStatParseError>(
      ParseLinuxProcStat(StatLine(1, "negative start", "S", "-1"))));
  CHECK(std::holds_alternative<ProcStatParseError>(
      ParseLinuxProcStat(StatLine(1, "overflow start", "S", "18446744073709551616"))));
  auto bad_numeric = StatLine(1, "bad numeric field", "S", "1");
  const auto numeric_position = bad_numeric.find(" S 0");
  CHECK(numeric_position != std::string::npos);
  if (numeric_position != std::string::npos)
    bad_numeric.replace(numeric_position + 3, 1, "x");
  CHECK(std::holds_alternative<ProcStatParseError>(ParseLinuxProcStat(bad_numeric)));
  auto nul_line = StatLine(1, "bad command", "S", "1");
  const auto command_position = nul_line.find(" (" );
  CHECK(command_position != std::string::npos);
  if (command_position != std::string::npos)
    nul_line.insert(command_position + 3, 1, '\0');
  CHECK(std::holds_alternative<ProcStatParseError>(ParseLinuxProcStat(nul_line)));
  CHECK(std::holds_alternative<ProcStatParseError>(ParseLinuxProcStat(
      std::string(kLinuxProcStatMaxBytes + 1, 'x'))));
}

void TestPidfdOpenClassification() {
  int close_calls = 0;
  int closed_fd = -1;
  auto close_record = [&](int fd) noexcept {
    ++close_calls;
    closed_fd = fd;
  };

  auto result = ClassifyPidfdOpen(17, 0, close_record);
  CHECK(result.kind == PidfdAttemptKind::ProcessExists);
  CHECK(close_calls == 1 && closed_fd == 17);

  result = ClassifyPidfdOpen(-1, ESRCH, close_record);
  CHECK(result.kind == PidfdAttemptKind::ProcessAbsent);
  CHECK(result.reason == LinuxProcessReason::None);
  CHECK(close_calls == 1);

  result = ClassifyPidfdOpen(-1, EINTR, close_record);
  CHECK(result.kind == PidfdAttemptKind::Interrupted);
  CHECK(result.reason == LinuxProcessReason::ProcUnavailable);

  for (const int error : {EACCES, EPERM}) {
    result = ClassifyPidfdOpen(-1, error, close_record);
    CHECK(result.kind == PidfdAttemptKind::Failed);
    CHECK(result.reason == LinuxProcessReason::PermissionDenied);
  }
  for (const int error : {ENOMEM, EMFILE, ENFILE}) {
    result = ClassifyPidfdOpen(-1, error, close_record);
    CHECK(result.kind == PidfdAttemptKind::Failed);
    CHECK(result.reason == LinuxProcessReason::ResourceLimit);
  }
  result = ClassifyPidfdOpen(-1, EBADF, close_record);
  CHECK(result.kind == PidfdAttemptKind::Failed);
  CHECK(result.reason == LinuxProcessReason::ProcUnavailable);

  const auto throwing_close = [](int) { throw std::runtime_error("close hook"); };
  result = ClassifyPidfdOpen(23, 0, throwing_close);
  CHECK(result.kind == PidfdAttemptKind::Failed);
  CHECK(result.reason == LinuxProcessReason::ProcUnavailable);
}

}  // namespace

int main() {
  TestProcStatFieldParsing();
  TestPidfdOpenClassification();
  if (failures != 0) {
    std::cerr << failures << " independent Linux process probe assertion(s) failed\n";
    return 1;
  }
  std::cout << "Independent process probe parser/pidfd helper checks passed\n";
  return 0;
}
