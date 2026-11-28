#include "platform/clock_linux.h"
#include "platform/clock_linux_detail.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <limits>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#if defined(__linux__)
#include <time.h>
#endif

using namespace rateguard::platform;
namespace detail = rateguard::platform::detail;

namespace {
#if defined(__linux__)
struct DirectNamespace {
  std::uint64_t device;
  std::uint64_t inode;
  friend bool operator==(const DirectNamespace&, const DirectNamespace&) = default;
};

bool StatPath(const char* path, DirectNamespace& out) {
  struct stat st {};
  if (::stat(path, &st) != 0 || st.st_ino == 0) return false;
  out = {static_cast<std::uint64_t>(st.st_dev),
         static_cast<std::uint64_t>(st.st_ino)};
  return true;
}

bool ReadText(const char* path, std::size_t limit, std::string& out) {
  std::ifstream input(path, std::ios::binary);
  if (!input) return false;
  out.resize(limit + 1);
  input.read(out.data(), static_cast<std::streamsize>(out.size()));
  const auto n = input.gcount();
  if (n < 0 || static_cast<std::size_t>(n) > limit || input.bad()) return false;
  out.resize(static_cast<std::size_t>(n));
  return true;
}

bool DirectProbe(ClockIdentity& identity) {
  std::string boot_text;
  if (!ReadText("/proc/sys/kernel/random/boot_id", 64, boot_text)) return false;
  auto boot = detail::ParseBootUuid(boot_text);
  if (auto* failure = std::get_if<ClockFailure>(&boot)) {
    (void)failure;
    return false;
  }
  DirectNamespace current_before{}, children_before{}, current_after{}, children_after{};
  if (!StatPath("/proc/self/ns/time", current_before) ||
      !StatPath("/proc/self/ns/time_for_children", children_before)) return false;
  std::string offsets;
  if (!ReadText("/proc/self/timens_offsets", 512, offsets)) return false;
  if (!StatPath("/proc/self/ns/time", current_after) ||
      !StatPath("/proc/self/ns/time_for_children", children_after)) return false;
  if (current_before != children_before || current_before != current_after ||
      current_before != children_after) return false;

  std::istringstream lines(offsets);
  std::string name1, name2, extra;
  std::int64_t sec1 = 0, sec2 = 0;
  std::uint64_t ns1 = 0, ns2 = 0;
  if (!(lines >> name1 >> sec1 >> ns1 >> name2 >> sec2 >> ns2) ||
      (lines >> extra) || ns1 > 999'999'999ULL || ns2 > 999'999'999ULL)
    return false;
  std::int64_t mono_sec = 0, boot_sec = 0;
  std::uint32_t mono_ns = 0, boot_ns = 0;
  if (name1 == "monotonic" && name2 == "boottime") {
    mono_sec = sec1; mono_ns = static_cast<std::uint32_t>(ns1);
    boot_sec = sec2; boot_ns = static_cast<std::uint32_t>(ns2);
  } else if (name1 == "boottime" && name2 == "monotonic") {
    boot_sec = sec1; boot_ns = static_cast<std::uint32_t>(ns1);
    mono_sec = sec2; mono_ns = static_cast<std::uint32_t>(ns2);
  } else {
    return false;
  }
  identity = {std::get<std::array<std::uint8_t, 16>>(boot),
              current_before.device, current_before.inode,
              mono_sec, mono_ns, boot_sec, boot_ns,
              static_cast<std::int32_t>(CLOCK_MONOTONIC)};
  return true;
}

std::string Format(const ClockIdentity& id, std::uint64_t sample) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (auto b : id.boot_uuid) out << std::setw(2) << static_cast<unsigned>(b);
  out << std::dec << '|' << id.namespace_device << '|' << id.namespace_inode
      << '|' << id.monotonic_offset_seconds << '|' << id.monotonic_offset_nanoseconds
      << '|' << id.boottime_offset_seconds << '|' << id.boottime_offset_nanoseconds
      << '|' << id.clock_id << '|' << sample << '\n';
  return out.str();
}

int ChildMode() {
  auto probe = detail::ProbeCurrentLinuxClockIdentity();
  auto* id = std::get_if<ClockIdentity>(&probe);
  if (!id) return 10;
  auto clock_result = CreateLinuxClock(*id);  // smoke-test-only self identity
  auto* clock_ptr = std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&clock_result);
  if (!clock_ptr) return 11;
  auto now = (*clock_ptr)->Now();
  auto* stamp = std::get_if<MonoNanos>(&now);
  if (!stamp) return 12;
  std::cout << Format(*id, stamp->value);
  return 0;
}
#endif
}  // namespace

int main(int argc, char** argv) {
#if !defined(__linux__)
  (void)argc;
  (void)argv;
  std::cout << "UNSUPPORTED: real Linux /proc and CLOCK_MONOTONIC provenance unavailable\n";
  return 77;
#else
  if (argc == 2 && std::string(argv[1]) == "--child") return ChildMode();

  ClockIdentity internal{};
  auto observed = detail::ProbeCurrentLinuxClockIdentity();
  if (const auto* failure = std::get_if<ClockFailure>(&observed)) {
    std::cout << "UNSUPPORTED: Linux clock provenance probe failed reason="
              << static_cast<unsigned>(failure->reason) << '\n';
    return 77;
  }
  internal = std::get<ClockIdentity>(observed);
  ClockIdentity direct{};
  if (!DirectProbe(direct)) {
    std::cerr << "FAIL: independent /proc identity read failed\n";
    return EXIT_FAILURE;
  }
  if (internal != direct) {
    std::cerr << "FAIL: internal identity differs from direct kernel/proc reads\n";
    return EXIT_FAILURE;
  }
  auto clock_result = CreateLinuxClock(internal);
  auto* clock_ptr = std::get_if<std::unique_ptr<LinuxMonotonicClock>>(&clock_result);
  if (!clock_ptr) {
    std::cerr << "FAIL: trusted identity did not create Linux clock\n";
    return EXIT_FAILURE;
  }
  auto parent_now = (*clock_ptr)->Now();
  auto* parent_stamp = std::get_if<MonoNanos>(&parent_now);
  if (!parent_stamp) {
    std::cerr << "FAIL: parent monotonic sample failed\n";
    return EXIT_FAILURE;
  }

  int pipe_fds[2];
  if (::pipe(pipe_fds) != 0) {
    std::cerr << "FAIL: pipe failed\n";
    return EXIT_FAILURE;
  }
  char resolved[PATH_MAX];
  if (!::realpath(argv[0], resolved)) {
    std::cerr << "FAIL: cannot resolve smoke executable path\n";
    return EXIT_FAILURE;
  }
  const pid_t child = ::fork();
  if (child < 0) {
    std::cerr << "FAIL: fork failed\n";
    return EXIT_FAILURE;
  }
  if (child == 0) {
    ::close(pipe_fds[0]);
    if (::dup2(pipe_fds[1], STDOUT_FILENO) < 0) _exit(20);
    ::close(pipe_fds[1]);
    ::execl(resolved, resolved, "--child", static_cast<char*>(nullptr));
    _exit(21);
  }
  ::close(pipe_fds[1]);
  std::string child_line;
  char chunk[512];
  for (;;) {
    const ssize_t n = ::read(pipe_fds[0], chunk, sizeof(chunk));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    child_line.append(chunk, static_cast<std::size_t>(n));
    if (child_line.size() > 1024) break;
  }
  ::close(pipe_fds[0]);
  int status = 0;
  if (::waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    std::cerr << "FAIL: fork/exec child identity probe failed\n";
    return EXIT_FAILURE;
  }
  const auto expected_child = Format(internal, 0);
  const auto separator = child_line.rfind('|');
  if (separator == std::string::npos ||
      child_line.substr(0, separator + 1) != expected_child.substr(0, expected_child.rfind('|') + 1)) {
    std::cerr << "FAIL: fork/exec child provenance differs from parent\n";
    return EXIT_FAILURE;
  }
  std::uint64_t child_sample = 0;
  try {
    child_sample = std::stoull(child_line.substr(separator + 1));
  } catch (...) {
    std::cerr << "FAIL: child timestamp is malformed\n";
    return EXIT_FAILURE;
  }
  if (child_sample < parent_stamp->value) {
    std::cerr << "FAIL: child timestamp precedes parent timestamp\n";
    return EXIT_FAILURE;
  }
  std::cout << "Linux clock provenance and fork/exec smoke checks passed\n";
  return EXIT_SUCCESS;
#endif
}
