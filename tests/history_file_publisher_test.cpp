#include "src/events/file_publisher.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>

using namespace rateguard::events;

namespace {
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::cerr << "FAIL line " << __LINE__ << ": " #expr " errno=" << errno << '\n'; ++failures; } } while (false)

RunPlan MakePlan() {
  RunPlan plan;
  plan.epoch_id[0] = 0x12;
  plan.policy_digest[0] = 0x34;
  plan.producers.push_back({ProducerOwner::Authority, 0, 2});
  plan.budget_bytes = kMaxRunBudgetBytes;
  return plan;
}
EventSnapshotV1 MakeCompleteSnapshot(RunPlan& plan) {
  const std::uint64_t required = kRunHeaderEncodedBytes + kRunTerminalEncodedBytes +
      kProducerEnvelopeEncodedBytes + 2*kEventSlotEncodedBytes + kProducerSealEncodedBytes;
  plan.budget_bytes = required;
  auto created = EventRecorder::Create(plan);
  CHECK(std::holds_alternative<EventRecorder>(created));
  if (!std::holds_alternative<EventRecorder>(created)) return {};
  auto& recorder = std::get<EventRecorder>(created);
  auto attached = recorder.AttachProducer(ProducerOwner::Authority, 0);
  CHECK(std::holds_alternative<EventRecorder::ProducerHandle>(attached));
  if (!std::holds_alternative<EventRecorder::ProducerHandle>(attached)) return {};
  auto& producer = std::get<EventRecorder::ProducerHandle>(attached);
  auto reserved = producer.Reserve();
  CHECK(std::holds_alternative<EventRecorder::EventReservation>(reserved));
  if (!std::holds_alternative<EventRecorder::EventReservation>(reserved)) return {};
  EventV1 event;
  event.stage = Stage::StrictDecision;
  event.outcome = Outcome::Allow;
  event.attempt_id[0] = 0xab;
  event.timestamp_ns = 0; // epoch-relative monotonic zero is valid
  event.cost_units = 1;
  CHECK(producer.Publish(std::move(std::get<EventRecorder::EventReservation>(reserved)), event) ==
        RecorderError::None);
  CHECK(producer.Seal() == RecorderError::None);
  auto exported = recorder.ExportSnapshotV1();
  CHECK(std::holds_alternative<EventSnapshotV1>(exported));
  return std::get<EventSnapshotV1>(std::move(exported));
}
std::string ReadAllAt(int dirfd, std::string_view name) {
  const std::string path(name);
  const int fd = ::openat(dirfd, path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return {};
  std::string result;
  char data[128];
  for (;;) {
    const auto n = ::read(fd, data, sizeof(data));
    if (n == 0) break;
    if (n < 0) { if (errno == EINTR) continue; break; }
    result.append(data, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return result;
}

void TestPublishCollisionIncompleteAndDirectoryContract() {
  char directory_template[] = "/tmp/rg005-publisher-test.XXXXXX";
  char* directory_name = ::mkdtemp(directory_template);
  CHECK(directory_name != nullptr);
  if (directory_name == nullptr) return;
  CHECK(::chmod(directory_name, 0700) == 0);
  const int dirfd = ::open(directory_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  CHECK(dirfd >= 0);
  if (dirfd < 0) { ::rmdir(directory_name); return; }

  auto expected = MakePlan();
  const auto snapshot = MakeCompleteSnapshot(expected);
  HistoryRunId run_id{};
  for (std::size_t i = 0; i < run_id.size(); ++i) run_id[i] = static_cast<std::uint8_t>(i);
  const auto published = PublishStrictHistoryFile(dirfd, 1'800'000'001, run_id, expected, snapshot);
  const std::string final_name = "rg-history-v1-1800000001-000102030405060708090a0b0c0d0e0f.bin";
  CHECK(published.status == FilePublishStatus::Published);
  CHECK(published.final_published && published.file_synced && published.temporary_removed &&
        published.directory_synced);
  CHECK(published.filename() == final_name);
  struct stat st{};
  CHECK(::fstatat(dirfd, final_name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0);
  CHECK(S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600);
  const auto bytes = ReadAllAt(dirfd, final_name);
  CHECK(bytes.size() == snapshot.planned_bytes);
  CHECK(bytes.substr(0, 8) == "RGHIST01");

  const auto collision = PublishStrictHistoryFile(dirfd, 1'800'000'001, run_id, expected, snapshot);
  CHECK(collision.status == FilePublishStatus::FinalNameExists);
  CHECK(!collision.final_published && collision.temporary_removed);
  CHECK(ReadAllAt(dirfd, final_name) == bytes); // never overwrite existing final file

  auto incomplete_expected = MakePlan();
  auto incomplete_created = EventRecorder::Create(incomplete_expected);
  CHECK(std::holds_alternative<EventRecorder>(incomplete_created));
  auto& incomplete_recorder = std::get<EventRecorder>(incomplete_created);
  auto incomplete_attached = incomplete_recorder.AttachProducer(ProducerOwner::Authority, 0);
  CHECK(std::holds_alternative<EventRecorder::ProducerHandle>(incomplete_attached));
  const auto incomplete = std::get<EventSnapshotV1>(incomplete_recorder.ExportSnapshotV1());
  HistoryRunId another_id{}; another_id[0] = 0xee;
  const auto rejected = PublishStrictHistoryFile(dirfd, 1'800'000'002, another_id,
                                                  incomplete_expected, incomplete);
  CHECK(rejected.status == FilePublishStatus::IncompleteHistory);
  CHECK(!rejected.final_published && rejected.temporary_removed);
  const std::string partial = "rg-history-v1-1800000002-ee000000000000000000000000000000.bin.partial";
  CHECK(::fstatat(dirfd, partial.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT);

  const auto invalid_second = PublishStrictHistoryFile(dirfd, 1'000'000'000'000ULL,
                                                        run_id, expected, snapshot);
  CHECK(invalid_second.status == FilePublishStatus::InvalidCreationSecond);

  const std::string existing_partial = "rg-history-v1-1800000003-000102030405060708090a0b0c0d0e0f.bin.partial";
  const int partfd = ::openat(dirfd, existing_partial.c_str(), O_CREAT | O_EXCL | O_WRONLY,
                              0600);
  CHECK(partfd >= 0);
  if (partfd >= 0) { const char marker[] = "keep"; CHECK(::write(partfd, marker, 4) == 4); ::close(partfd); }
  const auto stale_partial = PublishStrictHistoryFile(dirfd, 1'800'000'003, run_id,
                                                       expected, snapshot);
  CHECK(stale_partial.status == FilePublishStatus::TemporaryNameExists);
  CHECK(ReadAllAt(dirfd, existing_partial) == "keep");

  const int regular_fd = ::openat(dirfd, "not-a-directory", O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(regular_fd >= 0);
  const auto invalid_dir = PublishStrictHistoryFile(regular_fd, 1'800'000'004, run_id,
                                                     expected, snapshot);
  CHECK(invalid_dir.status == FilePublishStatus::InvalidDirectory);
  if (regular_fd >= 0) { ::close(regular_fd); ::unlinkat(dirfd, "not-a-directory", 0); }

  ::unlinkat(dirfd, existing_partial.c_str(), 0);
  ::unlinkat(dirfd, final_name.c_str(), 0);
  ::close(dirfd);
  CHECK(::rmdir(directory_name) == 0);
}
} // namespace

int main() {
  TestPublishCollisionIncompleteAndDirectoryContract();
  if (failures != 0) return 1;
  std::cout << "PASS history_file_publisher\n";
  return 0;
}
