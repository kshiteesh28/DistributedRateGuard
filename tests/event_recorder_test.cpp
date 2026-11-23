#include "src/events/event_recorder.h"

#include <array>
#include <barrier>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using namespace rateguard::events;

namespace {
int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::cerr << "FAIL line " << __LINE__ << ": " #expr "\n"; ++failures; } } while (false)

RunPlan Plan(std::vector<ProducerSpec> producers, std::uint64_t budget = 1ULL << 30) {
  RunPlan p;
  p.epoch_id[0] = 0x12;
  p.policy_digest[0] = 0x34;
  p.producers = std::move(producers);
  p.budget_bytes = budget;
  return p;
}

EventV1 Event(Stage stage, std::uint64_t seq, Outcome outcome = Outcome::Allow) {
  EventV1 e;
  e.stage = stage;
  e.outcome = outcome;
  e.attempt_id[0] = 0xA5;
  e.attempt_id[15] = static_cast<std::uint8_t>(seq);
  e.timestamp_ns = 100 + seq;
  e.cost_units = 5;
  return e;
}

bool IsError(const auto& result, RecorderError error) {
  return std::holds_alternative<RecorderError>(result) && std::get<RecorderError>(result) == error;
}

EventRecorder MakeRecorder(std::vector<ProducerSpec> producers,
                           std::uint64_t budget = 1ULL << 30) {
  auto made = EventRecorder::Create(Plan(std::move(producers), budget));
  CHECK(std::holds_alternative<EventRecorder>(made));
  return std::get<EventRecorder>(std::move(made));
}

EventRecorder::ProducerHandle Attach(EventRecorder& recorder, ProducerOwner owner,
                                     std::uint32_t index = 0) {
  auto attached = recorder.AttachProducer(owner, index);
  CHECK(std::holds_alternative<EventRecorder::ProducerHandle>(attached));
  return std::get<EventRecorder::ProducerHandle>(std::move(attached));
}

EventSnapshotV1 Snapshot(EventRecorder& recorder) {
  auto exported = recorder.ExportSnapshotV1();
  CHECK(std::holds_alternative<EventSnapshotV1>(exported));
  return std::get<EventSnapshotV1>(std::move(exported));
}

void Publish(EventRecorder::ProducerHandle& producer, Stage stage, std::uint64_t seq) {
  auto reserved = producer.Reserve();
  CHECK(std::holds_alternative<EventRecorder::EventReservation>(reserved));
  if (!std::holds_alternative<EventRecorder::EventReservation>(reserved)) return;
  auto reservation = std::get<EventRecorder::EventReservation>(std::move(reserved));
  CHECK(reservation.producer_sequence() == seq);
  CHECK(producer.Publish(std::move(reservation), Event(stage, seq)) == RecorderError::None);
}

std::uint64_t FnvByte(std::uint64_t h, std::uint8_t b) {
  return (h ^ b) * 1099511628211ULL;
}
void FnvU32(std::uint64_t& h, std::uint32_t n) {
  for (int s = 24; s >= 0; s -= 8) h = FnvByte(h, static_cast<std::uint8_t>(n >> s));
}
void FnvU64(std::uint64_t& h, std::uint64_t n) {
  for (int s = 56; s >= 0; s -= 8) h = FnvByte(h, static_cast<std::uint8_t>(n >> s));
}
void FnvText(std::uint64_t& h, const char* s) { while (*s) h = FnvByte(h, static_cast<std::uint8_t>(*s++)); }

template<std::size_t N> void FnvArray(std::uint64_t& h, const std::array<std::uint8_t,N>& a) {
  for (std::uint8_t b : a) h = FnvByte(h, b);
}
std::uint64_t IndependentEventChecksum(const EventV1& e) {
  std::uint64_t h = 14695981039346656037ULL;
  FnvText(h, "RGEV1");
  h = FnvByte(h, static_cast<std::uint8_t>(e.stage));
  h = FnvByte(h, static_cast<std::uint8_t>(e.outcome));
  FnvArray(h, e.attempt_id);
  FnvU64(h, e.timestamp_ns);
  FnvU64(h, e.cost_units);
  return h;
}
std::uint64_t IndependentSealChecksum(const ProducerSnapshotV1& p) {
  std::uint64_t h = 14695981039346656037ULL;
  FnvText(h, "RGPS1");
  h = FnvByte(h, static_cast<std::uint8_t>(p.owner));
  FnvU32(h, p.producer_index);
  FnvU64(h, p.capacity);
  FnvU64(h, p.reserved_count);
  FnvU64(h, p.published_count);
  h = FnvByte(h, p.sealed ? 1 : 0);
  h = FnvByte(h, p.incomplete ? 1 : 0);
  for (const auto& s : p.slots) {
    h = FnvByte(h, static_cast<std::uint8_t>(s.status));
    FnvU64(h, s.producer_sequence);
    FnvU64(h, s.checksum64);
  }
  return h;
}
std::uint64_t IndependentSnapshotChecksum(const EventSnapshotV1& s) {
  std::uint64_t h = 14695981039346656037ULL;
  FnvText(h, "RGRN1");
  FnvU32(h, s.schema_version);
  FnvArray(h, s.epoch_id);
  FnvArray(h, s.policy_digest);
  FnvU32(h, static_cast<std::uint32_t>(s.producers.size()));
  FnvU64(h, s.planned_bytes);
  FnvU64(h, s.budget_bytes);
  for (const auto& p : s.producers) {
    h = FnvByte(h, static_cast<std::uint8_t>(p.owner));
    FnvU32(h, p.producer_index);
    FnvU64(h, p.capacity);
    FnvU64(h, p.seal_checksum64);
  }
  h = FnvByte(h, s.complete ? 1 : 0);
  return h;
}

void TestBudgetBoundaries() {
  const std::uint64_t exact = kRunHeaderEncodedBytes + kRunTerminalEncodedBytes +
      kProducerEnvelopeEncodedBytes + kEventSlotEncodedBytes + kProducerSealEncodedBytes;
  auto accepted = EventRecorder::Create(Plan({{ProducerOwner::Authority, 0, 1}}, exact));
  CHECK(std::holds_alternative<EventRecorder>(accepted));
  if (std::holds_alternative<EventRecorder>(accepted)) {
    auto recorder = std::get<EventRecorder>(std::move(accepted));
    CHECK(recorder.planned_bytes() == exact);
    auto p = Attach(recorder, ProducerOwner::Authority);
    Publish(p, Stage::StrictDecision, 1);
    CHECK(p.Seal() == RecorderError::None);
    auto s = Snapshot(recorder);
    CHECK(s.complete && s.planned_bytes == exact && s.budget_bytes == exact);
  }
  auto below = EventRecorder::Create(Plan({{ProducerOwner::Authority, 0, 1}}, exact - 1));
  CHECK(IsError(below, RecorderError::InvalidPlan));
  // 97 + 7*39 + 21,053,754*51 = 1 GiB. Reject before allocating slots.
  std::vector<ProducerSpec> at_cap;
  for (unsigned i = 0; i < 7; ++i)
    at_cap.push_back({ProducerOwner::Replica, i, i == 0 ? 21053748ULL : 1ULL});
  CHECK(IsError(EventRecorder::Create(Plan(std::move(at_cap))), RecorderError::InvalidPlan));
  auto too_large_budget = EventRecorder::Create(Plan({{ProducerOwner::Authority, 0, 1}}, kMaxRunBudgetBytes + 1));
  CHECK(IsError(too_large_budget, RecorderError::InvalidPlan));
  auto duplicate_roster = EventRecorder::Create(Plan({{ProducerOwner::Authority, 0, 1},
                                                        {ProducerOwner::Authority, 0, 1}}));
  CHECK(IsError(duplicate_roster, RecorderError::InvalidPlan));
}

void TestOwnerSealAndChecksums() {
  auto recorder = MakeRecorder({{ProducerOwner::Authority, 0, 2}});
  auto p = Attach(recorder, ProducerOwner::Authority);
  Publish(p, Stage::StrictDecision, 1);
  Publish(p, Stage::StrictDecision, 2);
  CHECK(p.Seal() == RecorderError::None);
  CHECK(p.Reserve().index() == 1); // error alternative
  CHECK(std::get<RecorderError>(p.Reserve()) == RecorderError::ProducerSealed);
  auto s = Snapshot(recorder);
  CHECK(s.complete);
  CHECK(s.producers.size() == 1);
  const auto& row = s.producers[0];
  CHECK(row.reserved_count == 2 && row.published_count == 2 && row.sealed && !row.incomplete);
  CHECK(row.slots[0].status == SlotStatus::Published && row.slots[0].producer_sequence == 1);
  CHECK(row.slots[1].status == SlotStatus::Published && row.slots[1].producer_sequence == 2);
  CHECK(row.slots[0].checksum64 == IndependentEventChecksum(row.slots[0].event));
  CHECK(row.slots[1].checksum64 == IndependentEventChecksum(row.slots[1].event));
  CHECK(row.seal_checksum64 == IndependentSealChecksum(row));
  CHECK(s.checksum64 == IndependentSnapshotChecksum(s));

  auto wrong = MakeRecorder({{ProducerOwner::Authority, 0, 1}});
  auto authority = Attach(wrong, ProducerOwner::Authority);
  auto r = authority.Reserve();
  auto reservation = std::get<EventRecorder::EventReservation>(std::move(r));
  CHECK(authority.Publish(std::move(reservation), Event(Stage::Responded, 1)) == RecorderError::InvalidEvent);
  CHECK(wrong.stopped());
  CHECK(authority.Seal() == RecorderError::None);
  CHECK(!Snapshot(wrong).complete);
}

void TestGapAndStickyStop() {
  auto recorder = MakeRecorder({{ProducerOwner::Authority, 0, 2}});
  auto p = Attach(recorder, ProducerOwner::Authority);
  {
    auto reserved = p.Reserve();
    CHECK(std::holds_alternative<EventRecorder::EventReservation>(reserved));
    // Destruction without publication must persistently mark the reservation incomplete.
  }
  CHECK(recorder.stopped());
  CHECK(IsError(p.Reserve(), RecorderError::RunStopped));
  CHECK(p.Seal() == RecorderError::None);
  const auto s = Snapshot(recorder);
  CHECK(!s.complete);
  CHECK(s.producers[0].incomplete);
  CHECK(s.producers[0].slots[0].status == SlotStatus::Incomplete);
  CHECK(s.producers[0].slots[1].status == SlotStatus::Unused);
}

void TestPartitionFailureDoesNotBorrow() {
  auto recorder = MakeRecorder({{ProducerOwner::Authority, 0, 1},
                                {ProducerOwner::Replica, 0, 2}});
  auto authority = Attach(recorder, ProducerOwner::Authority);
  auto replica = Attach(recorder, ProducerOwner::Replica);
  Publish(authority, Stage::StrictDecision, 1);
  CHECK(IsError(authority.Reserve(), RecorderError::ProducerPartitionExhausted));
  CHECK(recorder.stopped());
  auto next = replica.Reserve();
  CHECK(IsError(next, RecorderError::RunStopped)); // remaining replica slots cannot be borrowed after run stop
  CHECK(replica.Seal() == RecorderError::None);
  const auto s = Snapshot(recorder);
  CHECK(!s.complete);
  CHECK(s.producers[0].capacity == 1 && s.producers[0].reserved_count == 1);
  CHECK(s.producers[1].capacity == 2 && s.producers[1].reserved_count == 0);
}

void TestOneShotProducerAndAbandonedHandle() {
  auto recorder = MakeRecorder({{ProducerOwner::Authority, 3, 1}});
  {
    auto p = Attach(recorder, ProducerOwner::Authority, 3);
    CHECK(p.Seal() == RecorderError::None);
  }
  CHECK(IsError(recorder.AttachProducer(ProducerOwner::Authority, 3), RecorderError::ProducerAlreadyAttached));
  auto never = MakeRecorder({{ProducerOwner::Backend, 0, 1}});
  { auto ignored = Attach(never, ProducerOwner::Backend); }
  CHECK(never.stopped());
  auto incomplete = Snapshot(never);
  CHECK(!incomplete.complete && incomplete.producers[0].incomplete && !incomplete.producers[0].sealed);
}

void TestTwoProducerIsolationAndCompleteness() {
  auto recorder = MakeRecorder({{ProducerOwner::WorkloadGenerator, 0, 1},
                                {ProducerOwner::Replica, 7, 1}});
  auto generator = Attach(recorder, ProducerOwner::WorkloadGenerator, 0);
  auto replica = Attach(recorder, ProducerOwner::Replica, 7);
  Publish(generator, Stage::Offered, 1);
  Publish(replica, Stage::Responded, 1);
  CHECK(generator.Seal() == RecorderError::None);
  CHECK(replica.Seal() == RecorderError::None);
  auto s = Snapshot(recorder);
  CHECK(s.complete && s.producers.size() == 2);
  CHECK(s.producers[0].owner == ProducerOwner::WorkloadGenerator);
  CHECK(s.producers[1].owner == ProducerOwner::Replica && s.producers[1].producer_index == 7);
}

void TestConcurrentLastSlotRace() {
  constexpr std::size_t workers = 12;
  auto recorder = MakeRecorder({{ProducerOwner::Authority, 0, 1}});
  auto producer = Attach(recorder, ProducerOwner::Authority);
  std::barrier start(static_cast<std::ptrdiff_t>(workers));
  std::atomic<unsigned> reserved_count{0}, published_count{0}, exhausted_count{0}, stopped_count{0};
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < workers; ++i) {
    threads.emplace_back([&, i] {
      start.arrive_and_wait();
      auto attempt = producer.Reserve();
      if (std::holds_alternative<EventRecorder::EventReservation>(attempt)) {
        reserved_count.fetch_add(1, std::memory_order_relaxed);
        auto reservation = std::get<EventRecorder::EventReservation>(std::move(attempt));
        const auto rc = producer.Publish(std::move(reservation), Event(Stage::StrictDecision, i + 1));
        if (rc == RecorderError::None) published_count.fetch_add(1, std::memory_order_relaxed);
      } else if (std::get<RecorderError>(attempt) == RecorderError::ProducerPartitionExhausted) {
        exhausted_count.fetch_add(1, std::memory_order_relaxed);
      } else if (std::get<RecorderError>(attempt) == RecorderError::RunStopped) {
        stopped_count.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  for (auto& t : threads) t.join();
  CHECK(reserved_count.load() == 1);
  CHECK(published_count.load() == 1);
  CHECK(exhausted_count.load() == 1);
  CHECK(stopped_count.load() == workers - 2);
  CHECK(recorder.stopped()); // full partition is an observable run stop, never a silent drop
  CHECK(producer.Seal() == RecorderError::None);
  const auto s = Snapshot(recorder);
  CHECK(!s.complete);
  CHECK(s.producers[0].reserved_count == 1 && s.producers[0].published_count == 1);
}

void TestSnapshotMutationChecksumsAreObservable() {
  auto recorder = MakeRecorder({{ProducerOwner::Backend, 0, 1}});
  auto backend = Attach(recorder, ProducerOwner::Backend);
  Publish(backend, Stage::Completed, 1);
  CHECK(backend.Seal() == RecorderError::None);
  auto s = Snapshot(recorder);
  CHECK(s.complete);
  auto bad_event = s;
  bad_event.producers[0].slots[0].event.cost_units++;
  CHECK(bad_event.producers[0].slots[0].checksum64 != IndependentEventChecksum(bad_event.producers[0].slots[0].event));
  auto bad_seal = s;
  bad_seal.producers[0].producer_index++;
  CHECK(bad_seal.producers[0].seal_checksum64 != IndependentSealChecksum(bad_seal.producers[0]));
  auto bad_run = s;
  bad_run.budget_bytes++;
  CHECK(bad_run.checksum64 != IndependentSnapshotChecksum(bad_run));
}
}

int main() {
  TestBudgetBoundaries();
  TestOwnerSealAndChecksums();
  TestGapAndStickyStop();
  TestPartitionFailureDoesNotBorrow();
  TestOneShotProducerAndAbandonedHandle();
  TestTwoProducerIsolationAndCompleteness();
  TestConcurrentLastSlotRace();
  TestSnapshotMutationChecksumsAreObservable();
  if (failures != 0) {
    std::cerr << "RG005 recorder tests failed: " << failures << "\n";
    return EXIT_FAILURE;
  }
  std::cout << "RG005 recorder component tests passed\n";
  return EXIT_SUCCESS;
}
