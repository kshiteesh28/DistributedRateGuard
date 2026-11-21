#include "src/events/history_exporter.h"

#include <sstream>
#include <string>
#include <variant>

using namespace rateguard::events;

int main() {
  RunPlan plan;
  plan.producers.push_back({ProducerOwner::Authority, 0, 2});
  auto recorder = std::get<EventRecorder>(EventRecorder::Create(plan));
  auto producer = std::get<EventRecorder::ProducerHandle>(
      recorder.AttachProducer(ProducerOwner::Authority, 0));
  auto reservation = std::get<EventRecorder::EventReservation>(producer.Reserve());
  EventV1 e;
  e.stage = Stage::StrictDecision;
  e.outcome = Outcome::Allow;
  e.timestamp_ns = 123;
  e.cost_units = 1;
  (void)producer.Publish(std::move(reservation), e);
  (void)producer.Seal();
  auto snapshot = std::get<EventSnapshotV1>(recorder.ExportSnapshotV1());
  std::ostringstream output;
  if (ExportStrictHistory(plan, snapshot, output) != ExportStatus::Complete) return 1;
  // Independent fixed-width layout: header, producer, 2 slots, seal, trailer.
  const std::string bytes = output.str();
  if (bytes.size() != 80 + 13 + 2 * 51 + 26 + 17 ||
      bytes.size() != snapshot.planned_bytes) return 2;
  if (bytes.substr(0, 8) != "RGHIST01" || bytes.substr(8, 4) != std::string("\0\0\0\1", 4) ||
      static_cast<unsigned char>(bytes[80]) != 2 ||
      static_cast<unsigned char>(bytes[93]) != 2 ||
      static_cast<unsigned char>(bytes[93 + 1 + 8 + 2 + 16 + 7]) != 123) return 3;
  std::ostream failed(nullptr);
  if (ExportStrictHistory(plan, snapshot, failed) != ExportStatus::WriteFailed) return 4;
  snapshot.producers[0].slots[0].event.timestamp_ns++;
  std::ostringstream rejected;
  if (ExportStrictHistory(plan, snapshot, rejected) != ExportStatus::IncompleteHistory ||
      !rejected.str().empty()) return 5;
}
