#include "src/events/history_exporter.h"
#include "tools/history/history_reader.h"

#include <sstream>

using namespace rateguard::events;

int main() {
  RunPlan plan;
  plan.producers = {{ProducerOwner::Adapter, 7, 1}};
  auto recorder = std::get<EventRecorder>(EventRecorder::Create(plan));
  auto adapter = std::get<EventRecorder::ProducerHandle>(recorder.AttachProducer(ProducerOwner::Adapter, 7));
  auto reservation = std::get<EventRecorder::EventReservation>(adapter.Reserve());
  EventV1 event;
  event.stage = Stage::Received;
  event.outcome = Outcome::Limited;
  if (adapter.Publish(std::move(reservation), event) != RecorderError::None ||
      adapter.Seal() != RecorderError::None) return 1;
  auto snapshot = std::get<EventSnapshotV1>(recorder.ExportSnapshotV1());
  std::ostringstream output;
  if (ExportStrictHistory(plan, snapshot, output) != ExportStatus::Complete) return 2;
  const auto bytes = output.str();
  auto accepts = [&](const std::string& candidate) {
    std::istringstream in(candidate);
    auto result = history::ReadStrictHistory(in, plan);
    const auto* decoded = std::get_if<EventSnapshotV1>(&result);
    return decoded && decoded->checksum64 == snapshot.checksum64;
  };
  if (!accepts(bytes) || accepts(bytes + "x")) return 3;
  for (size_t i = 0; i < bytes.size(); ++i)
    if (accepts(bytes.substr(0, i))) return 4;
  for (size_t i = 0; i < bytes.size(); ++i) {
    auto damaged = bytes;
    damaged[i] ^= 0x40;
    if (accepts(damaged)) return 5;
  }
  plan.producers.front().event_capacity++;
  if (accepts(bytes)) return 6;
}
