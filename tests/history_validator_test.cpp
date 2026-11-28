#include "src/events/event_recorder.h"
#include "src/events/history_validator.h"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <utility>

namespace {
using namespace rateguard::events;
using namespace rateguard::events::validation;

void Check(bool condition, std::string_view name) {
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    std::exit(1);
  }
}

RunPlan BasePlan(std::uint64_t budget = kMaxRunBudgetBytes) {
  RunPlan plan;
  plan.epoch_id[0] = 0xA1;
  plan.policy_digest[0] = 0xB2;
  plan.producers = {
      {ProducerOwner::Backend, 0, 1},
      {ProducerOwner::Adapter, 0, 1},
      {ProducerOwner::Replica, 0, 1},
      {ProducerOwner::Authority, 0, 1},
      {ProducerOwner::WorkloadGenerator, 0, 1},
  };
  plan.budget_bytes = budget;
  return plan;
}

Stage StageFor(ProducerOwner owner) {
  switch (owner) {
    case ProducerOwner::WorkloadGenerator: return Stage::Offered;
    case ProducerOwner::Authority: return Stage::StrictDecision;
    case ProducerOwner::Replica: return Stage::Responded;
    case ProducerOwner::Adapter: return Stage::Received;
    case ProducerOwner::Backend: return Stage::Completed;
  }
  return Stage::Offered;
}

EventSnapshotV1 CompleteSnapshot(const RunPlan& plan) {
  auto created = EventRecorder::Create(plan);
  Check(std::holds_alternative<EventRecorder>(created), "recorder_create");
  auto& recorder = std::get<EventRecorder>(created);
  for (const auto& spec : plan.producers) {
    auto attached = recorder.AttachProducer(spec.owner, spec.producer_index);
    Check(std::holds_alternative<EventRecorder::ProducerHandle>(attached), "attach_producer");
    auto handle = std::move(std::get<EventRecorder::ProducerHandle>(attached));
    auto reserved = handle.Reserve();
    Check(std::holds_alternative<EventRecorder::EventReservation>(reserved), "reserve_event");
    EventV1 event;
    event.stage = StageFor(spec.owner);
    event.outcome = Outcome::Allow;
    event.attempt_id[0] = 0xC3;
    event.timestamp_ns = 17;
    event.cost_units = 1;
    const auto publish = handle.Publish(
        std::move(std::get<EventRecorder::EventReservation>(reserved)), event);
    Check(publish == RecorderError::None, "publish_event");
    Check(handle.Seal() == RecorderError::None, "seal_producer");
  }
  auto exported = recorder.ExportSnapshotV1();
  Check(std::holds_alternative<EventSnapshotV1>(exported), "export_snapshot");
  return std::get<EventSnapshotV1>(std::move(exported));
}

bool Is(const EventSnapshotV1& snapshot, const RunPlan& plan, Verdict verdict, Reason reason) {
  const auto report = ValidateHistorySnapshot(snapshot, plan);
  return report.verdict == verdict && report.reason == reason;
}

void TestValidAndPermutedExpectedPlan() {
  auto plan = BasePlan();
  const auto snapshot = CompleteSnapshot(plan);
  const auto report = ValidateHistorySnapshot(snapshot, plan);
  Check(report.verdict == Verdict::Complete && report.reason == Reason::None,
        "complete_snapshot_passes_structure");
  Check(report.published_events == 5 && report.snapshot_bytes == snapshot.planned_bytes,
        "complete_snapshot_counts_and_extent");
  Check(!report.safety_pass_allowed(), "completeness_is_not_safety_pass");

  std::reverse(plan.producers.begin(), plan.producers.end());
  Check(Is(snapshot, plan, Verdict::Complete, Reason::None),
        "expected_roster_input_permutation_matches_canonical_snapshot");
}

void TestUnsealedAndGaps() {
  auto plan = BasePlan();
  auto snapshot = CompleteSnapshot(plan);
  snapshot.producers.front().sealed = false;
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::ProducerNotSealed),
        "unsealed_producer_is_incomplete");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers.front().slots.front().producer_sequence = 2;
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::ReservationGap),
        "sequence_gap_is_incomplete");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers.front().slots.front().status = SlotStatus::Reserved;
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::ReservedSlotUnpublished),
        "reserved_unpublished_slot_is_incomplete");
}

void TestCorruptionAndRoster() {
  auto plan = BasePlan();
  auto snapshot = CompleteSnapshot(plan);
  snapshot.producers.front().slots.front().checksum64 ^= 1;
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::EventChecksumMismatch),
        "event_checksum_corruption_is_incomplete");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers.front().seal_checksum64 ^= 1;
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::ProducerChecksumMismatch),
        "producer_seal_checksum_corruption_is_incomplete");

  snapshot = CompleteSnapshot(plan);
  snapshot.checksum64 ^= 1;
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::SnapshotChecksumMismatch),
        "run_checksum_corruption_is_incomplete");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers.front().slots.front().event.stage = Stage::Forwarded;
  Check(Is(snapshot, plan, Verdict::Invalid, Reason::StageOwnerMismatch),
        "wrong_stage_owner_is_invalid");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers.pop_back();
  Check(Is(snapshot, plan, Verdict::Incomplete, Reason::ProducerMissing),
        "missing_expected_producer_is_incomplete");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers[1] = snapshot.producers[0];
  Check(Is(snapshot, plan, Verdict::Invalid, Reason::ProducerOrderOrCapacityMismatch),
        "duplicate_or_noncanonical_producer_is_invalid");

  snapshot = CompleteSnapshot(plan);
  snapshot.producers.push_back(snapshot.producers.back());
  Check(Is(snapshot, plan, Verdict::Invalid, Reason::ProducerUnexpected),
        "unexpected_producer_is_invalid");
}

void TestExpectedPlanAndCaps() {
  auto plan = BasePlan();
  auto snapshot = CompleteSnapshot(plan);

  auto wrong_epoch = plan;
  wrong_epoch.epoch_id[0] ^= 1;
  Check(Is(snapshot, wrong_epoch, Verdict::Invalid, Reason::ExpectedPlanMismatch),
        "epoch_mismatch_rejected");
  auto wrong_digest = plan;
  wrong_digest.policy_digest[0] ^= 1;
  Check(Is(snapshot, wrong_digest, Verdict::Invalid, Reason::ExpectedPlanMismatch),
        "policy_digest_mismatch_rejected");
  auto wrong_capacity = plan;
  wrong_capacity.producers.front().event_capacity = 2;
  Check(Is(snapshot, wrong_capacity, Verdict::Invalid, Reason::ExpectedPlanMismatch),
        "producer_capacity_mismatch_rejected");
  auto wrong_budget = plan;
  --wrong_budget.budget_bytes;
  Check(Is(snapshot, wrong_budget, Verdict::Invalid, Reason::ExpectedPlanMismatch),
        "run_budget_mismatch_rejected");
  auto wrong_extent = snapshot;
  ++wrong_extent.planned_bytes;
  Check(Is(wrong_extent, plan, Verdict::Invalid, Reason::ExpectedPlanMismatch),
        "serialized_extent_mismatch_rejected");
  auto bad_schema = snapshot;
  bad_schema.schema_version = 2;
  Check(Is(bad_schema, plan, Verdict::Invalid, Reason::SchemaMismatch),
        "unknown_schema_rejected");

  // Fixed-width exact-budget plans below the global cap are valid.
  constexpr std::uint64_t exact_plan_bytes = 80 + 17 + 5 * (13 + 51 + 26);
  auto exact_plan = BasePlan(exact_plan_bytes);
  const auto exact_snapshot = CompleteSnapshot(exact_plan);
  Check(exact_snapshot.planned_bytes == exact_plan_bytes &&
        Is(exact_snapshot, exact_plan, Verdict::Complete, Reason::None),
        "exact_smaller_budget_plan_is_valid");

  auto undersized_plan = BasePlan(exact_plan_bytes - 1);
  Check(Is(exact_snapshot, undersized_plan, Verdict::Invalid, Reason::InvalidExpectedPlan),
        "budget_below_required_extent_rejected");
  auto oversized_budget = BasePlan(kMaxRunBudgetBytes + 1);
  Check(Is(exact_snapshot, oversized_budget, Verdict::Invalid, Reason::InvalidExpectedPlan),
        "budget_above_global_cap_rejected");
}

}  // namespace

int main() {
  TestValidAndPermutedExpectedPlan();
  TestUnsealedAndGaps();
  TestCorruptionAndRoster();
  TestExpectedPlanAndCaps();
  std::cout << "RG-005 validator cases passed\n";
}
