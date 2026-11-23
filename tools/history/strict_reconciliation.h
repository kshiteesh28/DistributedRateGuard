#pragma once

// Independent Release A stage reconciliation helper. It summarizes complete
// histories; it never decides quota safety or emits a PASS verdict.
#include "src/events/history_validator.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace rateguard::events::reconciliation {

using namespace rateguard::events;

struct AttemptDeadline final {
  AttemptId attempt_id{};
  std::uint64_t deadline_ns{0};
};

enum class EvidenceState : std::uint8_t { Complete = 1, Incomplete = 2, Invalid = 3 };
enum class AttemptState : std::uint8_t {
  TimelyAllow = 1,
  TimelyLimited,
  LateAllow,
  LateLimited,
  TerminalError,
  CommittedUnanswered,
  NoDecisionOrResponse,
  Unresolved,
  DuplicateStage,
  OrphanStage,
};

enum class Violation : std::uint8_t {
  None = 0,
  DuplicateDeadline,
  DeadlineWithoutOffer,
  DuplicateStage,
  OrphanStage,
  AllowWithoutCommittedAllow,
  DecisionResponseMismatch,
  TimestampOrderViolation,
  ForwardWithoutAllow,
  CompletionWithoutForward,
};

struct AttemptResult final {
  AttemptId attempt_id{};
  AttemptState state{AttemptState::Unresolved};
  bool has_deadline{false};
  bool has_strict_decision{false};
  bool committed{false};
  bool has_adapter_receipt{false};
  std::uint64_t duplicate_stage_count{0};
  bool timestamp_order_valid{true};
};

struct ReconciliationReport final {
  EvidenceState evidence{EvidenceState::Invalid};
  bool safety_pass_allowed{false};
  std::uint64_t offered_records{0};
  std::uint64_t offered_attempts{0};
  std::uint64_t strict_allow_commits{0};
  std::uint64_t strict_limited_decisions{0};
  std::uint64_t decision_unanswered{0};
  std::uint64_t limited_decision_unanswered{0};
  std::uint64_t adapter_receipts{0};
  std::uint64_t response_sends{0};
  std::uint64_t response_sent_unreceived{0};
  std::uint64_t timely_allow{0};
  std::uint64_t timely_limited{0};
  std::uint64_t late_allow{0};
  std::uint64_t late_limited{0};
  std::uint64_t terminal_errors{0};
  std::uint64_t committed_unanswered{0};
  std::uint64_t unresolved_attempts{0};
  std::uint64_t duplicate_stage_violations{0};
  std::uint64_t orphan_stage_attempts{0};
  std::uint64_t uncommitted_allow_responses{0};
  std::uint64_t decision_response_mismatches{0};
  std::uint64_t unmatched_deadlines{0};
  std::vector<AttemptResult> attempts;
  std::vector<Violation> violations;
};

namespace detail {
struct StageEvent final {
  AttemptId id{};
  Stage stage{};
  Outcome outcome{};
  std::uint64_t timestamp_ns{};
};
struct DeadlineRow final { AttemptId id{}; std::uint64_t deadline{}; };
struct AttemptRow final {
  AttemptId id{};
  std::array<const StageEvent*, 7> stage{};
  std::array<std::uint64_t, 7> counts{};
  bool offered{false};
};
inline bool IdLess(const AttemptId& a, const AttemptId& b) noexcept { return a < b; }
inline bool Add(std::uint64_t& value, std::uint64_t amount) noexcept {
  if (amount > std::numeric_limits<std::uint64_t>::max() - value) return false;
  value += amount;
  return true;
}
inline std::size_t StageIndex(Stage stage) noexcept { return static_cast<std::size_t>(stage); }
inline const DeadlineRow* FindDeadline(const std::vector<DeadlineRow>& rows,
                                       const AttemptId& id) noexcept {
  auto it = std::lower_bound(rows.begin(), rows.end(), id,
      [](const DeadlineRow& row, const AttemptId& key) { return row.id < key; });
  return it != rows.end() && it->id == id ? &*it : nullptr;
}
}  // namespace detail

// `deadlines` must come from the caller's offered-attempt schedule, keyed by
// the exact 16-byte AttemptId. No attempt ID is parsed or used to infer time.
inline ReconciliationReport ReconcileStrictHistory(
    const EventSnapshotV1& snapshot, const RunPlan& expected_plan,
    std::span<const AttemptDeadline> deadlines) noexcept {
  using namespace detail;
  ReconciliationReport report;
  const auto structural = validation::ValidateHistorySnapshot(snapshot, expected_plan);
  if (structural.verdict == validation::Verdict::Invalid) {
    report.evidence = EvidenceState::Invalid;
    return report;
  }
  if (structural.verdict != validation::Verdict::Complete) {
    report.evidence = EvidenceState::Incomplete;
    return report;
  }
  try {
    report.evidence = EvidenceState::Complete;
    std::vector<StageEvent> events;
    if (structural.published_events > std::numeric_limits<std::size_t>::max()) {
      report.evidence = EvidenceState::Invalid;
      return report;
    }
    events.reserve(static_cast<std::size_t>(structural.published_events));
    for (const auto& producer : snapshot.producers) {
      for (const auto& slot : producer.slots) {
        if (slot.status != SlotStatus::Published) continue;
        events.push_back({slot.event.attempt_id, slot.event.stage, slot.event.outcome,
                          slot.event.timestamp_ns});
      }
    }
    std::vector<DeadlineRow> deadline_rows;
    deadline_rows.reserve(deadlines.size());
    for (const auto& d : deadlines) {
      if (d.deadline_ns == 0) {
        report.evidence = EvidenceState::Invalid;
        return report;
      }
      deadline_rows.push_back({d.attempt_id, d.deadline_ns});
    }
    std::sort(deadline_rows.begin(), deadline_rows.end(),
              [](const auto& a, const auto& b) { return a.id < b.id; });
    for (std::size_t i = 1; i < deadline_rows.size(); ++i) {
      if (deadline_rows[i - 1].id == deadline_rows[i].id) {
        report.evidence = EvidenceState::Invalid;
        report.violations.push_back(Violation::DuplicateDeadline);
        return report;
      }
    }
    std::sort(events.begin(), events.end(), [](const auto& a, const auto& b) {
      return a.id < b.id || (a.id == b.id && a.stage < b.stage);
    });
    for (std::size_t begin = 0; begin < events.size();) {
      std::size_t end = begin + 1;
      while (end < events.size() && events[end].id == events[begin].id) ++end;
      AttemptRow row;
      row.id = events[begin].id;
      for (std::size_t i = begin; i < end; ++i) {
        const auto stage = StageIndex(events[i].stage);
        if (stage < 1 || stage > 6) {
          report.evidence = EvidenceState::Invalid;
          return report;
        }
        ++row.counts[stage];
        if (!row.stage[stage]) row.stage[stage] = &events[i];
        if (events[i].stage == Stage::Offered) row.offered = true;
      }
      if (row.offered) {
        if (!Add(report.offered_attempts, 1)) { report.evidence = EvidenceState::Invalid; return report; }
        if (!Add(report.offered_records, row.counts[StageIndex(Stage::Offered)])) { report.evidence = EvidenceState::Invalid; return report; }
      } else {
        if (!Add(report.orphan_stage_attempts, 1)) { report.evidence = EvidenceState::Invalid; return report; }
        report.violations.push_back(Violation::OrphanStage);
      }
      const auto* deadline = row.offered ? FindDeadline(deadline_rows, row.id) : nullptr;
      const bool duplicate = [&] {
        for (std::size_t stage = 1; stage <= 6; ++stage)
          if (row.counts[stage] > 1) return true;
        return false;
      }();
      std::uint64_t duplicate_count = 0;
      for (std::size_t stage = 1; stage <= 6; ++stage)
        if (row.counts[stage] > 1) {
          duplicate_count += row.counts[stage] - 1;
          if (!Add(report.duplicate_stage_violations, row.counts[stage] - 1)) {
            report.evidence = EvidenceState::Invalid; return report;
          }
          report.violations.push_back(Violation::DuplicateStage);
        }
      if (row.offered && !deadline) ++report.unmatched_deadlines;
      const auto decision_stage = StageIndex(Stage::StrictDecision);
      const auto received_stage = StageIndex(Stage::Received);
      const auto responded_stage = StageIndex(Stage::Responded);
      const auto* decision = row.counts[decision_stage] == 1 ? row.stage[decision_stage] : nullptr;
      const auto* received = row.counts[received_stage] == 1 ? row.stage[received_stage] : nullptr;
      const auto* responded = row.counts[responded_stage] == 1 ? row.stage[responded_stage] : nullptr;
      const bool committed_allow = decision && decision->outcome == Outcome::Allow;
      const bool decided_limited = decision && decision->outcome == Outcome::Limited;
      if (decision && (committed_allow || decided_limited)) {
        if (committed_allow) ++report.strict_allow_commits;
        else ++report.strict_limited_decisions;
      }
      if (received && !Add(report.adapter_receipts, row.counts[StageIndex(Stage::Received)])) { report.evidence = EvidenceState::Invalid; return report; }
      if (responded && !Add(report.response_sends, row.counts[StageIndex(Stage::Responded)])) { report.evidence = EvidenceState::Invalid; return report; }
      if (row.counts[responded_stage] == 1 && row.counts[received_stage] == 0)
        ++report.response_sent_unreceived;
      if (responded && received && responded->outcome != received->outcome) {
        ++report.decision_response_mismatches;
        report.violations.push_back(Violation::DecisionResponseMismatch);
      }
      bool timestamps_ordered = true;
      const Stage ordered_stages[] = {Stage::Offered, Stage::StrictDecision, Stage::Responded,
                                      Stage::Received, Stage::Forwarded, Stage::Completed};
      const StageEvent* prior = nullptr;
      for (Stage stage : ordered_stages) {
        const auto* current = row.stage[StageIndex(stage)];
        if (!current) continue;
        if (prior && current->timestamp_ns < prior->timestamp_ns) timestamps_ordered = false;
        prior = current;
      }
      if (!timestamps_ordered) report.violations.push_back(Violation::TimestampOrderViolation);
      const auto forward_stage = StageIndex(Stage::Forwarded);
      const auto completed_stage = StageIndex(Stage::Completed);
      const auto* forwarded = row.counts[forward_stage] == 1 ? row.stage[forward_stage] : nullptr;
      const auto* completed = row.counts[completed_stage] == 1 ? row.stage[completed_stage] : nullptr;
      const bool forwarding_permitted = committed_allow && received && deadline && received->outcome == Outcome::Allow &&
                                        received->timestamp_ns < deadline->deadline;
      if (forwarded && !forwarding_permitted)
        report.violations.push_back(Violation::ForwardWithoutAllow);
      if (completed && !forwarded) report.violations.push_back(Violation::CompletionWithoutForward);
      AttemptResult result;
      result.attempt_id = row.id;
      result.has_deadline = deadline != nullptr;
      result.has_strict_decision = decision != nullptr;
      result.committed = committed_allow;
      result.has_adapter_receipt = received != nullptr;
      result.duplicate_stage_count = duplicate_count;
      result.timestamp_order_valid = timestamps_ordered;
      if (!row.offered) {
        result.state = AttemptState::OrphanStage;
      } else if (duplicate) {
        result.state = AttemptState::DuplicateStage;
        ++report.unresolved_attempts;
      } else if (received && !deadline) {
        result.state = AttemptState::Unresolved;
        ++report.unresolved_attempts;
      } else if (received) {
        const bool timely = received->timestamp_ns < deadline->deadline;
        if (received->outcome == Outcome::Allow) {
          if (committed_allow) {
            result.state = timely ? AttemptState::TimelyAllow : AttemptState::LateAllow;
            if (timely) ++report.timely_allow; else ++report.late_allow;
          } else {
            result.state = AttemptState::Unresolved;
            ++report.unresolved_attempts;
            ++report.uncommitted_allow_responses;
            report.violations.push_back(Violation::AllowWithoutCommittedAllow);
          }
        } else if (received->outcome == Outcome::Limited) {
          if (decided_limited) {
            result.state = timely ? AttemptState::TimelyLimited : AttemptState::LateLimited;
            if (timely) ++report.timely_limited; else ++report.late_limited;
          } else {
            result.state = AttemptState::Unresolved;
            ++report.unresolved_attempts;
            if (decision && (committed_allow || decided_limited)) {
              ++report.decision_response_mismatches;
              report.violations.push_back(Violation::DecisionResponseMismatch);
            }
          }
        } else {
          result.state = AttemptState::TerminalError;
          ++report.terminal_errors;
        }
      } else if (committed_allow || decided_limited) {
        result.state = AttemptState::CommittedUnanswered;
        ++report.decision_unanswered;
        if (!deadline) ++report.unresolved_attempts;
        if (committed_allow) ++report.committed_unanswered;
        else ++report.limited_decision_unanswered;
      } else {
        result.state = AttemptState::NoDecisionOrResponse;
        ++report.unresolved_attempts;
      }
      report.attempts.push_back(result);
      begin = end;
    }
    for (const auto& d : deadline_rows) {
      const auto found = std::lower_bound(events.begin(), events.end(), d.id,
          [](const StageEvent& e, const AttemptId& id) { return e.id < id; });
      bool has_offer = false;
      for (auto it = found; it != events.end() && it->id == d.id; ++it)
        if (it->stage == Stage::Offered) { has_offer = true; break; }
      if (!has_offer) {
        ++report.unmatched_deadlines;
        report.violations.push_back(Violation::DeadlineWithoutOffer);
      }
    }
    return report;
  } catch (...) {
    report.evidence = EvidenceState::Incomplete;
    report.safety_pass_allowed = false;
    report.attempts.clear();
    return report;
  }
}

}  // namespace rateguard::events::reconciliation
