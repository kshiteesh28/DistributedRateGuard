#include "supervisor/epoch_gate.h"

#include <cassert>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace rateguard::supervisor;

class FakeController final : public IProcessController {
 public:
  std::map<std::string, ProcessState> states;
  std::vector<std::string> calls;
  bool throw_on_inspect{};
  bool wrong_ack{};
  std::string fail_stop_id;

  std::variant<StopAck, ControllerError> RequestStop(
      const Participant& expected, const OperationId& op) override {
    calls.push_back("stop:" + expected.participant_id);
    if (expected.participant_id == fail_stop_id) return ControllerError::Unavailable;
    states[expected.participant_id] = ProcessState::Exited;
    auto ack = op;
    if (wrong_ack) ack[0] ^= 1;
    return StopAck{ack};
  }
  std::variant<ProcessObservation, ControllerError> Inspect(
      const Participant& expected) override {
    calls.push_back("inspect:" + expected.participant_id);
    if (throw_on_inspect) throw 1;
    return ProcessObservation{expected, states.at(expected.participant_id)};
  }
};

static EpochCandidate Candidate() {
  EpochCandidate c;
  c.epoch_id[0] = 1;
  c.authority_incarnation[0] = 2;
  c.policy_digest[0] = 3;
  c.clock_identity.boot_uuid[0] = 4;
  c.clock_identity.namespace_device = 11;
  c.clock_identity.namespace_inode = 12;
  c.clock_identity.clock_id = 1;
  const auto add = [&](ParticipantRole role, std::uint32_t slot, const char* id,
                       std::uint8_t incarnation, char container, std::uint64_t pid) {
    Participant p;
    p.role = role;
    p.slot_id = slot;
    p.participant_id = id;
    p.incarnation[0] = incarnation;
    if (role == ParticipantRole::Authority) p.incarnation = c.authority_incarnation;
    p.process.container_id = std::string(64, container);
    p.process.pid = pid;
    p.process.pid_start_ticks = pid + 100;
    p.clock_identity = c.clock_identity;
    c.participants.push_back(p);
  };
  add(ParticipantRole::Authority, 0, "authority", 2, 'a', 101);
  add(ParticipantRole::Witness, 0, "witness", 5, 'b', 102);
  add(ParticipantRole::Replica, 0, "replica-zero", 6, 'c', 103);
  add(ParticipantRole::Replica, 17, "replica-seventeen", 7, 'd', 104);
  add(ParticipantRole::Adapter, 0, "adapter-a", 8, 'e', 105);
  add(ParticipantRole::Adapter, 0, "adapter-b", 9, 'f', 106);
  return c;
}

static OperationId Op() { OperationId o{}; o[0] = 7; return o; }
static bool IsError(const GateResult& result, GateError error) {
  const auto* value = std::get_if<GateError>(&result);
  return value && *value == error;
}

int main() {
  auto candidate = Candidate();
  FakeController controller;
  for (const auto& p : candidate.participants)
    controller.states[p.participant_id] = ProcessState::Running;
  auto created = EpochGate::Create(candidate, controller);
  assert(std::holds_alternative<std::shared_ptr<EpochGate>>(created));
  auto gate = std::get<std::shared_ptr<EpochGate>>(created);
  assert(gate->phase() == EpochPhase::PreActivation);
  assert(std::holds_alternative<GateError>(gate->TryAcquireCommitPermit(candidate.epoch_id)));
  assert(std::holds_alternative<std::monostate>(gate->Activate()));
  auto lease_result = gate->TryAcquireCommitPermit(candidate.epoch_id);
  assert(std::holds_alternative<CommitLease>(lease_result));
  assert(std::holds_alternative<std::monostate>(gate->BeginDrain(Op(), DrainCause::Requested)));
  assert(IsError(gate->FenceAndClose(Op()), GateError::InFlightCommit));
  lease_result.emplace<GateError>(GateError::Busy);
  assert(std::holds_alternative<std::monostate>(gate->FenceAndClose(Op())));
  assert(gate->phase() == EpochPhase::Closed);
  assert(std::holds_alternative<std::monostate>(gate->FenceAndClose(Op())));

  // Readiness failure remains preactivation but can be explicitly drained and fenced.
  FakeController not_ready;
  for (const auto& p : candidate.participants)
    not_ready.states[p.participant_id] = p.role == ParticipantRole::Adapter
                                             ? ProcessState::Unknown : ProcessState::Running;
  auto second_created = EpochGate::Create(candidate, not_ready);
  assert(std::holds_alternative<std::shared_ptr<EpochGate>>(second_created));
  auto second = std::get<std::shared_ptr<EpochGate>>(second_created);
  assert(IsError(second->Activate(), GateError::NotRunning));
  assert(std::holds_alternative<std::monostate>(second->BeginDrain(Op(), DrainCause::Requested)));
  assert(std::holds_alternative<std::monostate>(second->FenceAndClose(Op())));

  // A controller exception cannot activate or close an epoch.
  FakeController throwing;
  for (const auto& p : candidate.participants)
    throwing.states[p.participant_id] = ProcessState::Running;
  auto third_created = EpochGate::Create(candidate, throwing);
  auto third = std::get<std::shared_ptr<EpochGate>>(third_created);
  throwing.throw_on_inspect = true;
  assert(IsError(third->Activate(), GateError::ControllerFailure));
  assert(third->phase() == EpochPhase::PreActivation);
  assert(std::holds_alternative<std::monostate>(third->BeginDrain(Op(), DrainCause::Requested)));
  assert(IsError(third->FenceAndClose(Op()), GateError::ControllerFailure));
  assert(third->phase() == EpochPhase::Draining);

  // An unconfirmed ingress process blocks authority/witness stop and closure.
  FakeController partial;
  for (const auto& p : candidate.participants)
    partial.states[p.participant_id] = ProcessState::Running;
  auto partial_created = EpochGate::Create(candidate, partial);
  auto partial_gate = std::get<std::shared_ptr<EpochGate>>(partial_created);
  assert(std::holds_alternative<std::monostate>(partial_gate->Activate()));
  assert(std::holds_alternative<std::monostate>(
      partial_gate->BeginDrain(Op(), DrainCause::AuthorityFailure)));
  partial.fail_stop_id = "adapter-a";
  assert(IsError(partial_gate->FenceAndClose(Op()), GateError::NotExited));
  assert(partial_gate->phase() == EpochPhase::Draining);
  assert(std::find(partial.calls.begin(), partial.calls.end(), "stop:replica-zero") !=
         partial.calls.end());
  assert(std::find(partial.calls.begin(), partial.calls.end(), "stop:authority") ==
         partial.calls.end());
  assert(std::find(partial.calls.begin(), partial.calls.end(), "stop:witness") ==
         partial.calls.end());

  // Inventory catches reused container/PID identity and duplicate replica slot.
  auto duplicate = Candidate();
  duplicate.participants.back().process.container_id = duplicate.participants[4].process.container_id;
  assert(std::holds_alternative<GateError>(EpochGate::Create(duplicate, controller)));
  duplicate = Candidate();
  duplicate.participants[3].slot_id = duplicate.participants[2].slot_id;
  assert(std::holds_alternative<GateError>(EpochGate::Create(duplicate, controller)));

  // A lease owns the in-flight state even if the gate object is released first.
  FakeController lifetime_controller;
  auto fourth_created = EpochGate::Create(candidate, lifetime_controller);
  auto fourth = std::get<std::shared_ptr<EpochGate>>(fourth_created);
  for (const auto& p : candidate.participants)
    lifetime_controller.states[p.participant_id] = ProcessState::Running;
  assert(std::holds_alternative<std::monostate>(fourth->Activate()));
  auto survivor = fourth->TryAcquireCommitPermit(candidate.epoch_id);
  assert(std::holds_alternative<CommitLease>(survivor));
  fourth.reset();
  survivor.emplace<GateError>(GateError::Busy);

  std::cout << "epoch gate tests passed\n";
}
