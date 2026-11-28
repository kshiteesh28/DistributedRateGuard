#include "supervisor/epoch_gate.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <atomic>
#include <barrier>
#include <cstdint>
#include <cstdlib>
#include <condition_variable>
#include <limits>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using namespace rateguard::supervisor;
namespace {
std::atomic<int> failures{0};
#define CHECK(x) do { if (!(x)) { std::cerr<<"FAIL line "<<__LINE__<<": " #x "\n"; ++failures; } } while(0)

std::string HexContainer(unsigned value) {
  static constexpr char digits[]="0123456789abcdef";
  std::string s(64,'0');
  for (unsigned i=0;i<8;++i) { s[63-i]=digits[value&15]; value>>=4; }
  return s;
}
IncarnationId Inc(unsigned value) { IncarnationId a{}; a[15]=static_cast<std::uint8_t>(value); a[14]=static_cast<std::uint8_t>(value>>8); return a; }
EpochId Epoch(unsigned value) { EpochId a{}; a[15]=static_cast<std::uint8_t>(value); a[14]=static_cast<std::uint8_t>(value>>8); return a; }
PolicyDigest Digest() { PolicyDigest a{}; a[0]=0x55; return a; }
OperationId Op(unsigned value) { OperationId a{}; a[15]=static_cast<std::uint8_t>(value); return a; }
rateguard::platform::ClockIdentity Clock() {
  rateguard::platform::ClockIdentity c{}; c.boot_uuid[0]=1; c.namespace_device=2;
  c.namespace_inode=3; c.clock_id=1; return c;
}

struct Controller final : IProcessController {
  struct Call { bool stop; Participant participant; OperationId operation; };
  std::mutex mutex;
  std::vector<Call> calls;
  std::vector<std::pair<Participant,ProcessState>> states;
  std::optional<std::string> unknown_on_inspect;
  std::optional<std::string> mismatch_on_inspect;
  std::optional<std::string> timeout_inspect;
  std::optional<std::string> stop_error;
  std::optional<std::string> wrong_ack;
  std::optional<std::string> throw_inspect;
  std::optional<std::string> throw_stop;
  std::function<void()> inspect_hook;
  std::function<void()> stop_hook;

  void SetState(const Participant& p, ProcessState state) {
    std::lock_guard lock(mutex);
    for (auto& row:states) if (row.first==p) { row.second=state; return; }
    states.emplace_back(p,state);
  }
  std::vector<Call> Calls() { std::lock_guard lock(mutex); return calls; }
  std::variant<StopAck,ControllerError> RequestStop(const Participant& expected,const OperationId& op) override {
    {
      std::lock_guard lock(mutex); calls.push_back({true,expected,op});
      if (throw_stop && expected.participant_id==*throw_stop) throw std::runtime_error("stop fixture");
      if (stop_error && expected.participant_id==*stop_error) return ControllerError::Unavailable;
      for (auto& row:states) if (row.first==expected) { row.second=ProcessState::Exited; break; }
    }
    if (stop_hook) stop_hook();
    return StopAck{wrong_ack && expected.participant_id==*wrong_ack ? Op(0xEE) : op};
  }
  std::variant<ProcessObservation,ControllerError> Inspect(const Participant& expected) override {
    {
      std::lock_guard lock(mutex); calls.push_back({false,expected,{}});
      if (throw_inspect && expected.participant_id==*throw_inspect) throw std::runtime_error("inspect fixture");
      if (timeout_inspect && expected.participant_id==*timeout_inspect) return ControllerError::TimedOut;
      if (unknown_on_inspect && expected.participant_id==*unknown_on_inspect)
        return ProcessObservation{expected,ProcessState::Unknown};
      if (mismatch_on_inspect && expected.participant_id==*mismatch_on_inspect) {
        auto wrong=expected; ++wrong.process.pid_start_ticks;
        return ProcessObservation{wrong,ProcessState::Exited};
      }
    }
    if (inspect_hook) inspect_hook();
    std::lock_guard lock(mutex);
    for (const auto& row:states) if(row.first==expected) return ProcessObservation{expected,row.second};
    return ProcessObservation{expected,ProcessState::Unknown};
  }
};

Participant MakeParticipant(ParticipantRole role, std::uint32_t slot, unsigned i,
                            const rateguard::platform::ClockIdentity& clock,
                            unsigned participant_key=0) {
  Participant p; p.role=role; p.slot_id=slot; p.participant_id="p"+std::to_string(participant_key?participant_key:i);
  p.incarnation=Inc(i+1); p.process={HexContainer(i+1),1000+i,2000+i}; p.clock_identity=clock; return p;
}
EpochCandidate Candidate(std::size_t adapters=2,std::vector<std::uint32_t> slots={0,9}) {
  EpochCandidate c; c.epoch_id=Epoch(1); c.authority_incarnation=Inc(1); c.policy_digest=Digest(); c.clock_identity=Clock();
  unsigned n=1;
  auto authority=MakeParticipant(ParticipantRole::Authority,0,n++,c.clock_identity); authority.incarnation=c.authority_incarnation; authority.participant_id="authority"; c.participants.push_back(authority);
  auto witness=MakeParticipant(ParticipantRole::Witness,0,n++,c.clock_identity); witness.participant_id="witness"; c.participants.push_back(witness);
  unsigned rid=10;
  for(auto slot:slots) { auto r=MakeParticipant(ParticipantRole::Replica,slot,rid++,c.clock_identity); r.participant_id="replica-"+std::to_string(slot); c.participants.push_back(r); }
  for(std::size_t i=0;i<adapters;++i) { auto a=MakeParticipant(ParticipantRole::Adapter,0,static_cast<unsigned>(30+i),c.clock_identity); a.participant_id="adapter-"+std::to_string(i); c.participants.push_back(a); }
  return c;
}
std::shared_ptr<EpochGate> Create(EpochCandidate c,Controller& ctl) {
  for(const auto& p:c.participants) ctl.SetState(p,ProcessState::Running);
  auto result=EpochGate::Create(std::move(c),ctl);
  CHECK(std::holds_alternative<std::shared_ptr<EpochGate>>(result));
  if(!std::holds_alternative<std::shared_ptr<EpochGate>>(result)) return {};
  return std::get<std::shared_ptr<EpochGate>>(std::move(result));
}
bool IsError(const auto& result,GateError e) {
  return std::holds_alternative<GateError>(result) && std::get<GateError>(result)==e;
}
bool IsOk(const GateResult& result) { return std::holds_alternative<std::monostate>(result); }
void Activate(std::shared_ptr<EpochGate>& gate) { CHECK(IsOk(gate->Activate())); }
void TestCandidateValidationAndArbitrarySlotIds() {
  Controller ctl;
  auto valid=Candidate(2,{0,9,std::numeric_limits<std::uint32_t>::max()});
  auto gate=Create(std::move(valid),ctl);
  CHECK(gate && gate->phase()==EpochPhase::PreActivation);
  CHECK(gate->candidate().participants.size()==7);
  auto duplicate_slot=Candidate(1,{7,7});
  CHECK(IsError(EpochGate::Create(std::move(duplicate_slot),ctl),GateError::InvalidInventory));
  auto too_many_replicas=Candidate(1,{0,1,2,3,4,5,6,7,8});
  CHECK(IsError(EpochGate::Create(std::move(too_many_replicas),ctl),GateError::InvalidInventory));
  auto no_replica=Candidate(1,{});
  CHECK(IsError(EpochGate::Create(std::move(no_replica),ctl),GateError::InvalidInventory));
  auto many_adapters=Candidate(1022,{1});
  CHECK(IsError(EpochGate::Create(std::move(many_adapters),ctl),GateError::TooManyParticipants));
  auto duplicate=Candidate(2,{1});
  duplicate.participants.back().process.container_id=duplicate.participants[duplicate.participants[3].role==ParticipantRole::Adapter?3:0].process.container_id;
  CHECK(IsError(EpochGate::Create(std::move(duplicate),ctl),GateError::InvalidInventory));
  auto duplicate_pid=Candidate(2,{1});
  duplicate_pid.participants.back().process.pid=duplicate_pid.participants[3].process.pid;
  ++duplicate_pid.participants.back().process.pid_start_ticks;
  CHECK(IsError(EpochGate::Create(std::move(duplicate_pid),ctl),GateError::InvalidInventory));
  auto bad_identity=Candidate(1,{1});
  bad_identity.participants.back().clock_identity.clock_id=8;
  CHECK(IsError(EpochGate::Create(std::move(bad_identity),ctl),GateError::InvalidInventory));
  auto bad_container=Candidate(1,{1}); bad_container.participants.back().process.container_id[0]='A';
  CHECK(IsError(EpochGate::Create(std::move(bad_container),ctl),GateError::InvalidInventory));
  auto wrong_authority=Candidate(1,{1}); ++wrong_authority.participants[0].incarnation[0];
  CHECK(IsError(EpochGate::Create(std::move(wrong_authority),ctl),GateError::InvalidInventory));
}
void TestActivationIdentityTimeoutAndUnknown() {
  auto run=[](auto configure,GateError expected) {
    Controller ctl; auto c=Candidate(1,{7});
    auto gate=Create(std::move(c),ctl); if(!gate)return;
    configure(gate->candidate(),ctl);
    CHECK(IsError(gate->Activate(),expected)); CHECK(gate->phase()==EpochPhase::PreActivation);
    CHECK(IsError(gate->TryAcquireCommitPermit(gate->candidate().epoch_id),GateError::WrongPhase));
  };
  run([](const auto& c,auto& ctl){ctl.SetState(c.participants[0],ProcessState::Exited);},GateError::NotRunning);
  run([](const auto& c,auto& ctl){ctl.unknown_on_inspect=c.participants[0].participant_id;},GateError::NotRunning);
  run([](const auto& c,auto& ctl){ctl.timeout_inspect=c.participants[0].participant_id;},GateError::ControllerFailure);
  run([](const auto& c,auto& ctl){ctl.mismatch_on_inspect=c.participants[0].participant_id;},GateError::IdentityMismatch);
  run([](const auto& c,auto& ctl){ctl.throw_inspect=c.participants[0].participant_id;},GateError::ControllerFailure);
}
void TestLeaseDrainAndOrderedFence() {
  Controller ctl; auto gate=Create(Candidate(2,{0,9}),ctl); if(!gate)return; Activate(gate);
  auto bad=Epoch(99); CHECK(IsError(gate->TryAcquireCommitPermit(bad),GateError::WrongEpoch));
  auto lease_result=gate->TryAcquireCommitPermit(gate->candidate().epoch_id);
  CHECK(std::holds_alternative<CommitLease>(lease_result));
  if(!std::holds_alternative<CommitLease>(lease_result)) return;
  std::optional<CommitLease> lease; lease.emplace(std::get<CommitLease>(std::move(lease_result)));
  const auto op=Op(11); CHECK(IsOk(gate->BeginDrain(op,DrainCause::Requested)));
  CHECK(gate->phase()==EpochPhase::Draining);
  CHECK(IsOk(gate->BeginDrain(op,DrainCause::IntegrityFailure)));
  CHECK(IsError(gate->BeginDrain(Op(12),DrainCause::Requested),GateError::WrongOperation));
  CHECK(IsError(gate->TryAcquireCommitPermit(gate->candidate().epoch_id),GateError::WrongPhase));
  CHECK(IsError(gate->FenceAndClose(op),GateError::InFlightCommit));
  auto before_release=ctl.Calls();
  CHECK(std::none_of(before_release.begin(),before_release.end(),[](const auto& c){return c.stop;}));
  lease.reset();
  CHECK(IsOk(gate->FenceAndClose(op)));
  CHECK(gate->phase()==EpochPhase::Closed);
  auto calls=ctl.Calls();
  std::size_t first_auth_stop=calls.size(), last_ingress_stop=0, first_ingress_inspect=calls.size();
  bool auth_stop=false,witness_stop=false,ingress_stop_started=false;
  for(std::size_t i=0;i<calls.size();++i) {
    const auto& call=calls[i];
    if(call.stop && (call.participant.role==ParticipantRole::Authority || call.participant.role==ParticipantRole::Witness)) {
      first_auth_stop=std::min(first_auth_stop,i);
      if(call.participant.role==ParticipantRole::Authority) auth_stop=true;
      if(call.participant.role==ParticipantRole::Witness) witness_stop=true;
    }
    if(call.participant.role==ParticipantRole::Adapter || call.participant.role==ParticipantRole::Replica) {
      if(call.stop) { last_ingress_stop=std::max(last_ingress_stop,i); ingress_stop_started=true; }
      else if(ingress_stop_started) first_ingress_inspect=std::min(first_ingress_inspect,i);
    }
  }
  CHECK(auth_stop&&witness_stop);
  CHECK(last_ingress_stop < first_ingress_inspect); // issue all ingress stops before confirming any
  CHECK(first_ingress_inspect < first_auth_stop); // all ingress exits before authority/witness stop
  CHECK(IsOk(gate->BeginDrain(op,DrainCause::Requested)));
  CHECK(IsError(gate->BeginDrain(Op(13),DrainCause::Requested),GateError::WrongOperation));
  const auto before_replay=ctl.Calls().size();
  CHECK(IsOk(gate->FenceAndClose(op))); // closed operation replays idempotently
  CHECK(IsError(gate->FenceAndClose(Op(13)),GateError::WrongOperation));
  CHECK(ctl.Calls().size()==before_replay); // replay does not repeat lifecycle I/O
  CHECK(IsError(gate->Activate(),GateError::WrongPhase));
}
void TestUnknownStaleAndTimeoutPreventClose() {
  auto fail_case=[](auto configure,GateError expected) {
    Controller ctl; auto gate=Create(Candidate(2,{1,2}),ctl); if(!gate)return;
    Activate(gate); const auto op=Op(21); CHECK(IsOk(gate->BeginDrain(op,DrainCause::AuthorityFailure)));
    configure(ctl,gate->candidate());
    auto close_result=gate->FenceAndClose(op); CHECK(IsError(close_result,expected)); CHECK(gate->phase()==EpochPhase::Draining);
    auto calls=ctl.Calls();
    CHECK(std::none_of(calls.begin(),calls.end(),[](const auto& c){return c.stop && (c.participant.role==ParticipantRole::Authority || c.participant.role==ParticipantRole::Witness);}));
    if(expected==GateError::NotExited || expected==GateError::IdentityMismatch || expected==GateError::ControllerFailure) {
      // Clear the injected uncertainty and prove a later exact retry can close.
      ctl.unknown_on_inspect.reset(); ctl.timeout_inspect.reset(); ctl.mismatch_on_inspect.reset(); ctl.throw_inspect.reset(); ctl.stop_error.reset(); ctl.wrong_ack.reset(); ctl.throw_stop.reset();
      for(const auto& p:gate->candidate().participants) ctl.SetState(p,ProcessState::Exited);
      CHECK(IsOk(gate->FenceAndClose(op))); CHECK(gate->phase()==EpochPhase::Closed);
    }
  };
  fail_case([](auto& ctl,const auto& c){ctl.unknown_on_inspect=c.participants.back().participant_id;},GateError::NotExited);
  fail_case([](auto& ctl,const auto& c){ctl.timeout_inspect=c.participants.back().participant_id;},GateError::ControllerFailure);
  fail_case([](auto& ctl,const auto& c){ctl.mismatch_on_inspect=c.participants.back().participant_id;},GateError::IdentityMismatch);
  fail_case([](auto& ctl,const auto& c){ctl.throw_inspect=c.participants.back().participant_id;},GateError::ControllerFailure);
  fail_case([](auto& ctl,const auto& c){ctl.wrong_ack=c.participants.back().participant_id;},GateError::WrongOperation);
  fail_case([](auto& ctl,const auto& c){ctl.stop_error=c.participants.back().participant_id;},GateError::NotExited);
  fail_case([](auto& ctl,const auto& c){ctl.throw_stop=c.participants.back().participant_id;},GateError::NotExited);
}
void TestPreActivationDrainCleanup() {
  Controller ctl; auto gate=Create(Candidate(2,{0,9}),ctl); if(!gate)return;
  CHECK(gate->phase()==EpochPhase::PreActivation);
  CHECK(IsError(gate->BeginDrain(OperationId{},DrainCause::Requested),GateError::WrongOperation));
  const auto op=Op(31);
  CHECK(IsOk(gate->BeginDrain(op,DrainCause::IntegrityFailure)));
  CHECK(gate->phase()==EpochPhase::Draining);
  CHECK(IsOk(gate->FenceAndClose(op)));
  CHECK(gate->phase()==EpochPhase::Closed);
  auto calls=ctl.Calls();
  CHECK(!calls.empty());
  CHECK(calls.front().stop); // no activation/readiness inspect was required before the drain path
}
void TestLeaseKeepsStateAfterGateDestruction() {
  Controller ctl; auto gate=Create(Candidate(1,{5}),ctl); if(!gate)return; Activate(gate);
  auto lease_result=gate->TryAcquireCommitPermit(gate->candidate().epoch_id);
  CHECK(std::holds_alternative<CommitLease>(lease_result));
  if(!std::holds_alternative<CommitLease>(lease_result)) return;
  std::optional<CommitLease> lease; lease.emplace(std::get<CommitLease>(std::move(lease_result)));
  gate.reset(); // Lease owns GateState until its destructor releases the count.
  lease.reset();
}
void TestConcurrentActivationReturnsBusyAndNoLockAcrossController() {
  Controller ctl; auto gate=Create(Candidate(1,{1}),ctl); if(!gate)return;
  std::mutex m; std::condition_variable cv; bool entered=false,release=false;
  ctl.inspect_hook=[&]{ CHECK(gate->phase()==EpochPhase::PreActivation); std::unique_lock l(m); entered=true; cv.notify_all(); cv.wait(l,[&]{return release;}); };
  GateResult first; std::thread t([&]{first=gate->Activate();});
  {std::unique_lock l(m); cv.wait(l,[&]{return entered;});}
  CHECK(IsError(gate->Activate(),GateError::Busy));
  {std::lock_guard l(m);release=true;} cv.notify_all();t.join();CHECK(IsOk(first));
}
}
int main(){
 TestCandidateValidationAndArbitrarySlotIds();
 TestActivationIdentityTimeoutAndUnknown();
 TestLeaseDrainAndOrderedFence();
 TestUnknownStaleAndTimeoutPreventClose();
 TestPreActivationDrainCleanup();
 TestLeaseKeepsStateAfterGateDestruction();
 TestConcurrentActivationReturnsBusyAndNoLockAcrossController();
 if(failures){std::cerr<<"RG006 epoch gate QA failed: "<<failures<<"\n";return EXIT_FAILURE;}
 std::cout<<"RG006 epoch gate QA passed\n";return EXIT_SUCCESS;
}
