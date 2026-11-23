#include "tools/history/strict_reconciliation.h"
#include <array>
#include <cstdlib>
#include <iostream>
#include <map>
#include <variant>
#include <vector>

using namespace rateguard::events;
using namespace rateguard::events::reconciliation;
namespace {
int failures=0;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; ++failures; } } while(0)
struct Input { ProducerOwner owner; Stage stage; Outcome outcome; std::uint8_t id; std::uint64_t time; };
AttemptId Id(std::uint8_t x) { AttemptId id{}; id[0]=0xF0; id[15]=x; return id; }
EventSnapshotV1 Build(std::vector<Input> inputs, RunPlan& plan) {
  std::map<ProducerOwner,std::uint64_t> counts;
  for (const auto& x:inputs) ++counts[x.owner];
  plan={}; plan.epoch_id[0]=0x21; plan.policy_digest[0]=0x42;
  for (const auto& [owner,count]:counts) plan.producers.push_back({owner,0,count});
  auto made=EventRecorder::Create(plan); CHECK(std::holds_alternative<EventRecorder>(made));
  auto recorder=std::get<EventRecorder>(std::move(made));
  std::map<ProducerOwner,EventRecorder::ProducerHandle> handles;
  for(const auto& [owner,count]:counts) {
    (void)count; auto attached=recorder.AttachProducer(owner,0);
    CHECK(std::holds_alternative<EventRecorder::ProducerHandle>(attached));
    handles.emplace(owner,std::get<EventRecorder::ProducerHandle>(std::move(attached)));
  }
  std::map<ProducerOwner,std::uint64_t> sequence;
  for(const auto& x:inputs) {
    auto reservation_result=handles.at(x.owner).Reserve();
    CHECK(std::holds_alternative<EventRecorder::EventReservation>(reservation_result));
    auto reservation=std::get<EventRecorder::EventReservation>(std::move(reservation_result));
    EventV1 event; event.stage=x.stage; event.outcome=x.outcome; event.attempt_id=Id(x.id);
    event.timestamp_ns=x.time; event.cost_units=1;
    CHECK(handles.at(x.owner).Publish(std::move(reservation),event)==RecorderError::None);
    ++sequence[x.owner];
  }
  for(auto& [owner,handle]:handles) { (void)owner; CHECK(handle.Seal()==RecorderError::None); }
  auto snapshot=recorder.ExportSnapshotV1(); CHECK(std::holds_alternative<EventSnapshotV1>(snapshot));
  return std::get<EventSnapshotV1>(std::move(snapshot));
}
AttemptDeadline Deadline(std::uint8_t id,std::uint64_t ns) { return {Id(id),ns}; }
const AttemptResult* Find(const ReconciliationReport& r,std::uint8_t id) {
  for(const auto& a:r.attempts) if(a.attempt_id==Id(id)) return &a; return nullptr;
}
void TestTimelyAndEqualityLate() {
  RunPlan p; auto s=Build({
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,1,10},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,1,20},
    {ProducerOwner::Replica,Stage::Responded,Outcome::Allow,1,30},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Allow,1,40},
    {ProducerOwner::Adapter,Stage::Forwarded,Outcome::Allow,1,41},
    {ProducerOwner::Backend,Stage::Completed,Outcome::Error,1,50},
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,2,10},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,2,20},
    {ProducerOwner::Replica,Stage::Responded,Outcome::Allow,2,30},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Allow,2,41},
    {ProducerOwner::Adapter,Stage::Forwarded,Outcome::Allow,2,42},
  },p);
  const AttemptDeadline ds[]={Deadline(1,41),Deadline(2,41)};
  auto r=ReconcileStrictHistory(s,p,ds);
  CHECK(r.evidence==EvidenceState::Complete && !r.safety_pass_allowed);
  CHECK(r.offered_records==2 && r.offered_attempts==2);
  CHECK(r.strict_allow_commits==2 && r.response_sends==2 && r.adapter_receipts==2);
  CHECK(r.timely_allow==1 && r.late_allow==1);
  CHECK(Find(r,1)->state==AttemptState::TimelyAllow);
  CHECK(Find(r,2)->state==AttemptState::LateAllow); // equality is late: timely is strictly < deadline
  CHECK(Find(r,1)->timestamp_order_valid && Find(r,2)->timestamp_order_valid);
  bool denied_late_forward=false; for(auto v:r.violations) if(v==Violation::ForwardWithoutAllow) denied_late_forward=true;
  CHECK(denied_late_forward); // equal-to-deadline receipt cannot authorize forwarding
}
void TestLostResponseAndNoResponseLimited() {
  RunPlan p; auto s=Build({
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,3,10},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,3,20},
    {ProducerOwner::Replica,Stage::Responded,Outcome::Allow,3,30},
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,4,11},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Limited,4,21},
    {ProducerOwner::Replica,Stage::Responded,Outcome::Limited,4,31},
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,9,12},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,9,22},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Unavailable,9,32},
  },p);
  const AttemptDeadline ds[]={Deadline(3,100),Deadline(4,100),Deadline(9,100)};
  auto r=ReconcileStrictHistory(s,p,ds);
  CHECK(r.evidence==EvidenceState::Complete);
  CHECK(r.committed_unanswered==1); // only committed ALLOW debit
  CHECK(r.decision_unanswered==2); // known LIMITED is a decision but not debit
  CHECK(r.limited_decision_unanswered==1);
  CHECK(r.response_sent_unreceived==2 && r.adapter_receipts==1);
  CHECK(r.timely_limited==0); // no-response LIMITED is never counted delivered
  CHECK(r.terminal_errors==1 && r.decision_response_mismatches==0); // committed ALLOW may receive an application error
  CHECK(Find(r,3)->state==AttemptState::CommittedUnanswered);
  CHECK(Find(r,4)->state==AttemptState::CommittedUnanswered);
  CHECK(Find(r,9)->state==AttemptState::TerminalError);
}
void TestDuplicateStageAndUncommittedAllow() {
  RunPlan p; auto s=Build({
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,5,10},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,5,20},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Allow,5,30},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Allow,5,31},
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,6,10},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Allow,6,20},
  },p);
  const AttemptDeadline ds[]={Deadline(5,100),Deadline(6,100)};
  auto r=ReconcileStrictHistory(s,p,ds);
  CHECK(r.evidence==EvidenceState::Complete);
  CHECK(r.duplicate_stage_violations==1);
  CHECK(Find(r,5)->state==AttemptState::DuplicateStage);
  CHECK(r.uncommitted_allow_responses==1);
  CHECK(r.unresolved_attempts>=2);
  CHECK(r.timely_allow==0); // duplicates / no matching committed decision cannot inflate numerator
}
void TestExternalDeadlineRequiredAndDuplicateDeadlineRejected() {
  RunPlan p; auto s=Build({
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,0x7e,10},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,0x7e,20},
  },p);
  auto absent=ReconcileStrictHistory(s,p,{});
  CHECK(absent.evidence==EvidenceState::Complete);
  CHECK(absent.unmatched_deadlines==1 && absent.unresolved_attempts==1);
  CHECK(Find(absent,0x7e)->state==AttemptState::CommittedUnanswered);
  const AttemptDeadline duplicate[]={Deadline(0x7e,100),Deadline(0x7e,100)};
  auto bad=ReconcileStrictHistory(s,p,duplicate);
  CHECK(bad.evidence==EvidenceState::Invalid);
  CHECK(!bad.safety_pass_allowed);
}
void TestTimestampOrderAndOrphan() {
  RunPlan p; auto s=Build({
    {ProducerOwner::WorkloadGenerator,Stage::Offered,Outcome::None,7,30},
    {ProducerOwner::Authority,Stage::StrictDecision,Outcome::Allow,7,20},
    {ProducerOwner::Adapter,Stage::Received,Outcome::Allow,7,40},
    {ProducerOwner::Backend,Stage::Completed,Outcome::Error,8,50},
  },p);
  const AttemptDeadline ds[]={Deadline(7,100),Deadline(8,100)};
  auto r=ReconcileStrictHistory(s,p,ds);
  CHECK(r.evidence==EvidenceState::Complete);
  CHECK(!Find(r,7)->timestamp_order_valid);
  CHECK(r.orphan_stage_attempts==1 && r.unmatched_deadlines==1);
  CHECK(Find(r,8)->state==AttemptState::OrphanStage);
  CHECK(!r.safety_pass_allowed);
}
}
int main(){
 TestTimelyAndEqualityLate();
 TestLostResponseAndNoResponseLimited();
 TestDuplicateStageAndUncommittedAllow();
 TestExternalDeadlineRequiredAndDuplicateDeadlineRejected();
 TestTimestampOrderAndOrphan();
 if(failures){std::cerr<<"RG005 reconciliation tests failed: "<<failures<<"\n";return EXIT_FAILURE;}
 std::cout<<"RG005 reconciliation tests passed\n";return EXIT_SUCCESS;
}
