#include "proto/rateguard/v1/admission.pb.h"
#include "proto/rateguard/v1/authority.pb.h"
#include "rateguard/v1/error_contract.h"
#include "rateguard/v1/request_validation.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <google/protobuf/descriptor.h>
#include <string>
#include <string_view>

namespace rg = rateguard::v1;
namespace contract = rateguard::v1::contract;
namespace validation = rateguard::v1::validation;
using rg::AcquireCreditRequest;
using rg::AcquireCreditResponse;
using rg::AdmissionDecision;
using rg::CheckAdmissionRequest;

namespace {
int failures = 0;
void Check(bool ok, std::string_view label) {
  if (!ok) {
    std::cerr << "FAIL: " << label << '\n';
    ++failures;
  }
}
std::string ReadText(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) return {};
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
std::string ReadHex(const std::filesystem::path& path) {
  std::string compact, text = ReadText(path);
  for (char c : text) {
    if (c == '#' ) break;
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') compact.push_back(c);
  }
  std::string bytes;
  if (compact.size() % 2 != 0) return {};
  for (std::size_t i = 0; i < compact.size(); i += 2) {
    const auto digit = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = digit(compact[i]), lo = digit(compact[i + 1]);
    if (hi < 0 || lo < 0) return {};
    bytes.push_back(static_cast<char>((hi << 4) | lo));
  }
  return bytes;
}
std::string Seq(unsigned char start, std::size_t size) {
  std::string value;
  for (std::size_t i = 0; i < size; ++i)
    value.push_back(static_cast<char>(start + i));
  return value;
}
template <typename Message>
void RoundTrip(const std::filesystem::path& root, std::string_view fixture,
               Message& message, std::string_view label) {
  const std::string bytes = ReadHex(root / "tests/fixtures" / fixture);
  Check(!bytes.empty(), std::string(label) + " fixture readable");
  Check(message.ParseFromString(bytes), std::string(label) + " generated parser accepts fixture");
  std::string encoded;
  Check(message.SerializeToString(&encoded), std::string(label) + " generated serializer succeeds");
  Check(encoded == bytes, std::string(label) + " generated parse/serialize is byte-stable");
}
struct FakeStatePort {
  int calls = 0;
  void Apply() { ++calls; }
};
template <typename Request, typename Validator>
bool ValidateBeforeState(const Request& request, Validator validate, FakeStatePort& port) {
  if (validate(request).has_value()) return false;
  port.Apply();
  return true;
}
const google::protobuf::FieldDescriptor* Field(
    const google::protobuf::Descriptor* message, std::string_view name, int number) {
  const auto* field = message->FindFieldByName(std::string(name));
  Check(field != nullptr, std::string(message->name()) + "." + std::string(name) + " exists");
  if (field) Check(field->number() == number,
                   std::string(message->name()) + "." + std::string(name) + " number");
  return field;
}
}  // namespace

int main(int argc, char** argv) {
  const std::filesystem::path root = argc > 1 ? argv[1] : ".";

  const auto* check = CheckAdmissionRequest::descriptor();
  Field(check, "tenant_id", 1); Field(check, "operation_id", 2);
  Field(check, "attempt_id", 3); Field(check, "epoch_id", 4);
  Field(check, "policy_digest", 5);
  Check(check->field_count() == 5, "CheckAdmissionRequest has no client cost/mode/time fields");

  const auto* decision = AdmissionDecision::descriptor();
  Field(decision, "outcome", 1); Field(decision, "epoch_id", 2);
  Field(decision, "policy_digest", 3); Field(decision, "mode", 4);
  Field(decision, "attempt_id", 5); Field(decision, "retry_delay_ns", 6);
  const auto* acquire = AcquireCreditRequest::descriptor();
  Field(acquire, "tenant_id", 1); Field(acquire, "slot", 2);
  Field(acquire, "incarnation_id", 3); Field(acquire, "epoch_id", 4);
  Field(acquire, "policy_digest", 5); Field(acquire, "sequence", 6);
  Field(acquire, "trigger_cost_units", 7); Field(acquire, "trigger_operation_id", 8);
  const auto* grant_response = AcquireCreditResponse::descriptor();
  Field(grant_response, "grant_outcome", 1); Field(grant_response, "sequence", 2);
  Field(grant_response, "composite_grant_id", 3); Field(grant_response, "grant_units", 4);
  Field(grant_response, "epoch_id", 5); Field(grant_response, "policy_digest", 6);

  Check(static_cast<int>(DECISION_OUTCOME_UNSPECIFIED) == 0 &&
        static_cast<int>(DECISION_OUTCOME_ALLOW) == 1 &&
        static_cast<int>(DECISION_OUTCOME_OVERLOADED) == 6, "decision enum numeric contract");
  Check(static_cast<int>(GRANT_OUTCOME_UNSPECIFIED) == 0 &&
        static_cast<int>(GRANT_OUTCOME_GRANTED) == 1 &&
        static_cast<int>(GRANT_OUTCOME_OVERLOADED) == 5, "grant enum numeric contract");
  Check(static_cast<int>(ADMISSION_MODE_UNSPECIFIED) == 0 &&
        static_cast<int>(ADMISSION_MODE_CREDIT) == 2, "mode enum numeric contract");
  Check(!validation::IsKnownDecisionOutcome(0) && !validation::IsKnownDecisionOutcome(7), "reject unspecified/unknown decision");
  Check(!validation::IsKnownGrantOutcome(0) && !validation::IsKnownGrantOutcome(6), "reject unspecified/unknown grant");
  Check(!validation::IsKnownAdmissionMode(0) && !validation::IsKnownAdmissionMode(3), "reject unspecified/unknown mode");

  Check(contract::StatusFor(contract::ErrorCode::InvalidArgument) == contract::GrpcStatus::InvalidArgument,
        "INVALID_ARGUMENT status mapping");
  Check(contract::StatusFor(contract::ErrorCode::Unauthenticated) == contract::GrpcStatus::Unauthenticated,
        "UNAUTHENTICATED status mapping");
  Check(contract::StatusFor(contract::ErrorCode::PermissionDenied) == contract::GrpcStatus::PermissionDenied,
        "PERMISSION_DENIED status mapping");
  Check(contract::StatusFor(contract::ErrorCode::PayloadTooLarge) == contract::GrpcStatus::ResourceExhausted,
        "oversize pre-decode transport status mapping");
  Check(contract::StructuredDecisionStatus(5) == contract::GrpcStatus::Ok &&
        contract::StructuredDecisionStatus(6) == contract::GrpcStatus::Ok &&
        contract::StructuredGrantStatus(4) == contract::GrpcStatus::Ok &&
        contract::StructuredGrantStatus(5) == contract::GrpcStatus::Ok,
        "structured UNAVAILABLE/OVERLOADED use transport OK");
  Check(contract::StructuredDecisionStatus(3) == contract::GrpcStatus::Internal &&
        contract::StructuredDecisionStatus(0) == contract::GrpcStatus::Internal,
        "invalid/unspecified decision is not a successful structured response");
  Check(contract::CommitmentForTransportFailure(contract::DispatchPhase::BeforeDispatch) == contract::Commitment::NotCommitted,
        "predispatch transport failure is not committed");
  Check(contract::CommitmentForTransportFailure(contract::DispatchPhase::Dispatched) == contract::Commitment::Possible,
        "post-dispatch transport failure has possible commitment");
  Check(contract::RetryDispositionFor(contract::RpcOperation::StrictAdmission, contract::DispatchPhase::Dispatched) ==
            contract::RetryDisposition::NewAttempt &&
        contract::RetryDispositionFor(contract::RpcOperation::AcquireCredit, contract::DispatchPhase::Dispatched) ==
            contract::RetryDisposition::SameGrantSequence,
        "strict retries are fresh application attempts; uncertain grants reuse same sequence");
  Check(contract::IsAllowOutcome(contract::DecisionOutcome::Allow) &&
        !contract::IsAllowOutcome(contract::DecisionOutcome::Limited) &&
        !contract::IsAllowOutcome(contract::DecisionOutcome::Unavailable),
        "only ALLOW outcome can authorize forwarding");
  Check(contract::IsValidIdentifier("tenant-1.alpha_2") && !contract::IsValidIdentifier("") &&
        !contract::IsValidIdentifier("bad tenant") && !contract::IsValidIdentifier("x/y"),
        "identifier grammar and 1..128 byte bound");

  CheckAdmissionRequest req;
  RoundTrip(root, "check_admission_request.hex", req, "CheckAdmissionRequest");
  Check(req.tenant_id() == "acct-1" && req.operation_id() == "publish" &&
        req.attempt_id() == Seq(0x00, 16) && req.epoch_id() == Seq(0x10, 16) &&
        req.policy_digest() == Seq(0x20, 32), "check request fixture values");
  FakeStatePort admission_port;
  Check(ValidateBeforeState(req, [](const auto& x) { return validation::ValidateCheckAdmissionRequest(x, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32)); }, admission_port),
        "valid admission request accepted");
  auto bad_req = req; bad_req.set_attempt_id(Seq(0, 15));
  Check(!ValidateBeforeState(bad_req, [](const auto& x) { return validation::ValidateCheckAdmissionRequest(x, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32)); }, admission_port) &&
        admission_port.calls == 1, "invalid fixed-width ID rejected before state port");
  bad_req = req; bad_req.set_tenant_id(std::string(129, 'x'));
  Check(!ValidateBeforeState(bad_req, [](const auto& x) { return validation::ValidateCheckAdmissionRequest(x, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32)); }, admission_port) &&
        admission_port.calls == 1, "oversized identifier rejected before state port");
  bad_req = req;
  bad_req.set_epoch_id(Seq(0x30, 16));
  Check(!ValidateBeforeState(bad_req, [](const auto& x) { return validation::ValidateCheckAdmissionRequest(x, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32)); }, admission_port) &&
        admission_port.calls == 1, "stale epoch rejected before state port");
  // Unknown protobuf fields are parsed by proto3, but the decoded payload cap
  // still applies before any state-port mutation.
  std::string oversized_unknown = req.SerializeAsString();
  oversized_unknown.append("\xA2\x06\xE8\x84\x01", 5); // field 100, length-delimited 17000
  oversized_unknown.append(17000, 'z');
  Check(bad_req.ParseFromString(oversized_unknown), "oversized unknown field parses as protobuf");
  Check(!ValidateBeforeState(bad_req, [](const auto& x) { return validation::ValidateCheckAdmissionRequest(x, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32)); }, admission_port) &&
        admission_port.calls == 1, "oversized decoded payload rejected before state port");

  AdmissionDecision unknown_decision;
  const std::string unknown_enum("\x08\x4d", 2); // outcome value 77
  Check(unknown_decision.ParseFromString(unknown_enum), "proto3 parser retains unknown enum value");
  Check(!validation::IsKnownDecisionOutcome(static_cast<std::uint32_t>(unknown_decision.outcome())),
        "unknown enum rejected by contract validator");
  AdmissionDecision unspecified_decision;
  Check(unspecified_decision.ParseFromString(std::string("\x08\x00", 2)),
        "UNSPECIFIED enum wire value parses");
  Check(!validation::IsKnownDecisionOutcome(static_cast<std::uint32_t>(unspecified_decision.outcome())),
        "UNSPECIFIED decision rejected by contract validator");

  AdmissionDecision allow;
  RoundTrip(root, "admission_allow_retry_123.hex", allow, "AdmissionDecision/retry");
  Check(allow.outcome() == DECISION_OUTCOME_ALLOW && allow.mode() == ADMISSION_MODE_STRICT &&
        allow.has_retry_delay_ns() && allow.retry_delay_ns() == 123,
        "decision fields and present retry value");
  AdmissionDecision absent;
  RoundTrip(root, "admission_allow_retry_absent.hex", absent, "AdmissionDecision/no-retry");
  Check(!absent.has_retry_delay_ns(), "absent optional retry preserved");
  AdmissionDecision zero;
  RoundTrip(root, "admission_allow_retry_zero_present.hex", zero, "AdmissionDecision/zero-retry");
  Check(zero.has_retry_delay_ns() && zero.retry_delay_ns() == 0,
        "present zero retry distinct from absent");

  AcquireCreditRequest credit;
  RoundTrip(root, "acquire_credit_request.hex", credit, "AcquireCreditRequest");
  Check(credit.slot() == 3 && credit.sequence() == 7 &&
        credit.trigger_cost_units() == 5 && credit.trigger_operation_id() == "publish",
        "credit request fixture values");
  FakeStatePort grant_port;
  const std::string registered_incarnation = Seq(0x40, 16);
  const std::array<validation::RegisteredReplicaSlot, 1> registered_slots{{{3, registered_incarnation}}};
  auto valid_credit = [&](const auto& x) {
    return validation::ValidateAcquireCreditRequest(x, registered_slots, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32), 5, 100);
  };
  Check(ValidateBeforeState(credit, valid_credit, grant_port), "valid credit request accepted");
  auto bad_credit = credit; bad_credit.set_slot(8);
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "unregistered slot rejected before state port");
  bad_credit = credit; bad_credit.set_slot(7);
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "slot cap does not imply slot registration");
  bad_credit = credit; bad_credit.set_incarnation_id(Seq(0x50,16));
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "stale incarnation rejected before state port");
  bad_credit = credit; bad_credit.set_sequence(0);
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "zero grant sequence rejected before state port");
  bad_credit = credit; bad_credit.set_trigger_cost_units(6);
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "trigger cost/policy mismatch rejected before state port");
  bad_credit = credit; bad_credit.set_trigger_operation_id("other");
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "operation mismatch rejected before state port");
  bad_credit = credit; bad_credit.set_policy_digest(Seq(0x20, 31));
  Check(!ValidateBeforeState(bad_credit, valid_credit, grant_port) && grant_port.calls == 1,
        "bad digest width rejected before state port");

  AcquireCreditResponse limited;
  RoundTrip(root, "grant_result_limited_zero_units_present.hex", limited,
            "AcquireCreditResponse/limited-zero");
  Check(limited.grant_outcome() == GRANT_OUTCOME_LIMITED &&
        limited.has_grant_units() && limited.grant_units() == 0 &&
        limited.sequence() == 7, "known LIMITED preserves zero grant-units presence");

  AcquireCreditResponse granted;
  RoundTrip(root, "grant_result_granted_composite.hex", granted,
            "AcquireCreditResponse/granted-composite");
  Check(granted.grant_outcome() == GRANT_OUTCOME_GRANTED &&
        granted.sequence() == 7 && granted.has_composite_grant_id() &&
        granted.has_grant_units() && granted.grant_units() == 25,
        "GRANTED response preserves grant amount and composite identity");
  const auto& grant_id = granted.composite_grant_id();
  Check(grant_id.epoch_id() == Seq(0x10,16) && grant_id.tenant_id() == "acct-1" &&
        grant_id.slot() == 3 && grant_id.incarnation_id() == Seq(0x40,16) &&
        grant_id.sequence() == 7 && granted.epoch_id() == grant_id.epoch_id(),
        "nested grant ID tuple round-trips exactly");


  AcquireCreditResponse unknown_grant;
  Check(unknown_grant.ParseFromString(std::string("\x08\x4d", 2)),
        "generated parser preserves unknown grant outcome");
  Check(!validation::IsKnownGrantOutcome(static_cast<std::uint32_t>(unknown_grant.grant_outcome())),
        "unknown grant outcome rejected");
  AcquireCreditResponse unspecified_grant;
  Check(unspecified_grant.ParseFromString(""), "default grant parses");
  Check(!validation::IsKnownGrantOutcome(static_cast<std::uint32_t>(unspecified_grant.grant_outcome())),
        "unspecified grant rejected");
  AdmissionDecision unknown_mode;
  Check(unknown_mode.ParseFromString(std::string("\x20\x4d", 2)),
        "generated parser preserves unknown admission mode");
  Check(!validation::IsKnownAdmissionMode(static_cast<std::uint32_t>(unknown_mode.mode())),
        "unknown admission mode rejected");
  AdmissionDecision unspecified_mode;
  Check(unspecified_mode.ParseFromString(""), "default decision parses");
  Check(!validation::IsKnownAdmissionMode(static_cast<std::uint32_t>(unspecified_mode.mode())),
        "unspecified admission mode rejected");

  const std::array<std::string, 3> malformed_requests{
      std::string("\x0a\x05x", 3),  // truncated length-delimited tenant
      std::string("\x00", 1),       // illegal field number zero
      std::string("\x08", 1) + std::string(10, static_cast<char>(0x80))};
  FakeStatePort malformed_port;
  for (const auto& wire : malformed_requests) {
    CheckAdmissionRequest malformed;
    const bool parsed = malformed.ParseFromString(wire);
    Check(!parsed, "generated parser rejects malformed wire");
    if (parsed) {
      (void)ValidateBeforeState(malformed, [](const auto& x) {
        return validation::ValidateCheckAdmissionRequest(
            x, "acct-1", "publish", Seq(0x10,16), Seq(0x20,32));
      }, malformed_port);
    }
  }
  Check(malformed_port.calls == 0, "malformed wire never reaches test state port");

  if (failures) return 1;
  std::cout << "generated protobuf/error contract checks passed\n";
  return 0;
}
