#include "rateguard/v1/error_contract.h"

#include <cstdlib>
#include <iostream>
using namespace rateguard::v1::contract;

int main() {
  if (CommitmentForTransportFailure(DispatchPhase::BeforeDispatch) != Commitment::NotCommitted)
    return EXIT_FAILURE;
  if (CommitmentForTransportFailure(DispatchPhase::Dispatched) != Commitment::Possible)
    return EXIT_FAILURE;
  if (RetryDispositionFor(RpcOperation::StrictAdmission, DispatchPhase::Dispatched) !=
          RetryDisposition::NewAttempt ||
      RetryDispositionFor(RpcOperation::AcquireCredit, DispatchPhase::Dispatched) !=
          RetryDisposition::SameGrantSequence)
    return EXIT_FAILURE;
  if (StructuredDecisionStatus(5) != GrpcStatus::Ok ||
      StructuredDecisionStatus(6) != GrpcStatus::Ok ||
      StructuredGrantStatus(4) != GrpcStatus::Ok ||
      StructuredGrantStatus(5) != GrpcStatus::Ok)
    return EXIT_FAILURE;
  if (StatusFor(ErrorCode::InvalidArgument) != GrpcStatus::InvalidArgument ||
      StatusFor(ErrorCode::Unauthenticated) != GrpcStatus::Unauthenticated ||
      StatusFor(ErrorCode::PermissionDenied) != GrpcStatus::PermissionDenied ||
      StatusFor(ErrorCode::PayloadTooLarge) != GrpcStatus::ResourceExhausted)
    return EXIT_FAILURE;
  if (IsAllowOutcome(DecisionOutcome::Limited) ||
      IsAllowOutcome(DecisionOutcome::Unavailable))
    return EXIT_FAILURE;
  std::cout << "transport error contract checks passed\n";
  return EXIT_SUCCESS;
}
