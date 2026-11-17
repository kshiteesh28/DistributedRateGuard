#include "proto/rateguard/v1/admission.grpc.pb.h"
#include "rateguard/v1/channel_policy.h"
#include <grpcpp/grpcpp.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>

namespace {
class UnavailableService final : public rateguard::v1::AdmissionService::Service {
 public:
  std::atomic<int> calls{0};
  grpc::Status CheckAdmission(grpc::ServerContext*,
      const rateguard::v1::CheckAdmissionRequest*,
      rateguard::v1::AdmissionDecision*) override {
    calls.fetch_add(1, std::memory_order_relaxed);
    // No initial metadata or response is sent: configured retries may retry.
    return {grpc::StatusCode::UNAVAILABLE, "synthetic retry fixture"};
  }
};
const char* kRetryConfig = R"json({
  "methodConfig":[{
    "name":[{"service":"rateguard.v1.AdmissionService","method":"CheckAdmission"}],
    "retryPolicy":{"maxAttempts":4,"initialBackoff":"0.01s",
      "maxBackoff":"0.01s","backoffMultiplier":1,
      "retryableStatusCodes":["UNAVAILABLE"]}
  }]
})json";
bool Invoke(const std::shared_ptr<grpc::Channel>& channel) {
  auto stub = rateguard::v1::AdmissionService::NewStub(channel);
  grpc::ClientContext context;
  context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
  rateguard::v1::CheckAdmissionRequest request;
  rateguard::v1::AdmissionDecision response;
  return stub->CheckAdmission(&context, request, &response).error_code()
      == grpc::StatusCode::UNAVAILABLE;
}
}  // namespace

int main() {
  UnavailableService service;
  grpc::ServerBuilder builder;
  int port = 0;
  // Synthetic loopback fixture only. Runtime mTLS belongs to RG-004.
  builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
  builder.RegisterService(&service);
  auto server = builder.BuildAndStart();
  if (!server || port == 0) return 1;
  const auto target = "127.0.0.1:" + std::to_string(port);
  int failures = 0;

  // Positive control: demonstrate that this fixture really causes four
  // application invocations when configurable retries are enabled.
  grpc::ChannelArguments retry_enabled;
  retry_enabled.SetInt(GRPC_ARG_ENABLE_RETRIES, 1);
  retry_enabled.SetServiceConfigJSON(kRetryConfig);
  auto enabled = grpc::CreateCustomChannel(
      target, grpc::InsecureChannelCredentials(), retry_enabled);
  if (!Invoke(enabled) || service.calls.load() != 4) {
    std::cerr << "retry-enabled control must invoke service four times\n";
    ++failures;
  }

  service.calls.store(0);
  // Even with a retry policy supplied, enforcement arguments prevent an
  // invisible replay after the server application has observed the request.
  auto enforcement = rateguard::v1::transport::EnforcementChannelArguments();
  enforcement.SetServiceConfigJSON(kRetryConfig);
  auto disabled = grpc::CreateCustomChannel(
      target, grpc::InsecureChannelCredentials(), enforcement);
  if (!Invoke(disabled) || service.calls.load() != 1) {
    std::cerr << "enforcement policy must invoke service exactly once\n";
    ++failures;
  }
  enabled.reset();
  disabled.reset();
  server->Shutdown();
  server->Wait();
  if (failures) return 1;
  std::cout << "retry behavior: enabled=4, enforcement=1\n";
  return 0;
}
