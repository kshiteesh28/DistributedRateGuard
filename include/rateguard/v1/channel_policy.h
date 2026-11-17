#pragma once

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/channel_arguments.h>

#include <memory>
#include <string>
#include <utility>

namespace rateguard::v1::transport {

// Enforcement RPCs are state-changing. All retries, including transparent
// retries, must be decided by application logic so that uncertain commitment
// is surfaced instead of replayed invisibly by the transport.
[[nodiscard]] inline grpc::ChannelArguments EnforcementChannelArguments() {
  grpc::ChannelArguments args;
  args.SetInt(GRPC_ARG_ENABLE_RETRIES, 0);
#if defined(GRPC_ARG_EXPERIMENTAL_ENABLE_HEDGING)
  args.SetInt(GRPC_ARG_EXPERIMENTAL_ENABLE_HEDGING, 0);
#endif
  return args;
}

// The enforcement channel factory ensures callers do not accidentally omit
// the no-retry policy when creating an authority/admission client channel.
[[nodiscard]] inline std::shared_ptr<grpc::Channel> CreateEnforcementChannel(
    const std::string& target,
    const std::shared_ptr<grpc::ChannelCredentials>& credentials) {
  if (target.empty() || !credentials) return {};
  return grpc::CreateCustomChannel(target, credentials,
                                   EnforcementChannelArguments());
}

}  // namespace rateguard::v1::transport
