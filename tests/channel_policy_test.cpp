#include "rateguard/v1/channel_policy.h"

#include <grpc/grpc.h>

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
bool HasIntegerArg(const grpc_channel_args& args, const char* key, int expected) {
  for (std::size_t i = 0; i < args.num_args; ++i) {
    const grpc_arg& arg = args.args[i];
    if (arg.key != nullptr && std::string_view(arg.key) == key) {
      return arg.type == GRPC_ARG_INTEGER && arg.value.integer == expected;
    }
  }
  return false;
}
}

int main() {
  const auto args = rateguard::v1::transport::EnforcementChannelArguments();
  const grpc_channel_args raw = args.c_channel_args();
  if (!HasIntegerArg(raw, GRPC_ARG_ENABLE_RETRIES, 0)) {
    std::cerr << "enforcement channel must disable retries\n";
    return EXIT_FAILURE;
  }
#if defined(GRPC_ARG_EXPERIMENTAL_ENABLE_HEDGING)
  if (!HasIntegerArg(raw, GRPC_ARG_EXPERIMENTAL_ENABLE_HEDGING, 0)) {
    std::cerr << "enforcement channel must explicitly disable hedging\n";
    return EXIT_FAILURE;
  }
#endif

  const std::shared_ptr<grpc::ChannelCredentials> no_credentials;
  if (rateguard::v1::transport::CreateEnforcementChannel("dns:///127.0.0.1:1", no_credentials) ||
      rateguard::v1::transport::CreateEnforcementChannel("", grpc::InsecureChannelCredentials())) {
    std::cerr << "enforcement channel factory must reject invalid arguments\n";
    return EXIT_FAILURE;
  }

  const auto channel = rateguard::v1::transport::CreateEnforcementChannel(
      "dns:///127.0.0.1:1", grpc::InsecureChannelCredentials());
  if (!channel) {
    std::cerr << "enforcement channel factory returned null\n";
    return EXIT_FAILURE;
  }
  std::cout << "enforcement channel retry/hedging policy checks passed\n";
  return EXIT_SUCCESS;
}
