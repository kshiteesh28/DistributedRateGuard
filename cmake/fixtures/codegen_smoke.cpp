#include "build_smoke.grpc.pb.h"

#include <string>
#include <type_traits>

int main() {
  static_assert(std::is_base_of_v<grpc::Service, rateguard::ci::BuildSmoke::Service>);

  rateguard::ci::EchoRequest request;
  request.set_request_id("rg001-codegen-smoke");

  std::string wire;
  if (!request.SerializeToString(&wire)) {
    return 1;
  }

  rateguard::ci::EchoRequest decoded;
  if (!decoded.ParseFromString(wire)) {
    return 2;
  }

  if (decoded.request_id() != "rg001-codegen-smoke") {
    return 3;
  }

  rateguard::ci::BuildSmoke::Service service;
  (void)service;
  return 0;
}
