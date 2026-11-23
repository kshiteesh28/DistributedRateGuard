cmake_minimum_required(VERSION 3.31.6)
project(DistributedRateGuard VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
include(FetchContent)
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RATEGUARD_FETCH_GRPC "Fetch the pinned gRPC source and its pinned submodules" OFF)
option(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS "Fail unless product protos and contract tests are present" OFF)

if(RATEGUARD_FETCH_GRPC)
  # This build consumes source-tree targets and does not install dependencies.
  set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
  set(utf8_range_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(gRPC_INSTALL OFF CACHE BOOL "" FORCE)
  set(gRPC_BUILD_CODEGEN ON CACHE BOOL "" FORCE)
  set(gRPC_BUILD_GRPC_CPP_PLUGIN ON CACHE BOOL "" FORCE)
  set(gRPC_ABSL_PROVIDER module CACHE STRING "" FORCE)
  set(gRPC_CARES_PROVIDER module CACHE STRING "" FORCE)
  set(gRPC_PROTOBUF_PROVIDER module CACHE STRING "" FORCE)
  set(gRPC_RE2_PROVIDER module CACHE STRING "" FORCE)
  set(gRPC_SSL_PROVIDER package CACHE STRING "" FORCE)
  set(gRPC_ZLIB_PROVIDER package CACHE STRING "" FORCE)
  set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(protobuf_BUILD_PROTOC_BINARIES ON CACHE BOOL "" FORCE)
  FetchContent_Declare(
    grpc
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    GIT_TAG v1.85.0
    GIT_SHALLOW FALSE
    GIT_SUBMODULES_RECURSE TRUE
  )
  FetchContent_MakeAvailable(grpc)
  if(TARGET grpc++ AND NOT TARGET gRPC::grpc++)
    add_library(gRPC::grpc++ ALIAS grpc++)
  endif()
  set(RG_GRPC_SOURCE_DIR "${grpc_SOURCE_DIR}")
else()
  find_package(Protobuf REQUIRED MODULE)
  find_package(gRPC CONFIG REQUIRED)
  set(RG_GRPC_SOURCE_DIR "")
endif()

# Package exports use a namespace; the generation helper uses one stable name.
if(NOT TARGET grpc_cpp_plugin)
  if(TARGET gRPC::grpc_cpp_plugin)
    add_executable(grpc_cpp_plugin ALIAS gRPC::grpc_cpp_plugin)
  else()
    find_program(RATEGUARD_GRPC_CPP_PLUGIN NAMES grpc_cpp_plugin REQUIRED)
    add_executable(grpc_cpp_plugin IMPORTED GLOBAL)
    set_property(TARGET grpc_cpp_plugin PROPERTY IMPORTED_LOCATION "${RATEGUARD_GRPC_CPP_PLUGIN}")
  endif()
endif()

include(cmake/GenerateProto.cmake)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/codegen-tools.json"
  CONTENT "{\"protoc\":\"$<TARGET_FILE:protobuf::protoc>\",\"grpc_cpp_plugin\":\"$<TARGET_FILE:grpc_cpp_plugin>\"}\n")

# Always compile one isolated code-generation fixture so this infrastructure PR
# remains verifiable before the junior-owned product schemas arrive.
rateguard_generate_proto_library(
  rateguard_codegen_smoke
  PROTO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/cmake/fixtures"
  PROTO_FILES "${CMAKE_CURRENT_SOURCE_DIR}/cmake/fixtures/build_smoke.proto"
)
add_executable(rateguard_codegen_smoke_test cmake/fixtures/codegen_smoke.cpp)
target_link_libraries(rateguard_codegen_smoke_test PRIVATE rateguard_codegen_smoke)
add_test(NAME rateguard.codegen_smoke COMMAND rateguard_codegen_smoke_test)

file(GLOB_RECURSE RATEGUARD_PRODUCT_PROTO_FILES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/proto/rateguard/v1/*.proto")
if(RATEGUARD_PRODUCT_PROTO_FILES)
  rateguard_generate_proto_library(
    rateguard_proto
    PROTO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}"
    PROTO_FILES ${RATEGUARD_PRODUCT_PROTO_FILES}
  )
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/contract_test.cpp")
    add_executable(rateguard_contract_tests tests/contract_test.cpp)
    target_include_directories(rateguard_contract_tests PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_link_libraries(rateguard_contract_tests PRIVATE rateguard_proto)
    add_test(NAME rateguard.contracts
      COMMAND rateguard_contract_tests "${CMAKE_CURRENT_SOURCE_DIR}")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/contracts/transport_error_test.cpp")
      add_executable(rateguard_transport_error_tests
        tests/contracts/transport_error_test.cpp)
      target_include_directories(rateguard_transport_error_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include")
      add_test(NAME rateguard.transport_errors
        COMMAND rateguard_transport_error_tests)
    elseif(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS)
      message(FATAL_ERROR "tests/contracts/transport_error_test.cpp is required")
    endif()
  elseif(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS)
    message(FATAL_ERROR "Product proto files exist but tests/contract_test.cpp is missing")
  endif()
  add_executable(rateguard_channel_policy_tests tests/channel_policy_test.cpp)
  target_include_directories(rateguard_channel_policy_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_link_libraries(rateguard_channel_policy_tests PRIVATE gRPC::grpc++)
  add_test(NAME rateguard.channel_policy COMMAND rateguard_channel_policy_tests)
  add_executable(rateguard_retry_behavior_tests tests/retry_behavior_test.cpp)
  target_include_directories(rateguard_retry_behavior_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_link_libraries(rateguard_retry_behavior_tests PRIVATE rateguard_proto)
  add_test(NAME rateguard.retry_behavior COMMAND rateguard_retry_behavior_tests)
  set_tests_properties(rateguard.retry_behavior PROPERTIES TIMEOUT 20)
elseif(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS)
  message(FATAL_ERROR "Product proto files are required but none were found under proto/rateguard/v1")
endif()

if(BUILD_TESTING)
  add_custom_target(capture-build-manifest
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/capture_build_manifest.py"
      --source-root "${CMAKE_CURRENT_SOURCE_DIR}"
      --build-dir "${CMAKE_BINARY_DIR}"
      --grpc-source "${RG_GRPC_SOURCE_DIR}"
      --protoc "$<TARGET_FILE:protobuf::protoc>"
      --grpc-plugin "$<TARGET_FILE:grpc_cpp_plugin>"
      --output "${CMAKE_BINARY_DIR}/build-manifest.json"
      --build-result not-yet-run
    BYPRODUCTS "${CMAKE_BINARY_DIR}/build-manifest.json"
    VERBATIM
    COMMENT "Capturing observed toolchain and source revisions (not a lock validation)"
  )
endif()

# RG-002 pure arithmetic: no clock/RPC/state ownership in this component.
add_executable(rateguard_bucket_math_tests tests/bucket_math_test.cpp)
target_include_directories(rateguard_bucket_math_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_test(NAME rateguard.bucket_math COMMAND rateguard_bucket_math_tests)
add_test(NAME rateguard.bucket_math_oracle
  COMMAND "${CMAKE_COMMAND}" -E env "CXX=${CMAKE_CXX_COMPILER}"
    "RATEGUARD_REPO_ROOT=${CMAKE_CURRENT_SOURCE_DIR}"
    "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/bucket_math_oracle.py")
set_tests_properties(rateguard.bucket_math_oracle PROPERTIES TIMEOUT 60)

# RG-002 immutable policy, canonical identity, and independent serialization oracle.
find_package(nlohmann_json 3.11.3 EXACT CONFIG REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
add_library(rateguard_policy
  src/policy/policy_loader.cpp
  src/policy/canonical_codec.cpp)
target_include_directories(rateguard_policy PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(rateguard_policy PUBLIC nlohmann_json::nlohmann_json OpenSSL::Crypto)
target_compile_options(rateguard_policy PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(rateguard_policy_tests tests/policy_test.cpp)
target_link_libraries(rateguard_policy_tests PRIVATE rateguard_policy)
add_test(NAME rateguard.policy
  COMMAND rateguard_policy_tests "${CMAKE_CURRENT_SOURCE_DIR}")
add_executable(policy_driver tests/policy_driver.cpp)
target_link_libraries(policy_driver PRIVATE rateguard_policy)
add_test(NAME rateguard.policy_oracle
  COMMAND "${CMAKE_COMMAND}" -E env
    "RATEGUARD_POLICY_DRIVER=$<TARGET_FILE:policy_driver>"
    "RATEGUARD_REPO_ROOT=${CMAKE_CURRENT_SOURCE_DIR}"
    "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/policy_loader_integration.py")
set_tests_properties(rateguard.policy rateguard.policy_oracle PROPERTIES TIMEOUT 60)

option(RATEGUARD_SANITIZE_CLOCK "Instrument clock library/tests with address and undefined-behavior sanitizers" OFF)

# RG-003 verified Linux clock provenance and serialized sticky-fail sampling.
find_package(Threads REQUIRED)
add_library(rateguard_clock src/platform/clock_linux.cpp)
target_include_directories(rateguard_clock PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_clock PUBLIC Threads::Threads)
target_compile_options(rateguard_clock PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_CLOCK)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "Clock sanitizer checks require a supported GCC/Clang compiler")
  endif()
  target_compile_options(rateguard_clock PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rateguard_clock INTERFACE -fsanitize=address,undefined)
endif()
add_executable(rateguard_clock_tests tests/clock_test.cpp)
target_link_libraries(rateguard_clock_tests PRIVATE rateguard_clock)
add_test(NAME rateguard.clock COMMAND rateguard_clock_tests)
add_executable(rateguard_clock_independent_tests tools/tests/clock_independent_test.cpp)
target_link_libraries(rateguard_clock_independent_tests PRIVATE rateguard_clock)
add_test(NAME rateguard.clock_independent COMMAND rateguard_clock_independent_tests)
add_test(NAME rateguard.clock_clamp_mutation
  COMMAND "${CMAKE_COMMAND}" -E env "CXX=${CMAKE_CXX_COMPILER}"
    "RG003_SOURCE_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/src"
    "RG003_INCLUDE_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/clock_mutation_test.py")
set_tests_properties(rateguard.clock_clamp_mutation PROPERTIES TIMEOUT 120)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(rateguard_clock_linux_smoke tests/clock_linux_smoke_test.cpp)
  target_link_libraries(rateguard_clock_linux_smoke PRIVATE rateguard_clock)
  add_test(NAME rateguard.clock_linux COMMAND rateguard_clock_linux_smoke)
  # Unsupported provenance on the supported Linux lane must FAIL, never skip.
  set_tests_properties(rateguard.clock_linux PROPERTIES TIMEOUT 20)
endif()

# RG-004 compatibility inputs; these are not quota-service integration.
option(RATEGUARD_SANITIZE_SECURITY "Instrument security components/tests with ASan and UBSan" OFF)
add_library(rateguard_security src/security/tls_certificate_verifier.cpp)
target_include_directories(rateguard_security PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_security PUBLIC gRPC::grpc++ OpenSSL::Crypto)
target_compile_options(rateguard_security PRIVATE -Wall -Wextra -Werror -pedantic)
add_library(rateguard_trusted_wall_clock src/security/trusted_wall_clock.cpp)
target_include_directories(rateguard_trusted_wall_clock PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_trusted_wall_clock PUBLIC Threads::Threads)
target_compile_options(rateguard_trusted_wall_clock PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_SECURITY)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "Security sanitizer checks require GCC or Clang")
  endif()
  foreach(rg_security_target IN ITEMS rateguard_security rateguard_trusted_wall_clock)
    target_compile_options(${rg_security_target} PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${rg_security_target} INTERFACE -fsanitize=address,undefined)
  endforeach()
endif()
add_executable(rateguard_tls_compatibility_tests
  tests/security/ephemeral_pki.cpp tests/security/mtls_probe_test.cpp)
target_include_directories(rateguard_tls_compatibility_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_tls_compatibility_tests PRIVATE
  rateguard_security rateguard_proto OpenSSL::Crypto Threads::Threads)
add_test(NAME rateguard.mtls_compatibility
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/mtls_probe_output_test.py"
    "$<TARGET_FILE:rateguard_tls_compatibility_tests>")
set_tests_properties(rateguard.mtls_compatibility PROPERTIES TIMEOUT 110)
add_executable(rateguard_trusted_wall_clock_tests tests/security/trusted_wall_clock_test.cpp)
target_link_libraries(rateguard_trusted_wall_clock_tests PRIVATE rateguard_trusted_wall_clock)
add_test(NAME rateguard.trusted_wall_clock COMMAND rateguard_trusted_wall_clock_tests)
add_executable(rateguard_trusted_wall_clock_independent_tests tools/tests/trusted_wall_clock_independent_test.cpp)
target_link_libraries(rateguard_trusted_wall_clock_independent_tests PRIVATE rateguard_trusted_wall_clock)
add_test(NAME rateguard.trusted_wall_clock_independent COMMAND rateguard_trusted_wall_clock_independent_tests)
add_executable(trusted_wall_clock_probe tools/probes/trusted_wall_clock_probe.cpp)
target_link_libraries(trusted_wall_clock_probe PRIVATE rateguard_trusted_wall_clock)

# Test-only verifier bypass: never linked into the real security library.
set(RG004_MUTANT_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/test-mutants/tls_certificate_verifier_bypass.cpp")
add_custom_command(OUTPUT "${RG004_MUTANT_SOURCE}"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/generate_mtls_verifier_bypass_mutant.py"
    --source "${CMAKE_CURRENT_SOURCE_DIR}/src/security/tls_certificate_verifier.cpp"
    --output "${RG004_MUTANT_SOURCE}"
  DEPENDS src/security/tls_certificate_verifier.cpp tools/tests/generate_mtls_verifier_bypass_mutant.py
  VERBATIM)
add_library(rateguard_security_verifier_mutant STATIC "${RG004_MUTANT_SOURCE}")
target_include_directories(rateguard_security_verifier_mutant PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_security_verifier_mutant PUBLIC gRPC::grpc++ OpenSSL::Crypto)
target_compile_options(rateguard_security_verifier_mutant PRIVATE -Wall -Wextra -Werror -pedantic -Wno-unused-function)
add_executable(rateguard_tls_bypass_mutant tests/security/ephemeral_pki.cpp tests/security/mtls_probe_test.cpp)
target_include_directories(rateguard_tls_bypass_mutant PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_tls_bypass_mutant PRIVATE
  rateguard_security_verifier_mutant rateguard_proto OpenSSL::Crypto Threads::Threads)
add_test(NAME rateguard.mtls_verifier_bypass
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/mtls_verifier_bypass_mutation_test.py"
    "$<TARGET_FILE:rateguard_tls_bypass_mutant>")
set_tests_properties(rateguard.mtls_verifier_bypass PROPERTIES TIMEOUT 110)

# RG-004-B1 typed certificate input; no manifest or request authorization.
add_library(rateguard_certificate_registry src/security/certificate_registry.cpp)
target_include_directories(rateguard_certificate_registry PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_certificate_registry PUBLIC
  rateguard_security rateguard_trusted_wall_clock rateguard_policy OpenSSL::Crypto)
target_compile_options(rateguard_certificate_registry PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_SECURITY)
  target_compile_options(rateguard_certificate_registry PUBLIC
    -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rateguard_certificate_registry INTERFACE -fsanitize=address,undefined)
endif()
add_executable(rateguard_certificate_registry_tests
  tests/security/certificate_registry_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_certificate_registry_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_certificate_registry_tests PRIVATE rateguard_certificate_registry)
target_compile_options(rateguard_certificate_registry_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.certificate_registry COMMAND rateguard_certificate_registry_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
add_executable(rateguard_certificate_registry_profile_tests
  tests/security/certificate_registry_profile_test.cpp)
target_link_libraries(rateguard_certificate_registry_profile_tests PRIVATE rateguard_certificate_registry)
target_compile_options(rateguard_certificate_registry_profile_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.certificate_registry_profile COMMAND rateguard_certificate_registry_profile_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
add_executable(rateguard_certificate_registry_independent_tests
  tools/tests/certificate_registry_independent_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_certificate_registry_independent_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_certificate_registry_independent_tests PRIVATE rateguard_certificate_registry)
target_compile_options(rateguard_certificate_registry_independent_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.certificate_registry_independent COMMAND rateguard_certificate_registry_independent_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.certificate_registry rateguard.certificate_registry_profile
  rateguard.certificate_registry_independent PROPERTIES TIMEOUT 120)

# This separate target deliberately violates one invariant for QA only.
set(RG004_ROOT_PIN_MUTANT "${CMAKE_CURRENT_BINARY_DIR}/test-mutants/certificate_registry_root_pin.cpp")
add_custom_command(OUTPUT "${RG004_ROOT_PIN_MUTANT}"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/generate_wrong_root_pin_mutant.py"
    --source "${CMAKE_CURRENT_SOURCE_DIR}/src/security/certificate_registry.cpp"
    --output "${RG004_ROOT_PIN_MUTANT}"
  DEPENDS src/security/certificate_registry.cpp tools/tests/generate_wrong_root_pin_mutant.py
  VERBATIM)
add_library(rateguard_certificate_registry_mutant STATIC "${RG004_ROOT_PIN_MUTANT}")
target_include_directories(rateguard_certificate_registry_mutant PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_certificate_registry_mutant PUBLIC
  rateguard_security rateguard_trusted_wall_clock rateguard_policy OpenSSL::Crypto)
target_compile_options(rateguard_certificate_registry_mutant PRIVATE -Wall -Wextra -Werror -pedantic)
add_executable(rateguard_certificate_registry_root_pin_mutant
  tools/tests/certificate_registry_independent_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_certificate_registry_root_pin_mutant PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_certificate_registry_root_pin_mutant PRIVATE rateguard_certificate_registry_mutant)
add_test(NAME rateguard.certificate_registry_root_pin_mutation
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/root_pin_mutation_test.py"
    --normal "$<TARGET_FILE:rateguard_certificate_registry_independent_tests>"
    --mutant "$<TARGET_FILE:rateguard_certificate_registry_root_pin_mutant>"
    --fixture "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.certificate_registry_root_pin_mutation PROPERTIES TIMEOUT 250)

# RG-004-B2 identity/permission inputs; no quota-state implementation.
add_library(rateguard_peer_authenticator src/security/peer_authenticator.cpp)
target_include_directories(rateguard_peer_authenticator PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_peer_authenticator PUBLIC rateguard_certificate_registry gRPC::grpc++)
target_compile_options(rateguard_peer_authenticator PRIVATE -Wall -Wextra -Werror -pedantic)
add_library(rateguard_authorization src/security/authorization_resolver.cpp)
target_include_directories(rateguard_authorization PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_authorization PUBLIC rateguard_peer_authenticator rateguard_proto)
target_compile_options(rateguard_authorization PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_SECURITY)
  foreach(rg_auth_target IN ITEMS rateguard_peer_authenticator rateguard_authorization)
    target_compile_options(${rg_auth_target} PUBLIC
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${rg_auth_target} INTERFACE -fsanitize=address,undefined)
  endforeach()
endif()
add_executable(rateguard_peer_authenticator_tests
  tests/security/peer_authenticator_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_peer_authenticator_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_peer_authenticator_tests PRIVATE rateguard_peer_authenticator)
target_compile_options(rateguard_peer_authenticator_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.peer_authenticator COMMAND rateguard_peer_authenticator_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
add_executable(rateguard_authorization_tests
  tests/security/authorization_resolver_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_authorization_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_authorization_tests PRIVATE rateguard_authorization)
target_compile_options(rateguard_authorization_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.authorization COMMAND rateguard_authorization_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.peer_authenticator rateguard.authorization PROPERTIES TIMEOUT 90)

# Independent real TLS fixture and isolated test-only unsafe variants.
add_executable(rateguard_peer_authorization_rpc_tests
  tools/tests/peer_authorization_rpc_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_peer_authorization_rpc_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_peer_authorization_rpc_tests PRIVATE rateguard_authorization)
target_compile_options(rateguard_peer_authorization_rpc_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.peer_authorization_rpc
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/b2_mutation_test.py"
    --normal-rpc "$<TARGET_FILE:rateguard_peer_authorization_rpc_tests>"
    --fixture "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.peer_authorization_rpc PROPERTIES TIMEOUT 140)

set(RG_B2_MUTANT_DIR "${CMAKE_CURRENT_BINARY_DIR}/test-mutants/b2")
set(RG_B2_PAIR_MUTANT "${RG_B2_MUTANT_DIR}/authorization_resolver_pair_mutant.cpp")
set(RG_B2_PIN_MUTANT "${RG_B2_MUTANT_DIR}/peer_authenticator_pin_mutant.cpp")
add_custom_command(OUTPUT "${RG_B2_PAIR_MUTANT}" "${RG_B2_PIN_MUTANT}"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/generate_b2_mutants.py"
    --resolver-src "${CMAKE_CURRENT_SOURCE_DIR}/src/security/authorization_resolver.cpp"
    --auth-src "${CMAKE_CURRENT_SOURCE_DIR}/src/security/peer_authenticator.cpp"
    --out-dir "${RG_B2_MUTANT_DIR}"
  DEPENDS src/security/authorization_resolver.cpp src/security/peer_authenticator.cpp
    tools/tests/generate_b2_mutants.py
  VERBATIM)
add_library(rateguard_authorization_pair_mutant STATIC "${RG_B2_PAIR_MUTANT}")
target_include_directories(rateguard_authorization_pair_mutant PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_authorization_pair_mutant PUBLIC
  rateguard_peer_authenticator rateguard_proto)
target_compile_options(rateguard_authorization_pair_mutant PRIVATE -Wall -Wextra -Werror -pedantic)
add_executable(rateguard_peer_authorization_pair_mutant
  tools/tests/peer_authorization_rpc_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_peer_authorization_pair_mutant PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_peer_authorization_pair_mutant PRIVATE rateguard_authorization_pair_mutant)
add_library(rateguard_peer_auth_pin_mutant STATIC "${RG_B2_PIN_MUTANT}")
target_include_directories(rateguard_peer_auth_pin_mutant PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_peer_auth_pin_mutant PUBLIC rateguard_certificate_registry gRPC::grpc++)
target_compile_options(rateguard_peer_auth_pin_mutant PRIVATE -Wall -Wextra -Werror -pedantic)
add_executable(rateguard_peer_authenticator_pin_mutant
  tests/security/peer_authenticator_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_peer_authenticator_pin_mutant PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_peer_authenticator_pin_mutant PRIVATE rateguard_peer_auth_pin_mutant)
add_test(NAME rateguard.peer_authorization_mutation
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/b2_mutation_test.py"
    --normal-rpc "$<TARGET_FILE:rateguard_peer_authorization_rpc_tests>"
    --pair-mutant-rpc "$<TARGET_FILE:rateguard_peer_authorization_pair_mutant>"
    --normal-auth "$<TARGET_FILE:rateguard_peer_authenticator_tests>"
    --pin-mutant-auth "$<TARGET_FILE:rateguard_peer_authenticator_pin_mutant>"
    --fixture "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.peer_authorization_mutation PROPERTIES TIMEOUT 500)

# RG-004-B3 client trust inputs, not quota/forwarding implementations.
add_library(rateguard_client_call_guard src/security/client_call_guard.cpp)
target_include_directories(rateguard_client_call_guard PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_client_call_guard PUBLIC rateguard_certificate_registry)
target_compile_options(rateguard_client_call_guard PRIVATE -Wall -Wextra -Werror -pedantic)
add_library(rateguard_pinned_peer_rpc_client src/security/pinned_peer_rpc_client.cpp)
target_include_directories(rateguard_pinned_peer_rpc_client PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_pinned_peer_rpc_client PUBLIC
  rateguard_client_call_guard rateguard_proto gRPC::grpc++ OpenSSL::Crypto)
target_compile_options(rateguard_pinned_peer_rpc_client PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_SECURITY)
  foreach(rg_b3_target IN ITEMS rateguard_client_call_guard rateguard_pinned_peer_rpc_client)
    target_compile_options(${rg_b3_target} PUBLIC
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${rg_b3_target} INTERFACE -fsanitize=address,undefined)
  endforeach()
endif()
add_executable(rateguard_client_call_guard_tests
  tests/security/client_call_guard_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_client_call_guard_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_client_call_guard_tests PRIVATE rateguard_client_call_guard)
target_compile_options(rateguard_client_call_guard_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.client_call_guard COMMAND rateguard_client_call_guard_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
add_executable(rateguard_pinned_client_contract_tests
  tests/security/pinned_peer_rpc_client_contract_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_pinned_client_contract_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_pinned_client_contract_tests PRIVATE rateguard_pinned_peer_rpc_client)
target_compile_options(rateguard_pinned_client_contract_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.pinned_client_contract COMMAND rateguard_pinned_client_contract_tests
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.client_call_guard rateguard.pinned_client_contract PROPERTIES TIMEOUT 90)

# Independent sealed-client TLS checks and isolated preflight defect.
add_executable(rateguard_pinned_client_rpc_tests
  tools/tests/pinned_peer_rpc_client_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_pinned_client_rpc_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_pinned_client_rpc_tests PRIVATE rateguard_pinned_peer_rpc_client)
target_compile_options(rateguard_pinned_client_rpc_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.pinned_client_rpc
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/pinned_client_test_runner.py"
    --binary "$<TARGET_FILE:rateguard_pinned_client_rpc_tests>"
    --fixture "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.pinned_client_rpc PROPERTIES TIMEOUT 140)
set(RG_B3_MUTANT "${CMAKE_CURRENT_BINARY_DIR}/test-mutants/client_preflight_bypass.cpp")
add_custom_command(OUTPUT "${RG_B3_MUTANT}"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/generate_client_preflight_mutant.py"
    --source "${CMAKE_CURRENT_SOURCE_DIR}/src/security/client_call_guard.cpp"
    --output "${RG_B3_MUTANT}"
  DEPENDS src/security/client_call_guard.cpp tools/tests/generate_client_preflight_mutant.py
  VERBATIM)
add_library(rateguard_pinned_client_preflight_mutant STATIC
  "${RG_B3_MUTANT}" src/security/pinned_peer_rpc_client.cpp)
target_include_directories(rateguard_pinned_client_preflight_mutant PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(rateguard_pinned_client_preflight_mutant PUBLIC
  rateguard_certificate_registry rateguard_proto gRPC::grpc++ OpenSSL::Crypto)
target_compile_options(rateguard_pinned_client_preflight_mutant PRIVATE -Wall -Wextra -Werror -pedantic)
add_executable(rateguard_pinned_client_preflight_mutant_tests
  tools/tests/pinned_peer_rpc_client_test.cpp tests/security/ephemeral_pki.cpp)
target_include_directories(rateguard_pinned_client_preflight_mutant_tests PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/security")
target_link_libraries(rateguard_pinned_client_preflight_mutant_tests PRIVATE
  rateguard_pinned_client_preflight_mutant)
add_test(NAME rateguard.pinned_client_preflight_mutation
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/pinned_client_test_runner.py"
    --binary "$<TARGET_FILE:rateguard_pinned_client_rpc_tests>"
    --mutant "$<TARGET_FILE:rateguard_pinned_client_preflight_mutant_tests>"
    --fixture "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/policy_v1.json")
set_tests_properties(rateguard.pinned_client_preflight_mutation PROPERTIES TIMEOUT 270)

# RG-006 per-epoch local lifecycle logic. Real process/manifest integration is pending.
option(RATEGUARD_SANITIZE_SUPERVISOR "Instrument lifecycle tests with ASan and UBSan" OFF)
add_library(rateguard_epoch_gate INTERFACE)
target_include_directories(rateguard_epoch_gate INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_epoch_gate INTERFACE Threads::Threads)
if(RATEGUARD_SANITIZE_SUPERVISOR)
  target_compile_options(rateguard_epoch_gate INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rateguard_epoch_gate INTERFACE -fsanitize=address,undefined)
endif()
add_executable(rateguard_epoch_gate_tests tests/supervisor/epoch_gate_test.cpp)
target_link_libraries(rateguard_epoch_gate_tests PRIVATE rateguard_epoch_gate)
target_compile_options(rateguard_epoch_gate_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.epoch_gate COMMAND rateguard_epoch_gate_tests)
set_tests_properties(rateguard.epoch_gate PROPERTIES TIMEOUT 30)

add_executable(rateguard_epoch_gate_independent_tests tests/supervisor/epoch_gate_independent_test.cpp)
target_link_libraries(rateguard_epoch_gate_independent_tests PRIVATE rateguard_epoch_gate)
target_compile_options(rateguard_epoch_gate_independent_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.epoch_gate_independent COMMAND rateguard_epoch_gate_independent_tests)
set_tests_properties(rateguard.epoch_gate_independent PROPERTIES TIMEOUT 30)

# RG-006 bounded canonical persistence codec.
option(RATEGUARD_SANITIZE_MANIFEST "Instrument manifest components with ASan and UBSan" OFF)
add_library(rateguard_manifest_codec src/supervisor/manifest_codec.cpp)
target_include_directories(rateguard_manifest_codec PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_manifest_codec PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto)
target_link_libraries(rateguard_manifest_codec PUBLIC Threads::Threads)
target_compile_options(rateguard_manifest_codec PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_MANIFEST)
  target_compile_options(rateguard_manifest_codec PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rateguard_manifest_codec PUBLIC -fsanitize=address,undefined)
endif()

add_library(rateguard_manifest_store src/supervisor/manifest_store.cpp)
target_link_libraries(rateguard_manifest_store PUBLIC rateguard_manifest_codec)
target_compile_options(rateguard_manifest_store PRIVATE -Wall -Wextra -Werror -pedantic)

add_executable(rateguard_manifest_codec_tests tests/supervisor/manifest_codec_test.cpp)
target_link_libraries(rateguard_manifest_codec_tests PRIVATE rateguard_manifest_codec)
target_compile_options(rateguard_manifest_codec_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.manifest_codec COMMAND rateguard_manifest_codec_tests)
set_tests_properties(rateguard.manifest_codec PROPERTIES TIMEOUT 60)

add_executable(rateguard_manifest_store_tests tests/supervisor/manifest_store_test.cpp)
target_link_libraries(rateguard_manifest_store_tests PRIVATE rateguard_manifest_store)
target_compile_options(rateguard_manifest_store_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.manifest_store COMMAND rateguard_manifest_store_tests)
add_executable(rateguard_manifest_store_independent_tests tests/supervisor/manifest_store_independent_test.cpp)
target_link_libraries(rateguard_manifest_store_independent_tests PRIVATE rateguard_manifest_store)
target_compile_options(rateguard_manifest_store_independent_tests PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME rateguard.manifest_store_independent COMMAND rateguard_manifest_store_independent_tests)
set_tests_properties(rateguard.manifest_store rateguard.manifest_store_independent PROPERTIES TIMEOUT 90)

# RG-006 supervisor ownership across epoch directories under the configured root.
option(RATEGUARD_SANITIZE_RUNTIME "Instrument runtime ownership with ASan and UBSan" OFF)
add_library(rateguard_runtime_owner src/supervisor/runtime_owner.cpp)
target_include_directories(rateguard_runtime_owner PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(rateguard_runtime_owner PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto)
target_link_libraries(rateguard_runtime_owner PUBLIC Threads::Threads)
target_compile_options(rateguard_runtime_owner PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_RUNTIME)
  target_compile_options(rateguard_runtime_owner PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rateguard_runtime_owner PUBLIC -fsanitize=address,undefined)
endif()

# RG-005 component checks. Use std::thread for the last-slot contention case.
option(RATEGUARD_SANITIZE_HISTORY "Instrument history component tests with ASan and UBSan" OFF)
function(add_history_test target source name)
  add_executable(${target} ${source})
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(${target} PRIVATE Threads::Threads)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -pedantic)
  if(RATEGUARD_SANITIZE_HISTORY)
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
  add_test(NAME rateguard.${name} COMMAND ${target})
endfunction()
add_history_test(rateguard_event_recorder_tests tests/event_recorder_test.cpp event_recorder)
add_history_test(rateguard_history_export_tests tests/history_export_test.cpp history_export)
add_history_test(rateguard_history_validator_tests tests/history_validator_test.cpp history_validator)
add_history_test(rateguard_history_reader_tests tests/history_reader_test.cpp history_reader)
add_history_test(rateguard_aggregate_metrics_tests tests/aggregate_metrics_test.cpp aggregate_metrics)
add_history_test(rateguard_history_file_publisher_tests tests/history_file_publisher_test.cpp history_file_publisher)
add_history_test(rateguard_strict_reconciliation_tests tests/strict_reconciliation_test.cpp strict_reconciliation)

# RG-005 offline structural inspection with an independently supplied plan.
add_executable(rateguard_history_inspect tools/history/inspect_main.cpp)
target_include_directories(rateguard_history_inspect PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(rateguard_history_inspect PRIVATE nlohmann_json::nlohmann_json)
target_compile_options(rateguard_history_inspect PRIVATE -Wall -Wextra -Werror -pedantic)
if(RATEGUARD_SANITIZE_HISTORY)
  target_compile_options(rateguard_history_inspect PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rateguard_history_inspect PRIVATE -fsanitize=address,undefined)
endif()

add_test(NAME rateguard.history_inspector
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/tests/history_inspector_integration.py"
    "$<TARGET_FILE:rateguard_history_inspect>")
set_tests_properties(rateguard.history_inspector PROPERTIES TIMEOUT 60)
