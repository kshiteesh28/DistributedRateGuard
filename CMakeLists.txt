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
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
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
