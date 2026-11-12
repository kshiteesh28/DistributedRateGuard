cmake_minimum_required(VERSION 3.31.6)
project(DistributedRateGuard VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
include(FetchContent)
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RATEGUARD_FETCH_GRPC "Fetch the pinned gRPC source and its pinned submodules" ON)
option(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS "Fail unless product protos and contract tests are present" OFF)

if(RATEGUARD_FETCH_GRPC)
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
  FetchContent_Declare(
    grpc
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    GIT_TAG v1.85.0
    GIT_SHALLOW FALSE
    GIT_SUBMODULES_RECURSE TRUE
  )
  FetchContent_MakeAvailable(grpc)
  set(RG_GRPC_SOURCE_DIR "${grpc_SOURCE_DIR}")
else()
  find_package(Protobuf CONFIG REQUIRED)
  find_package(gRPC CONFIG REQUIRED)
  set(RG_GRPC_SOURCE_DIR "")
endif()

include(cmake/GenerateProto.cmake)

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
  elseif(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS)
    message(FATAL_ERROR "Product proto files exist but tests/contract_test.cpp is missing")
  endif()
elseif(RATEGUARD_REQUIRE_PRODUCT_CONTRACTS)
  message(FATAL_ERROR "Product proto files are required but none were found under proto/rateguard/v1")
endif()

if(BUILD_TESTING)
  add_custom_target(capture-build-manifest
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/capture_build_manifest.py"
      --source-root "${CMAKE_CURRENT_SOURCE_DIR}"
      --build-dir "${CMAKE_BINARY_DIR}"
      --grpc-source "${RG_GRPC_SOURCE_DIR}"
      --output "${CMAKE_BINARY_DIR}/build-manifest.json"
      --build-result not-yet-run
    BYPRODUCTS "${CMAKE_BINARY_DIR}/build-manifest.json"
    VERBATIM
    COMMENT "Capturing observed toolchain and source revisions (not a lock validation)"
  )
endif()
