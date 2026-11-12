# Build and contract verification

The supported contract-build path is GitHub Actions on the `ubuntu-24.04` runner label. It builds in C++20 mode, generates protobuf and gRPC C++ sources from the product schemas, runs the contract test executable, and uploads an observed toolchain/source manifest. The runner label is mutable; each manifest records `ImageOS`, `ImageVersion`, OS package versions, compiler, CMake, Ninja, `protoc`, and resolved dependency commits. No runner image digest is claimed.

## Target Linux build

Install CMake 3.31.6, Ninja 1.11.1, Python 3, a C++20 compiler, Git, OpenSSL development headers, and zlib development headers. Then run:

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DRATEGUARD_FETCH_GRPC=ON \
  -DRATEGUARD_REQUIRE_PRODUCT_CONTRACTS=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
python3 tools/capture_build_manifest.py \
  --source-root . --build-dir build \
  --grpc-source build/_deps/grpc-src \
  --output build/build-manifest.json --build-result passed
```

The gRPC source is fetched from the fixed `v1.85.0` release tag with recursive submodules; protobuf and its C++ runtime come from the commit-pinned protobuf submodule in that gRPC tree. This keeps `protoc` and `libprotobuf` from different upstream revisions from being mixed. Product `.proto` files under `proto/rateguard/v1` are generated under `build/generated/rateguard_proto` while preserving the repository-relative `proto/rateguard/v1/...` include path. The build fixture under `cmake/fixtures` independently proves that both protobuf and gRPC code generation compile.

`build-lock.json` is a candidate, not a validated lock. The CI artifact is the first source of actual resolved commit IDs and host versions. Promote any lock only after a passing target-Linux build, review the observed versions and commit IDs, and update the lock to immutable SHAs where upstream tags resolve to commits. Do not treat a missing manifest field or an unrun local build as success.

## Targets

- `rateguard_codegen_smoke_test`: generated protobuf serialization and generated gRPC service compile smoke test.
- `rateguard_proto`: generated product messages and services.
- `rateguard_contract_tests`: junior-owned API/error/wire golden tests, registered as `rateguard.contracts` by CTest.
- `capture-build-manifest`: captures current environment and fetched-source revisions; it does not validate the lock itself.
