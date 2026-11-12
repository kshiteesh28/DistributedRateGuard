include(CMakeParseArguments)

function(rateguard_generate_proto_library target)
  cmake_parse_arguments(RG "" "PROTO_ROOT" "PROTO_FILES" ${ARGN})
  if(NOT RG_PROTO_ROOT OR NOT RG_PROTO_FILES)
    message(FATAL_ERROR "${target}: PROTO_ROOT and at least one PROTO_FILES entry are required")
  endif()

  set(generated_sources)
  foreach(proto IN LISTS RG_PROTO_FILES)
    file(RELATIVE_PATH relative_proto "${RG_PROTO_ROOT}" "${proto}")
    get_filename_component(relative_dir "${relative_proto}" DIRECTORY)
    get_filename_component(proto_stem "${relative_proto}" NAME_WE)
    set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/${target}/${relative_dir}")
    set(pb_cc "${output_dir}/${proto_stem}.pb.cc")
    set(pb_h "${output_dir}/${proto_stem}.pb.h")
    set(grpc_cc "${output_dir}/${proto_stem}.grpc.pb.cc")
    set(grpc_h "${output_dir}/${proto_stem}.grpc.pb.h")

    add_custom_command(
      OUTPUT "${pb_cc}" "${pb_h}" "${grpc_cc}" "${grpc_h}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${output_dir}"
      COMMAND "$<TARGET_FILE:protobuf::protoc>"
        "--proto_path=${RG_PROTO_ROOT}"
        "--cpp_out=${CMAKE_CURRENT_BINARY_DIR}/generated/${target}"
        "--grpc_out=${CMAKE_CURRENT_BINARY_DIR}/generated/${target}"
        "--plugin=protoc-gen-grpc=$<TARGET_FILE:grpc_cpp_plugin>"
        "${proto}"
      DEPENDS ${RG_PROTO_FILES} protobuf::protoc grpc_cpp_plugin
      COMMENT "Generating C++ protobuf and gRPC sources for ${relative_proto}"
      VERBATIM
    )
    list(APPEND generated_sources "${pb_cc}" "${grpc_cc}")
  endforeach()

  add_library(${target} STATIC ${generated_sources})
  target_include_directories(${target} PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}/generated/${target}")
  target_link_libraries(${target} PUBLIC protobuf::libprotobuf gRPC::grpc++)
  target_compile_features(${target} PUBLIC cxx_std_20)
endfunction()
