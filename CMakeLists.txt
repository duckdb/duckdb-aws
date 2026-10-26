cmake_minimum_required(VERSION 3.5...3.29)

# Set extension name here
set(TARGET_NAME aws)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
project(${TARGET_NAME})
include_directories(src/include)

# Capture the duckdb-aws extension's git short SHA at build time. Surfaced at
# runtime as the `created-by-version` auto-tag on every stack the
# cloudformation_* functions create.
execute_process(
  COMMAND git rev-parse --short HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE DUCKDB_AWS_GIT_SHA
  OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT DUCKDB_AWS_GIT_SHA)
  set(DUCKDB_AWS_GIT_SHA "unknown")
endif()
add_compile_definitions(DUCKDB_AWS_GIT_SHA="${DUCKDB_AWS_GIT_SHA}")

set(EXTENSION_SOURCES
    src/arn_storage.cpp
    src/aws_default_secret_storage.cpp
    src/aws_extension.cpp
    src/aws_http_client.cpp
    src/aws_secret.cpp
    src/cloudformation_functions.cpp
    src/create_aws_legacy_function_stubs.cpp
    src/rds/rds_utils.cpp
    src/rds/rds_storage.cpp
    src/quack_on_ec2_resource.cpp
    src/redshift/redshift_utils.cpp
    src/redshift/redshift_serverless_utils.cpp
    src/redshift/redshift_storage.cpp
    src/utils/utils.cpp)
if(EMSCRIPTEN)
  # On wasm the loadable target is an archive and DuckDB produces the side module in a separate emcc step that
  # links only what this variable names; target_link_libraries below does not reach it. Without the SDK archives
  # the module imports every out-of-line Aws:: symbol from the host and fails to load. aws-c-cal is built there
  # without a crypto backend (vcpkg_ports), so the hashes come from DuckDB's mbedtls, linked in like httpfs does.
  list(APPEND EXTENSION_SOURCES src/wasm_support.cpp)
  set(DUCKDB_EXTENSION_AWS_LINKED_LIBS "../../vcpkg_installed/wasm32-emscripten/lib/lib*.a"
                                       "../../third_party/mbedtls/libduckdb_mbedtls.a")
endif()

add_library(${EXTENSION_NAME} STATIC ${EXTENSION_SOURCES})

set(PARAMETERS "-warnings")
build_loadable_extension(${TARGET_NAME} ${PARAMETERS} ${EXTENSION_SOURCES})

if(EMSCRIPTEN)
  # orders the mbedtls archive before the side-module link
  target_link_libraries(aws_loadable_extension duckdb_mbedtls)
endif()

# Weirdly we need to manually do this; otherwise, linking against
# ${AWSSDK_LINK_LIBRARIES} fails for some reason
find_package(ZLIB REQUIRED)
find_package(
  AWSSDK REQUIRED
  COMPONENTS core
             sso
             sts
             identity-management
             rds
             redshift
             redshift-serverless
             cloudformation)

# Build static lib
target_include_directories(${EXTENSION_NAME}
                           PUBLIC $<BUILD_INTERFACE:${AWSSDK_INCLUDE_DIRS}>)
target_link_libraries(${EXTENSION_NAME} ${AWSSDK_LINK_LIBRARIES})

# Build loadable binary
target_include_directories(aws_loadable_extension
                           PRIVATE $<BUILD_INTERFACE:${AWSSDK_INCLUDE_DIRS}>)
target_link_libraries(aws_loadable_extension ${AWSSDK_LINK_LIBRARIES})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
