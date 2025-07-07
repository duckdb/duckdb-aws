cmake_minimum_required(VERSION 3.5...3.29)

# Set extension name here
set(TARGET_NAME aws)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
project(${TARGET_NAME})
include_directories(src/include)

set(EXTENSION_SOURCES src/aws_extension.cpp src/aws_secret.cpp)
add_library(${EXTENSION_NAME} STATIC ${EXTENSION_SOURCES})

set(PARAMETERS "-warnings")
build_loadable_extension(${TARGET_NAME} ${PARAMETERS} ${EXTENSION_SOURCES})

# Weirdly we need to manually do this; otherwise, linking against
# ${AWSSDK_LINK_LIBRARIES} fails for some reason
find_package(ZLIB REQUIRED)
find_package(AWSSDK REQUIRED COMPONENTS core sso sts identity-management)

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
