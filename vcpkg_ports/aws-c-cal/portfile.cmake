# Overlay of the vcpkg port (cd61e1e2): on wasm the library is built with BYO_CRYPTO, so it needs no libcrypto and
# the extension supplies the SHA-256 / HMAC implementations through aws_set_*_new_fn.
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO awslabs/aws-c-cal
    REF "v${VERSION}"
    SHA512 c78bf0a1bc96eaedc6c5eb93020b2925bf7b7f2c99b3603181381b2e007c0a601e54a2d1bf9a52759150f911a19e60a7b14f286d6dd8acc5ebfb40144db1a9b7
    HEAD_REF master
    PATCHES remove-libcrypto-messages.patch
)

set(USE_OPENSSL OFF)
set(BYO_CRYPTO OFF)
if(VCPKG_TARGET_IS_EMSCRIPTEN)
    set(BYO_CRYPTO ON)
elseif (NOT (VCPKG_TARGET_IS_WINDOWS OR VCPKG_TARGET_IS_OSX))
    set(USE_OPENSSL ON)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        "-DCMAKE_MODULE_PATH=${CURRENT_INSTALLED_DIR}/share/aws-c-common" # use extra cmake files
        -DBUILD_TESTING=FALSE
        -DUSE_OPENSSL=${USE_OPENSSL}
        -DBYO_CRYPTO=${BYO_CRYPTO}
)

vcpkg_cmake_install()

string(REPLACE "dynamic" "shared" subdir "${VCPKG_LIBRARY_LINKAGE}")
vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}/${subdir}" DO_NOT_DELETE_PARENT_CONFIG_PATH)
vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}")
vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/share/${PORT}/${PORT}-config.cmake" [[/${type}/]] "/")

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/lib/${PORT}"
    "${CURRENT_PACKAGES_DIR}/debug/share"
    "${CURRENT_PACKAGES_DIR}/lib/${PORT}"
)

vcpkg_copy_pdbs()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
