vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO awslabs/aws-c-io
    REF "v${VERSION}"
    SHA512 dd897e063a8cd3fb1f6ea2ab356789a6368ee239cb8f03e26c02a21232b020150c9ec2938fda34e7c7e81f5e6910afabc422ef07d5350b186dbef5e5effa417c
    HEAD_REF master
    PATCHES no_op_implementation.patch
)

# No TLS implementation on wasm: the browser terminates TLS and nothing here opens a socket, so s2n stays out.
set(BYO_CRYPTO OFF)
if(VCPKG_TARGET_IS_EMSCRIPTEN)
    set(BYO_CRYPTO ON)
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        "-DCMAKE_MODULE_PATH=${CURRENT_INSTALLED_DIR}/share/aws-c-common" # use extra cmake files
        -DBUILD_TESTING=FALSE
        -DBYO_CRYPTO=${BYO_CRYPTO}
)

vcpkg_cmake_install()

string(REPLACE "dynamic" "shared" subdir "${VCPKG_LIBRARY_LINKAGE}")
vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}/${subdir}" DO_NOT_DELETE_PARENT_CONFIG_PATH)
vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}")
vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/share/${PORT}/${PORT}-config.cmake" [[/${type}/]] "/")
if(BYO_CRYPTO)
    # the installed config tests BYO_CRYPTO in the consumer's configure, where it is not set
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/share/${PORT}/${PORT}-config.cmake" "if (UNIX AND NOT BYO_CRYPTO)" "if (FALSE) # built with BYO_CRYPTO: no s2n")
endif()

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/lib/${PORT}"
    "${CURRENT_PACKAGES_DIR}/debug/share"
    "${CURRENT_PACKAGES_DIR}/lib/${PORT}"
)

vcpkg_copy_pdbs()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
