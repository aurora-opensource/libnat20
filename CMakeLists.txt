# Copyright 2024 Aurora Operations, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.22)

project(LibNat20 VERSION 0.0.1)

# Enable the libnat20 test suite by specifying
# -DNAT20_WITH_TESTS=ON on the `cmake -B` command line.
# The test can be run with `make test` or `ctest`.
option(NAT20_WITH_TESTS "Build the test suite." OFF)

# Enable libnat20 documentation generation by specifying
# -DNAT20_WITH_DOCS=ON on the `cmake -B` command line.
# Build the docs by building the target `make nat20_docs`.
option(NAT20_WITH_DOCS "Create the documentation target." OFF)

# Enable the libnat20 reference implementation for the
# libnat20 crypto interface by specifying -DNAT20_WITH_CRYPTO_BSSL=ON
# on the `cmake -B` command line.
option(NAT20_WITH_CRYPTO_BSSL "Compile the crypto reference implementation." OFF)

# The C standard shall be C11.
set(CMAKE_C_STANDARD 11)

# CMake shall generate a compile_commands.json file for
# the benfit of clangd based IDE support.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

###################################################################################################
# The following section defines all the groups of source files.
# All files must be specified explicitly; no globbing or other generation is allowed.

set(LIBNAT20_SOURCES
    # Add the core library source files here.
    src/core/asn1.c
    src/core/cbor.c
    src/core/functionality.c
    src/core/oid.c
    src/core/stream.c
    src/core/x509_ext_open_dice_input.c
    src/core/x509_ext_tcg_dice_tcb_freshness.c
    src/core/x509_ext_tcg_dice_tcb_info.c
    src/core/x509_ext_tcg_dice_ueid.c
    src/core/x509.c
)

set(LIBNAT20_PUB_HEADERS
    # Add the public headers here.
    # These files will be included in the generation of the API documentation.
    include/nat20/asn1.h
    include/nat20/cbor.h
    include/nat20/crypto.h
    include/nat20/error.h
    include/nat20/functionality.h
    include/nat20/oid.h
    include/nat20/stream.h
    include/nat20/types.h
    include/nat20/x509_ext_open_dice_input.h
    include/nat20/x509_ext_tcg_dice_tcb_freshness.h
    include/nat20/x509_ext_tcg_dice_tcb_info.h
    include/nat20/x509_ext_tcg_dice_ueid.h
    include/nat20/x509.h
)

set(LIBNAT20_CRYPTO_NAT20_SOURCES
    # Add the core library source files here.
    src/crypto/nat20/crypto.c
    src/crypto/nat20/sha256.c
    src/crypto/nat20/sha512.c
)

set(LIBNAT20_CRYPTO_NAT20_PUB_HEADERS
    # Add the public headers here.
    # These files will be included in the generation of the API documentation.
    include/nat20/crypto/nat20/crypto.h
    include/nat20/crypto/nat20/sha.h
)


set(LIBNAT20_TEST_SOURCES
    # Add test source files here.
    src/core/test/asn1.cpp
    src/core/test/cbor.cpp
    src/core/test/functionality.cpp
    src/core/test/oid.cpp
    src/core/test/stream.cpp
    src/core/test/test.cpp
    src/core/test/test_vectors.cpp
    src/core/test/x509.cpp
    src/core/test/x509_ext_open_dice_input.cpp
    src/core/test/x509_ext_tcg_dice_tcb_freshness.cpp
    src/core/test/x509_ext_tcg_dice_tcb_info.cpp
    src/core/test/x509_ext_tcg_dice_ueid.cpp
)

set(LIBNAT20_SERVICE_SOURCES
    # Add service source files here.
    src/service/gnostic.c
    src/service/service.c
)

set(LIBNAT20_SERVICE_PUB_HEADERS
    # Add service public headers here.
    include/nat20/service/gnostic.h
    include/nat20/service/service.h
)

set(LIBNAT20_DOC_PAGES
    # Add additional input files for doxygen here.
    README.md
    CONTRIBUTING.md
)

set(LIBNAT20_PUB_BSSL_HEADERS
    include/nat20/crypto_bssl/crypto.h
)

set(LIBNAT20_CRYPTO_BSSL_SOURCES
    src/crypto/crypto_boringssl.cpp
)

set(LIBNAT20_CRYPTO_TEST_SOURCES
    src/crypto/test/test.cpp
    src/crypto/test/crypto.cpp
    src/crypto/test/test_vectors.cpp
)

set(LIBNAT20_TEST_UTILS_HEADERS
    include/nat20/testing/test_utils.h
    include/nat20/testing/test_vector_reader.h
)

set(LIBNAT20_TEST_UTILS_SOURCES
    src/testing/test_utils.cpp
    src/testing/test_vector_reader.cpp
)


###################################################################################################

###################################################################################################
# The nat20 library is the core product of this project.
# It will always be compiled.
add_library(nat20 STATIC)

target_sources(nat20
    PRIVATE ${LIBNAT20_SOURCES}
    INTERFACE ${LIBNAT20_PUB_HEADERS}
)

target_compile_options(nat20
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

target_include_directories(nat20
    PUBLIC include
)

###################################################################################################

###################################################################################################
# The nat20_service library is also part of the product of this project.
# It will always be compiled.
add_library(nat20_service STATIC)

target_sources(nat20_service
    PRIVATE ${LIBNAT20_SERVICE_SOURCES}
    INTERFACE ${LIBNAT20_SERVICE_PUB_HEADERS}
)

target_compile_options(nat20_service
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

target_include_directories(nat20_service
    PUBLIC include
)

target_link_libraries(nat20_service nat20)

###################################################################################################

###################################################################################################
# The nat20_crypto_nat20 library implements some crypto
# algorithms using the native C standard library.

add_library(nat20_crypto_nat20 STATIC)

target_sources(nat20_crypto_nat20
    PRIVATE ${LIBNAT20_CRYPTO_NAT20_SOURCES}
    INTERFACE ${LIBNAT20_CRYPTO_NAT20_PUB_HEADERS}
)

target_compile_options(nat20_crypto_nat20
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

target_include_directories(nat20_crypto_nat20
    PUBLIC include
)

###################################################################################################

###################################################################################################
# Import boringssl and compile nat20_crypto_boringssl when building the test and/or the reference
# crypto implementation.

if(NAT20_WITH_TESTS OR NAT20_WITH_CRYPTO_BSSL)
    include(FetchContent)

    FetchContent_Declare(
        crypto
        GIT_REPOSITORY https://boringssl.googlesource.com/boringssl
        GIT_TAG        dc65229e58a98c0768d017d0c9bbe376f20c2577 # tag 0.20241024.0
    )
    FetchContent_MakeAvailable(crypto)

    add_library(nat20_crypto_boringssl)

    target_sources(nat20_crypto_boringssl
        PRIVATE ${LIBNAT20_CRYPTO_BSSL_SOURCES}
        INTERFACE ${LIBNAT20_PUB_CRYPTO_BSSL_HEADERS}
    )

    target_compile_options(nat20_crypto_boringssl
        PRIVATE -pedantic
        PRIVATE -Wall
        PRIVATE -Wextra
        PRIVATE -Werror
    )

    target_include_directories(nat20_crypto_boringssl
        PUBLIC include
    )

    target_link_libraries(nat20_crypto_boringssl crypto)

    add_definitions(-DN20_CONFIG_WITH_BSSL=1)
endif()

###################################################################################################

###################################################################################################
# The libnat20 test suite. It, along with its additional dependencies is only compiled
# when selected by setting `-DNAT20_WITH_TESTS=ON` on the `cmake -B` command line.
if (NAT20_WITH_TESTS)

    # Print test details if tests fail.
    set(CMAKE_CTEST_ARGUMENTS "--output-on-failure")

    include(FetchContent)

    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/5376968f6948923e2411081fd9372e71a59d8e77.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    file(COPY
        "src/crypto/test/test_data/"
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/test_data/crypto"
        FILES_MATCHING PATTERN "*"
    )

    file(INSTALL
        "src/core/test/test_data/"
        DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/test_data/core"
        FILES_MATCHING PATTERN "*"
    )

    # Add the nat20 library test utils.
    add_library(nat20_test_utils STATIC)
    target_sources(nat20_test_utils
        PRIVATE ${LIBNAT20_TEST_UTILS_SOURCES}
        INTERFACE ${LIBNAT20_TEST_UTILS_HEADERS}
    )
    target_include_directories(nat20_test_utils
        PUBLIC include
    )

    add_executable(nat20_test_bin)
    target_sources(nat20_test_bin
        PRIVATE ${LIBNAT20_TEST_SOURCES}
    )
    target_link_libraries(nat20_test_bin gtest_main nat20 crypto pki nat20_crypto_boringssl nat20_test_utils)
    add_test(NAME nat20_test COMMAND nat20_test_bin)

    add_executable(nat20_crypto_test_bin)
    target_sources(nat20_crypto_test_bin
        PRIVATE ${LIBNAT20_CRYPTO_TEST_SOURCES}
    )
    target_link_libraries(nat20_crypto_test_bin gtest_main nat20 crypto pki nat20_test_utils)
    add_test(NAME nat20_crypto_test COMMAND nat20_crypto_test_bin)

    target_sources(nat20_crypto_test_bin
        PRIVATE src/crypto/test/crypto_boringssl.cpp
    )
    target_link_libraries(nat20_crypto_test_bin nat20_crypto_boringssl)
    add_definitions(-DN20_CONFIG_ENABLE_CRYPTO_TEST_IMPL=1)

    target_sources(nat20_crypto_test_bin
        PRIVATE src/crypto/test/crypto_nat20.cpp
    )
    target_link_libraries(nat20_crypto_test_bin nat20_crypto_nat20)


endif() # NAT20_WITH_TESTS

###################################################################################################

###################################################################################################
# The doxygen docs generation target is only created if enabled by setting `-DNAT20_WITH_DOCS=ON`
# on the `cmake -B` command line.

if (NAT20_WITH_DOCS)

    find_package(Doxygen REQUIRED dot)

    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE README.md)
    set(DOXYGEN_MACRO_EXPANSION YES)

    doxygen_add_docs(nat20_docs
        ${LIBNAT20_PUB_HEADERS}
        ${LIBNAT20_DOC_PAGES}
        ${LIBNAT20_TEST_UTILS_HEADERS}
        ${LIBNAT20_CRYPTO_NAT20_PUB_HEADERS}
    )

endif() # NAT20_WITH_DOCS
