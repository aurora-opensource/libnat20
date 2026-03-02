# Copyright 2024 Aurora Operations, Inc.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
#
# This work is dual licensed.
# You may use it under Apache-2.0 or GPL-2.0 at your option.
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
#
# OR
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see
# <https://www.gnu.org/licenses/>.


cmake_minimum_required(VERSION 3.22)

project(LibNat20 VERSION 0.0.1 LANGUAGES C)

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

# Enable code coverage reporting by specifying
# -DNAT20_WITH_COVERAGE=ON on the `cmake -B` command line.
# This option is only valid when building the test suite.
option(NAT20_WITH_COVERAGE "Enable code coverage reporting." OFF)

# This option controls the maximum path length for stateless service implementations.
# In stateless service implementations, all of the context required to derive the effective
# CDI must be provided in the request. This means a request is potentially unbounded in size.
# The reference implementation limits the path length to 8. Integrators may change this
# value as needed or implement an alternative service with a dynamic memory allocation strategy.
# Note that increasing this value will increase the stack usage of the service implementation.
# The maximum path length is the number of elements in the path, not the number of bytes.
# Each path element is a SHA512 hash (64 bytes).
if(NOT NAT20_STATELESS_MAX_PATH_LENGTH)
    set(NAT20_STATELESS_MAX_PATH_LENGTH 8)
endif()

# The C standard shall be C11.
set(CMAKE_C_STANDARD 11)

# CMake shall generate a compile_commands.json file for
# the benfit of clangd based IDE support.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NAT20_WITH_TESTS OR NAT20_WITH_CRYPTO_BSSL)
    # When building the test suite or the reference crypto implementation,
    # we need to enable C++ support for the test code.
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 17)
endif()

include(GNUInstallDirs)

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
    include/nat20/constants.h
    include/nat20/crypto.h
    include/nat20/endian.h
    include/nat20/error.h
    include/nat20/functionality.h
    include/nat20/limits.h
    include/nat20/oid.h
    include/nat20/open_dice.h
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
    src/crypto/nat20/rfc6979.c
    src/crypto/nat20/sha256.c
    src/crypto/nat20/sha512.c
)

set(LIBNAT20_CRYPTO_NAT20_PUB_HEADERS
    # Add the public headers here.
    # These files will be included in the generation of the API documentation.
    include/nat20/crypto/nat20/crypto.h
    include/nat20/crypto/nat20/rfc6979.h
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
    src/service/messages.c
)

set(LIBNAT20_SERVICE_PUB_HEADERS
    # Add service public headers here.
    include/nat20/service/messages.h
)

set(LIBNAT20_SERVICE_TEST_SOURCES
    src/service/test/messages.cpp
    src/service/test/test.cpp
)

set(LIBNAT20_DOC_PAGES
    # Add additional input files for doxygen here.
    README.md
    CONTRIBUTING.md
)

set(LIBNAT20_PUB_CRYPTO_BSSL_HEADERS
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
    include/nat20/testing/test_bssl_utils.h
    include/nat20/testing/test_utils.h
    include/nat20/testing/test_vector_reader.h
)

set(LIBNAT20_TEST_UTILS_SOURCES
    src/testing/test_bssl_utils.cpp
    src/testing/test_utils.cpp
    src/testing/test_vector_reader.cpp
)


###################################################################################################

###################################################################################################
# The nat20 library is the core product of this project.
# It will always be compiled.
add_library(nat20 STATIC)
add_library(LibNat20::nat20 ALIAS nat20)

target_sources(nat20
    PRIVATE ${LIBNAT20_SOURCES}
    PRIVATE ${LIBNAT20_PUB_HEADERS}
)
set_target_properties(nat20 PROPERTIES PUBLIC_HEADER "${LIBNAT20_PUB_HEADERS}")

target_compile_options(nat20
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

target_include_directories(nat20 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS nat20
    EXPORT LibNat20Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nat20
)

if(NAT20_WITH_COVERAGE AND NAT20_WITH_TESTS)
    add_library(nat20_coverage STATIC)

    target_sources(nat20_coverage
        PRIVATE ${LIBNAT20_SOURCES}
        PRIVATE ${LIBNAT20_PUB_HEADERS}
    )

    target_compile_options(nat20_coverage
        PRIVATE -pedantic
        PRIVATE -Wall
        PRIVATE -Wextra
        PRIVATE -Werror
    )

    target_compile_options(nat20_coverage
        PRIVATE --coverage
    )
    target_link_options(nat20_coverage
        PRIVATE --coverage
    )
    target_include_directories(nat20_coverage PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
endif()


###################################################################################################

###################################################################################################
# The nat20_service library is also part of the product of this project.
# It will always be compiled.
add_library(nat20_service STATIC)
add_library(LibNat20::nat20_service ALIAS nat20_service)

target_sources(nat20_service
    PRIVATE ${LIBNAT20_SERVICE_SOURCES}
    PRIVATE ${LIBNAT20_SERVICE_PUB_HEADERS}
)
set_target_properties(nat20_service PROPERTIES PUBLIC_HEADER "${LIBNAT20_SERVICE_PUB_HEADERS}")


target_compile_options(nat20_service
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

# Add -DN20_STATELESS_MAX_PATH_LENGTH=<value> to the compiler command line.
target_compile_definitions(nat20_service
    PUBLIC N20_STATELESS_MAX_PATH_LENGTH=${NAT20_STATELESS_MAX_PATH_LENGTH}
)

target_include_directories(nat20_service PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(nat20_service nat20)

install(TARGETS nat20_service
    EXPORT LibNat20Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nat20/service
)


if(NAT20_WITH_COVERAGE AND NAT20_WITH_TESTS)
    add_library(nat20_service_coverage STATIC)

    target_sources(nat20_service_coverage
        PRIVATE ${LIBNAT20_SERVICE_SOURCES}
        PRIVATE ${LIBNAT20_SERVICE_PUB_HEADERS}
    )

    target_compile_options(nat20_service_coverage
        PRIVATE -pedantic
        PRIVATE -Wall
        PRIVATE -Wextra
        PRIVATE -Werror
    )

    # Add -DN20_STATELESS_MAX_PATH_LENGTH=<value> to the compiler command line.
    target_compile_definitions(nat20_service_coverage
        PUBLIC N20_STATELESS_MAX_PATH_LENGTH=${NAT20_STATELESS_MAX_PATH_LENGTH}
    )

    target_include_directories(nat20_service_coverage PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    target_link_libraries(nat20_service_coverage nat20)

    target_compile_options(nat20_service_coverage
        PRIVATE --coverage
    )
    target_link_options(nat20_service_coverage
        PRIVATE --coverage
    )
endif()


###################################################################################################

###################################################################################################
# The nat20_crypto_nat20 library implements some crypto
# algorithms using the native C standard library.

add_library(nat20_crypto_nat20 STATIC)
add_library(LibNat20::nat20_crypto_nat20 ALIAS nat20_crypto_nat20)

target_sources(nat20_crypto_nat20
    PRIVATE ${LIBNAT20_CRYPTO_NAT20_SOURCES}
    PRIVATE ${LIBNAT20_CRYPTO_NAT20_PUB_HEADERS}
)
set_target_properties(nat20_crypto_nat20 PROPERTIES PUBLIC_HEADER "${LIBNAT20_CRYPTO_NAT20_PUB_HEADERS}")

target_compile_options(nat20_crypto_nat20
    PRIVATE -pedantic
    PRIVATE -Wall
    PRIVATE -Wextra
    PRIVATE -Werror
)

target_include_directories(nat20_crypto_nat20 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS nat20_crypto_nat20
    EXPORT LibNat20Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nat20/crypto/nat20
)

if(NAT20_WITH_COVERAGE AND NAT20_WITH_TESTS)
    add_library(nat20_crypto_nat20_coverage STATIC)

    target_sources(nat20_crypto_nat20_coverage
        PRIVATE ${LIBNAT20_CRYPTO_NAT20_SOURCES}
        PRIVATE ${LIBNAT20_CRYPTO_NAT20_PUB_HEADERS}
    )

    target_compile_options(nat20_crypto_nat20_coverage
        PRIVATE -pedantic
        PRIVATE -Wall
        PRIVATE -Wextra
        PRIVATE -Werror
    )

    target_include_directories(nat20_crypto_nat20_coverage PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    target_compile_options(nat20_crypto_nat20_coverage
        PRIVATE --coverage
    )
    target_link_options(nat20_crypto_nat20_coverage
        PRIVATE --coverage
    )
endif()

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
        PRIVATE ${LIBNAT20_PUB_CRYPTO_BSSL_HEADERS}
    )
    set_target_properties(nat20_crypto_boringssl PROPERTIES PUBLIC_HEADER "${LIBNAT20_PUB_CRYPTO_BSSL_HEADERS}")

    target_compile_options(nat20_crypto_boringssl
        PRIVATE -pedantic
        PRIVATE -Wall
        PRIVATE -Wextra
        PRIVATE -Werror
    )

    target_include_directories(nat20_crypto_boringssl PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    target_link_libraries(nat20_crypto_boringssl crypto)

    # NOTE:
    # nat20_crypto_boringssl links against the BoringSSL "crypto" library
    # obtained via FetchContent. Since that dependency is not installed /
    # exported as part of this project, installing nat20_crypto_boringssl
    # would create a non-relocatable target for downstream consumers.
    # Therefore, nat20_crypto_boringssl is intentionally *not* installed
    # or exported as part of LibNat20. It is intended for in-tree use only.

    if(NAT20_WITH_COVERAGE AND NAT20_WITH_TESTS)
        add_library(nat20_crypto_boringssl_coverage)

        target_sources(nat20_crypto_boringssl_coverage
            PRIVATE ${LIBNAT20_CRYPTO_BSSL_SOURCES}
            PRIVATE ${LIBNAT20_PUB_CRYPTO_BSSL_HEADERS}
        )

        target_compile_options(nat20_crypto_boringssl_coverage
            PRIVATE -pedantic
            PRIVATE -Wall
            PRIVATE -Wextra
            PRIVATE -Werror
        )

        target_include_directories(nat20_crypto_boringssl_coverage
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        )

        target_link_libraries(nat20_crypto_boringssl_coverage crypto)

        target_compile_options(nat20_crypto_boringssl_coverage
            PRIVATE --coverage
        )
        target_link_options(nat20_crypto_boringssl_coverage
            PRIVATE --coverage
        )
    endif()

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
        PRIVATE ${LIBNAT20_TEST_UTILS_HEADERS}
    )
    set_target_properties(nat20_test_utils PROPERTIES PUBLIC_HEADER "${LIBNAT20_TEST_UTILS_HEADERS}")

    target_link_libraries(nat20_test_utils gtest_main nat20 crypto)
    target_include_directories(nat20_test_utils PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    add_executable(nat20_test_bin)
    target_sources(nat20_test_bin
        PRIVATE ${LIBNAT20_TEST_SOURCES}
    )
    if(NAT20_WITH_COVERAGE)
        target_link_options(nat20_test_bin
            PRIVATE --coverage
        )
        target_link_libraries(nat20_test_bin nat20_coverage)
    else()
        target_link_libraries(nat20_test_bin nat20)
    endif()
    target_link_libraries(nat20_test_bin gtest_main crypto pki nat20_crypto_boringssl nat20_test_utils)
    add_test(NAME nat20_test COMMAND nat20_test_bin)

    add_executable(nat20_service_test_bin)
    target_sources(nat20_service_test_bin
        PRIVATE ${LIBNAT20_SERVICE_TEST_SOURCES}
    )
    if(NAT20_WITH_COVERAGE)
        target_link_options(nat20_service_test_bin
            PRIVATE --coverage
        )
        target_link_libraries(nat20_service_test_bin nat20_service_coverage)
    else()
        target_link_libraries(nat20_service_test_bin nat20_service)
    endif()
    target_link_libraries(nat20_service_test_bin gtest_main nat20 crypto pki nat20_crypto_boringssl nat20_test_utils)
    add_test(NAME nat20_service_test COMMAND nat20_service_test_bin)


    add_executable(nat20_crypto_test_bin)
    target_sources(nat20_crypto_test_bin
        PRIVATE ${LIBNAT20_CRYPTO_TEST_SOURCES}
    )
    if(NAT20_WITH_COVERAGE)
        target_link_options(nat20_crypto_test_bin
            PRIVATE --coverage
        )
    endif()
    target_link_libraries(nat20_crypto_test_bin gtest_main nat20 crypto pki nat20_test_utils)
    add_test(NAME nat20_crypto_test COMMAND nat20_crypto_test_bin)

    target_sources(nat20_crypto_test_bin
        PRIVATE src/crypto/test/crypto_boringssl.cpp
    )
    if(NAT20_WITH_COVERAGE)
        target_link_libraries(nat20_crypto_test_bin nat20_crypto_boringssl_coverage)
    else()
        target_link_libraries(nat20_crypto_test_bin nat20_crypto_boringssl)
    endif()
    add_definitions(-DN20_CONFIG_ENABLE_CRYPTO_TEST_IMPL=1)

    target_sources(nat20_crypto_test_bin
        PRIVATE src/crypto/test/crypto_nat20.cpp
    )
    if(NAT20_WITH_COVERAGE)
        target_link_libraries(nat20_crypto_test_bin nat20_crypto_nat20_coverage)
    else()
        target_link_libraries(nat20_crypto_test_bin nat20_crypto_nat20)
    endif()

    if(NAT20_WITH_COVERAGE)
        find_program(LCOV_EXECUTABLE lcov)
        if(NOT LCOV_EXECUTABLE)
            message(FATAL_ERROR "lcov executable not found. Please install lcov or disable code coverage reporting.")
        endif()
        find_program(GENHTML_EXECUTABLE genhtml)
        if(NOT GENHTML_EXECUTABLE)
            message(FATAL_ERROR "genhtml executable not found. Please install genhtml or disable code coverage reporting.")
        endif()
        add_custom_target(coverage
            # Clear any previous coverage data
            COMMAND lcov --zerocounters --rc lcov_branch_coverage=1 --base-directory ${CMAKE_SOURCE_DIR} --directory ${CMAKE_BINARY_DIR}

            # Run the tests to generate new coverage data
            COMMAND ctest

            # Capture the coverage data into coverage.info
            COMMAND lcov --capture --no-external --rc lcov_branch_coverage=1 --base-directory ${CMAKE_SOURCE_DIR} --directory ${CMAKE_BINARY_DIR} --output-file ${CMAKE_BINARY_DIR}/coverage.info

            # Remove system header files from the report
            COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '*/_deps/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info --rc lcov_branch_coverage=1

            # Generate the HTML report into the specified directory
            COMMAND genhtml ${CMAKE_BINARY_DIR}/coverage.info --output-directory ${CMAKE_BINARY_DIR}/coverage_html --rc lcov_branch_coverage=1

            # Provide a comment for the build output
            COMMENT "Generating code coverage report..."

            # Run the commands in the build directory
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}

            # Make sure this target depends on the main test executable
            DEPENDS nat20_test_bin
            DEPENDS nat20_crypto_test_bin
            DEPENDS nat20_service_test_bin
        )
    endif()

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

include(CMakePackageConfigHelpers)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibNat20Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/LibNat20Config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibNat20
    PATH_VARS
        CMAKE_INSTALL_INCLUDEDIR
        CMAKE_INSTALL_LIBDIR
)

# Generate the version file for find_package version checking
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/LibNat20ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Generate and install the targets file
install(EXPORT LibNat20Targets
    FILE LibNat20Targets.cmake
    NAMESPACE LibNat20::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibNat20
)

# Install the package configuration files
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/LibNat20Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/LibNat20ConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibNat20
)

