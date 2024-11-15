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
# -DNAT20_WITH_TESTS=ON on the `cmake --build` command line.
# The test can be run with `make test` or `ctest`.
option(NAT20_WITH_TESTS "Build the test suite." OFF)

# Enable libnat20 documentation generation by specifying
# -DNAT20_WITH_DOCS=ON on the `cmake --build` command line.
# Build the docs by building the target `make nat20_docs`.
option(NAT20_WITH_DOCS "Create the documentation target." OFF)

# The C standard shall be C11.
set(CMAKE_C_STANDARD 11)

# CMake shall generate a compile_commands.json file for
# the benfit of clangd based IDE support.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

###################################################################################################
# The following section defines all the groups of source files.
# All files must be specified explicitely; no globbing or other generation is allowed.

set(LIBNAT20_SOURCES
    # Add the core library source files here.
    src/asn1.c
    src/oid.c
    src/x509.c
)

set(LIBNAT20_PUB_HEADERS
    # Add the public headers here.
    # These files will be included in the generation of the API documentation.
    include/nat20/asn1.h
    include/nat20/oid.h
    include/nat20/x509.h
)

set(LIBNAT20_TEST_SOURCES
    # Add test source files here.
    test/test.cpp
    test/asn1.cpp
)

set(LIBNAT20_DOC_PAGES
    # Add additional input files for doxygen here.
    README.md
    CONTRIBUTING.md
)

###################################################################################################

###################################################################################################
# The nat20 libarary is the core product of this project.
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
# The libnat20 test suite. It, along with its additional dependencies is only compiled
# when selected by setting `-DNAT20_WITH_TESTS=ON` on the `cmake --build` command line.
if (NAT20_WITH_TESTS)

    include(FetchContent)

    FetchContent_Declare(
        crypto
        GIT_REPOSITORY https://boringssl.googlesource.com/boringssl
        GIT_TAG        dc65229e58a98c0768d017d0c9bbe376f20c2577 # tag 0.20241024.0
    )
    FetchContent_MakeAvailable(crypto)

    FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/5376968f6948923e2411081fd9372e71a59d8e77.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(nat20test)
    target_sources(nat20test
        PRIVATE ${LIBNAT20_TEST_SOURCES}
    )
    target_link_libraries(nat20test gtest_main nat20 crypto)
    add_test(NAME nat20_test COMMAND nat20test)

endif() # NAT20_WITH_TESTS

###################################################################################################


###################################################################################################
# The doxygen docs generation target is only created if enabled by setting `-DNAT20_WITH_DOCS=ON`
# on the `cmake --build` command line.
if (NAT20_WITH_DOCS)

    find_package(Doxygen REQUIRED dot)

    doxygen_add_docs(nat20_docs
        ${LIBNAT20_PUB_HEADERS}
        ${LIBNAT20_DOC_PAGES}
    )

endif() # NAT20_WITH_DOCS
