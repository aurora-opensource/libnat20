cmake_minimum_required(VERSION 3.22)

project(LibNat20 VERSION 0.0.1)

# Enable the libnat20 test suite by specifying
# -DNAT20_WITH_TESTS=ON on the `cmake --build` command line.
# The test can be run with `make test` or `ctest`.
option(NAT20_WITH_TESTS "Build the test suite." OFF)

# CMake shall generate a compile_commands.json file for
# the benfit of clangd based IDE support.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

###################################################################################################
# The following section defines all the groups of source files.
# All files must be specified explicitely; no globbing or other generation is allowed.

set(LIBNAT20_TEST_SOURCES
    # Add test source files here.
    test/test.cpp
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
    target_link_libraries(nat20test gtest_main crypto)
    add_test(NAME nat20_test COMMAND nat20test)

endif() # NAT20_WITH_TESTS

###################################################################################################
