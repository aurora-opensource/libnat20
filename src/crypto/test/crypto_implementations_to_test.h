#pragma once

#include <gtest/gtest.h>

// To add a crypto implementation to the list of test
// create a class that implements the following static
// member functions.
// struct MyCryptoImplementation {
//     static n20_crypto_error_t open(n20_crypto_context_t** ctx);
//     static n20_crypto_error_t close(n20_crypto_context_t* ctx);
// };
// Include it here and then add the class name to the types list below.

#ifdef N20_CONFIG_ENABLE_CRYPTO_TEST_IMPL

using CryptoImplementationsToTest = ::testing::Types<
    // Add crypto implementations to the list in order to run
    // the crypto test against them.

    // End of list.
    >;

#endif
