/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto_nat20.h"

#include <gtest/gtest.h>
#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/crypto/nat20/sha.h>
#include <nat20/testing/test_utils.h>

#include <vector>

#include "test_vectors.h"

n20_error_t CryptoImplNat20::open(n20_crypto_digest_context_t** ctx) {
    return n20_crypto_nat20_open(ctx);
}
n20_error_t CryptoImplNat20::close(n20_crypto_digest_context_t* ctx) {
    return n20_crypto_nat20_close(ctx);
}

/*
 * Tests below are specific to the nat20 reference implementation of
 * the nat20_crypto_digest interface. They are not intended to be run against
 * other implementations of the nat20_crypto interface.
 */

class Sha2TestFixture : public testing::TestWithParam<std::tuple<std::string,
                                                                 n20_crypto_digest_algorithm_t,
                                                                 std::vector<uint8_t>,
                                                                 std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(Sha2Test,
                        Sha2TestFixture,
                        testing::ValuesIn(sha2TestVectors),
                        [](testing::TestParamInfo<Sha2TestFixture::ParamType> const& info)
                            -> std::string { return std::get<0>(info.param); });

TEST_P(Sha2TestFixture, ShaDigestTest) {
    auto [_, alg, msg, want_digest] = GetParam();

    if (alg == n20_crypto_digest_algorithm_sha2_224_e) {
        n20_sha224_sha256_state_t state = n20_sha224_init();
        n20_sha224_update(&state, {msg.size(), msg.data()});
        std::vector<uint8_t> got_digest(28);
        n20_sha224_finalize(&state, got_digest.data());
        EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hex(want_digest) << std::endl
                                           << "Actual digest: " << hex(got_digest) << std::endl;
        return;
    } else if (alg == n20_crypto_digest_algorithm_sha2_256_e) {
        n20_sha224_sha256_state_t state = n20_sha256_init();
        n20_sha256_update(&state, {msg.size(), msg.data()});
        std::vector<uint8_t> got_digest(32);
        n20_sha256_finalize(&state, got_digest.data());
        EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hex(want_digest) << std::endl
                                           << "Actual digest: " << hex(got_digest) << std::endl;
        return;
    } else if (alg == n20_crypto_digest_algorithm_sha2_384_e) {
        n20_sha384_sha512_state_t state = n20_sha384_init();
        n20_sha384_update(&state, {msg.size(), msg.data()});
        std::vector<uint8_t> got_digest(48);
        n20_sha384_finalize(&state, got_digest.data());
        EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hex(want_digest) << std::endl
                                           << "Actual digest: " << hex(got_digest) << std::endl;
        return;
    } else if (alg == n20_crypto_digest_algorithm_sha2_512_e) {
        n20_sha384_sha512_state_t state = n20_sha512_init();
        n20_sha512_update(&state, {msg.size(), msg.data()});
        std::vector<uint8_t> got_digest(64);
        n20_sha512_finalize(&state, got_digest.data());
        EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hex(want_digest) << std::endl
                                           << "Actual digest: " << hex(got_digest) << std::endl;
        return;
    } else {
        FAIL() << "Unexpected algorithm: " << alg;
    }
}
