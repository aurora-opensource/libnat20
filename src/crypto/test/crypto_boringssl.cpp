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

#include "crypto_boringssl.h"

#include <gtest/gtest.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <openssl/bn.h>

#include <optional>
#include <variant>
#include <vector>

#include "openssl/base.h"

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

n20_crypto_error_t CryptoImplBSSL::open(n20_crypto_context_t** ctx) {
    n20_crypto_slice_t cdi = {sizeof(test_cdi), const_cast<uint8_t*>(&test_cdi[0])};
    return n20_crypto_open_boringssl(ctx, &cdi);
}
n20_crypto_error_t CryptoImplBSSL::close(n20_crypto_context_t* ctx) {
    return n20_crypto_close_boringssl(ctx);
}

/*
 * Tests below are specific to the boringssl reference implementation of
 * the nat20_crypto interface. They are not intended to be run against
 * other implementations of the nat20_crypto interface.
 */

/*
 * This function implements the RFC 6979 k generation algorithm for ECDSA
 * signatures. This symbol is exported only for testing purposes by the
 * boring ssl implementation of the nat20_crypto interface. Therefore,
 * it is not part of the public API and should not be used outside of
 * the test suite.
 */
extern std::variant<n20_crypto_error_t, bssl::UniquePtr<BIGNUM>> __n20_testing_rfc6979_k_generation(
    std::vector<uint8_t> const& x_octets,
    std::optional<std::vector<uint8_t>> const& m_octets,
    n20_crypto_digest_algorithm_t digest_algorithm,
    BIGNUM const* q);

/*
 * Test the RFC 6979 k generation function.
 *
 * RFC 6979 specifies a deterministic way to generate a
 * nonce (k) for ECDSA signatures based on the private key (x)
 * and the message (m). This test verifies that the k generation
 * function produces the expected k value for a given x and m.
 *
 * The test vector is taken from RFC 6979 Appendix A.1.2, which provides
 * an example of how to compute k for a specific private key and message.
 */
TEST(CryptoBoringsslTest, Test_rfc6979_k_generation) {

    std::vector<uint8_t> m_octets = {'s', 'a', 'm', 'p', 'l', 'e'};
    std::vector<uint8_t> x_octets = {0x00, 0x9a, 0x4d, 0x67, 0x92, 0x29, 0x5a,
                                     0x7f, 0x73, 0x0f, 0xc3, 0xf2, 0xb4, 0x9c,
                                     0xbc, 0x0f, 0x62, 0xe8, 0x62, 0x27, 0x2f};

    n20_crypto_digest_algorithm_t digest_algorithm = n20_crypto_digest_algorithm_sha2_256_e;
    auto q = bssl::UniquePtr<BIGNUM>(BN_new());
    BIGNUM* q_ptr = q.get();
    ASSERT_EQ(41, BN_hex2bn(&q_ptr, "4000000000000000000020108A2E0CC0D99F8A5EF"));

    auto result = __n20_testing_rfc6979_k_generation(x_octets, m_octets, digest_algorithm, q.get());
    ASSERT_TRUE(std::holds_alternative<bssl::UniquePtr<BIGNUM>>(result));

    auto k = bssl::UniquePtr<BIGNUM>(BN_new());
    BIGNUM* k_ptr = k.get();
    ASSERT_EQ(41, BN_hex2bn(&k_ptr, "23AF4074C90A02B3FE61D286D5C87F425E6BDD81B"));

    auto got_k = std::get<bssl::UniquePtr<BIGNUM>>(result).get();

    ASSERT_EQ(0, BN_cmp(k.get(), got_k)) << BN_bn2hex(got_k);
}
