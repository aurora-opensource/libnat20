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

n20_error_t CryptoImplBSSL::open(n20_crypto_context_t** ctx) {
    return n20_crypto_boringssl_open(ctx);
}
n20_error_t CryptoImplBSSL::close(n20_crypto_context_t* ctx) {
    return n20_crypto_boringssl_close(ctx);
}

n20_error_t CryptoImplBSSL::get_cdi(n20_crypto_context_t* ctx, n20_crypto_key_t* out_cdi) {
    n20_slice_t cdi = {sizeof(test_cdi), const_cast<uint8_t*>(&test_cdi[0])};
    return n20_crypto_boringssl_make_secret(ctx, &cdi, out_cdi);
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
extern std::variant<n20_error_t, bssl::UniquePtr<BIGNUM>> __n20_testing_rfc6979_k_generation(
    std::vector<uint8_t> const& x_octets,
    std::optional<std::vector<uint8_t>> const& m_octets,
    n20_crypto_digest_algorithm_t digest_algorithm,
    BIGNUM const* q);

std::optional<std::vector<uint8_t>> const SAMPLE_MSG = {{'s', 'a', 'm', 'p', 'l', 'e'}};
std::optional<std::vector<uint8_t>> const TEST_MSG = {{'t', 'e', 's', 't'}};
std::optional<std::vector<uint8_t>> const EMPTY_MSG = {{}};
std::optional<std::vector<uint8_t>> const NULL_MSG = std::nullopt;

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
 * The significance of this test is that Appendix A.1.2 provides
 * intermediate values which is useful for debugging the k generation
 * function.
 */
TEST(CryptoBoringsslTest, Test_rfc6979_k_generation) {

    auto m_octets = SAMPLE_MSG;
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

class RFC6979KGenerationTestP256
    : public testing::TestWithParam<std::tuple<n20_crypto_digest_algorithm_t,
                                               std::optional<std::vector<uint8_t>>,
                                               std::string>> {};

INSTANTIATE_TEST_CASE_P(
    RFC6979KGenerationTestInstance,
    RFC6979KGenerationTestP256,
    testing::Values(
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   SAMPLE_MSG,
                   "103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   SAMPLE_MSG,
                   "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   SAMPLE_MSG,
                   "09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   SAMPLE_MSG,
                   "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5"),
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   TEST_MSG,
                   "669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   TEST_MSG,
                   "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   TEST_MSG,
                   "16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   TEST_MSG,
                   "6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F"),
        /*
         * The following test vectors where computed using the same algorithm while
         * verifying that the intermediate h1_digest is equal to the digest of the
         * emtpy message for the corresponding digest algorithms.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   EMPTY_MSG,
                   "e6a082bf249944014406a9280befd1aa2369a98b31fe1eed9fa91098363cd60b"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   EMPTY_MSG,
                   "3c7eca3784e9809c912f21d6c1894e70b8a709d3222982ae499b270bac245246"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   EMPTY_MSG,
                   "bbbe969da70f10ecb28a059dad2589817cd64d7917dabb82cb6c52164415d530"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   EMPTY_MSG,
                   "2d255f20e3aa839fcb4116e2819568ae8e15be3db130bac7c38ec5eba003ccd2"),
        /*
         * The following test vectors where computed using the same algorithm while
         * omitting the message entirely.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   NULL_MSG,
                   "402ea153bb5ccccc8f87abb88a647a27eb2e7a51b92ece286dcb991e83a7efd3"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   NULL_MSG,
                   "c3e0374fbfa3752b760374a626c649ed798b7146e869c2482cb17a54c94ebae3"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   NULL_MSG,
                   "b868001fb7f5ed86ae0de3db439fe10bc56bf63ce776aeb6a2b011283d19ca17"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   NULL_MSG,
                   "bbbb46f35c82170d767ed845f4a7d942bcc3ccc82bb39eb0f3b607ee18867ea2")));

/*
 * Test the RFC 6979 k generation function.
 *
 * RFC 6979 specifies a deterministic way to generate a
 * nonce (k) for ECDSA signatures based on the private key (x)
 * and the message (m). This test verifies that the k generation
 * function produces the expected k value for a given x and m.
 *
 * The first 8 test vectors for this test are taken from RFC 6979 Appendix A2.5
 * for the P-256 curve.
 */
TEST_P(RFC6979KGenerationTestP256, Test_rfc6979_k_P_256_generation) {
    auto [digest_algorithm, m_octets, k_str] = GetParam();

    auto x_octets =
        std::vector<uint8_t>{0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
                             0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
                             0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

    auto q = bssl::UniquePtr<BIGNUM>(BN_new());
    BIGNUM* q_ptr = q.get();
    ASSERT_EQ(
        64, BN_hex2bn(&q_ptr, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));

    auto k = bssl::UniquePtr<BIGNUM>(BN_new());
    BIGNUM* k_ptr = k.get();
    ASSERT_EQ(64, BN_hex2bn(&k_ptr, k_str.c_str()));

    auto result = __n20_testing_rfc6979_k_generation(x_octets, m_octets, digest_algorithm, q.get());
    ASSERT_TRUE(std::holds_alternative<bssl::UniquePtr<BIGNUM>>(result));

    auto got_k = std::get<bssl::UniquePtr<BIGNUM>>(result).get();

    ASSERT_EQ(0, BN_cmp(k.get(), got_k)) << BN_bn2hex(got_k);
}

class RFC6979KGenerationTestP384
    : public testing::TestWithParam<std::tuple<n20_crypto_digest_algorithm_t,
                                               std::optional<std::vector<uint8_t>>,
                                               std::string>> {};

INSTANTIATE_TEST_CASE_P(
    RFC6979KGenerationTestInstance,
    RFC6979KGenerationTestP384,
    testing::Values(
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   SAMPLE_MSG,
                   "A4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB8083EE4E3C45B06"
                   "A5899EA56C51B5879"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   SAMPLE_MSG,
                   "180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C89"
                   "9F9F2EDF9747A9B60"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   SAMPLE_MSG,
                   "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA9536"
                   "8623B8C4686915CF9"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   SAMPLE_MSG,
                   "92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52"
                   "980D0E3AAA5E10EC3"),
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   TEST_MSG,
                   "18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E3D33BE4DC5EB888"
                   "6A8ECD093F2935726"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   TEST_MSG,
                   "0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FAA48DD070BA79921"
                   "A3457ABFF2D630AD7"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   TEST_MSG,
                   "015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA9"
                   "8ADB95837DB8312EA"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   TEST_MSG,
                   "3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE0E2CC8A136036DC"
                   "4B9C00E6888F66B6C"),
        /*
         * The following test vectors where computed using the same algorithm while
         * verifying that the intermediate h1_digest is equal to the digest of the
         * emtpy message for the corresponding digest algorithms.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   EMPTY_MSG,
                   "9f505a478bed79931bfddfea0b9716f70e40f62d7d0adf30bb150d12a6347d15732a04d05e476dc"
                   "2c4d53a8af47cb38b"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   EMPTY_MSG,
                   "116adedf47ab686d7a08423f10f71ec8f7a50377e1b0064a34e10c003ec9ec01e07530d15422b4e"
                   "b44231470388e5c1a"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   EMPTY_MSG,
                   "7854122f919247f959d67fa203d21d82492833774cf53d2cff2a140b7613550716c29249efaa647"
                   "7798834bd138397cf"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   EMPTY_MSG,
                   "3d17a14dc514d778ec13054653bfa748666d9c6e0d4d1d75b66c5cadd6506ef4a76967423746a3f"
                   "47118bea059434338"),
        /*
         * The following test vectors where computed using the same algorithm while
         * omitting the message entirely.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   NULL_MSG,
                   "5d466efc7b95beff2bc2e4790e22091afc20afbcbe1e9d3cec9f4bcb468218dd20e133333dc252d"
                   "07d101d4150423b65"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   NULL_MSG,
                   "e4bb15ea89ee2b6e4093f2e95cd931b6abbbeed39a0ee99cda944a6a083b2401034203492fa593d"
                   "cdffd7a1495c3fd2a"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   NULL_MSG,
                   "27d6797656786c57d7bfc0ac25eb421aa6d0ff4864c82792e68d08f7945eb5ba514d1c9a5a58398"
                   "0e00b4bda1cbf1656"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   NULL_MSG,
                   "589de498de6c4c596445d6ebec4c29336b15f5feccb4af3a911a28ab0bac78ee81e0218fefaf5f1"
                   "05e7f896d92e1ede1")));

/*
 * Test the RFC 6979 k generation function.
 *
 * RFC 6979 specifies a deterministic way to generate a
 * nonce (k) for ECDSA signatures based on the private key (x)
 * and the message (m). This test verifies that the k generation
 * function produces the expected k value for a given x and m.
 *
 * The first 8 test vectors for this test are taken from RFC 6979 Appendix A2.6
 * for the P-384 curve.
 */
TEST_P(RFC6979KGenerationTestP384, Test_rfc6979_k_P_384_generation) {
    auto [digest_algorithm, m_octets, k_str] = GetParam();

    auto x_octets = std::vector<uint8_t>{0x6b, 0x9d, 0x3d, 0xad, 0x2e, 0x1b, 0x8c, 0x1c, 0x05, 0xb1,
                                         0x98, 0x75, 0xb6, 0x65, 0x9f, 0x4d, 0xe2, 0x3c, 0x3b, 0x66,
                                         0x7b, 0xf2, 0x97, 0xba, 0x9a, 0xa4, 0x77, 0x40, 0x78, 0x71,
                                         0x37, 0xd8, 0x96, 0xd5, 0x72, 0x4e, 0x4c, 0x70, 0xa8, 0x25,
                                         0xf8, 0x72, 0xc9, 0xea, 0x60, 0xd2, 0xed, 0xf5};

    auto q = bssl::UniquePtr<BIGNUM>(BN_new());
    BIGNUM* q_ptr = q.get();
    ASSERT_EQ(96,
              BN_hex2bn(&q_ptr,
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248"
                        "B0A77AECEC196ACCC52973"));

    auto k = bssl::UniquePtr<BIGNUM>(BN_new());
    BIGNUM* k_ptr = k.get();
    ASSERT_EQ(96, BN_hex2bn(&k_ptr, k_str.c_str()));

    auto result = __n20_testing_rfc6979_k_generation(x_octets, m_octets, digest_algorithm, q.get());
    ASSERT_TRUE(std::holds_alternative<bssl::UniquePtr<BIGNUM>>(result));

    auto got_k = std::get<bssl::UniquePtr<BIGNUM>>(result).get();

    ASSERT_EQ(0, BN_cmp(k.get(), got_k)) << BN_bn2hex(got_k);
}
