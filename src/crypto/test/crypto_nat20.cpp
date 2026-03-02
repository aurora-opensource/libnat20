/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
 *
 * This work is dual licensed.
 * You may use it under Apache-2.0 or GPL-2.0 at your option.
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
 *
 * OR
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "crypto_nat20.h"

#include <gtest/gtest.h>
#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/crypto/nat20/rfc6979.h>
#include <nat20/crypto/nat20/sha.h>
#include <nat20/error.h>
#include <nat20/testing/test_utils.h>
#include <nat20/testing/test_vector_reader.h>
#include <nat20/types.h>

#include <memory>
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

std::optional<std::vector<uint8_t>> const SAMPLE_MSG = {{'s', 'a', 'm', 'p', 'l', 'e'}};
std::optional<std::vector<uint8_t>> const TEST_MSG = {{'t', 'e', 's', 't'}};
std::optional<std::vector<uint8_t>> const EMPTY_MSG = {{}};
std::optional<std::vector<uint8_t>> const NULL_MSG = std::nullopt;

class Nat20RFC6979KGenerationTestP256
    : public testing::TestWithParam<std::tuple<n20_crypto_digest_algorithm_t,
                                               std::optional<std::vector<uint8_t>>,
                                               std::string,
                                               std::string>> {};

INSTANTIATE_TEST_CASE_P(
    Nat20RFC6979KGenerationTestInstance,
    Nat20RFC6979KGenerationTestP256,
    testing::Values(
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   SAMPLE_MSG,
                   "103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473",
                   "273e7b85422107fc55b45c5db23e7021288e7fe8ee06f9164d776f65945da209"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   SAMPLE_MSG,
                   "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
                   "8e83dc490bc5fc4d5992bd63cd87f254adffcb930f8a8011702a88870f638fdb"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   SAMPLE_MSG,
                   "09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4",
                   "6a344c70adaa24d1f758c8fca623efa725f3857e01757e2d99cdc6d73501d5c5"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   SAMPLE_MSG,
                   "5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5",
                   "93a91fa90cbea561665d37f94431ca1a40a817981ae7181d2194f44a1168e19b"),
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   TEST_MSG,
                   "669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7",
                   "7e4af2397675acb54c095c7e07c11e59729e74198ce1cf5806a9a8d271f4c9aa"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   TEST_MSG,
                   "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
                   "ed6fc87dcb558274e84d7d3799f12f8f279c07fa5301a7cd33f0ad9866cd8ca0"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   TEST_MSG,
                   "16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8",
                   "83092c432d924d545245519fb7ebe88214028dce01328ffd435835340d5f8774"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   TEST_MSG,
                   "6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F",
                   "0ab4cb1796526c9eef6a74bf8313338d172bb0ee7434b6daeea9df348c29b019"),
        /*
         * The following test vectors where computed using the same algorithm while
         * verifying that the intermediate h1_digest is equal to the digest of the
         * empty message for the corresponding digest algorithms.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   EMPTY_MSG,
                   "e6a082bf249944014406a9280befd1aa2369a98b31fe1eed9fa91098363cd60b",
                   "9027a9799ed42fce1fd0b8d1ec68f9094c4de0fa34b0901e5dcdec5e357e7b5a"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   EMPTY_MSG,
                   "3c7eca3784e9809c912f21d6c1894e70b8a709d3222982ae499b270bac245246",
                   "8028d2cb169ac62cf40d7ec556966a730dd562d2cc0bad4ba46665d72605d634"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   EMPTY_MSG,
                   "bbbe969da70f10ecb28a059dad2589817cd64d7917dabb82cb6c52164415d530",
                   "5f9e27991933bf22a7e8fc2842ba944912def5eb2faf93eff4662f4d5e4394d7"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   EMPTY_MSG,
                   "2d255f20e3aa839fcb4116e2819568ae8e15be3db130bac7c38ec5eba003ccd2",
                   "b5592a850280dfa59583fdd2b8af27dfd8751b17552e270b9cda01b677784b2c"),
        /*
         * The following test vectors where computed using the same algorithm while
         * omitting the message entirely.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   NULL_MSG,
                   "402ea153bb5ccccc8f87abb88a647a27eb2e7a51b92ece286dcb991e83a7efd3",
                   "06eb01bd23070c66badeb84d411e78daa6323f733ed0ad91d95b894a4584fedf"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   NULL_MSG,
                   "c3e0374fbfa3752b760374a626c649ed798b7146e869c2482cb17a54c94ebae3",
                   "8d738cbc6f3a28d6ace66ce605cb9d1dca1d401004757b4e57770cb7795160cf"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   NULL_MSG,
                   "b868001fb7f5ed86ae0de3db439fe10bc56bf63ce776aeb6a2b011283d19ca17",
                   "3b080f3774e8e3c4f6c3d6e3b490138fc858921a14dbea3cb9832677fd4f713f"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   NULL_MSG,
                   "bbbb46f35c82170d767ed845f4a7d942bcc3ccc82bb39eb0f3b607ee18867ea2",
                   "7af6da172c2b73f5b149834670d666d7f0901726434f7949dabc78c5b976de80")));

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
TEST_P(Nat20RFC6979KGenerationTestP256, Test_rfc6979_k_P_256_generation) {
    auto [digest_algorithm, m_octets, k_str, k1_str] = GetParam();

    n20_crypto_digest_context_t* ctx = nullptr;
    ASSERT_EQ(n20_error_ok_e, n20_crypto_nat20_open(&ctx));
    auto ctx_ptr_guard =
        std::unique_ptr<n20_crypto_digest_context_t, decltype(&n20_crypto_nat20_close)>(
            ctx, n20_crypto_nat20_close);

    auto x_octets =
        std::vector<uint8_t>{0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
                             0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
                             0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

    n20_slice_t x_octets_slice = {x_octets.size(), (uint8_t*)x_octets.data()};
    n20_slice_t m_octets_slice = N20_SLICE_NULL;
    n20_crypto_gather_list_t m_octets_gather_list = {1, &m_octets_slice};
    n20_crypto_gather_list_t const* m_octets_gather_list_ptr = nullptr;
    if (m_octets.has_value()) {
        m_octets_slice = {m_octets->size(), (uint8_t*)m_octets->data()};
        m_octets_gather_list_ptr = &m_octets_gather_list;
    }

    uint32_t k_bits[8];
    n20_bn_t k_bn = {8, k_bits};

    auto err = n20_rfc6979_k_generation(ctx,
                                        digest_algorithm,
                                        n20_crypto_key_type_secp256r1_e,
                                        &x_octets_slice,
                                        m_octets_gather_list_ptr,
                                        &k_bn,
                                        0);
    ASSERT_EQ(n20_error_ok_e, err);

    auto want_k = hex_string_parser::parse(k_str);
    ASSERT_TRUE(want_k.has_value());
    std::vector<uint8_t> got_k(want_k->size());

    n20_bn_to_octets(got_k.data(), got_k.size(), &k_bn);

    ASSERT_EQ(want_k.value(), got_k) << "Expected k: " << hex(want_k.value()) << std::endl
                                     << "Actual k: " << hex(got_k) << std::endl;

    err = n20_rfc6979_k_generation(ctx,
                                   digest_algorithm,
                                   n20_crypto_key_type_secp256r1_e,
                                   &x_octets_slice,
                                   m_octets_gather_list_ptr,
                                   &k_bn,
                                   1);
    ASSERT_EQ(n20_error_ok_e, err);

    auto want_k1 = hex_string_parser::parse(k1_str);
    ASSERT_TRUE(want_k1.has_value());
    std::vector<uint8_t> got_k1(want_k1->size());

    n20_bn_to_octets(got_k1.data(), got_k1.size(), &k_bn);

    ASSERT_EQ(want_k1.value(), got_k1) << "Expected k1: " << hex(want_k1.value()) << std::endl
                                       << "Actual k1: " << hex(got_k1) << std::endl;
}

class Nat20RFC6979KGenerationTestP384
    : public testing::TestWithParam<std::tuple<n20_crypto_digest_algorithm_t,
                                               std::optional<std::vector<uint8_t>>,
                                               std::string,
                                               std::string>> {};

INSTANTIATE_TEST_CASE_P(
    Nat20RFC6979KGenerationTestP384Instance,
    Nat20RFC6979KGenerationTestP384,
    testing::Values(
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   SAMPLE_MSG,
                   "A4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB8083EE4E3C45B06"
                   "A5899EA56C51B5879",
                   "f1706c2c8cc55db3b12d0d33b3c20f1e74b34da5819543b4bea9f578981d822be31dbda24f3c377"
                   "deb85d0efc41fa65b"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   SAMPLE_MSG,
                   "180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C89"
                   "9F9F2EDF9747A9B60",
                   "241bd74f1c179a78a711d90e71fb198b5f9332adb1a0f11dcbb08fa2030279ef72cced0eaad4c72"
                   "3d20f75de4d69430a"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   SAMPLE_MSG,
                   "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA9536"
                   "8623B8C4686915CF9",
                   "9d63ce4c96d070a67f7bee49e870b64838c0ac65bb7440cf46017dca69d35d236219aae5e00a9f0"
                   "1f13e7774be1339fc"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   SAMPLE_MSG,
                   "92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52"
                   "980D0E3AAA5E10EC3",
                   "d9b606bf6d00c9d2525c2dce4e514453140c090d14f79aba1e593ba24141dd738170de878630766"
                   "4144ea0f49216a1ef"),
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   TEST_MSG,
                   "18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E3D33BE4DC5EB888"
                   "6A8ECD093F2935726",
                   "e27a4ad8b6798b2f57943cf0f5a234402f6570f22316cf861731096a6d84b3aea3fe6b526d52b62"
                   "ab23dcccd7d5ebc62"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   TEST_MSG,
                   "0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FAA48DD070BA79921"
                   "A3457ABFF2D630AD7",
                   "793e80637606aeaf668767adbf04f742afb42fd2c97f0d7287d0b77c01e779f971737cf821e4e84"
                   "0d51458a776c72fbf"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   TEST_MSG,
                   "015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA9"
                   "8ADB95837DB8312EA",
                   "9cc959b70dd7367bc45ead8352b899ea744e5e94f6524f0cd8c21a548ebc562fc7d5329e4d5f906"
                   "a0cff9c2157105309"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   TEST_MSG,
                   "3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE0E2CC8A136036DC"
                   "4B9C00E6888F66B6C",
                   "461f5961d27ad17cd4ad2ed2e4480d682c70aee8a0ad73af10c439745ea71b4ee0bbda7b43312b1"
                   "339f1c90300c506e5"),
        /*
         * The following test vectors where computed using the same algorithm while
         * verifying that the intermediate h1_digest is equal to the digest of the
         * empty message for the corresponding digest algorithms.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   EMPTY_MSG,
                   "9f505a478bed79931bfddfea0b9716f70e40f62d7d0adf30bb150d12a6347d15732a04d05e476dc"
                   "2c4d53a8af47cb38b",
                   "af9dc3599ab91f5516da8c2aba785e8d57a84628e5e946d0542d155a3e23d221d3ad231e682c8d7"
                   "c03d79ea5040499aa"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   EMPTY_MSG,
                   "116adedf47ab686d7a08423f10f71ec8f7a50377e1b0064a34e10c003ec9ec01e07530d15422b4e"
                   "b44231470388e5c1a",
                   "8c9e00b4398d819448f99bef29e19cba04c4b760820f58210756119d8381dc319182fca72ae7f20"
                   "7eb86cae735dce320"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   EMPTY_MSG,
                   "7854122f919247f959d67fa203d21d82492833774cf53d2cff2a140b7613550716c29249efaa647"
                   "7798834bd138397cf",
                   "233d8b73324b3b28d30e00dabae0ebd886f4f5bd24f44cc8ce3efba6ba5cdb232970bdd73cc4782"
                   "f23b51582ad7888ae"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   EMPTY_MSG,
                   "3d17a14dc514d778ec13054653bfa748666d9c6e0d4d1d75b66c5cadd6506ef4a76967423746a3f"
                   "47118bea059434338",
                   "fe4308d5954e2ade6cf8ae3d42d291161dc5a73b00e42cd5168bc7fdb79a15091dab8cb541d2e24"
                   "804fd7b1ddbd8a9fc"),
        /*
         * The following test vectors where computed using the same algorithm while
         * omitting the message entirely.
         */
        std::tuple(n20_crypto_digest_algorithm_sha2_224_e,
                   NULL_MSG,
                   "5d466efc7b95beff2bc2e4790e22091afc20afbcbe1e9d3cec9f4bcb468218dd20e133333dc252d"
                   "07d101d4150423b65",
                   "1d5685b7e0a9c962c605f898304ce7c7e9959056ad6b379e844ffc6f15558c86577b88e3bbbf813"
                   "eb8e1acac2ea4e387"),
        std::tuple(n20_crypto_digest_algorithm_sha2_256_e,
                   NULL_MSG,
                   "e4bb15ea89ee2b6e4093f2e95cd931b6abbbeed39a0ee99cda944a6a083b2401034203492fa593d"
                   "cdffd7a1495c3fd2a",
                   "36cfa7daff14401fab1c237cee3acb3423b391ee93ed8ebded9b48d5c892677bfebf41a7a63d27f"
                   "b63845203ad195899"),
        std::tuple(n20_crypto_digest_algorithm_sha2_384_e,
                   NULL_MSG,
                   "27d6797656786c57d7bfc0ac25eb421aa6d0ff4864c82792e68d08f7945eb5ba514d1c9a5a58398"
                   "0e00b4bda1cbf1656",
                   "9724b23faa2a7dacbdcc1408b97ea97d080513492275e47242fd24316ac667f8175e038d3d6fce7"
                   "81cda89facd4ecf86"),
        std::tuple(n20_crypto_digest_algorithm_sha2_512_e,
                   NULL_MSG,
                   "589de498de6c4c596445d6ebec4c29336b15f5feccb4af3a911a28ab0bac78ee81e0218fefaf5f1"
                   "05e7f896d92e1ede1",
                   "460057d0836f0baf91be9dc87b64fc42de6333eef1962d65c5a1783847d2ece1dc1699823955505"
                   "8195abef432e517ba")));

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
TEST_P(Nat20RFC6979KGenerationTestP384, Test_rfc6979_k_P_384_generation) {
    auto [digest_algorithm, m_octets, k_str, k1_str] = GetParam();

    n20_crypto_digest_context_t* ctx = nullptr;
    ASSERT_EQ(n20_error_ok_e, n20_crypto_nat20_open(&ctx));
    auto ctx_ptr_guard =
        std::unique_ptr<n20_crypto_digest_context_t, decltype(&n20_crypto_nat20_close)>(
            ctx, n20_crypto_nat20_close);

    auto x_octets = std::vector<uint8_t>{0x6b, 0x9d, 0x3d, 0xad, 0x2e, 0x1b, 0x8c, 0x1c, 0x05, 0xb1,
                                         0x98, 0x75, 0xb6, 0x65, 0x9f, 0x4d, 0xe2, 0x3c, 0x3b, 0x66,
                                         0x7b, 0xf2, 0x97, 0xba, 0x9a, 0xa4, 0x77, 0x40, 0x78, 0x71,
                                         0x37, 0xd8, 0x96, 0xd5, 0x72, 0x4e, 0x4c, 0x70, 0xa8, 0x25,
                                         0xf8, 0x72, 0xc9, 0xea, 0x60, 0xd2, 0xed, 0xf5};

    n20_slice_t x_octets_slice = {x_octets.size(), (uint8_t*)x_octets.data()};
    n20_slice_t m_octets_slice = N20_SLICE_NULL;
    n20_crypto_gather_list_t m_octets_gather_list = {1, &m_octets_slice};
    n20_crypto_gather_list_t const* m_octets_gather_list_ptr = nullptr;
    if (m_octets.has_value()) {
        m_octets_slice = {m_octets->size(), (uint8_t*)m_octets->data()};
        m_octets_gather_list_ptr = &m_octets_gather_list;
    }

    uint32_t k_bits[12];
    n20_bn_t k_bn = {12, k_bits};

    auto err = n20_rfc6979_k_generation(ctx,
                                        digest_algorithm,
                                        n20_crypto_key_type_secp384r1_e,
                                        &x_octets_slice,
                                        m_octets_gather_list_ptr,
                                        &k_bn,
                                        0);
    ASSERT_EQ(n20_error_ok_e, err);

    auto want_k = hex_string_parser::parse(k_str);
    ASSERT_TRUE(want_k.has_value());
    std::vector<uint8_t> got_k(want_k->size());

    n20_bn_to_octets(got_k.data(), got_k.size(), &k_bn);

    ASSERT_EQ(want_k.value(), got_k) << "Expected k: " << hex(want_k.value()) << std::endl
                                     << "Actual k: " << hex(got_k) << std::endl;

    err = n20_rfc6979_k_generation(ctx,
                                   digest_algorithm,
                                   n20_crypto_key_type_secp384r1_e,
                                   &x_octets_slice,
                                   m_octets_gather_list_ptr,
                                   &k_bn,
                                   1);
    ASSERT_EQ(n20_error_ok_e, err);

    auto want_k1 = hex_string_parser::parse(k1_str);
    ASSERT_TRUE(want_k1.has_value());
    std::vector<uint8_t> got_k1(want_k1->size());

    n20_bn_to_octets(got_k1.data(), got_k1.size(), &k_bn);

    ASSERT_EQ(want_k1.value(), got_k1) << "Expected k1: " << hex(want_k1.value()) << std::endl
                                       << "Actual k1: " << hex(got_k1) << std::endl;
}
