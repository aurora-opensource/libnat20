/*
 * Copyright 2026 Aurora Operations, Inc.
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

#include <gtest/gtest.h>
#include <nat20/cose.h>
#include <nat20/stream.h>
#include <nat20/testing/test_utils.h>

static uint8_t const TEST_X_COORDINATE[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

static uint8_t const TEST_Y_COORDINATE[] = {
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb};

static uint8_t const TEST_PRIVATE_KEY[] = {
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc};

// clang-format off
std::vector<uint8_t> const TEST_COSE_PUBLIC_KEY_ES384 = {
    // Map header (6 items)
    0xa6,
    // kty: EC2 (2)
    0x01, 0x02,
    // alg: ES384 (-35)
    0x03, 0x38, 0x22,
    // key ops: verify (2)
    0x04, 0x81, 0x02,
    // crv: P-384 (2)
    0x20, 0x02,
    // x coordinate label
    0x21,
    // x coordinate byte string with 48 bytes
    0x58, 0x30,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // y coordinate label
    0x22,
    // y coordinate byte string with 48 bytes
    0x58, 0x30,
    // y coordinate value
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb
};

std::vector<uint8_t> const TEST_COSE_PRIVATE_PUBLIC_KEY_ES384 = {
    // Map header (7 items)
    0xa7,
    // kty: EC2 (2)
    0x01, 0x02,
    // alg: ES384 (-35)
    0x03, 0x38, 0x22,
    // key ops: sign (1), verify (2)
    0x04, 0x82, 0x01, 0x02,
    // crv: P-384 (2)
    0x20, 0x02,
    // x coordinate label
    0x21,
    // x coordinate byte string with 48 bytes
    0x58, 0x30,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // y coordinate label
    0x22,
    // y coordinate byte string with 48 bytes
    0x58, 0x30,
    // y coordinate value
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    // d (private key) label
    0x23,
    // d (private key) byte string with 48 bytes
    0x58, 0x30,
    // d (private key) value
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};

std::vector<uint8_t> const TEST_COSE_PUBLIC_KEY_ES256 = {
    // Map header (6 items)
    0xa6,
    // kty: EC2 (2)
    0x01, 0x02,
    // alg: ES256 (-7)
    0x03, 0x26,
    // key ops: verify (2)
    0x04, 0x81, 0x02,
    // crv: P-256 (1)
    0x20, 0x01,
    // x coordinate label
    0x21,
    // x coordinate byte string with 32 bytes
    0x58, 0x20,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // y coordinate label
    0x22,
    // y coordinate byte string with 32 bytes
    0x58, 0x20,
    // y coordinate value
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
};

std::vector<uint8_t> const TEST_COSE_PRIVATE_PUBLIC_KEY_ES256 = {
    // Map header (7 items)
    0xa7,
    // kty: EC2 (2)
    0x01, 0x02,
    // alg: ES384 (-7)
    0x03, 0x26,
    // key ops: sign (1), verify (2)
    0x04, 0x82, 0x01, 0x02,
    // crv: P-256 (1)
    0x20, 0x01,
    // x coordinate label
    0x21,
    // x coordinate byte string with 32 bytes
    0x58, 0x20,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // y coordinate label
    0x22,
    // y coordinate byte string with 32 bytes
    0x58, 0x20,
    // y coordinate value
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    // d (private key) label
    0x23,
    // d (private key) byte string with 32 bytes
    0x58, 0x20,
    // d (private key) value
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
};

std::vector<uint8_t> const TEST_COSE_PUBLIC_KEY_EDDSA = {
    // Map header (5 items)
    0xa5,
    // kty: OKP (1)
    0x01, 0x01,
    // alg: EDDSA (-8)
    0x03, 0x27,
    // key ops: verify (2)
    0x04, 0x81, 0x02,
    // crv: ED25519 (6)
    0x20, 0x06,
    // x coordinate label
    0x21,
    // x coordinate byte string with 32 bytes
    0x58, 0x20,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};

std::vector<uint8_t> const TEST_COSE_PRIVATE_PUBLIC_KEY_EDDSA = {
    // Map header (6 items)
    0xa6,
    // kty: OKP (1)
    0x01, 0x01,
    // alg: EDDSA (-8)
    0x03, 0x27,
    // key ops: sign (1), verify (2)
    0x04, 0x82, 0x01, 0x02,
    // crv: ED25519 (6)
    0x20, 0x06,
    // x coordinate label
    0x21,
    // x coordinate byte string with 32 bytes
    0x58, 0x20,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // d (private key) label
    0x23,
    // d (private key) byte string with 32 bytes
    0x58, 0x20,
    // d (private key) value
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
};

std::vector<uint8_t> const TEST_COSE_PUBLIC_KEY_EDDSA_WITH_ALL_OPS = {
    // Map header (5 items)
    0xa5,
    // kty: OKP (1)
    0x01, 0x01,
    // alg: EDDSA (-8)
    0x03, 0x27,
    // key ops: verify (2)
    0x04, 0x8a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    // crv: ED25519 (6)
    0x20, 0x06,
    // x coordinate label
    0x21,
    // x coordinate byte string with 32 bytes
    0x58, 0x20,
    // x coordinate value
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};

// clang-format on

class WriteCoseKeyTestFixture
    : public testing::TestWithParam<std::tuple<n20_cose_key_t, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
    WriteCoseKeyTestCase,
    WriteCoseKeyTestFixture,
    testing::Values(std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)(1 << n20_cose_key_op_verify_e),
                            .algorithm_id = n20_cose_algorithm_id_es384_e,
                            .x = {.size = 48, .buffer = TEST_X_COORDINATE},
                            .y = {.size = 48, .buffer = TEST_Y_COORDINATE},
                            .d = N20_SLICE_NULL,
                        },
                        TEST_COSE_PUBLIC_KEY_ES384),
                    std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)((1 << n20_cose_key_op_verify_e) |
                                                                (1 << n20_cose_key_op_sign_e)),
                            .algorithm_id = n20_cose_algorithm_id_es384_e,
                            .x = {.size = 48, .buffer = TEST_X_COORDINATE},
                            .y = {.size = 48, .buffer = TEST_Y_COORDINATE},
                            .d = {.size = 48, .buffer = TEST_PRIVATE_KEY},
                        },
                        TEST_COSE_PRIVATE_PUBLIC_KEY_ES384),
                    std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)(1 << n20_cose_key_op_verify_e),
                            .algorithm_id = n20_cose_algorithm_id_es256_e,
                            .x = {.size = 32, .buffer = TEST_X_COORDINATE},
                            .y = {.size = 32, .buffer = TEST_Y_COORDINATE},
                            .d = N20_SLICE_NULL,
                        },
                        TEST_COSE_PUBLIC_KEY_ES256),
                    std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)((1 << n20_cose_key_op_verify_e) |
                                                                (1 << n20_cose_key_op_sign_e)),
                            .algorithm_id = n20_cose_algorithm_id_es256_e,
                            .x = {.size = 32, .buffer = TEST_X_COORDINATE},
                            .y = {.size = 32, .buffer = TEST_Y_COORDINATE},
                            .d = {.size = 32, .buffer = TEST_PRIVATE_KEY},
                        },
                        TEST_COSE_PRIVATE_PUBLIC_KEY_ES256),
                    std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)(1 << n20_cose_key_op_verify_e),
                            .algorithm_id = n20_cose_algorithm_id_eddsa_e,
                            .x = {.size = 32, .buffer = TEST_X_COORDINATE},
                            .y = N20_SLICE_NULL,
                            .d = N20_SLICE_NULL,
                        },
                        TEST_COSE_PUBLIC_KEY_EDDSA),
                    std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)((1 << n20_cose_key_op_verify_e) |
                                                                (1 << n20_cose_key_op_sign_e)),
                            .algorithm_id = n20_cose_algorithm_id_eddsa_e,
                            .x = {.size = 32, .buffer = TEST_X_COORDINATE},
                            .y = N20_SLICE_NULL,
                            .d = {.size = 32, .buffer = TEST_PRIVATE_KEY},
                        },
                        TEST_COSE_PRIVATE_PUBLIC_KEY_EDDSA),
                    std::make_tuple(
                        n20_cose_key_t{
                            .key_ops = (n20_cose_key_ops_map_t)(1 << n20_cose_key_op_sign_e |
                                                                1 << n20_cose_key_op_verify_e |
                                                                1 << n20_cose_key_op_encrypt_e |
                                                                1 << n20_cose_key_op_decrypt_e |
                                                                1 << n20_cose_key_op_wrap_e |
                                                                1 << n20_cose_key_op_unwrap_e |
                                                                1 << n20_cose_key_op_derive_key_e |
                                                                1 << n20_cose_key_op_derive_bits_e |
                                                                1 << n20_cose_key_op_mac_sign_e |
                                                                1 << n20_cose_key_op_mac_verify_e),
                            .algorithm_id = n20_cose_algorithm_id_eddsa_e,
                            .x = {.size = 32, .buffer = TEST_X_COORDINATE},
                            .y = N20_SLICE_NULL,
                            .d = N20_SLICE_NULL,
                        },
                        TEST_COSE_PUBLIC_KEY_EDDSA_WITH_ALL_OPS),
                    std::make_tuple(n20_cose_key_t{}, std::vector<uint8_t>{0xf6})));

TEST_P(WriteCoseKeyTestFixture, WriteCoseKeyTest) {
    auto [cose_key, want_encoded] = GetParam();

    n20_stream_t s;
    n20_stream_init(&s, nullptr, 0);

    n20_cose_write_key(&s, &cose_key);

    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    size_t size = n20_stream_byte_count(&s);

    std::vector<uint8_t> got_encoded(size);

    n20_stream_init(&s, got_encoded.data(), got_encoded.size());
    n20_cose_write_key(&s, &cose_key);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));

    ASSERT_EQ(got_encoded, want_encoded)
        << hexdump_side_by_side("Expected:", want_encoded, "Got:     ", got_encoded)
        << "Got as C array: " << hex_as_c_array(got_encoded);
}

TEST(CoseTest, KeyOpsIsSetTest) {
    n20_cose_key_t key = {};

    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_sign_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_verify_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_encrypt_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_decrypt_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_wrap_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_unwrap_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_derive_key_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_derive_bits_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_mac_sign_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_mac_verify_e));

    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_sign_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_verify_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_encrypt_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_decrypt_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_wrap_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_unwrap_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_derive_key_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_derive_bits_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_mac_sign_e);
    n20_cose_key_ops_set(&key.key_ops, n20_cose_key_op_mac_verify_e);

    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_sign_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_verify_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_encrypt_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_decrypt_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_wrap_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_unwrap_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_derive_key_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_derive_bits_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_mac_sign_e));
    ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_mac_verify_e));

    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_sign_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_verify_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_encrypt_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_decrypt_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_wrap_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_unwrap_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_derive_key_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_derive_bits_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_mac_sign_e);
    n20_cose_key_ops_unset(&key.key_ops, n20_cose_key_op_mac_verify_e);

    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_sign_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_verify_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_encrypt_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_decrypt_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_wrap_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_unwrap_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_derive_key_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_derive_bits_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_mac_sign_e));
    ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, n20_cose_key_op_mac_verify_e));

    for (int i = 1; i <= n20_cose_key_op_mac_verify_e; i++) {
        ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, (n20_cose_key_ops_t)i));
        n20_cose_key_ops_set(&key.key_ops, (n20_cose_key_ops_t)i);
        for (int j = 1; j <= n20_cose_key_op_mac_verify_e; j++) {
            if (i == j) {
                ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, (n20_cose_key_ops_t)j));
            } else {
                ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, (n20_cose_key_ops_t)j));
            }
        }
        ASSERT_TRUE(n20_cose_key_ops_is_set(key.key_ops, (n20_cose_key_ops_t)i));
        n20_cose_key_ops_unset(&key.key_ops, (n20_cose_key_ops_t)i);
        ASSERT_FALSE(n20_cose_key_ops_is_set(key.key_ops, (n20_cose_key_ops_t)i));
    }
}

// clang-format off
std::vector<uint8_t> const TEST_COSE_SIGN1_ES256 = {
    // Array of 4 items
    0x84,
    // Byte string of length 3 (protected header)
    0x43,
    //   Map of 1 item: alg: ES256 (-7)
    0xa1, 0x01, 0x26,
    //   Empty map (unprotected header)
    0xa0,
    // Byte string of length 3 (payload): "abc"
    0x43, 0x61, 0x62, 0x63,
    // Byte string of length 64 (signature)
    0x58, 0x40
};

std::vector<uint8_t> const TEST_COSE_SIGN1_ES384 = {
    // Array of 4 items
    0x84,
    // Byte string of length 4 (protected header)
    0x44,
    //   Map of 1 item: alg: ES384 (-35)
    0xa1, 0x01, 0x38, 0x22,
    //   Empty map (unprotected header)
    0xa0,
    // Byte string of length 3 (payload): "abc"
    0x43, 0x61, 0x62, 0x63,
    // Byte string of length 96 (signature)
    0x58, 0x60
};

std::vector<uint8_t> const TEST_COSE_SIGN1_EDDSA = {
    // Array of 4 items
    0x84,
    // Byte string of length 3 (protected header)
    0x43,
    //   Map of 1 item: alg: EDDSA (-8)
    0xa1, 0x01, 0x27,
    //   Empty map (unprotected header)
    0xa0,
    // Byte string of length 3 (payload): "abc"
    0x43, 0x61, 0x62, 0x63,
    // Byte string of length 64 (signature)
    0x58, 0x40
};

std::vector<uint8_t> const TEST_COSE_SIGN1_INVALID_ALG = {
    // Array of 4 items
    0x84,
    // Byte string of length 3 (protected header)
    0x43,
    //   Map of 1 item: alg: 0
    0xa1, 0x01, 0x00,
    //   Empty map (unprotected header)
    0xa0,
    // Byte string of length 4 (payload): "abcd"
    0x44, 0x61, 0x62, 0x63, 0x64,
    // Empty byte string (signature)
    0x40
};
// clang-format on

class WriteCoseSign1TestFixture
    : public testing::TestWithParam<std::tuple<n20_cose_algorithm_id_t,
                                               void (*)(n20_stream_t *, void *),
                                               n20_slice_t,
                                               std::vector<uint8_t>,
                                               size_t,
                                               size_t,
                                               size_t,
                                               size_t>> {};

INSTANTIATE_TEST_CASE_P(
    WriteCoseSign1TestCase,
    WriteCoseSign1TestFixture,
    testing::Values(
        std::make_tuple(
            n20_cose_algorithm_id_es256_e,
            [](n20_stream_t *s, void *ctx) {
                n20_slice_t *payload = (n20_slice_t *)ctx;
                n20_stream_prepend(s, payload->buffer, payload->size);
            },
            (n20_slice_t{.size = 3, .buffer = reinterpret_cast<uint8_t const *>("abc")}),
            TEST_COSE_SIGN1_ES256,
            // protected attributes offset
            1,
            // protected attributes size
            4,
            // payload offset
            6,
            // payload size
            4),
        std::make_tuple(
            n20_cose_algorithm_id_es384_e,
            [](n20_stream_t *s, void *ctx) {
                n20_slice_t *payload = (n20_slice_t *)ctx;
                n20_stream_prepend(s, payload->buffer, payload->size);
            },
            (n20_slice_t{.size = 3, .buffer = reinterpret_cast<uint8_t const *>("abc")}),
            TEST_COSE_SIGN1_ES384,
            // protected attributes offset
            1,
            // protected attributes size
            5,
            // payload offset
            7,
            // payload size
            4),
        std::make_tuple(
            n20_cose_algorithm_id_eddsa_e,
            [](n20_stream_t *s, void *ctx) {
                n20_slice_t *payload = (n20_slice_t *)ctx;
                n20_stream_prepend(s, payload->buffer, payload->size);
            },
            (n20_slice_t{.size = 3, .buffer = reinterpret_cast<uint8_t const *>("abc")}),
            TEST_COSE_SIGN1_EDDSA,
            // protected attributes offset
            1,
            // protected attributes size
            4,
            // payload offset
            6,
            // payload size
            4),
        std::make_tuple(
            // Invalid algorithm ID
            (n20_cose_algorithm_id_t)0,
            [](n20_stream_t *s, void *ctx) {
                n20_slice_t *payload = (n20_slice_t *)ctx;
                n20_stream_prepend(s, payload->buffer, payload->size);
            },
            (n20_slice_t{.size = 4, .buffer = reinterpret_cast<uint8_t const *>("abcd")}),
            TEST_COSE_SIGN1_INVALID_ALG,
            // protected attributes offset
            1,
            // protected attributes size
            4,
            // payload offset
            6,
            // payload size
            5)));

TEST_P(WriteCoseSign1TestFixture, WriteCoseSign1Test) {
    auto [algorithm_id,
          payload_cb,
          payload_ctx,
          want_encoded,
          protected_attributes_offset,
          protected_attributes_size,
          payload_offset,
          payload_size] = GetParam();

    n20_stream_t s;
    n20_stream_init(&s, nullptr, 0);

    n20_slice_t tbs_gather_list[4] = {};

    n20_cose_render_sign1_with_payload(&s, algorithm_id, payload_cb, &payload_ctx, tbs_gather_list);

    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    size_t size = n20_stream_byte_count(&s);

    std::vector<uint8_t> got_encoded(size);

    n20_stream_init(&s, got_encoded.data(), got_encoded.size());

    n20_cose_render_sign1_with_payload(&s, algorithm_id, payload_cb, &payload_ctx, tbs_gather_list);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));

    ASSERT_EQ(got_encoded, want_encoded)
        << hexdump_side_by_side("Expected:", want_encoded, "Got:", got_encoded)
        << "Got as C array: " << hex_as_c_array(got_encoded);

    ASSERT_EQ(tbs_gather_list[0].size, 12);
    ASSERT_EQ(memcmp(tbs_gather_list[0].buffer, (uint8_t *)"\x84\x6aSignature1", 12), 0);
    ASSERT_EQ(tbs_gather_list[1].size, protected_attributes_size);
    ASSERT_EQ(tbs_gather_list[1].buffer, got_encoded.data() + protected_attributes_offset);
    ASSERT_EQ(tbs_gather_list[2].size, 1);
    ASSERT_EQ(memcmp(tbs_gather_list[2].buffer, (uint8_t *)"\x40", 1), 0);
    ASSERT_EQ(tbs_gather_list[3].size, payload_size);
    ASSERT_EQ(tbs_gather_list[3].buffer, got_encoded.data() + payload_offset);
}
