/*
 * Copyright 2024 Aurora Operations, Inc.
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

#include <gtest/gtest.h>
#include <nat20/asn1.h>

class IntegerTest : public testing::TestWithParam<std::tuple<int64_t, std::vector<uint8_t>>> {};

std::vector<uint8_t> const ENCODED_0 = {0x02, 0x01, 0x0};
std::vector<uint8_t> const ENCODED_127 = {0x02, 0x01, 0x7f};
std::vector<uint8_t> const ENCODED_128 = {0x02, 0x02, 0x00, 0x80};
std::vector<uint8_t> const ENCODED_256 = {0x02, 0x02, 0x01, 0x00};
std::vector<uint8_t> const ENCODED_MINUS_128 = {0x02, 0x01, 0x80};
std::vector<uint8_t> const ENCODED_MINUS_129 = {0x02, 0x02, 0xff, 0x7f};

INSTANTIATE_TEST_CASE_P(Asn1IntegerTest,
                        IntegerTest,
                        testing::Values(std::tuple(0, ENCODED_0),
                                        std::tuple(127, ENCODED_127),
                                        std::tuple(128, ENCODED_128),
                                        std::tuple(256, ENCODED_256),
                                        std::tuple(-128, ENCODED_MINUS_128),
                                        std::tuple(-129, ENCODED_MINUS_129)));

TEST_P(IntegerTest, IntegerEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_int64(&s, i);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class BitStringTest : public testing::TestWithParam<std::tuple<size_t, std::vector<uint8_t>>> {};

std::vector<uint8_t> const PROTO_BITS = {0x6e, 0x5d, 0xc5};

std::vector<uint8_t> const ENCODED_BITS_16 = {0x03, 0x03, 0x00, 0x6e, 0x5d};
std::vector<uint8_t> const ENCODED_BITS_17 = {0x03, 0x04, 0x07, 0x6e, 0x5d, 0x80};
std::vector<uint8_t> const ENCODED_BITS_18 = {0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0};
std::vector<uint8_t> const ENCODED_BITS_23 = {0x03, 0x04, 0x01, 0x6e, 0x5d, 0xc4};
std::vector<uint8_t> const ENCODED_BITS_24 = {0x03, 0x04, 0x00, 0x6e, 0x5d, 0xc5};

INSTANTIATE_TEST_CASE_P(Asn1BitStringTest,
                        BitStringTest,
                        testing::Values(std::tuple(16, ENCODED_BITS_16),
                                        std::tuple(17, ENCODED_BITS_17),
                                        std::tuple(18, ENCODED_BITS_18),
                                        std::tuple(23, ENCODED_BITS_23),
                                        std::tuple(24, ENCODED_BITS_24)));

TEST_P(BitStringTest, BitStringEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_bitstring(&s, PROTO_BITS.data(), i);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}
