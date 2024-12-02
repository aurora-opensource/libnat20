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

#include <string>

class BooleanTest : public testing::TestWithParam<std::tuple<bool, std::vector<uint8_t>>> {};

std::vector<uint8_t> const ENCODED_FALSE = {0x01, 0x01, 0x00};
std::vector<uint8_t> const ENCODED_TRUE = {0x01, 0x01, 0xff};

INSTANTIATE_TEST_CASE_P(Asn1BooleanTest,
                        BooleanTest,
                        testing::Values(std::tuple(false, ENCODED_FALSE),
                                        std::tuple(true, ENCODED_TRUE)));

TEST_P(BooleanTest, BooleanEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_boolean(&s, i);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

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

class OctetStringTest
    : public testing::TestWithParam<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>> {};

std::vector<uint8_t> const BYTES_ZERO = {};
std::vector<uint8_t> const BYTES_ONE = {0x03};
std::vector<uint8_t> const BYTES_TWO = {0x02, 0x01};
std::vector<uint8_t> const BYTES_THREE = {0xff, 0x00, 0xa1};

std::vector<uint8_t> const ENCODED_BYTES_ZERO = {0x04, 0x0};
std::vector<uint8_t> const ENCODED_BYTES_ONE = {0x04, 0x01, 0x03};
std::vector<uint8_t> const ENCODED_BYTES_TWO = {0x04, 0x02, 0x02, 0x01};
std::vector<uint8_t> const ENCODED_BYTES_THREE = {0x04, 0x03, 0xff, 0x00, 0xa1};

INSTANTIATE_TEST_CASE_P(Asn1OctetStringTest,
                        OctetStringTest,
                        testing::Values(std::tuple(BYTES_ZERO, ENCODED_BYTES_ZERO),
                                        std::tuple(BYTES_ONE, ENCODED_BYTES_ONE),
                                        std::tuple(BYTES_TWO, ENCODED_BYTES_TWO),
                                        std::tuple(BYTES_THREE, ENCODED_BYTES_THREE)));

TEST_P(OctetStringTest, OctetStringEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_octetstring(&s, i.data(), i.size());
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class NullTest : public testing::Test {};

std::vector<uint8_t> const ENCODED_NULL = {0x05, 0x00};

TEST(NullTest, NullEncoding) {
    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_null(&s);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_NULL.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_NULL, got);
}

class PrintableStringTest
    : public testing::TestWithParam<std::tuple<std::string, std::vector<uint8_t>>> {};

std::vector<uint8_t> const ENCODED_STRING_EMPTY = {0x13, 0x00};
std::vector<uint8_t> const ENCODED_STRING_NOT_EMPTY = {0x13, 0x01, 0x7e};
std::vector<uint8_t> const ENCODED_STRING_FULL_CHARSET = {
    0x13, 0x4a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
    0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x20, 0x27, 0x28, 0x29, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x3a, 0x3d, 0x3f};

INSTANTIATE_TEST_CASE_P(
    Asn1PrintableStringTest,
    PrintableStringTest,
    testing::Values(
        std::tuple("", ENCODED_STRING_EMPTY),
        std::tuple("~", ENCODED_STRING_NOT_EMPTY),
        std::tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?",
                   ENCODED_STRING_FULL_CHARSET)));

TEST_P(PrintableStringTest, OctetStringEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_printablestring(&s, i.c_str());
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class GeneralizedTimeTest
    : public testing::TestWithParam<std::tuple<std::string, std::vector<uint8_t>>> {};

std::vector<uint8_t> const ENCODED_TIME_ZERO = {0x18,
                                          0x0f,
                                          0x30,
                                          0x30,
                                          0x30,
                                          0x31,
                                          0x30,
                                          0x31,
                                          0x30,
                                          0x31,
                                          0x30,
                                          0x30,
                                          0x30,
                                          0x30,
                                          0x30,
                                          0x30,
                                          0x5a};
std::vector<uint8_t> const ENCODED_TIME_NOT_ZERO = {0x18,
                                              0x0f,
                                              0x32,
                                              0x30,
                                              0x32,
                                              0x34,
                                              0x31,
                                              0x31,
                                              0x32,
                                              0x37,
                                              0x30,
                                              0x33,
                                              0x31,
                                              0x34,
                                              0x35,
                                              0x38,
                                              0x5a};

INSTANTIATE_TEST_CASE_P(Asn1GeneralizedTimeTest,
                        GeneralizedTimeTest,
                        testing::Values(std::tuple("00010101000000Z", ENCODED_TIME_ZERO),
                                        std::tuple("20241127031458Z", ENCODED_TIME_NOT_ZERO)));

TEST_P(GeneralizedTimeTest, OctetStringEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_generalized_time(&s, i.c_str());
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}
