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

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

class HeaderTest : public testing::TestWithParam<
                       std::tuple<n20_asn1_class_t, bool, uint32_t, size_t, std::vector<uint8_t>>> {
};

std::vector<uint8_t> const ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_0_LEN_0 = {0x00, 0x00};
std::vector<uint8_t> const ENCODED_CLASS_1_CONSTRUCTED_FALSE_TAG_0_LEN_0 = {0x40, 0x00};
std::vector<uint8_t> const ENCODED_CLASS_0_CONSTRUCTED_TRUE_TAG_0_LEN_0 = {0x20, 0x00};
std::vector<uint8_t> const ENCODED_CLASS_1_CONSTRUCTED_TRUE_TAG_0_LEN_0 = {0x60, 0x00};

std::vector<uint8_t> const ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_8_LEN_0 = {0x08, 0x00};
std::vector<uint8_t> const ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_500_LEN_0 = {
    0x1f, 0x83, 0x74, 0x00};
std::vector<uint8_t> const ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_0_LEN_8 = {0x00, 0x08};
std::vector<uint8_t> const ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_0_LEN_500 = {
    0x00, 0x82, 0x01, 0xf4};

std::vector<uint8_t> const ENCODED_CLASS_2_CONSTRUCTED_TRUE_TAG_808_LEN_450 = {
    0xbf, 0x86, 0x28, 0x82, 0x01, 0xc2};

INSTANTIATE_TEST_CASE_P(
    Asn1HeaderTest,
    HeaderTest,
    testing::Values(
        std::tuple(0, false, 0, 0, ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_0_LEN_0),
        std::tuple(1, false, 0, 0, ENCODED_CLASS_1_CONSTRUCTED_FALSE_TAG_0_LEN_0),
        std::tuple(0, true, 0, 0, ENCODED_CLASS_0_CONSTRUCTED_TRUE_TAG_0_LEN_0),
        std::tuple(1, true, 0, 0, ENCODED_CLASS_1_CONSTRUCTED_TRUE_TAG_0_LEN_0),

        std::tuple(0, false, 8, 0, ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_8_LEN_0),
        std::tuple(0, false, 500, 0, ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_500_LEN_0),
        std::tuple(0, false, 0, 8, ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_0_LEN_8),
        std::tuple(0, false, 0, 500, ENCODED_CLASS_0_CONSTRUCTED_FALSE_TAG_0_LEN_500),

        std::tuple(2, true, 808, 450, ENCODED_CLASS_2_CONSTRUCTED_TRUE_TAG_808_LEN_450)));

TEST_P(HeaderTest, HeaderEncoding) {
    auto [class_, constructed, tag, len, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_header(&s, class_, constructed, tag, len);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}
class HeaderWithContentTest
    : public testing::TestWithParam<
          std::tuple<void (*)(n20_asn1_stream_t *, void *), void *, std::vector<uint8_t>>> {};

void noop(n20_asn1_stream_t *s, void *cb_context) {}

void prepend_five_zeros(n20_asn1_stream_t *s, void *cb_context) {
    std::vector<uint8_t> zeros(5, 0);

    n20_asn1_stream_prepend(s, zeros.data(), zeros.size());
}

void prepend_zeros(n20_asn1_stream_t *s, void *cb_context) {
    size_t const *size = (size_t const *)cb_context;
    std::vector<uint8_t> zeros(*size, 0);

    n20_asn1_stream_prepend(s, zeros.data(), zeros.size());
}

size_t const EIGHT = 8;

std::vector<uint8_t> const ENCODED_HEADER_WITH_CONTENT_NOOP = {0x00, 0x00};
std::vector<uint8_t> const ENCODED_HEADER_WITH_CONTENT_FIVE_ZEROS = {
    0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00};
std::vector<uint8_t> const ENCODED_HEADER_WITH_CONTENT_EIGHT_ZEROS = {
    0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

INSTANTIATE_TEST_CASE_P(
    Asn1HeaderWithContentTest,
    HeaderWithContentTest,
    testing::Values(std::tuple(nullptr, nullptr, ENCODED_HEADER_WITH_CONTENT_NOOP),
                    std::tuple(&noop, nullptr, ENCODED_HEADER_WITH_CONTENT_NOOP),
                    std::tuple(&prepend_five_zeros, nullptr, ENCODED_HEADER_WITH_CONTENT_FIVE_ZEROS),
                    std::tuple(&prepend_zeros, (void*)&EIGHT, ENCODED_HEADER_WITH_CONTENT_EIGHT_ZEROS)));

TEST_P(HeaderWithContentTest, HeaderWithContentEncoding) {
    auto [content_cb, cb_context, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_header_with_content(&s, 0, 0, 0, content_cb, cb_context);
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

class IntegerTest : public testing::TestWithParam<
                        std::tuple<std::vector<uint8_t>, bool const, std::vector<uint8_t>>> {};

std::vector<uint8_t> const BYTES_EMPTY = {};
std::vector<uint8_t> const BYTES_0 = {0x00};
std::vector<uint8_t> const BYTES_1 = {0x01};
std::vector<uint8_t> const BYTES_127 = {0x7f};
std::vector<uint8_t> const BYTES_128 = {0x80};
std::vector<uint8_t> const BYTES_128_PADDED = {0x00, 0x80};
std::vector<uint8_t> const BYTES_256_BIG_ENDIAN = {0x01, 0x00};
std::vector<uint8_t> const BYTES_7355608_BIG_ENDIAN = {0x70, 0x3c, 0xd8};
std::vector<uint8_t> const BYTES_7355608_BIG_ENDIAN_PADDED = {0x00, 0x70, 0x3c, 0xd8};
std::vector<uint8_t> const BYTES_9223372036854775808_BIG_ENDIAN = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
std::vector<uint8_t> const BYTES_MINUS_128_BIG_ENDIAN = {0xff, 0x80};
std::vector<uint8_t> const BYTES_MINUS_129_BIG_ENDIAN = {0xff, 0x7f};
std::vector<uint8_t> const BYTES_MINUS_129_BIG_ENDIAN_PADDED = {0xff, 0xff, 0x7f};

std::vector<uint8_t> const ENCODED_0 = {0x02, 0x01, 0x0};
std::vector<uint8_t> const ENCODED_127 = {0x02, 0x01, 0x7f};
std::vector<uint8_t> const ENCODED_128 = {0x02, 0x02, 0x00, 0x80};
std::vector<uint8_t> const ENCODED_256 = {0x02, 0x02, 0x01, 0x00};
std::vector<uint8_t> const ENCODED_7355608 = {0x02, 0x03, 0x70, 0x3c, 0xd8};
std::vector<uint8_t> const ENCODED_9223372036854775808 = {
    0x02, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
std::vector<uint8_t> const ENCODED_MINUS_128 = {0x02, 0x01, 0x80};
std::vector<uint8_t> const ENCODED_MINUS_129 = {0x02, 0x02, 0xff, 0x7f};

INSTANTIATE_TEST_CASE_P(
    Asn1IntegerTest,
    IntegerTest,
    testing::Values(
        std::tuple(BYTES_EMPTY, false, ENCODED_NULL),
        std::tuple(BYTES_0, false, ENCODED_0),
        std::tuple(BYTES_127, false, ENCODED_127),
        std::tuple(BYTES_128, false, ENCODED_128),
        std::tuple(BYTES_128_PADDED, false, ENCODED_128),
        std::tuple(BYTES_256_BIG_ENDIAN, false, ENCODED_256),
        std::tuple(BYTES_7355608_BIG_ENDIAN, false, ENCODED_7355608),
        std::tuple(BYTES_7355608_BIG_ENDIAN_PADDED, false, ENCODED_7355608),
        std::tuple(BYTES_9223372036854775808_BIG_ENDIAN, false, ENCODED_9223372036854775808),
        std::tuple(BYTES_MINUS_128_BIG_ENDIAN, true, ENCODED_MINUS_128),
        std::tuple(BYTES_MINUS_129_BIG_ENDIAN, true, ENCODED_MINUS_129),
        std::tuple(BYTES_MINUS_129_BIG_ENDIAN_PADDED, true, ENCODED_MINUS_129)));

TEST_P(IntegerTest, IntegerEncodingBigEndian) {
    auto [bytes, i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_integer(&s, bytes.data(), bytes.size(), false, i);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

TEST_P(IntegerTest, IntegerEncodingLittleEndian) {
    auto [bytes, i, expected] = GetParam();
    std::vector<uint8_t> bytes_reversed(bytes.rbegin(), bytes.rend());

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_integer(&s, bytes_reversed.data(), bytes.size(), true, i);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class Int64Test : public testing::TestWithParam<
                      std::tuple<std::variant<uint64_t, int64_t>, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(Asn1Int64Test,
                        Int64Test,
                        testing::Values(std::tuple(0UL, ENCODED_0),
                                        std::tuple(127UL, ENCODED_127),
                                        std::tuple(128UL, ENCODED_128),
                                        std::tuple(256UL, ENCODED_256),
                                        std::tuple(0L, ENCODED_0),
                                        std::tuple(127L, ENCODED_127),
                                        std::tuple(128L, ENCODED_128),
                                        std::tuple(256L, ENCODED_256),
                                        std::tuple(-128L, ENCODED_MINUS_128),
                                        std::tuple(-129L, ENCODED_MINUS_129)));

TEST_P(Int64Test, Int64Encoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    if (uint64_t const *ptr = std::get_if<uint64_t>(&i)) {
        n20_asn1_uint64(&s, *ptr);
    }
    if (int64_t const *ptr = std::get_if<int64_t>(&i)) {
        n20_asn1_int64(&s, *ptr);
    }
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class BitStringTest : public testing::TestWithParam<
                          std::tuple<std::vector<uint8_t>, size_t, std::vector<uint8_t>>> {};

std::vector<uint8_t> const PROTO_BITS_EMPTY = {};
std::vector<uint8_t> const PROTO_BITS = {0x6e, 0x5d, 0xc5};

std::vector<uint8_t> const ENCODED_BITS_EMPTY = {0x03, 0x01, 0x00};
std::vector<uint8_t> const ENCODED_BITS_16 = {0x03, 0x03, 0x00, 0x6e, 0x5d};
std::vector<uint8_t> const ENCODED_BITS_17 = {0x03, 0x04, 0x07, 0x6e, 0x5d, 0x80};
std::vector<uint8_t> const ENCODED_BITS_18 = {0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0};
std::vector<uint8_t> const ENCODED_BITS_23 = {0x03, 0x04, 0x01, 0x6e, 0x5d, 0xc4};
std::vector<uint8_t> const ENCODED_BITS_24 = {0x03, 0x04, 0x00, 0x6e, 0x5d, 0xc5};

INSTANTIATE_TEST_CASE_P(Asn1BitStringTest,
                        BitStringTest,
                        testing::Values(std::tuple(PROTO_BITS_EMPTY, 0, ENCODED_BITS_EMPTY),
                                        std::tuple(PROTO_BITS, 0, ENCODED_BITS_EMPTY),
                                        std::tuple(PROTO_BITS, 16, ENCODED_BITS_16),
                                        std::tuple(PROTO_BITS, 17, ENCODED_BITS_17),
                                        std::tuple(PROTO_BITS, 18, ENCODED_BITS_18),
                                        std::tuple(PROTO_BITS, 23, ENCODED_BITS_23),
                                        std::tuple(PROTO_BITS, 24, ENCODED_BITS_24)));

TEST_P(BitStringTest, BitStringEncoding) {
    auto [bits, i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_bitstring(&s, bits.data(), i);
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

class PrintableStringTest
    : public testing::TestWithParam<std::tuple<std::optional<std::string>, std::vector<uint8_t>>> {
};

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
        std::tuple(std::nullopt, ENCODED_STRING_EMPTY),
        std::tuple("", ENCODED_STRING_EMPTY),
        std::tuple("~", ENCODED_STRING_NOT_EMPTY),
        std::tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?",
                   ENCODED_STRING_FULL_CHARSET)));

TEST_P(PrintableStringTest, PrintableStringEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    if (i.has_value()) {
        n20_asn1_printablestring(&s, i.value().c_str());
    } else {
        n20_asn1_printablestring(&s, nullptr);
    }
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class GeneralizedTimeTest
    : public testing::TestWithParam<std::tuple<std::optional<std::string>, std::vector<uint8_t>>> {
};

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
                        testing::Values(std::tuple(std::nullopt, ENCODED_NULL),
                                        std::tuple("00010101000000Z", ENCODED_TIME_ZERO),
                                        std::tuple("20241127031458Z", ENCODED_TIME_NOT_ZERO)));

TEST_P(GeneralizedTimeTest, GeneralizedTimeEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    if (i.has_value()) {
        n20_asn1_generalized_time(&s, i.value().c_str());
    } else {
        n20_asn1_generalized_time(&s, nullptr);
    }
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class SequenceTest
    : public testing::TestWithParam<
          std::tuple<void (*)(n20_asn1_stream_t *, void *), void *, std::vector<uint8_t>>> {};

void flat(n20_asn1_stream_t *s, void *cb_context) {
    n20_asn1_printablestring(s, "flat");
    n20_asn1_boolean(s, true);
}

void nested(n20_asn1_stream_t *s, void *cb_context) {
    n20_asn1_printablestring(s, "nested");
    n20_asn1_sequence(s, &flat, cb_context);
}

std::vector<uint8_t> const ENCODED_SEQUENCE_NULL = {0x30, 0x00};
std::vector<uint8_t> const ENCODED_SEQUENCE_NOOP = {0x30, 0x00};
std::vector<uint8_t> const ENCODED_SEQUENCE_FLAT = {
    0x30, 0x09, 0x01, 0x01, 0xff, 0x13, 0x04, 0x66, 0x6c, 0x61, 0x74};
std::vector<uint8_t> const ENCODED_SEQUENCE_NESTED = {0x30, 0x13, 0x30, 0x09, 0x01, 0x01, 0xff,
                                                      0x13, 0x04, 0x66, 0x6c, 0x61, 0x74, 0x13,
                                                      0x06, 0x6e, 0x65, 0x73, 0x74, 0x65, 0x64};

INSTANTIATE_TEST_CASE_P(Asn1SequenceTest,
                        SequenceTest,
                        testing::Values(std::tuple(nullptr, nullptr, ENCODED_SEQUENCE_NULL),
                                        std::tuple(&noop, nullptr, ENCODED_SEQUENCE_NOOP),
                                        std::tuple(&flat, nullptr, ENCODED_SEQUENCE_FLAT),
                                        std::tuple(&nested, nullptr, ENCODED_SEQUENCE_NESTED)));

TEST_P(SequenceTest, SequenceEncoding) {
    auto [content_cb, cb_context, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_asn1_sequence(&s, content_cb, cb_context);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class ObjectIdentifierTest
    : public testing::TestWithParam<
          std::tuple<std::optional<struct n20_asn1_object_identifier>, std::vector<uint8_t>>> {};

struct n20_asn1_object_identifier OID_GOOGLE = {7, {1, 3, 6, 1, 4, 1, 11129}};

std::vector<uint8_t> const ENCODED_OID_SHA256_WITH_RSA_ENC = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
std::vector<uint8_t> const ENCODED_OID_GOOGLE = {
    0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79};

INSTANTIATE_TEST_CASE_P(Asn1ObjectIdentifierTest,
                        ObjectIdentifierTest,
                        testing::Values(std::tuple(std::nullopt, ENCODED_NULL),
                                        std::tuple(OID_SHA256_WITH_RSA_ENC,
                                                   ENCODED_OID_SHA256_WITH_RSA_ENC),
                                        std::tuple(OID_GOOGLE, ENCODED_OID_GOOGLE)));

TEST_P(ObjectIdentifierTest, ObjectIdentifierEncoding) {
    auto [i, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    if (i.has_value()) {
        n20_asn1_object_identifier(&s, &i.value());
    } else {
        n20_asn1_object_identifier(&s, nullptr);
    }
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}
