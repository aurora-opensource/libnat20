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

#include <gtest/gtest.h>
#include <nat20/cbor.h>
#include <nat20/stream.h>

#include <cstdint>
#include <tuple>
#include <variant>
#include <vector>

class CborIntegerTestFixture
    : public testing::TestWithParam<
          std::tuple<std::variant<uint64_t, int64_t>, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
    CborIntegerTestInstance,
    CborIntegerTestFixture,
    testing::Values(
        /* CBOR encoding encoding size boundary conditions. */
        std::tuple(UINT64_C(0), std::vector<uint8_t>{0x00}),
        std::tuple(UINT64_C(1), std::vector<uint8_t>{0x01}),
        std::tuple(UINT64_C(23), std::vector<uint8_t>{0x17}),
        std::tuple(UINT64_C(24), std::vector<uint8_t>{0x18, 0x18}),
        std::tuple(UINT64_C(255), std::vector<uint8_t>{0x18, 0xff}),
        std::tuple(UINT64_C(256), std::vector<uint8_t>{0x19, 0x01, 0x00}),
        std::tuple(UINT64_C(0xffff), std::vector<uint8_t>{0x19, 0xff, 0xff}),
        std::tuple(UINT64_C(0x10000), std::vector<uint8_t>{0x1a, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffff), std::vector<uint8_t>{0x1a, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(UINT64_C(0x100000000),
                   std::vector<uint8_t>{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffffffffffff),
                   std::vector<uint8_t>{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
        /* Repeat the same constants as above but force using the
         * the indirection through n20_cbor_write_int. */
        std::tuple(INT64_C(0), std::vector<uint8_t>{0x00}),
        std::tuple(INT64_C(1), std::vector<uint8_t>{0x01}),
        std::tuple(INT64_C(23), std::vector<uint8_t>{0x17}),
        std::tuple(INT64_C(24), std::vector<uint8_t>{0x18, 0x18}),
        std::tuple(INT64_C(255), std::vector<uint8_t>{0x18, 0xff}),
        std::tuple(INT64_C(256), std::vector<uint8_t>{0x19, 0x01, 0x00}),
        std::tuple(INT64_C(0xffff), std::vector<uint8_t>{0x19, 0xff, 0xff}),
        std::tuple(INT64_C(0x10000), std::vector<uint8_t>{0x1a, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(INT64_C(0xffffffff), std::vector<uint8_t>{0x1a, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(INT64_C(0x100000000),
                   std::vector<uint8_t>{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        std::tuple(INT64_MAX,
                   std::vector<uint8_t>{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(INT64_C(-1), std::vector<uint8_t>{0x20}),
        std::tuple(INT64_C(-24), std::vector<uint8_t>{0x37}),
        std::tuple(INT64_C(-25), std::vector<uint8_t>{0x38, 0x18}),
        std::tuple(INT64_C(-256), std::vector<uint8_t>{0x38, 0xff}),
        std::tuple(INT64_C(-257), std::vector<uint8_t>{0x39, 0x01, 0x00}),
        std::tuple(INT64_C(-65536), std::vector<uint8_t>{0x39, 0xff, 0xff}),
        std::tuple(INT64_C(-65537), std::vector<uint8_t>{0x3a, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(INT64_C(-4294967296), std::vector<uint8_t>{0x3a, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(INT64_C(-4294967297),
                   std::vector<uint8_t>{0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        /* This is not the lowest integer that can be represented with
         * CBOR major type 1, but it is the lowest that can be represented
         * using 64 bits 2s-complement. And thus the limit of the
         * integer encoding functions as of now. */
        std::tuple(INT64_MIN,
                   std::vector<uint8_t>{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),

        /* Known OpenDICE label values. */
        std::tuple(INT64_C(-4670545), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x50}),
        std::tuple(INT64_C(-4670546), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x51}),
        std::tuple(INT64_C(-4670547), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x52}),
        std::tuple(INT64_C(-4670548), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x53}),
        std::tuple(INT64_C(-4670549), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x54}),
        std::tuple(INT64_C(-4670550), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x55}),
        std::tuple(INT64_C(-4670551), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x56}),
        std::tuple(INT64_C(-4670552), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x57}),
        std::tuple(INT64_C(-4670553), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x58}),
        std::tuple(INT64_C(-4670554), std::vector<uint8_t>{0x3a, 0x00, 0x47, 0x44, 0x59})));

TEST_P(CborIntegerTestFixture, CborIntegerTest) {
    auto [integer, encoding] = GetParam();

    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    if (std::holds_alternative<uint64_t>(integer)) {
        n20_cbor_write_uint(&s, std::get<uint64_t>(integer));
    } else {
        n20_cbor_write_int(&s, std::get<int64_t>(integer));
    }

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, encoding);
}

TEST(CborTests, CborWriteNullTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_null(&s);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    ASSERT_EQ(bytes_written, 1);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0xf6});
}

TEST(CborTests, CborWriteBoolTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_bool(&s, true);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    ASSERT_EQ(bytes_written, 1);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0xf5});

    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_bool(&s, false);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    bytes_written = n20_stream_byte_count(&s);
    got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    ASSERT_EQ(bytes_written, 1);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0xf4});
}

class CborTagTestFixture
    : public testing::TestWithParam<std::tuple<uint64_t, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
    CborTagTestInstance,
    CborTagTestFixture,
    testing::Values(
        /* CBOR encoding encoding size boundary conditions. */
        std::tuple(UINT64_C(0), std::vector<uint8_t>{0xc0}),
        std::tuple(UINT64_C(1), std::vector<uint8_t>{0xc1}),
        std::tuple(UINT64_C(23), std::vector<uint8_t>{0xd7}),
        std::tuple(UINT64_C(24), std::vector<uint8_t>{0xd8, 0x18}),
        std::tuple(UINT64_C(255), std::vector<uint8_t>{0xd8, 0xff}),
        std::tuple(UINT64_C(256), std::vector<uint8_t>{0xd9, 0x01, 0x00}),
        std::tuple(UINT64_C(0xffff), std::vector<uint8_t>{0xd9, 0xff, 0xff}),
        std::tuple(UINT64_C(0x10000), std::vector<uint8_t>{0xda, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffff), std::vector<uint8_t>{0xda, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(UINT64_C(0x100000000),
                   std::vector<uint8_t>{0xdb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffffffffffff),
                   std::vector<uint8_t>{0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})));

TEST_P(CborTagTestFixture, CborTagTest) {
    auto [integer, encoding] = GetParam();

    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_tag(&s, integer);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, encoding);
}

TEST(CborTests, CborWriteByteStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    uint8_t bytes[] = {0x01, 0x02, 0x03, 0x04};
    n20_cbor_write_byte_string(&s, bytes, sizeof(bytes));

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    auto want_encoding = std::vector<uint8_t>{0x44, 0x01, 0x02, 0x03, 0x04};

    ASSERT_EQ(bytes_written, 5);
    ASSERT_EQ(got_encoding, want_encoding);
}

TEST(CborTests, CborWriteStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    char const *str = "Hello";
    n20_cbor_write_text_string(&s, str, strlen(str));

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    auto want_encoding = std::vector<uint8_t>{0x65, 0x48, 0x65, 0x6c, 0x6c, 0x6f};

    ASSERT_EQ(bytes_written, 6);
    ASSERT_EQ(got_encoding, want_encoding);
}


class CborArrayHeaderTestFixture
    : public testing::TestWithParam<std::tuple<uint64_t, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
    CborArrayHeaderTestInstance,
    CborArrayHeaderTestFixture,
    testing::Values(
        /* CBOR encoding encoding size boundary conditions. */
        std::tuple(UINT64_C(0), std::vector<uint8_t>{0x80}),
        std::tuple(UINT64_C(1), std::vector<uint8_t>{0x81}),
        std::tuple(UINT64_C(23), std::vector<uint8_t>{0x97}),
        std::tuple(UINT64_C(24), std::vector<uint8_t>{0x98, 0x18}),
        std::tuple(UINT64_C(255), std::vector<uint8_t>{0x98, 0xff}),
        std::tuple(UINT64_C(256), std::vector<uint8_t>{0x99, 0x01, 0x00}),
        std::tuple(UINT64_C(0xffff), std::vector<uint8_t>{0x99, 0xff, 0xff}),
        std::tuple(UINT64_C(0x10000), std::vector<uint8_t>{0x9a, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffff), std::vector<uint8_t>{0x9a, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(UINT64_C(0x100000000),
                   std::vector<uint8_t>{0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffffffffffff),
                   std::vector<uint8_t>{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})));

TEST_P(CborArrayHeaderTestFixture, CborArrayHeaderTest) {
    auto [integer, encoding] = GetParam();

    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_array_header(&s, integer);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, encoding);
}

class CborMapHeaderTestFixture
    : public testing::TestWithParam<std::tuple<uint64_t, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
    CborMapHeaderTestInstance,
    CborMapHeaderTestFixture,
    testing::Values(
        /* CBOR encoding encoding size boundary conditions. */
        std::tuple(UINT64_C(0), std::vector<uint8_t>{0xa0}),
        std::tuple(UINT64_C(1), std::vector<uint8_t>{0xa1}),
        std::tuple(UINT64_C(23), std::vector<uint8_t>{0xb7}),
        std::tuple(UINT64_C(24), std::vector<uint8_t>{0xb8, 0x18}),
        std::tuple(UINT64_C(255), std::vector<uint8_t>{0xb8, 0xff}),
        std::tuple(UINT64_C(256), std::vector<uint8_t>{0xb9, 0x01, 0x00}),
        std::tuple(UINT64_C(0xffff), std::vector<uint8_t>{0xb9, 0xff, 0xff}),
        std::tuple(UINT64_C(0x10000), std::vector<uint8_t>{0xba, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffff), std::vector<uint8_t>{0xba, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(UINT64_C(0x100000000),
                   std::vector<uint8_t>{0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        std::tuple(UINT64_C(0xffffffffffffffff),
                   std::vector<uint8_t>{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})));

TEST_P(CborMapHeaderTestFixture, CborMapHeaderTest) {
    auto [integer, encoding] = GetParam();

    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_map_header(&s, integer);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, encoding);
}

