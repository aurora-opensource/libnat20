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

#include <gtest/gtest.h>
#include <nat20/cbor.h>
#include <nat20/stream.h>

#include <tuple>
#include <variant>
#include <vector>

class CborHeaderTestFixture
    : public testing::TestWithParam<std::tuple<n20_cbor_type_t, uint64_t, std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
    CborHeaderTestInstance,
    CborHeaderTestFixture,
    testing::Values(
        /* CBOR encoding encoding size boundary conditions. */
        std::tuple(n20_cbor_type_map_e, UINT64_C(0), std::vector<uint8_t>{0xa0}),
        std::tuple(n20_cbor_type_map_e, UINT64_C(1), std::vector<uint8_t>{0xa1}),
        std::tuple(n20_cbor_type_map_e, UINT64_C(23), std::vector<uint8_t>{0xb7}),
        std::tuple(n20_cbor_type_map_e, UINT64_C(24), std::vector<uint8_t>{0xb8, 0x18}),
        std::tuple(n20_cbor_type_map_e, UINT64_C(255), std::vector<uint8_t>{0xb8, 0xff}),
        std::tuple(n20_cbor_type_map_e, UINT64_C(256), std::vector<uint8_t>{0xb9, 0x01, 0x00}),
        std::tuple(n20_cbor_type_map_e, UINT64_C(0xffff), std::vector<uint8_t>{0xb9, 0xff, 0xff}),
        std::tuple(n20_cbor_type_map_e,
                   UINT64_C(0x10000),
                   std::vector<uint8_t>{0xba, 0x00, 0x01, 0x00, 0x00}),
        std::tuple(n20_cbor_type_map_e,
                   UINT64_C(0xffffffff),
                   std::vector<uint8_t>{0xba, 0xff, 0xff, 0xff, 0xff}),
        std::tuple(n20_cbor_type_map_e,
                   UINT64_C(0x100000000),
                   std::vector<uint8_t>{0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
        std::tuple(n20_cbor_type_map_e,
                   UINT64_C(0xffffffffffffffff),
                   std::vector<uint8_t>{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
        /* Invalid types map to "undefined" CBOR type (0xf7). */
        std::tuple(n20_cbor_type_none_e, UINT64_C(0), std::vector<uint8_t>{0xf7}),
        std::tuple((n20_cbor_type_t)8, UINT64_C(0), std::vector<uint8_t>{0xf7})));

TEST_P(CborHeaderTestFixture, CborHeaderTest) {
    auto [type, integer, encoding] = GetParam();

    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_header(&s, type, integer);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, encoding);
}

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
    n20_cbor_write_byte_string(&s, {.size = sizeof(bytes), .buffer = bytes});

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    auto want_encoding = std::vector<uint8_t>{0x44, 0x01, 0x02, 0x03, 0x04};

    ASSERT_EQ(bytes_written, 5);
    ASSERT_EQ(got_encoding, want_encoding);
}

TEST(CborTests, CborWriteMalformedSliceByteStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_byte_string(&s, {.size = 4, .buffer = nullptr});

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0xf6});
}

TEST(CborTests, CborWriteEmptySliceByteStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_byte_string(&s, {.size = 0, .buffer = nullptr});

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0x40});
}

TEST(CborTests, CborWriteStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_string_slice_t str = N20_STR_C("Hello");
    n20_cbor_write_text_string(&s, str);

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);

    auto want_encoding = std::vector<uint8_t>{0x65, 0x48, 0x65, 0x6c, 0x6c, 0x6f};

    ASSERT_EQ(bytes_written, 6);
    ASSERT_EQ(got_encoding, want_encoding);
}

TEST(CborTests, CborWriteMalformedSliceTextStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_text_string(&s, {.size = 4, .buffer = nullptr});

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0xf6});
}

TEST(CborTests, CborWriteEmptySliceTextStringTest) {
    uint8_t buffer[20];

    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], sizeof(buffer));

    n20_cbor_write_text_string(&s, {.size = 0, .buffer = nullptr});

    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    size_t bytes_written = n20_stream_byte_count(&s);
    auto got_encoding = std::vector(n20_stream_data(&s), n20_stream_data(&s) + bytes_written);
    ASSERT_EQ(got_encoding, std::vector<uint8_t>{0x60});
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

class CborReadTest : public testing::Test {
   protected:
    void SetUp() override { buffer.clear(); }

    void CreateStream() { n20_istream_init(&stream, buffer.data(), buffer.size()); }

    // Helper to write CBOR data for testing
    void WriteCborData(std::vector<uint8_t> const& data) { buffer = data; }

    std::vector<uint8_t> buffer;
    n20_istream_t stream;
};

// Tests for n20_cbor_read_header
TEST_F(CborReadTest, ReadHeaderUnsignedInteger) {
    // Test small value (direct encoding)
    WriteCborData({0x05});  // uint 5
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 5);
}

TEST_F(CborReadTest, ReadHeaderUnsignedIntegerLarge) {
    // Test 1-byte value (24 + value)
    WriteCborData({0x18, 0xFF});  // uint 255
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 255);
}

TEST_F(CborReadTest, ReadHeaderUnsignedInteger2Bytes) {
    // Test 2-byte value
    WriteCborData({0x19, 0x01, 0x00});  // uint 256
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 256);
}

TEST_F(CborReadTest, ReadHeaderUnsignedInteger4Bytes) {
    // Test 4-byte value
    WriteCborData({0x1A, 0x00, 0x01, 0x00, 0x00});  // uint 65536
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 65536);
}

TEST_F(CborReadTest, ReadHeaderUnsignedInteger8Bytes) {
    // Test 8-byte value
    WriteCborData({0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});  // uint 4294967296
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 0x100000000ULL);
}

TEST_F(CborReadTest, ReadHeaderNegativeInteger) {
    WriteCborData({0x29});  // nint -10 (encoded as 9)
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_nint_e);
    EXPECT_EQ(value, 9);  // -10 is encoded as 9
}

TEST_F(CborReadTest, ReadHeaderByteString) {
    WriteCborData({0x45, 'h', 'e', 'l', 'l', 'o'});  // bytes "hello"
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_bytes_e);
    EXPECT_EQ(value, 5);
}

TEST_F(CborReadTest, ReadHeaderTextString) {
    WriteCborData({0x65, 'h', 'e', 'l', 'l', 'o'});  // text "hello"
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_string_e);
    EXPECT_EQ(value, 5);
}

TEST_F(CborReadTest, ReadHeaderArray) {
    WriteCborData({0x83});  // array of 3 items
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_array_e);
    EXPECT_EQ(value, 3);
}

TEST_F(CborReadTest, ReadHeaderMap) {
    WriteCborData({0xA2});  // map with 2 key-value pairs
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_map_e);
    EXPECT_EQ(value, 2);
}

TEST_F(CborReadTest, ReadHeaderTag) {
    WriteCborData({0xC1});  // tag 1
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_tag_e);
    EXPECT_EQ(value, 1);
}

TEST_F(CborReadTest, ReadHeaderSimpleValues) {
    // Test false
    WriteCborData({0xF4});  // false
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_simple_float_e);
    EXPECT_EQ(value, N20_SIMPLE_FALSE);

    // Test true
    WriteCborData({0xF5});  // true
    CreateStream();
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_simple_float_e);
    EXPECT_EQ(value, N20_SIMPLE_TRUE);

    // Test null
    WriteCborData({0xF6});  // null
    CreateStream();
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_simple_float_e);
    EXPECT_EQ(value, N20_SIMPLE_NULL);

    // Test undefined
    WriteCborData({0xF7});  // undefined
    CreateStream();
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_simple_float_e);
    EXPECT_EQ(value, N20_SIMPLE_UNDEFINED);
}

TEST_F(CborReadTest, ReadHeaderEmptyStream) {
    WriteCborData({});  // empty
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_FALSE(n20_cbor_read_header(&stream, &type, &value));
}

TEST_F(CborReadTest, ReadHeaderIncompleteMultiByte) {
    WriteCborData({0x18});  // incomplete 1-byte value
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_FALSE(n20_cbor_read_header(&stream, &type, &value));
}

TEST_F(CborReadTest, ReadHeaderNullStream) {
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_FALSE(n20_cbor_read_header(nullptr, &type, &value));
}

// Tests for n20_cbor_read_skip_item
TEST_F(CborReadTest, SkipSimpleValues) {
    // Skip unsigned integer
    WriteCborData({0x05, 0x06});  // uint 5, uint 6
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at the second item
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 6);
}

TEST_F(CborReadTest, SkipByteString) {
    WriteCborData({0x45, 'h', 'e', 'l', 'l', 'o', 0x01});  // bytes "hello", uint 1
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 1
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 1);
}

TEST_F(CborReadTest, SkipTextString) {
    WriteCborData({0x65, 'h', 'e', 'l', 'l', 'o', 0x02});  // text "hello", uint 2
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 2
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 2);
}

TEST_F(CborReadTest, SkipEmptyArray) {
    WriteCborData({0x80, 0x01});  // empty array, uint 1
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 1
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 1);
}

TEST_F(CborReadTest, SkipArrayWithElements) {
    WriteCborData({0x83, 0x01, 0x02, 0x03, 0x04});  // array [1, 2, 3], uint 4
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 4
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 4);
}

TEST_F(CborReadTest, SkipNestedArray) {
    WriteCborData({0x82, 0x82, 0x01, 0x02, 0x03, 0x04});  // array [array [1, 2], 3], uint 4
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 4
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 4);
}

TEST_F(CborReadTest, SkipEmptyMap) {
    WriteCborData({0xA0, 0x01});  // empty map, uint 1
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 1
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 1);
}

TEST_F(CborReadTest, SkipMapWithElements) {
    WriteCborData({0xA2, 0x01, 0x02, 0x03, 0x04, 0x05});  // map {1: 2, 3: 4}, uint 5
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 5
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 5);
}

TEST_F(CborReadTest, SkipNestedMap) {
    WriteCborData({0xA1, 0x01, 0xA1, 0x02, 0x03, 0x04});  // map {1: {2: 3}}, uint 4
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 4
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 4);
}

TEST_F(CborReadTest, FailOnMapWithMissingElement) {
    WriteCborData({0xA2, 0x01, 0x02});  // map expecting 2 key-value pairs, only 1 present
    CreateStream();

    EXPECT_FALSE(n20_cbor_read_skip_item(&stream));
}

TEST_F(CborReadTest, SkipTag) {
    WriteCborData({0xC1, 0x05, 0x06});  // tag 1, uint 5, uint 6
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 6 (skipped tag and tagged item)
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 6);
}

TEST_F(CborReadTest, SkipTaggedArray) {
    WriteCborData({0xC1, 0x83, 0x01, 0x02, 0x03, 0x04});  // tag 1, array [1, 2, 3], uint 4
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 4
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 4);
}

TEST_F(CborReadTest, SkipComplexStructure) {
    // Complex structure: array containing map and tagged item
    WriteCborData({
        0x83,  // array of 3 items
        0xA1,
        0x01,
        0x02,  // map {1: 2}
        0xC1,
        0x03,  // tag 1, uint 3
        0x84,
        0x04,
        0x05,
        0x06,
        0x07,  // array [4, 5, 6, 7]
        0x08   // uint 8
    });
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at uint 8
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 8);
}

TEST_F(CborReadTest, SkipItemIncompleteArray) {
    WriteCborData({0x82, 0x01});  // array expecting 2 items, only 1 present
    CreateStream();

    EXPECT_FALSE(n20_cbor_read_skip_item(&stream));
}

TEST_F(CborReadTest, SkipItemIncompleteMap) {
    WriteCborData({0xA1, 0x01});  // map expecting 1 key-value pair, only key present
    CreateStream();

    EXPECT_FALSE(n20_cbor_read_skip_item(&stream));
}

TEST_F(CborReadTest, SkipItemIncompleteString) {
    WriteCborData({0x45, 'h', 'e'});  // byte string expecting 5 bytes, only 2 present
    CreateStream();

    EXPECT_FALSE(n20_cbor_read_skip_item(&stream));
}

TEST_F(CborReadTest, SkipItemIncompleteTag) {
    WriteCborData({0xC1});  // tag without following item
    CreateStream();

    EXPECT_FALSE(n20_cbor_read_skip_item(&stream));
}

TEST_F(CborReadTest, SkipItemNullStream) { EXPECT_FALSE(n20_cbor_read_skip_item(nullptr)); }

TEST_F(CborReadTest, SkipItemEmptyStream) {
    WriteCborData({});
    CreateStream();

    EXPECT_FALSE(n20_cbor_read_skip_item(&stream));
}

// Edge case tests
TEST_F(CborReadTest, SkipLargeArray) {
    std::vector<uint8_t> data;
    data.push_back(0x98);  // array of 24 items
    data.push_back(24);
    for (int i = 0; i < 24; ++i) {
        // items 0-23 - coincides with the CBOR encoding of unsigned integers
        data.push_back(i);
    }
    data.push_back(0xFF);  // marker after array

    WriteCborData(data);
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));

    // Should be positioned at marker
    uint8_t got_marker;
    EXPECT_TRUE(n20_istream_read(&stream, &got_marker, 1));
    EXPECT_EQ(got_marker, 0xFF);
}

TEST_F(CborReadTest, SkipZeroLengthStrings) {
    WriteCborData({0x40, 0x60, 0x01});  // empty byte string, empty text string, uint 1
    CreateStream();

    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));  // skip empty byte string
    EXPECT_TRUE(n20_cbor_read_skip_item(&stream));  // skip empty text string

    // Should be positioned at uint 1
    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, n20_cbor_type_uint_e);
    EXPECT_EQ(value, 1);
}

class CborInvalidHeaderTestFixture
    : public CborReadTest,
      public testing::WithParamInterface<std::tuple<n20_cbor_type_t, uint8_t>> {};

INSTANTIATE_TEST_SUITE_P(
    FailOnInvalidHeaderByteTestsInstance,
    CborInvalidHeaderTestFixture,
    testing::Combine(testing::Values(n20_cbor_type_uint_e,
                                     n20_cbor_type_nint_e,
                                     n20_cbor_type_bytes_e,
                                     n20_cbor_type_string_e,
                                     n20_cbor_type_array_e,
                                     n20_cbor_type_map_e,
                                     n20_cbor_type_tag_e,
                                     n20_cbor_type_simple_float_e),
                     testing::Values(28, 29, 30, 31)),
    [](testing::TestParamInfo<CborInvalidHeaderTestFixture::ParamType> const& info) {
        return std::to_string(std::get<0>(info.param)) + "_" +
               std::to_string(std::get<1>(info.param));
    });

TEST_P(CborInvalidHeaderTestFixture, FailOnInvalidHeaderByte) {
    auto [major_type, addl_info] = GetParam();
    uint8_t invalid_header = (major_type << 5) | addl_info;
    WriteCborData({invalid_header});
    CreateStream();

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_FALSE(n20_cbor_read_header(&stream, &type, &value));
}

// Parameterized tests for various CBOR types
class CborReadParameterizedTest
    : public testing::TestWithParam<std::tuple<uint8_t, n20_cbor_type_t, uint64_t>> {
   protected:
    void SetUp() override {
        auto param = GetParam();
        header_byte = std::get<0>(param);
        expected_type = std::get<1>(param);
        expected_value = std::get<2>(param);
    }

    uint8_t header_byte;
    n20_cbor_type_t expected_type;
    uint64_t expected_value;
    std::vector<uint8_t> buffer;
    n20_istream_t stream;
};

TEST_P(CborReadParameterizedTest, ReadHeaderVariousTypes) {
    buffer = {header_byte};
    n20_istream_init(&stream, buffer.data(), buffer.size());

    n20_cbor_type_t type;
    uint64_t value;
    EXPECT_TRUE(n20_cbor_read_header(&stream, &type, &value));
    EXPECT_EQ(type, expected_type);
    EXPECT_EQ(value, expected_value);
}

INSTANTIATE_TEST_SUITE_P(
    CborReadTests,
    CborReadParameterizedTest,
    testing::Values(std::make_tuple(0x00, n20_cbor_type_uint_e, 0),    // uint 0
                    std::make_tuple(0x01, n20_cbor_type_uint_e, 1),    // uint 1
                    std::make_tuple(0x17, n20_cbor_type_uint_e, 23),   // uint 23
                    std::make_tuple(0x20, n20_cbor_type_nint_e, 0),    // nint -1
                    std::make_tuple(0x21, n20_cbor_type_nint_e, 1),    // nint -2
                    std::make_tuple(0x40, n20_cbor_type_bytes_e, 0),   // empty byte string
                    std::make_tuple(0x60, n20_cbor_type_string_e, 0),  // empty text string
                    std::make_tuple(0x80, n20_cbor_type_array_e, 0),   // empty array
                    std::make_tuple(0xA0, n20_cbor_type_map_e, 0),     // empty map
                    std::make_tuple(0xC0, n20_cbor_type_tag_e, 0),     // tag 0
                    std::make_tuple(0xF4, n20_cbor_type_simple_float_e, N20_SIMPLE_FALSE),
                    std::make_tuple(0xF5, n20_cbor_type_simple_float_e, N20_SIMPLE_TRUE),
                    std::make_tuple(0xF6, n20_cbor_type_simple_float_e, N20_SIMPLE_NULL),
                    std::make_tuple(0xF7, n20_cbor_type_simple_float_e, N20_SIMPLE_UNDEFINED)));
