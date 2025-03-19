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
#include <nat20/oid.h>
#include <nat20/stream.h>

#include <cstdint>
#include <vector>

class StreamTest
    : public testing::TestWithParam<std::tuple<size_t, std::vector<std::vector<uint8_t>>, bool>> {};

std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_EMPTY = {};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULLPTR = {{}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULLPTR_NULLPTR = {{}, {}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULL = {{0x05, 0x00}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR = {
    {}, {0x05, 0x00}, {}};
std::vector<std::vector<uint8_t>> const BYTES_TO_PREPEND_SEQUENCE = {
    {0x6e, 0x65, 0x73, 0x74, 0x65, 0x64},
    {0x13, 0x06},
    {0x66, 0x6c, 0x61, 0x74},
    {0x13, 0x04},
    {0xff},
    {0x01, 0x01},
    {0x30, 0x09},
    {0x30, 0x13}};

INSTANTIATE_TEST_CASE_P(N20StreamTest,
                        StreamTest,
                        testing::Values(std::tuple(1, BYTES_TO_PREPEND_EMPTY, false),
                                        std::tuple(2, BYTES_TO_PREPEND_EMPTY, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULLPTR, false),
                                        std::tuple(2, BYTES_TO_PREPEND_NULLPTR, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULLPTR_NULLPTR, false),
                                        std::tuple(2, BYTES_TO_PREPEND_NULLPTR_NULLPTR, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULL, true),
                                        std::tuple(2, BYTES_TO_PREPEND_NULL, false),
                                        std::tuple(3, BYTES_TO_PREPEND_NULL, false),
                                        std::tuple(1, BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR, true),
                                        std::tuple(2, BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR, false),
                                        std::tuple(3, BYTES_TO_PREPEND_NULLPTR_NULL_NULLPTR, false),
                                        std::tuple(1, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(2, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(10, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(20, BYTES_TO_PREPEND_SEQUENCE, true),
                                        std::tuple(21, BYTES_TO_PREPEND_SEQUENCE, false),
                                        std::tuple(22, BYTES_TO_PREPEND_SEQUENCE, false)));

TEST_P(StreamTest, StreamPrepend) {
    auto [buffer_size, bytes_to_prepend, has_overflow] = GetParam();

    // Reverse
    std::vector<std::vector<uint8_t>> bytes_to_prepend_copy(bytes_to_prepend);
    std::reverse(bytes_to_prepend_copy.begin(), bytes_to_prepend_copy.end());
    // Flatten
    std::vector<uint8_t> expected;
    for (auto const &bytes : bytes_to_prepend_copy) {
        for (auto const &byte : bytes) {
            expected.push_back(byte);
        }
    }

    n20_stream_t s;
    uint8_t buffer[buffer_size];
    n20_stream_init(&s, buffer, buffer_size);
    for (auto const &bytes : bytes_to_prepend) {
        n20_stream_prepend(&s, bytes.data(), bytes.size());
    }
    ASSERT_EQ(has_overflow, n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), expected.size());
    if (!has_overflow) {
        std::vector<uint8_t> got = std::vector<uint8_t>(
            n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
        ASSERT_EQ(expected, got);
    }
}

TEST(StreamTest, StreamCounterOverflow) {
    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));

    n20_stream_prepend(&s, nullptr, std::numeric_limits<uint64_t>::max());
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    n20_stream_prepend(&s, nullptr, 1);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_TRUE(n20_stream_has_write_position_overflow(&s));

    n20_stream_prepend(&s, nullptr, std::numeric_limits<uint64_t>::max() - 1);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_TRUE(n20_stream_has_write_position_overflow(&s));

    n20_stream_prepend(&s, nullptr, 1);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_TRUE(n20_stream_has_write_position_overflow(&s));
}
