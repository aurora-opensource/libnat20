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
#include <nat20/oid.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_tcg_dice_tcb_freshness.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <tuple>
#include <vector>

class X509ExtTcgTcbFreshnessTest
    : public testing::TestWithParam<
          std::tuple<std::optional<std::vector<uint8_t>>, std::vector<uint8_t> const>> {};

std::vector<uint8_t> const TEST_NONCE = {
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
};

// clang-format off
std::vector<uint8_t> const EXPECTED_TCB_FRESHNESS_EXTENSION = {
    // Extension header
    0xA3, 0x1D,
    // Extensions sequence header
    0x30, 0x1B,
    // TCG TCB Freshness extension sequence header
    0x30, 0x19,
    // TCG TCB Freshness OID
    0x06, 0x06, 0x67, 0x81, 0x05,0x05, 0x04, 0x0B,
    // Critical = True
    0x01, 0x01, 0xFF,
    // TCG TCB Freshness Extension Octet String
    0x04, 0x0c,
    // TCG TCB Freshness Extension Sequence header
    0x30, 0x0a,
    // Nonce
    0x04, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};
// clang-format on

INSTANTIATE_TEST_CASE_P(TcgTcbFreshnessEncoding,
                        X509ExtTcgTcbFreshnessTest,
                        testing::Values(std::tuple(TEST_NONCE, EXPECTED_TCB_FRESHNESS_EXTENSION)));

TEST_P(X509ExtTcgTcbFreshnessTest, TcgTcbFreshnessEncoding) {
    auto [optional_nonce, expected] = GetParam();
    n20_slice_t freshness = N20_SLICE_NULL;

    if (optional_nonce.has_value()) {
        freshness.buffer = optional_nonce.value().data();
        freshness.size = optional_nonce.value().size();
    }

    n20_x509_extension_t extensions[] = {
        {
            .oid = &OID_TCG_DICE_TCB_FRESHNESS,
            .critical = true,
            .content_cb = n20_x509_ext_tcg_dice_tcb_freshness_content,
            .context = &freshness,
        },
    };

    n20_x509_extensions_t exts = {
        .extensions_count = 1,
        .extensions = extensions,
    };

    // DER encode the extension.
    // First, run the formatting function with NULL stream buffer
    // to compute the length of the extension.
    n20_stream_t s;
    n20_stream_init(&s, nullptr, 0);
    n20_x509_extension(&s, &exts);
    auto exts_size = n20_stream_byte_count(&s);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
    ASSERT_EQ(expected.size(), exts_size);

    // Now allocate a buffer large enough to hold the extension,
    // reinitialize the asn1_stream and write the tbs part again.
    uint8_t buffer[2000] = {};
    n20_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_extension(&s, &exts);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));

    ASSERT_EQ(expected, got);
}

TEST(X509ExtTcgTcbFreshnessTest, NullPointer) {
    n20_stream_t s;
    n20_stream_init(&s, nullptr, 0);

    n20_x509_ext_tcg_dice_tcb_freshness_content(&s, nullptr);
    auto bytes_written = n20_stream_byte_count(&s);
    ASSERT_TRUE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
    ASSERT_EQ(0, bytes_written);
}
