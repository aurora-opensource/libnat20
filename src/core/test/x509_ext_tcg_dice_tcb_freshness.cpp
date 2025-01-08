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

#include "nat20/x509_ext_tcg_dice_tcb_freshness.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <tuple>
#include <vector>

#include "nat20/oid.h"
#include "nat20/x509.h"

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
    n20_x509_ext_tcg_dice_tcb_freshness_t freshness;
    std::memset(&freshness, 0, sizeof(freshness));

    if (optional_nonce.has_value()) {
        freshness.nonce.buffer = optional_nonce.value().data();
        freshness.nonce.size = optional_nonce.value().size();
    } else {
        freshness.nonce.buffer = nullptr;
        freshness.nonce.size = 0;
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
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);
    n20_x509_extension(&s, &exts);
    auto exts_size = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(expected.size(), exts_size);

    // Now allocate a buffer large enough to hold the extension,
    // reinitialize the asn1_stream and write the tbs part again.
    uint8_t buffer[2000] = {};
    n20_asn1_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_extension(&s, &exts);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));

    ASSERT_EQ(expected, got);
}

TEST(X509ExtTcgTcbFreshnessTest, NullPointer) {
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);

    n20_x509_ext_tcg_dice_tcb_freshness_content(&s, nullptr);
    auto bytes_written = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(0, bytes_written);
}
