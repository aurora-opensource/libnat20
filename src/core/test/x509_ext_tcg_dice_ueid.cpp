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

#include "nat20/x509_ext_tcg_dice_ueid.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <tuple>
#include <vector>

#include "nat20/oid.h"
#include "nat20/x509.h"

class X509ExtTcgUeidTest
    : public testing::TestWithParam<
          std::tuple<std::optional<std::vector<uint8_t>>, std::vector<uint8_t> const>> {};

std::vector<uint8_t> const TEST_UEID = {
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
std::vector<uint8_t> const EXPECTED_UEID_EXTENSION = {
    // Extension header
    0xA3, 0x1a,
    // Extensions sequence header
    0x30, 0x18,
    // TCG UEID extension sequence header
    0x30, 0x16,
    // TCG UEID OID
    0x06, 0x06, 0x67, 0x81, 0x05,0x05, 0x04, 0x04,
    // TCG UEID Extension Octet String
    0x04, 0x0c,
    // TCG UEID Extension Sequence header
    0x30, 0x0a,
    // TCG UEID
    0x04, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};
// clang-format on

INSTANTIATE_TEST_CASE_P(TcgUeidEncoding,
                        X509ExtTcgUeidTest,
                        testing::Values(std::tuple(TEST_UEID, EXPECTED_UEID_EXTENSION)));

TEST_P(X509ExtTcgUeidTest, TcgUeidEncoding) {
    auto [optional_ueid, expected] = GetParam();
    n20_x509_ext_tcg_dice_ueid_t ueid;
    std::memset(&ueid, 0, sizeof(ueid));

    if (optional_ueid.has_value()) {
        ueid.ueid.buffer = optional_ueid.value().data();
        ueid.ueid.size = optional_ueid.value().size();
    } else {
        ueid.ueid.buffer = nullptr;
        ueid.ueid.size = 0;
    }

    n20_x509_extension_t extensions[] = {
        {
            .oid = &OID_TCG_DICE_UEID,
            .critical = false,
            .content_cb = n20_x509_ext_tcg_dice_ueid_content,
            .context = &ueid,
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

TEST(X509ExtTcgUeidTest, NullPointer) {
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);

    n20_x509_ext_tcg_dice_ueid_content(&s, nullptr);
    auto bytes_written = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(0, bytes_written);
}
