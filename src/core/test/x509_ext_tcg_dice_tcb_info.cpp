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

#include "nat20/x509_ext_tcg_dice_tcb_info.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "nat20/oid.h"
#include "nat20/x509.h"

class X509ExtTcgTcbInfoTest
    : public testing::TestWithParam<
          std::tuple<std::optional<std::string>,
                     std::optional<std::string>,
                     std::optional<std::string>,
                     uint64_t const,
                     uint64_t const,
                     uint64_t const,
                     std::optional<n20_x509_ext_tcg_dice_tcb_info_fwid_list_t>,
                     n20_x509_ext_tcg_dice_tcb_info_operational_flags_t const,
                     n20_x509_ext_tcg_dice_tcb_info_operational_flags_t const,
                     std::optional<std::vector<uint8_t>>,
                     std::optional<std::vector<uint8_t>>,
                     std::vector<uint8_t> const>> {};

std::array<uint8_t, 32> const TEST_DIGEST_1 = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,

};

std::array<uint8_t, 64> const TEST_DIGEST_2 = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,

};

n20_x509_ext_tcg_dice_tcb_info_fwid_t TEST_FWID_1 = {
    .hash_algo = OID_SHA256,
    .digest =
        {
            .buffer = TEST_DIGEST_1.data(),
            .size = TEST_DIGEST_1.size(),
        },
};

n20_x509_ext_tcg_dice_tcb_info_fwid_t TEST_FWID_2 = {
    .hash_algo = OID_SHA512,
    .digest =
        {
            .buffer = TEST_DIGEST_2.data(),
            .size = TEST_DIGEST_2.size(),
        },
};

std::array<n20_x509_ext_tcg_dice_tcb_info_fwid_t, 2> TEST_FWIDS = {
    TEST_FWID_1,
    TEST_FWID_2,
};

n20_x509_ext_tcg_dice_tcb_info_fwid_list_t const TEST_FWID_LIST = {
    .list = TEST_FWIDS.data(),
    .count = TEST_FWIDS.size(),
};

n20_x509_ext_tcg_dice_tcb_info_operational_flags_t const TEST_FLAGS = {
    .operational_flags_mask = {0x80, 0x80, 0x00, 0x01}};

n20_x509_ext_tcg_dice_tcb_info_operational_flags_t const TEST_FLAGS_MASK = {
    .operational_flags_mask = {0xff, 0x80, 0x00, 0x01}};

std::vector<uint8_t> TEST_TYPE = {
    0x54,
    0x59,
    0x50,
    0x45,
};

std::vector<uint8_t> TEST_VENDOR_INFO = {
    0x56,
    0x45,
    0x4E,
    0x44,
    0x4F,
    0x53,
};

// clang-format off
std::vector<uint8_t> const EXPECTED_EXTENSION_WITH_ALL_FIELDS = {
    // Extension header
    0xA3, 0x81, 0xD4,
    // Extensions sequence header
    0x30, 0x81, 0xD1,
    // TCG TCB Info extension sequence header
    0x30, 0x81, 0xCE,
    // TCG TCB Info OID
    0x06, 0x06, 0x67, 0x81, 0x05,0x05, 0x04, 0x01,
    // Critical = True
    0x01, 0x01, 0xFF,
    // TCG TCB Info Extension Octet String
    0x04, 0x81, 0xC0,
    // TCG TCB Info Extension Sequence header
    0x30, 0x81, 0xBD,
    // TCG TCB Info Vendor (Implicitly tagged 0)
    0x80, 0x06, 0x61,0x75,0x72,0x6f,0x72,0x61,
    // TCG TCB Info Model (Implicitly tagged 1)
    0x81, 0x07, 0x70, 0x65, 0x72, 0x73, 0x65, 0x75, 0x73,
    // TCG TCB Info Version (Implicitly tagged 2)
    0x82, 0x05, 0x31,0x2e,0x30,0x2e,0x35,
    // TCG TCB Info SVN (Implicitly tagged 3)
    0x83, 0x01, 0x05,
    // TCG TCB Info Layer (Implicitly tagged 4)
    0x84, 0x01, 0x06,
    // TCG TCB Info Index (Implicitly tagged 5)
    0x85, 0x01, 0x07,
    // TCG TCB Info FWIDs (Implicitly tagged 6)
    0xA6, 0x7E,
    // FWID 1
    0x30, 0x2D,
    // FWID 1 - hash algo
    0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    // FWID 1 - digest
    0x04, 0x20, 
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // FWID 2
    0x30,0x4D,
    // FWID 2 - hash algo SHA512
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    // FWID 2 - digest
    0x04, 0x40,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    // TCG TCB Info Operational Flags (Implicitly tagged 7)
    0x87, 0x05, 0x00, 0x80, 0x80, 0x00, 0x01,
    // TCG TCB Info Vendor Info (Implicitly tagged 8)
    0x88, 0x06, 0x56, 0x45, 0x4E, 0x44, 0x4F, 0x53,
    // TCG TCB Info Type (Implicitly tagged 9)
    0x89, 0x04, 0x54, 0x59, 0x50, 0x45,
    // TCG TCB Info Operational Flags Mask (Implicitly tagged 10)
    0x8A, 0x05, 0x00, 0xff, 0x80, 0x00, 0x01,
};

std::vector<uint8_t> const EXPECTED_EXTENSION_WITH_SOME_FIELDS = {
    // Extension header
    0xA3, 0x2A,
    // Extensions sequence header
    0x30, 0x28,
    // TCG TCB Info extension sequence header
    0x30, 0x26,
    // TCG TCB Info OID
    0x06, 0x06, 0x67, 0x81, 0x05,0x05, 0x04, 0x01,
    // Critical = True
    0x01, 0x01, 0xFF,
    // TCG TCB Info Extension Octet String
    0x04, 0x19,
    // TCG TCB Info Extension Sequence header
    0x30, 0x17,
    // TCG TCB Info SVN (Implicitly tagged 3)
    0x83, 0x01, 0x05,
    // TCG TCB Info Layer (Implicitly tagged 4)
    0x84, 0x01, 0x06,
    // TCG TCB Info Index (Implicitly tagged 5)
    0x85, 0x01, 0x07,
    // TCG TCB Info Operational Flags (Implicitly tagged 7)
    0x87, 0x05, 0x00, 0x80, 0x80, 0x00, 0x01,
    // TCG TCB Info Operational Flags Mask (Implicitly tagged 10)
    0x8A, 0x05, 0x00, 0xff, 0x80, 0x00, 0x01,
};

std::vector<uint8_t> const EXPECTED_MULTI_TCB_INFO_EXTENSION = {
    // Extension header
    0xA3, 0x81, 0xF0,
    // Extensions sequence header
    0x30, 0x81, 0xED,
    // TCG Multi TCB Info extension sequence header
    0x30, 0x81, 0xEA,
    // TCG Multi TCB Info OID
    0x06, 0x06, 0x67, 0x81, 0x05,0x05, 0x04, 0x05,
    // Critical = True
    0x01, 0x01, 0xFF,
    // TCG TCB Multi Info Extension Octet String
    0x04, 0x81, 0xDC,
    // TCG TCB Multi Info Extension Sequence header
    0x30, 0x81, 0xD9,
    // TCG TCB Info 1 Extension Sequence header
    0x30, 0x81, 0xBD,
    // TCG TCB Info 1 Vendor (Implicitly tagged 0)
    0x80, 0x06, 0x61,0x75,0x72,0x6f,0x72,0x61,
    // TCG TCB Info 1 Model (Implicitly tagged 1)
    0x81, 0x07, 0x70, 0x65, 0x72, 0x73, 0x65, 0x75, 0x73,
    // TCG TCB Info 1 Version (Implicitly tagged 2)
    0x82, 0x05, 0x31,0x2e,0x30,0x2e,0x35,
    // TCG TCB Info 1 SVN (Implicitly tagged 3)
    0x83, 0x01, 0x05,
    // TCG TCB Info 1 Layer (Implicitly tagged 4)
    0x84, 0x01, 0x06,
    // TCG TCB Info 1 Index (Implicitly tagged 5)
    0x85, 0x01, 0x07,
    // TCG TCB Info 1 FWIDs (Implicitly tagged 6)
    0xA6, 0x7E,
    // FWID 1
    0x30, 0x2D,
    // FWID 1 - hash algo
    0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    // FWID 1 - digest
    0x04, 0x20, 
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    // FWID 2
    0x30,0x4D,
    // FWID 2 - hash algo SHA512
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    // FWID 2 - digest
    0x04, 0x40,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    // TCG TCB Info 1 Operational Flags (Implicitly tagged 7)
    0x87, 0x05, 0x00, 0x80, 0x80, 0x00, 0x01,
    // TCG TCB Inf 1 Vendor Info (Implicitly tagged 8)
    0x88, 0x06, 0x56, 0x45, 0x4E, 0x44, 0x4F, 0x53,
    // TCG TCB Info 1 Type (Implicitly tagged 9)
    0x89, 0x04, 0x54, 0x59, 0x50, 0x45,
    // TCG TCB Info 1 Operational Flags Mask (Implicitly tagged 10)
    0x8A, 0x05, 0x00, 0xff, 0x80, 0x00, 0x01,
     // TCG TCB Info 2 Extension Sequence header
    0x30, 0x17,
    // TCG TCB Info 2 SVN (Implicitly tagged 3)
    0x83, 0x01, 0x05,
    // TCG TCB Info 2 Layer (Implicitly tagged 4)
    0x84, 0x01, 0x06,
    // TCG TCB Info 2 Index (Implicitly tagged 5)
    0x85, 0x01, 0x07,
    // TCG TCB Info 2 Operational Flags (Implicitly tagged 7)
    0x87, 0x05, 0x00, 0x80, 0x80, 0x00, 0x01,
    // TCG TCB Info 2 Operational Flags Mask (Implicitly tagged 10)
    0x8A, 0x05, 0x00, 0xff, 0x80, 0x00, 0x01,
};
// clang-format on

INSTANTIATE_TEST_CASE_P(TcgTcbInfoEncoding,
                        X509ExtTcgTcbInfoTest,
                        testing::Values(std::tuple("aurora",
                                                   "perseus",
                                                   "1.0.5",
                                                   5,
                                                   6,
                                                   7,
                                                   TEST_FWID_LIST,
                                                   TEST_FLAGS,
                                                   TEST_FLAGS_MASK,
                                                   TEST_VENDOR_INFO,
                                                   TEST_TYPE,
                                                   EXPECTED_EXTENSION_WITH_ALL_FIELDS),
                                        std::tuple(std::nullopt,
                                                   std::nullopt,
                                                   std::nullopt,
                                                   5,
                                                   6,
                                                   7,
                                                   std::nullopt,
                                                   TEST_FLAGS,
                                                   TEST_FLAGS_MASK,
                                                   std::nullopt,
                                                   std::nullopt,
                                                   EXPECTED_EXTENSION_WITH_SOME_FIELDS)));

TEST_P(X509ExtTcgTcbInfoTest, TcgTcbInfoEncoding) {
    auto [optional_vendor,
          optional_model,
          optional_version,
          svn,
          layer,
          index,
          optional_fwids,
          flags,
          flags_mask,
          optional_vendor_info,
          optional_type,
          expected] = GetParam();
    n20_x509_ext_tcg_dice_tcb_info_t tcb_info;
    std::memset(&tcb_info, 0, sizeof(tcb_info));

    if (optional_vendor.has_value()) {
        tcb_info.vendor = optional_vendor.value().c_str();
    } else {
        tcb_info.vendor = nullptr;
    }

    if (optional_model.has_value()) {
        tcb_info.model = optional_model.value().c_str();
    } else {
        tcb_info.model = nullptr;
    }

    if (optional_version.has_value()) {
        tcb_info.version = optional_version.value().c_str();
    } else {
        tcb_info.version = nullptr;
    }

    tcb_info.svn = svn;
    tcb_info.layer = layer;
    tcb_info.index = index;

    if (optional_fwids.has_value()) {
        tcb_info.fwids = optional_fwids.value();
    } else {
        tcb_info.fwids.list = nullptr;
        tcb_info.fwids.count = 0;
    }

    tcb_info.flags = flags;
    tcb_info.flags_mask = flags_mask;

    if (optional_vendor_info.has_value()) {
        tcb_info.vendor_info.buffer = optional_vendor_info.value().data();
        tcb_info.vendor_info.size = optional_vendor_info.value().size();
    } else {
        tcb_info.vendor_info.buffer = nullptr;
        tcb_info.vendor_info.size = 0;
    }

    if (optional_type.has_value()) {
        tcb_info.type.buffer = optional_type.value().data();
        tcb_info.type.size = optional_type.value().size();
    } else {
        tcb_info.type.buffer = nullptr;
        tcb_info.type.size = 0;
    }

    n20_x509_extension_t extensions[] = {
        {
            .oid = &OID_TCG_DICE_TCB_INFO,
            .critical = true,
            .content_cb = n20_x509_ext_tcg_dice_tcb_info_content,
            .context = &tcb_info,
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

TEST(X509ExtTcgTcbInfoTest, NullPointer) {
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);

    n20_x509_ext_tcg_dice_tcb_info_content(&s, nullptr);
    auto bytes_written = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(0, bytes_written);
}

TEST(X509ExtTcgMultiTcbInfoTest, TcgTcbMultiInfoEncoding) {
    n20_x509_ext_tcg_dice_tcb_info_t list[] = {
        {
            .vendor = "aurora",
            .model = "perseus",
            .version = "1.0.5",
            .svn = 5,
            .layer = 6,
            .index = 7,
            .fwids = TEST_FWID_LIST,
            .flags = TEST_FLAGS,
            .flags_mask = TEST_FLAGS_MASK,
            .vendor_info =
                {
                    .buffer = TEST_VENDOR_INFO.data(),
                    .size = TEST_VENDOR_INFO.size(),
                },
            .type =
                {
                    .buffer = TEST_TYPE.data(),
                    .size = TEST_TYPE.size(),
                },
        },
        {
            .vendor = nullptr,
            .model = nullptr,
            .version = nullptr,
            .svn = 5,
            .layer = 6,
            .index = 7,
            .fwids =
                {
                    .list = nullptr,
                    .count = 0,
                },
            .flags = TEST_FLAGS,
            .flags_mask = TEST_FLAGS_MASK,
            .vendor_info =
                {
                    .buffer = nullptr,
                    .size = 0,
                },
            .type =
                {
                    .buffer = nullptr,
                    .size = 0,
                },
        },
    };

    n20_x509_ext_tcg_dice_multi_tcb_info_t multi_tcb_info{
        .list = list,
        .count = 2,
    };

    n20_x509_extension_t extensions[] = {
        {
            .oid = &OID_TCG_DICE_MULTI_TCB_INFO,
            .critical = true,
            .content_cb = n20_x509_ext_tcg_dice_multi_tcb_info_content,
            .context = &multi_tcb_info,
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
    ASSERT_EQ(EXPECTED_MULTI_TCB_INFO_EXTENSION.size(), exts_size);

    // Now allocate a buffer large enough to hold the extension,
    // reinitialize the asn1_stream and write the tbs part again.
    uint8_t buffer[2000] = {};
    n20_asn1_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_extension(&s, &exts);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));

    ASSERT_EQ(EXPECTED_MULTI_TCB_INFO_EXTENSION, got);
}

TEST(X509ExtTcgMultiTcbInfoTest, NullPointer) {
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);

    n20_x509_ext_tcg_dice_multi_tcb_info_content(&s, nullptr);
    auto bytes_written = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(0, bytes_written);
}
