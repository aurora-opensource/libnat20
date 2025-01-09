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
#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

class X509ExtOpenDiceInputTest
    : public testing::TestWithParam<std::tuple<std::optional<std::vector<uint8_t>>,
                                               std::optional<std::vector<uint8_t>>,
                                               n20_x509_ext_open_dice_configuration_format_t const,
                                               std::optional<std::vector<uint8_t>>,
                                               std::optional<std::vector<uint8_t>>,
                                               std::optional<std::vector<uint8_t>>,
                                               std::optional<std::vector<uint8_t>>,
                                               std::optional<std::vector<uint8_t>>,
                                               n20_x509_ext_open_dice_modes_t const,
                                               std::optional<std::string>,
                                               std::vector<uint8_t> const>> {};

std::vector<uint8_t> const CODE_HASH = {
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
};

std::vector<uint8_t> const CODE_DESCRIPTOR = {0x63, 0x6f, 0x64, 0x65};

std::vector<uint8_t> const CONFIGURATION_INLINE = {
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
};

std::vector<uint8_t> const CONFIGURATION_HASH = {
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
};

std::vector<uint8_t> const CONFIGURATION_DESCRIPTOR = {0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67};

std::vector<uint8_t> const AUTHORITY_HASH = {
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

std::vector<uint8_t> const AUTHORITY_DESCRIPTOR = {0x61, 0x75, 0x74, 0x68};

// clang-format off
std::vector<uint8_t> const EXTENSION_WITH_INLINE_CONFIGURATION = {
    // Extension header
    0xA3, 0x82, 0x01, 0x19,
    // Extensions sequence header
    0x30, 0x82, 0x01, 0x15,
    // OpenDICEInputs extension sequence header
    0x30, 0x82, 0x01, 0x11,
    // OpenDICEInputs OID
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x18,
    // Critical = True
    0x01, 0x01, 0xFF,
    // OpenDICEInputs Extension Octet String
    0x04, 0x81, 0xFF,
    // OpenDICEInputs Extension Sequence header
    0x30, 0x81, 0xFC,
    // Code Hash
    0xA0, 0x42,
    0x04, 0x40,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    // Code Descriptor
    0xA1, 0x06,
    0x04, 0x04,
    0x63, 0x6f, 0x64, 0x65,
    // Inline Configuration
    0xA3, 0x42,
    0x04, 0x40,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
    // Authority Hash
    0xA4, 0x42,
    0x04, 0x40,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    // Authority Descriptor
    0xA5, 0x06,
    0x04, 0x04,
    0x61, 0x75, 0x74, 0x68,
    // Mode
    0xA6, 0x03,
    0x02, 0x01, 0x01,
    // Profile Name
    0xA7, 0x19,
    0x13, 0x17,
    'A', 'u', 'r', 'o', 'r', 'a', ' ', 
    'O', 'p', 'e', 'n', 'D', 'I', 'C', 
    'E', ' ', 'P', 'r', 'o', 'f', 'i', 
    'l', 'e',
};

std::vector<uint8_t> const EXTENSION_WITH_CONFIGURATION_DESCRIPTOR = {
    // Extension header
    0xA3, 0x82, 0x01, 0x25,
    // Extensions sequence header
    0x30, 0x82, 0x01, 0x21,
    // OpenDICEInputs extension sequence header
    0x30, 0x82, 0x01, 0x1D,
    // OpenDICEInputs OID
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x18,
    // Critical = True
    0x01, 0x01, 0xFF,
    // OpenDICEInputs Extension Octet String
    0x04, 0x82, 0x01, 0x0A,
    // OpenDICEInputs Extension Sequence header
    0x30, 0x82, 0x01, 0x06,
    // Code Hash
    0xA0, 0x42,
    0x04, 0x40,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
    // Code Descriptor
    0xA1, 0x06,
    0x04, 0x04,
    0x63, 0x6f, 0x64, 0x65,
    // Configuration Hash
    0xA2, 0x42,
    0x04, 0x40,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
    // Configuration Descriptor
    0xA3, 0x08,
    0x04, 0x06,
    0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
    // Authority Hash
    0xA4, 0x42,
    0x04, 0x40,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    // Authority Descriptor
    0xA5, 0x06,
    0x04, 0x04,
    0x61, 0x75, 0x74, 0x68,
    // Mode
    0xA6, 0x03,
    0x02, 0x01, 0x01,
    // Profile Name
    0xA7, 0x19,
    0x13, 0x17,
    'A', 'u', 'r', 'o', 'r', 'a', ' ', 
    'O', 'p', 'e', 'n', 'D', 'I', 'C', 
    'E', ' ', 'P', 'r', 'o', 'f', 'i', 
    'l', 'e',
};

std::vector<uint8_t> const EXTENSION_WITHOUT_OPTIONALS = {
    // Extension header
    0xA3, 0x1C,
    // Extensions sequence header
    0x30, 0x1A,
    // OpenDICEInputs extension sequence header
    0x30, 0x18,
    // OpenDICEInputs OID
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x18,
    // Critical = True
    0x01, 0x01, 0xFF,
    // OpenDICEInputs Extension Octet String
    0x04, 0x07,
    // OpenDICEInputs Extension Sequence header
    0x30, 0x05,
    // Mode
    0xA6, 0x03,
    0x02, 0x01, 0x00,
};
// clang-format on

std::string const AURORA_OPEN_DICE_PROFILE = "Aurora OpenDICE Profile";

INSTANTIATE_TEST_CASE_P(
    OpenDiceInputEncoding,
    X509ExtOpenDiceInputTest,
    testing::Values(std::tuple(CODE_HASH,
                               CODE_DESCRIPTOR,
                               n20_x509_ext_open_dice_configuration_format_inline_e,
                               CONFIGURATION_INLINE,
                               std::nullopt,
                               std::nullopt,
                               AUTHORITY_HASH,
                               AUTHORITY_DESCRIPTOR,
                               n20_x509_ext_open_dice_normal_e,
                               AURORA_OPEN_DICE_PROFILE,
                               EXTENSION_WITH_INLINE_CONFIGURATION),
                    std::tuple(CODE_HASH,
                               CODE_DESCRIPTOR,
                               n20_x509_ext_open_dice_configuration_format_descriptor_e,
                               std::nullopt,
                               CONFIGURATION_HASH,
                               CONFIGURATION_DESCRIPTOR,
                               AUTHORITY_HASH,
                               AUTHORITY_DESCRIPTOR,
                               n20_x509_ext_open_dice_normal_e,
                               AURORA_OPEN_DICE_PROFILE,
                               EXTENSION_WITH_CONFIGURATION_DESCRIPTOR),
                    std::tuple(std::nullopt,
                               std::nullopt,
                               n20_x509_ext_open_dice_configuration_format_inline_e,
                               std::nullopt,
                               std::nullopt,
                               std::nullopt,
                               std::nullopt,
                               std::nullopt,
                               n20_x509_ext_open_dice_not_configured_e,
                               std::nullopt,
                               EXTENSION_WITHOUT_OPTIONALS)));

template <typename T>
inline static n20_asn1_slice_t v2slice(T const& v) {
    if (v.has_value()) {
        return n20_asn1_slice_t{v->data(), v->size()};
    }
    return n20_asn1_slice_t{nullptr, 0};
}

TEST_P(X509ExtOpenDiceInputTest, OpenDiceInputEncoding) {
    auto [optional_code_hash,
          optional_code_descriptor,
          configuration_format,
          optional_configuration_inline,
          optional_configuration_hash,
          optional_configuration_descriptor,
          optional_authority_hash,
          optional_authority_descriptor,
          mode,
          optional_profile,
          expected] = GetParam();

    n20_x509_ext_open_dice_input_t inputs;
    std::memset(&inputs, 0, sizeof(n20_x509_ext_open_dice_input_t));

    inputs.code_hash = v2slice(optional_code_hash);
    inputs.code_descriptor = v2slice(optional_code_descriptor);

    inputs.configuration_format = configuration_format;
    switch (inputs.configuration_format) {
        case n20_x509_ext_open_dice_configuration_format_inline_e:
            inputs.configuration_inline = v2slice(optional_configuration_inline);
            break;
        case n20_x509_ext_open_dice_configuration_format_descriptor_e:
            inputs.configuration_hash = v2slice(optional_configuration_hash);
            inputs.configuration_descriptor = v2slice(optional_configuration_descriptor);
            break;
    }

    inputs.authority_hash = v2slice(optional_authority_hash);
    inputs.authority_descriptor = v2slice(optional_authority_descriptor);
    inputs.mode = mode;

    if (optional_profile.has_value()) {
        inputs.profile_name = optional_profile.value().c_str();
    }

    n20_x509_extension_t extensions[] = {
        {
            .oid = &OID_OPEN_DICE_INPUT,
            .critical = true,
            .content_cb = n20_x509_ext_open_dice_input_content,
            .context = &inputs,
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

TEST(X509ExtOpenDiceInputTest, NullPointers) {
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);

    n20_x509_ext_open_dice_input_content(&s, nullptr);
    auto bytes_written = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(0, bytes_written);
}
