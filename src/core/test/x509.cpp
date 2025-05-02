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
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/oid.h>
#include <nat20/x509.h>
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pki/verify.h>
#include <openssl/x509.h>

#include <iomanip>
#include <memory>
#include <ostream>
#include <sstream>
#include <vector>

#define MAKE_PTR(name) using name##_PTR_t = bssl::UniquePtr<name>

MAKE_PTR(EVP_PKEY);
MAKE_PTR(EVP_PKEY_CTX);
MAKE_PTR(EVP_MD_CTX);
MAKE_PTR(BIO);
MAKE_PTR(X509);
MAKE_PTR(EC_KEY);

std::string hexdump(std::vector<uint8_t> const& data) {
    std::stringstream s;
    int i;
    for (i = 0; i < data.size() - 1; ++i) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i % 16 == 15) {
            s << "\n";
        } else if (i % 16 == 7) {
            s << "  ";
        } else {
            s << " ";
        }
    }
    if (i < data.size()) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

std::string BsslError() {
    char buffer[2000];
    auto error = ERR_get_error();
    ERR_error_string_n(error, buffer, 2000);
    return std::string(buffer);
}

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

uint8_t const test_cdi2[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

class NameTest : public testing::TestWithParam<std::tuple<n20_x509_name_t*, std::vector<uint8_t>>> {
};

n20_x509_name_t NAME_EMPTY = {.element_count = 0, .elements = {}};
n20_x509_name_t NAME_ONE = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"));
n20_x509_name_t NAME_TWO = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                                         N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"));
n20_x509_name_t NAME_NINE = {.element_count = 9, .elements = {}};

std::vector<uint8_t> const ENCODED_NAME_NULL = {0x30, 0x02, 0x05, 0x00};
std::vector<uint8_t> const ENCODED_NAME_EMPTY = {0x30, 0x00};
std::vector<uint8_t> const ENCODED_NAME_ONE = {
    0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53};
std::vector<uint8_t> const ENCODED_NAME_TWO = {
    0x30, 0x22, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07,
    0x13, 0x0a, 0x50, 0x69, 0x74, 0x74, 0x73, 0x62, 0x75, 0x72, 0x67, 0x68};

INSTANTIATE_TEST_CASE_P(X509NameTest,
                        NameTest,
                        testing::Values(std::tuple(nullptr, ENCODED_NAME_NULL),
                                        std::tuple(&NAME_EMPTY, ENCODED_NAME_EMPTY),
                                        std::tuple(&NAME_ONE, ENCODED_NAME_ONE),
                                        std::tuple(&NAME_TWO, ENCODED_NAME_TWO),
                                        std::tuple(&NAME_NINE, ENCODED_NAME_NULL)));

// This test tests name encoding. It verifies that slices with one or two well formed
// names are encoded correctly as well as the following corner cases: null slice, empty
// slice, and slice with more names than the maximum supported by this library.
TEST_P(NameTest, NameEncoding) {
    auto [p, expected] = GetParam();

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_name(&s, p);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), expected.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(expected, got);
}
class ExtensionTest
    : public testing::TestWithParam<
          std::tuple<std::variant<n20_x509_extensions_t*, std::vector<n20_x509_extension_t>>,
                     std::vector<uint8_t>>> {};

void key_usage_content_cb(n20_stream_t* s, void* cb_context) {
    uint8_t n = 0x05;

    n20_asn1_bitstring(s, &n, 3, n20_asn1_tag_info_no_override());
}

void basic_constraints_content_cb(n20_stream_t* s, void* cb_context) {
    n20_asn1_sequence(s, nullptr, nullptr, n20_asn1_tag_info_no_override());
}

n20_x509_extensions_t EXTENSIONS_EMPTY = {};
std::vector<n20_x509_extension_t> const EXTENSIONS_ONE_EMPTY_EXTN_VALUE = {
    {.oid = &OID_KEY_USAGE, .critical = false, .content_cb = nullptr}};
std::vector<n20_x509_extension_t> const EXTENSIONS_ONE = {
    {.oid = &OID_KEY_USAGE, .critical = true, .content_cb = &key_usage_content_cb}};
std::vector<n20_x509_extension_t> const EXTENSIONS_TWO = {
    {.oid = &OID_KEY_USAGE, .critical = true, .content_cb = &key_usage_content_cb},
    {.oid = &OID_BASIC_CONSTRAINTS, .critical = true, .content_cb = &basic_constraints_content_cb}};

std::vector<uint8_t> const ENCODED_EXTENSIONS_EMPTY = {};
std::vector<uint8_t> const ENCODED_EXTENSIONS_ONE_EMPTY_EXTN_VALUE = {
    0xa3, 0x0b, 0x30, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x00};
std::vector<uint8_t> const ENCODED_EXTENSIONS_ONE = {0xa3, 0x12, 0x30, 0x10, 0x30, 0x0e, 0x06,
                                                     0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
                                                     0x04, 0x04, 0x03, 0x02, 0x05, 0x00};
std::vector<uint8_t> const ENCODED_EXTENSIONS_TWO = {
    0xa3, 0x20, 0x30, 0x1e, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};

INSTANTIATE_TEST_CASE_P(X509ExtensionTest,
                        ExtensionTest,
                        testing::Values(std::tuple(nullptr, ENCODED_EXTENSIONS_EMPTY),
                                        std::tuple(&EXTENSIONS_EMPTY, ENCODED_EXTENSIONS_EMPTY),
                                        std::tuple(EXTENSIONS_ONE_EMPTY_EXTN_VALUE,
                                                   ENCODED_EXTENSIONS_ONE_EMPTY_EXTN_VALUE),
                                        std::tuple(EXTENSIONS_ONE, ENCODED_EXTENSIONS_ONE),
                                        std::tuple(EXTENSIONS_TWO, ENCODED_EXTENSIONS_TWO)));

// This test tests extension encoding. It verifies that vectors with one or two well formed
// extensions are encoded correctly as well as the following corner cases: null vector, empty
// vector, and vector with one extension with an empty value.
TEST_P(ExtensionTest, ExtensionEncoding) {
    auto [p, expected] = GetParam();

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    if (auto extensions = std::get_if<n20_x509_extensions_t*>(&p)) {
        n20_x509_extension(&s, *extensions);
    }
    if (auto extensions_vector = std::get_if<std::vector<n20_x509_extension_t>>(&p)) {
        n20_x509_extensions_t extensions = {.extensions_count = extensions_vector->size(),
                                            .extensions = extensions_vector->data()};
        n20_x509_extension(&s, &extensions);
    }
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), expected.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(expected, got);
}

class BasicConstraintsTest
    : public testing::TestWithParam<std::tuple<bool, bool, uint32_t, std::vector<uint8_t>>> {};

std::vector<uint8_t> const ENCODED_BASIC_CONSTRAINTS_NOT_CA_NO_PATH_LENGTH = {0x30, 0x00};
std::vector<uint8_t> const ENCODED_BASIC_CONSTRAINTS_NOT_CA_HAS_PATH_LENGTH =
    ENCODED_BASIC_CONSTRAINTS_NOT_CA_NO_PATH_LENGTH;
std::vector<uint8_t> const ENCODED_BASIC_CONSTRAINTS_IS_CA_NO_PATH_LENGTH = {
    0x30, 0x03, 0x01, 0x01, 0xff};
std::vector<uint8_t> const ENCODED_BASIC_CONSTRAINTS_IS_CA_HAS_PATH_LENGTH = {
    0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00};
std::vector<uint8_t> const ENCODED_BASIC_CONSTRAINTS_IS_CA_HAS_PATH_LENGTH_ONE = {
    0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01};

INSTANTIATE_TEST_CASE_P(
    X509BasicConstraintsTest,
    BasicConstraintsTest,
    testing::Values(
        std::tuple(false, false, 0, ENCODED_BASIC_CONSTRAINTS_NOT_CA_NO_PATH_LENGTH),
        std::tuple(false, true, 0, ENCODED_BASIC_CONSTRAINTS_NOT_CA_HAS_PATH_LENGTH),
        std::tuple(true, false, 0, ENCODED_BASIC_CONSTRAINTS_IS_CA_NO_PATH_LENGTH),
        std::tuple(true, true, 0, ENCODED_BASIC_CONSTRAINTS_IS_CA_HAS_PATH_LENGTH),
        std::tuple(true, true, 1, ENCODED_BASIC_CONSTRAINTS_IS_CA_HAS_PATH_LENGTH_ONE)));

// This test tests basic constraints encoding. It verifies that basic constraints with various
// arguments are encoded correctly.
TEST_P(BasicConstraintsTest, BasicConstraintsEncoding) {
    auto [is_ca, has_path_length, path_length, expected] = GetParam();

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_basic_constraints_t context = {
        .is_ca = is_ca, .has_path_length = has_path_length, .path_length = path_length};
    n20_x509_ext_basic_constraints_content(&s, &context);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), expected.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(expected, got);
}

class KeyUsageTest : public testing::Test {};

std::vector<uint8_t> const ENCODED_KEY_USAGE_ZERO_BITS = {0x03, 0x01, 0x00};

// This test tests key usage encoding. It verifies that a key usage mask that uses zero bits is
// encoded correctly.
TEST(KeyUsageTest, KeyUsageZeroBitsEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_KEY_USAGE_ZERO_BITS.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_ZERO_BITS, got);
}

std::vector<uint8_t> const ENCODED_KEY_USAGE_SIX_BITS = {0x03, 0x02, 0x02, 0x84};

// This test tests key usage encoding. It verifies that a key usage mask that uses six bits is
// encoded correctly.
TEST(KeyUsageTest, KeyUsageSixBitsEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_KEY_USAGE_SIX_BITS.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_SIX_BITS, got);
}

std::vector<uint8_t> const ENCODED_KEY_USAGE_NINE_BITS = {0x03, 0x03, 0x07, 0x84, 0x80};

// This test tests key usage encoding. It verifies that a key usage mask that uses nine bits is
// encoded correctly.
TEST(KeyUsageTest, KeyUsageNineBitsEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);
    N20_X509_KEY_USAGE_SET_DECIPHER_ONLY(&key_usage);

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_KEY_USAGE_NINE_BITS.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_NINE_BITS, got);
}

std::vector<uint8_t> const ENCODED_KEY_USAGE_NINE_BITS_ALL_SET = {0x03, 0x03, 0x07, 0xff, 0x80};

// This test tests key usage encoding. It verifies that a key usage mask with nine bits all set
// is encoded correctly.
TEST(KeyUsageTest, KeyUsageNineBitsAllSetEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_CONTENT_COMMITMENT(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_ENCIPHERMENT(&key_usage);
    N20_X509_KEY_USAGE_SET_DATA_ENCIPHERMENT(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_AGREEMENT(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);
    N20_X509_KEY_USAGE_SET_CRL_SIGN(&key_usage);
    N20_X509_KEY_USAGE_SET_ENCIPHER_ONLY(&key_usage);
    N20_X509_KEY_USAGE_SET_DECIPHER_ONLY(&key_usage);

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_KEY_USAGE_NINE_BITS_ALL_SET.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_NINE_BITS_ALL_SET, got);
}

// This test tests key usage encoding. It verifies that a key usage mask with sixteen bits all set
// is encoded correctly.
TEST(KeyUsageTest, KeyUsageSixteenBitsAllSetEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0xff, 0xff}};

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_KEY_USAGE_NINE_BITS_ALL_SET.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_NINE_BITS_ALL_SET, got);
}

class CertTBSTest : public testing::Test {};

std::vector<uint8_t> const ENCODED_CERT_TBS_NULL = {0x30, 0x00};

// Test the encoding of a null tbs structure.
TEST(CertTBSTest, CertTBSNullEncoding) {
    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert_tbs(&s, nullptr);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_CERT_TBS_NULL.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_CERT_TBS_NULL, got);
}

// clang-format off
std::vector<uint8_t> const ENCODED_CERT_TBS_ZERO = {
    0x30, 0x3d,
    // version
    0xa0, 0x03, 0x02, 0x01, 0x02,
    // serialNumber
    0x02, 0x01, 0x00,
    // signature
    0x30, 0x02, 0x05, 0x00,
    // issuer
    0x30, 0x00,
    // validity
    0x30, 0x22, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
    0x39, 0x35, 0x39, 0x5a,
    // subject
    0x30, 0x00,
    // subjectPublicKeyInfo
    0x30, 0x07, 0x30, 0x02, 0x05, 0x00, 0x03, 0x01, 0x00,
};
// clang-format on

// Test the encoding of a zero tbs structure.
TEST(CertTBSTest, CertTBSZeroEncoding) {
    n20_x509_tbs_t tbs = {0};

    n20_stream_t s;
    uint8_t buffer[128];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_CERT_TBS_ZERO.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_CERT_TBS_ZERO, got);
}

// clang-format off
std::vector<uint8_t> const ENCODED_CERT_TBS_NONZERO = {
    0x30, 0x81, 0xe5,
    // version
    0xa0, 0x03, 0x02, 0x01, 0x02,
    // serialNumber
    0x02, 0x01, 0x01,
    // signature
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    // issuer
    0x30, 0x37, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x63, 0x72, 0x61, 0x6e, 0x74,
    0x6f, 0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x54, 0x65, 0x73,
    0x74, 0x20, 0x44, 0x49, 0x43, 0x45, 0x20, 0x43, 0x41,
    // validity
    0x30, 0x22, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x30, 0x30, 0x39, 0x30, 0x32, 0x31, 0x33, 0x32, 0x35,
    0x32, 0x36, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x30, 0x30, 0x39, 0x30, 0x32, 0x31, 0x33, 0x32,
    0x35, 0x32, 0x36, 0x5a,
    // subject
    0x30, 0x37, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x63, 0x72, 0x61, 0x6e, 0x74,
    0x6f, 0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x54, 0x65, 0x73,
    0x74, 0x20, 0x44, 0x49, 0x43, 0x45, 0x20, 0x43, 0x41,
    // subjectPublicKeyInfo
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x3b, 0xa9, 0x2f, 0xfd,
    0xcb, 0x17, 0x66, 0xde, 0x40, 0xa2, 0x92, 0xf7, 0x93, 0xde, 0x30, 0xf8, 0x0a, 0x23, 0xa8, 0x31,
    0x21, 0x5d, 0xd0, 0x07, 0xd8, 0x63, 0x24, 0x2e, 0xff, 0x68, 0x21, 0x85,
    // extensions
    0xa3, 0x12, 0x30, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
    0x03, 0x02, 0x05, 0x00
};
// clang-format on

// Test the encoding of a non zero tbs structure.
TEST(CertTBSTest, CertTBSNonzeroEncoding) {
    std::vector<uint8_t> public_key_v = {0x3b, 0xa9, 0x2f, 0xfd, 0xcb, 0x17, 0x66, 0xde,
                                         0x40, 0xa2, 0x92, 0xf7, 0x93, 0xde, 0x30, 0xf8,
                                         0x0a, 0x23, 0xa8, 0x31, 0x21, 0x5d, 0xd0, 0x07,
                                         0xd8, 0x63, 0x24, 0x2e, 0xff, 0x68, 0x21, 0x85};
    n20_x509_tbs_t tbs = {
        .serial_number = 1,
        .signature_algorithm =
            {
                .oid = &OID_ED25519,
                .params =
                    {
                        .variant = n20_x509_pv_none_e,
                        .ec_curve = nullptr,
                    },
            },
        .issuer_name = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                                     N20_X509_RDN(&OID_LOCALITY_NAME, "Scranton"),
                                     N20_X509_RDN(&OID_COMMON_NAME, "Test DICE CA")),
        .validity = {.not_before = "20200902132526Z", .not_after = "20200902132526Z"},
        .subject_name = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                                      N20_X509_RDN(&OID_LOCALITY_NAME, "Scranton"),
                                      N20_X509_RDN(&OID_COMMON_NAME, "Test DICE CA")),
        .subject_public_key_info =
            {
                .algorithm_identifier = {.oid = &OID_ED25519,
                                         .params = {.variant = n20_x509_pv_none_e,
                                                    .ec_curve = nullptr}},
                .public_key_bits = 256,
                .public_key = public_key_v.data(),
            },
        .extensions =
            {
                .extensions_count = EXTENSIONS_ONE.size(),
                .extensions = EXTENSIONS_ONE.data(),
            },
    };

    n20_stream_t s;
    uint8_t buffer[256];
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_EQ(n20_stream_byte_count(&s), ENCODED_CERT_TBS_NONZERO.size());
    std::vector<uint8_t> got =
        std::vector<uint8_t>(n20_stream_data(&s), n20_stream_data(&s) + n20_stream_byte_count(&s));
    ASSERT_EQ(ENCODED_CERT_TBS_NONZERO, got);
}

class CertTest : public testing::TestWithParam<std::tuple<n20_crypto_key_type_t,
                                                          n20_x509_algorithm_identifier_t,
                                                          n20_x509_algorithm_identifier_t,
                                                          bool>> {};

INSTANTIATE_TEST_CASE_P(
    X509CertTest,
    CertTest,
    testing::Values(
        std::tuple(n20_crypto_key_type_ed25519_e,
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_ED25519,
                       .params = {.variant = n20_x509_pv_none_e, .ec_curve = nullptr},
                   },
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_ED25519,
                       .params = {.variant = n20_x509_pv_none_e, .ec_curve = nullptr},
                   },
                   true),
        std::tuple(n20_crypto_key_type_ed25519_e,
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_ED25519,
                       .params = {.variant = n20_x509_pv_none_e, .ec_curve = nullptr},
                   },
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_ED25519,
                       .params = {.variant = n20_x509_pv_none_e, .ec_curve = nullptr},
                   },
                   false),
        std::tuple(n20_crypto_key_type_secp256r1_e,
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_ECDSA_WITH_SHA256,
                       .params = {.variant = n20_x509_pv_none_e, .ec_curve = nullptr},
                   },
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_EC_PUBLIC_KEY,
                       .params = {.variant = n20_x509_pv_ec_curve_e, .ec_curve = &OID_SECP256R1},
                   },
                   true),
        std::tuple(n20_crypto_key_type_secp384r1_e,
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_ECDSA_WITH_SHA384,
                       .params = {.variant = n20_x509_pv_none_e, .ec_curve = nullptr},
                   },
                   n20_x509_algorithm_identifier_t{
                       .oid = &OID_EC_PUBLIC_KEY,
                       .params = {.variant = n20_x509_pv_ec_curve_e, .ec_curve = &OID_SECP384R1},
                   },
                   true)));

EVP_PKEY_PTR_t n20_crypto_key_to_evp_pkey_ptr(n20_crypto_key_type_s key_type,
                                              uint8_t* public_key,
                                              size_t public_key_size) {
    switch (key_type) {
        case n20_crypto_key_type_ed25519_e: {
            auto key = EVP_PKEY_PTR_t(
                EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, public_key_size));
            if (!key) {
                ADD_FAILURE();
                return nullptr;
            }

            return key;
        }
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            auto ec_key = EC_KEY_PTR_t(EC_KEY_new_by_curve_name(
                key_type == n20_crypto_key_type_secp256r1_e ? NID_X9_62_prime256v1
                                                            : NID_secp384r1));
            if (!ec_key) {
                ADD_FAILURE();
                return nullptr;
            }

            auto ec_key_p = ec_key.get();
            uint8_t const* p = public_key;
            if (!o2i_ECPublicKey(&ec_key_p, &p, public_key_size)) {
                ADD_FAILURE();
                return nullptr;
            }

            auto key = EVP_PKEY_PTR_t(EVP_PKEY_new());
            if (!key || !EVP_PKEY_assign_EC_KEY(key.get(), ec_key.release())) {
                ADD_FAILURE();
                return nullptr;
            }

            return key;
        }
        default: {
            ADD_FAILURE();
            return nullptr;
        }
    }
}

typedef struct n20_x509_rs_s {
    uint8_t const* signature;
    size_t signature_size;
} n20_x509_rs_t;

void n20_x509_rs_content(n20_stream_t* const s, void* context) {
    n20_x509_rs_t const* rs = (n20_x509_rs_t const*)context;

    n20_asn1_integer(s,
                     rs->signature + rs->signature_size / 2,
                     rs->signature_size / 2,
                     false,
                     false,
                     n20_asn1_tag_info_no_override());
    n20_asn1_integer(
        s, rs->signature, rs->signature_size / 2, false, false, n20_asn1_tag_info_no_override());
}

void n20_x509_rs(n20_stream_t* const s, n20_x509_rs_t const* const rs) {
    n20_asn1_sequence(s, n20_x509_rs_content, (void*)rs, n20_asn1_tag_info_no_override());
}

// Test the encoding and successful verification of a well formed cert. It additionally also tests
// that a well formed cert created using a different cdi does not verify.
TEST_P(CertTest, CertEncoding) {
    auto [key_type, signature_algorithm, subject_public_key_info_algorithm, has_path_length] =
        GetParam();

    // Create a key with test_cdi.
    n20_crypto_context_t* ctx = nullptr;
    n20_slice_t cdi_slice{.size = sizeof(test_cdi), .buffer = test_cdi};
    n20_crypto_error_t err = n20_crypto_open_boringssl(&ctx, &cdi_slice);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    n20_crypto_key_t cdi_key = nullptr;
    err = ctx->get_cdi(ctx, &cdi_key);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    n20_crypto_gather_list_t empty_context{.count = 0, .list = nullptr};

    n20_crypto_key_t signing_key = nullptr;
    err = ctx->kdf(ctx, cdi_key, key_type, &empty_context, &signing_key);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    uint8_t public_key_buffer[128];
    uint8_t* public_key = &public_key_buffer[1];
    size_t public_key_size = sizeof(public_key_buffer) - 1;
    err = ctx->key_get_public_key(ctx, signing_key, public_key, &public_key_size);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    if (key_type != n20_crypto_key_type_ed25519_e) {
        public_key_buffer[0] = 0x04;
        public_key = &public_key_buffer[0];
        public_key_size += 1;
    }

    // Assemble the to-be-signed part of the certificate.
    n20_x509_ext_key_usage_t key_usage = {0};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_x509_ext_basic_constraints_t basic_constraints = {
        .is_ca = 1,
        .has_path_length = has_path_length,
        .path_length = 1,
    };
    std::vector<n20_x509_extension_t> extensions_v = {
        {
            .oid = &OID_KEY_USAGE,
            .critical = 1,
            .content_cb = n20_x509_ext_key_usage_content,
            .context = &key_usage,
        },
        {
            .oid = &OID_BASIC_CONSTRAINTS,
            .critical = 1,
            .content_cb = n20_x509_ext_basic_constraints_content,
            .context = &basic_constraints,
        },
    };
    n20_x509_tbs_t tbs = {
        .serial_number = 1,
        .signature_algorithm = signature_algorithm,
        .issuer_name = N20_X509_NAME(
            N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
            N20_X509_RDN(&OID_LOCALITY_NAME, "Scranton"),
            N20_X509_RDN(&OID_ORGANIZATION_NAME, "Dunder Mifflin Paper Company, Inc."),
            N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Dunder Mifflin Information Security"),
            N20_X509_RDN(&OID_COMMON_NAME, "Dunder Mifflin DICE Authority")),
        .validity =
            {
                .not_before = nullptr,
                .not_after = nullptr,
            },
        .subject_name = N20_X509_NAME(
            N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
            N20_X509_RDN(&OID_LOCALITY_NAME, "Scranton"),
            N20_X509_RDN(&OID_ORGANIZATION_NAME, "Dunder Mifflin Paper Company, Inc."),
            N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Dunder Mifflin Information Security"),
            N20_X509_RDN(&OID_COMMON_NAME, "Dunder Mifflin DICE Authority")),
        .subject_public_key_info =
            {
                .algorithm_identifier = subject_public_key_info_algorithm,
                .public_key_bits = public_key_size * 8,
                .public_key = public_key,
            },
        .extensions =
            {
                .extensions_count = extensions_v.size(),
                .extensions = extensions_v.data(),
            },
    };

    // DER encode the to-be-signed part of the certificate.
    n20_stream_t s;
    uint8_t buffer[2000];
    n20_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    n20_slice_t tbs_der_slice{.size = n20_stream_byte_count(&s), .buffer = n20_stream_data(&s)};
    n20_crypto_gather_list_t tbs_der_gather{.count = 1, .list = &tbs_der_slice};

    // Sign the to-be-signed part of the certificate.
    uint8_t signature[128];
    size_t signature_size = sizeof(signature);
    err = ctx->sign(ctx, signing_key, &tbs_der_gather, signature, &signature_size);
    ASSERT_EQ(n20_crypto_error_ok_e, err);
    ctx->key_free(ctx, signing_key);
    n20_crypto_close_boringssl(ctx);

    switch (key_type) {
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            n20_x509_rs_t rs = {.signature = signature, .signature_size = signature_size};
            n20_stream_init(&s, &buffer[0], sizeof(buffer));
            n20_x509_rs(&s, &rs);
            ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
            ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
            memcpy(signature, n20_stream_data(&s), n20_stream_byte_count(&s));
            signature_size = n20_stream_byte_count(&s);
        }
        default:
            break;
    }

    // Assemble the full certificate and DER encode it.
    n20_x509_t cert = {
        .tbs = &tbs,
        .signature_algorithm = tbs.signature_algorithm,
        .signature_bits = signature_size * 8,
        .signature = signature,
    };
    n20_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert(&s, &cert);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    // Now verify the certificate.
    uint8_t const* p = n20_stream_data(&s);
    auto x509i = X509_PTR_t(d2i_X509(nullptr, &p, (long)n20_stream_byte_count(&s)));
    ASSERT_TRUE(!!x509i) << BsslError() << "\n"
                         << hexdump(std::vector<uint8_t>(
                                n20_stream_data(&s),
                                n20_stream_data(&s) + n20_stream_byte_count(&s)));
    X509_print_ex_fp(stdout, x509i.get(), 0, X509V3_EXT_DUMP_UNKNOWN);
    auto key = n20_crypto_key_to_evp_pkey_ptr(key_type, public_key, public_key_size);
    auto rc = X509_verify(x509i.get(), key.get());
    ASSERT_EQ(rc, 1) << BsslError();

    bssl::CertificateVerifyOptions cert_opts{};
    bssl::VerifyError v_error{};
    bssl::CertificateVerifyStatus v_status{};
    std::unique_ptr<bssl::VerifyTrustStore> trust_store;

    // The validation code in boringssl's pki library does not understand ED25519, so we have to
    // skip this test for now.
    if (key_type != n20_crypto_key_type_ed25519_e) {
        // Validate the self signed certificate.
        std::string diag;
        auto cert_string_view = std::string_view(reinterpret_cast<char const*>(n20_stream_data(&s)),
                                                 n20_stream_byte_count(&s));
        trust_store = bssl::VerifyTrustStore::FromDER(cert_string_view, &diag);
        ASSERT_TRUE(!!trust_store) << "Diag: " << diag;
        cert_opts.leaf_cert = cert_string_view;
        cert_opts.trust_store = trust_store.get();
        auto verify_result = bssl::CertificateVerify(cert_opts, &v_error, &v_status);
        ASSERT_TRUE(!!verify_result);
        ASSERT_EQ(v_error.Code(), bssl::VerifyError::StatusCode::PATH_VERIFIED)
            << "Diag: " << v_error.DiagnosticString();
    }

    // Now create a certificate signed with a different key. It is expected to fail the
    // verification.

    // Create a key with test_cdi2.
    n20_crypto_context_t* ctx2 = nullptr;
    n20_slice_t cdi_slice2{.size = sizeof(test_cdi2), .buffer = test_cdi2};
    err = n20_crypto_open_boringssl(&ctx2, &cdi_slice2);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    n20_crypto_key_t cdi_key2 = nullptr;
    err = ctx2->get_cdi(ctx2, &cdi_key2);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    n20_crypto_key_t signing_key2 = nullptr;
    err = ctx2->kdf(ctx2, cdi_key2, key_type, &empty_context, &signing_key2);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    uint8_t public_key_buffer2[128];
    uint8_t* public_key2 = &public_key_buffer2[1];
    size_t public_key_size2 = sizeof(public_key_buffer2) - 1;
    err = ctx2->key_get_public_key(ctx2, signing_key2, public_key2, &public_key_size2);
    ASSERT_EQ(n20_crypto_error_ok_e, err);

    if (key_type != n20_crypto_key_type_ed25519_e) {
        public_key_buffer2[0] = 0x04;
        public_key2 = &public_key_buffer2[0];
        public_key_size2 += 1;
    }

    // DER encode the to-be-signed part of the certificate.
    uint8_t buffer2[2000];
    n20_stream_init(&s, &buffer2[0], sizeof(buffer2));
    n20_x509_cert_tbs(&s, &tbs);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    n20_slice_t tbs_der_slice2{.size = n20_stream_byte_count(&s), .buffer = n20_stream_data(&s)};
    n20_crypto_gather_list_t tbs_der_gather2{.count = 1, .list = &tbs_der_slice2};

    // Sign the to-be-signed part of the certificate.
    uint8_t signature2[128];
    size_t signature_size2 = sizeof(signature2);
    err = ctx2->sign(ctx2, signing_key2, &tbs_der_gather2, signature2, &signature_size2);
    ASSERT_EQ(n20_crypto_error_ok_e, err);
    ctx2->key_free(ctx2, signing_key2);
    n20_crypto_close_boringssl(ctx2);

    switch (key_type) {
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            n20_x509_rs_t rs = {.signature = signature2, .signature_size = signature_size2};
            n20_stream_init(&s, &buffer2[0], sizeof(buffer2));
            n20_x509_rs(&s, &rs);
            ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
            ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));
            memcpy(signature2, n20_stream_data(&s), n20_stream_byte_count(&s));
            signature_size2 = n20_stream_byte_count(&s);
        }
        default:
            break;
    }

    // Assemble the full certificate and DER encode it.
    n20_x509_t cert2 = {
        .tbs = &tbs,
        .signature_algorithm = tbs.signature_algorithm,
        .signature_bits = signature_size2 * 8,
        .signature = signature2,
    };
    n20_stream_init(&s, &buffer2[0], sizeof(buffer2));
    n20_x509_cert(&s, &cert2);
    ASSERT_FALSE(n20_stream_has_buffer_overflow(&s));
    ASSERT_FALSE(n20_stream_has_write_position_overflow(&s));

    // Now verify the new certificate with the new key.
    uint8_t const* p2 = n20_stream_data(&s);
    auto x509i2 = X509_PTR_t(d2i_X509(nullptr, &p2, (long)n20_stream_byte_count(&s)));
    ASSERT_TRUE(!!x509i2) << BsslError() << "\n"
                          << hexdump(std::vector<uint8_t>(
                                 n20_stream_data(&s),
                                 n20_stream_data(&s) + n20_stream_byte_count(&s)));
    X509_print_ex_fp(stdout, x509i2.get(), 0, X509V3_EXT_DUMP_UNKNOWN);
    auto key2 = n20_crypto_key_to_evp_pkey_ptr(key_type, public_key2, public_key_size2);
    auto rc2 = X509_verify(x509i2.get(), key2.get());
    ASSERT_EQ(rc2, 1) << BsslError();

    // Now assert that the old key fails to verify new certificate.
    auto rc3 = X509_verify(x509i2.get(), key.get());
    ASSERT_EQ(rc3, 0) << BsslError();

    // The validation code in boringssl's pki library does not understand
    // ED25519, so we have to skip this test for now.
    if (key_type != n20_crypto_key_type_ed25519_e) {
        auto cert_string_view2 = std::string_view(
            reinterpret_cast<char const*>(n20_stream_data(&s)), n20_stream_byte_count(&s));

        cert_opts.leaf_cert = cert_string_view2;
        auto verify_result = bssl::CertificateVerify(cert_opts, &v_error, &v_status);
        ASSERT_FALSE(!!verify_result)
            << "raw cert:\n"
            << hexdump(std::vector<uint8_t>(n20_stream_data(&s),
                                            n20_stream_data(&s) + n20_stream_byte_count(&s)))
            << std::endl;
        ASSERT_EQ(v_error.Code(), bssl::VerifyError::StatusCode::CERTIFICATE_INVALID_SIGNATURE)
            << "Diag: " << v_error.DiagnosticString();
    }
}
