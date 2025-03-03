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
#include <optional>
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

uint8_t const test_uds[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

constexpr int secp256r1 = 1;
constexpr int secp384r1 = 2;

EVP_PKEY_PTR_t make_key(int type, std::string const& context, int curve) {
    std::vector<uint8_t> out_key(32);
    int rc = HKDF_expand(out_key.data(),
                         out_key.size(),
                         EVP_sha256(),
                         test_uds,
                         sizeof(test_uds),
                         reinterpret_cast<uint8_t const*>(context.data()),
                         context.size());

    if (type == EVP_PKEY_ED25519) {

        auto key = EVP_PKEY_PTR_t(
            EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, out_key.data(), out_key.size()));
        EXPECT_TRUE(!!key);

        return key;
    }

    if (type == EVP_PKEY_EC) {
        EC_GROUP const* group;
        if (curve == secp256r1) {
            group = EC_group_p256();
        } else {
            group = EC_group_p384();
        }

        auto ec_key =
            EC_KEY_PTR_t(EC_KEY_derive_from_secret(group, out_key.data(), out_key.size()));
        EXPECT_TRUE(ec_key != NULL);
        if (!ec_key) return {};

        auto key = EVP_PKEY_PTR_t(EVP_PKEY_new());
        EXPECT_TRUE(!!key);
        if (!key) return key;

        EVP_PKEY_assign_EC_KEY(key.get(), ec_key.release());
        return key;
    }

    return {};
}

EVP_PKEY_PTR_t generate_key(int type, uint32_t key_bits_curve, std::string const& context) {

    if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_EC) {
        return make_key(type, context, key_bits_curve);
    }

    auto evp_ctx = EVP_PKEY_CTX_PTR_t(EVP_PKEY_CTX_new_id(type, NULL));
    if (!evp_ctx) {
        ADD_FAILURE();
        return nullptr;
    }

    if (!EVP_PKEY_keygen_init(evp_ctx.get())) {
        ADD_FAILURE();
        return nullptr;
    }

    if (type == EVP_PKEY_RSA) {
        if (!EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx.get(), key_bits_curve)) {
            ADD_FAILURE();
            return nullptr;
        }
    }

    if (type == EVP_PKEY_EC) {
        if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx.get(), NID_X9_62_prime256v1)) {
            ADD_FAILURE();
            return nullptr;
        }
    }

    EVP_PKEY* key = NULL;
    if (!EVP_PKEY_keygen(evp_ctx.get(), &key)) {
        ADD_FAILURE();
        return nullptr;
    }
    return EVP_PKEY_PTR_t(key);
}

std::optional<std::vector<uint8_t>> sign(EVP_PKEY_PTR_t const& key,
                                         std::vector<uint8_t> const& message) {
    size_t sig_size;
    auto md_ctx = EVP_MD_CTX_PTR_t(EVP_MD_CTX_new());
    if (!md_ctx) {
        ADD_FAILURE();
        return std::nullopt;
    }

    if (EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519) {
        EVP_MD const* md = EVP_sha256();
        if (1 != EVP_DigestSignInit(md_ctx.get(), NULL, md, NULL, key.get())) {
            ADD_FAILURE() << BsslError();
            return std::nullopt;
        }

        if (1 != EVP_DigestSignUpdate(md_ctx.get(), message.data(), message.size())) {
            ADD_FAILURE() << BsslError();
            return std::nullopt;
        }

        if (1 != EVP_DigestSignFinal(md_ctx.get(), NULL, &sig_size)) {
            ADD_FAILURE();
            return std::nullopt;
        }

        std::vector<uint8_t> result(sig_size);

        if (1 != EVP_DigestSignFinal(md_ctx.get(), result.data(), &sig_size)) {
            ADD_FAILURE();
            return std::nullopt;
        }

        EXPECT_LE(sig_size, result.size());
        result.resize(sig_size);
        // EXPECT_EQ(sig_size, result.size());

        return result;
    } else {
        EVP_MD const* md = nullptr;
        if (1 != EVP_DigestSignInit(md_ctx.get(), NULL, md, NULL, key.get())) {
            ADD_FAILURE() << BsslError();
            return std::nullopt;
        }

        size_t sig_size;

        if (1 != EVP_DigestSign(md_ctx.get(), NULL, &sig_size, message.data(), message.size())) {
            ADD_FAILURE();
            return std::nullopt;
        }

        std::vector<uint8_t> result(sig_size);

        if (1 != EVP_DigestSign(
                     md_ctx.get(), result.data(), &sig_size, message.data(), message.size())) {
            ADD_FAILURE();
            return std::nullopt;
        }
        EXPECT_EQ(sig_size, result.size());

        return result;
    }
}

bool verify(EVP_PKEY_PTR_t const& key,
            std::vector<uint8_t> const& message,
            std::vector<uint8_t> const& signature) {

    auto md_ctx = EVP_MD_CTX_PTR_t(EVP_MD_CTX_new());
    if (!md_ctx) {
        ADD_FAILURE();
        return false;
    }

    if (EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519) {

        if (1 != EVP_DigestVerifyInit(md_ctx.get(), NULL, EVP_sha256(), NULL, key.get())) {
            ADD_FAILURE();
            return false;
        }

        if (1 != EVP_DigestVerifyUpdate(md_ctx.get(), message.data(), message.size())) {
            ADD_FAILURE();
            return false;
        }

        if (1 != EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size())) {
            ADD_FAILURE();
            return false;
        }

    } else {
        if (1 != EVP_DigestVerifyInit(md_ctx.get(), NULL, NULL, NULL, key.get())) {
            ADD_FAILURE();
            return false;
        }

        if (1 !=
            EVP_DigestVerify(
                md_ctx.get(), signature.data(), signature.size(), message.data(), message.size())) {
            ADD_FAILURE();
            return false;
        }
    }
    return true;
}

class NameTest : public testing::TestWithParam<std::tuple<n20_x509_name_t*, std::vector<uint8_t>>> {
};

n20_x509_name_t NAME_EMPTY = {.element_count = 0, .elements = nullptr};
n20_x509_name_t NAME_ONE = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"));
n20_x509_name_t NAME_TWO = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                                         N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"));
n20_x509_name_t NAME_NINE = {.element_count = 9, .elements = nullptr};

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

TEST_P(NameTest, NameEncoding) {
    auto [p, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_name(&s, p);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}
class ExtensionTest
    : public testing::TestWithParam<
          std::tuple<std::variant<n20_x509_extensions_t*, std::vector<n20_x509_extension_t>>,
                     std::vector<uint8_t>>> {};

void key_usage_content_cb(n20_asn1_stream_t* s, void* cb_context) {
    uint8_t n = 0x05;

    n20_asn1_bitstring(s, &n, 3, n20_asn1_tag_info_no_override());
}

void basic_constraints_content_cb(n20_asn1_stream_t* s, void* cb_context) {
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

TEST_P(ExtensionTest, ExtensionEncoding) {
    auto [p, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    if (auto extensions = std::get_if<n20_x509_extensions_t*>(&p)) {
        n20_x509_extension(&s, *extensions);
    }
    if (auto extensions_vector = std::get_if<std::vector<n20_x509_extension_t>>(&p)) {
        n20_x509_extensions_t extensions = {.extensions_count = extensions_vector->size(),
                                            .extensions = extensions_vector->data()};
        n20_x509_extension(&s, &extensions);
    }
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
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

TEST_P(BasicConstraintsTest, BasicConstraintsEncoding) {
    auto [is_ca, has_path_length, path_length, expected] = GetParam();

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_basic_constraints_t context = {
        .is_ca = is_ca, .has_path_length = has_path_length, .path_length = path_length};
    n20_x509_ext_basic_constraints_content(&s, &context);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), expected.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(expected, got);
}

class KeyUsageTest : public testing::Test {};

std::vector<uint8_t> const ENCODED_KEY_USAGE_ZERO_BITS = {0x03, 0x01, 0x00};

TEST(KeyUsageTest, KeyUsageZeroBitsEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_KEY_USAGE_ZERO_BITS.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_ZERO_BITS, got);
}

std::vector<uint8_t> const ENCODED_KEY_USAGE_SIX_BITS = {0x03, 0x02, 0x02, 0x84};

TEST(KeyUsageTest, KeyUsageSixBitsEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_KEY_USAGE_SIX_BITS.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_SIX_BITS, got);
}

std::vector<uint8_t> const ENCODED_KEY_USAGE_NINE_BITS = {0x03, 0x03, 0x07, 0x84, 0x80};

TEST(KeyUsageTest, KeyUsageNineBitsEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0, 0}};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);
    N20_X509_KEY_USAGE_SET_DECIPHER_ONLY(&key_usage);

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_KEY_USAGE_NINE_BITS.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_NINE_BITS, got);
}

std::vector<uint8_t> const ENCODED_KEY_USAGE_NINE_BITS_ALL_SET = {0x03, 0x03, 0x07, 0xff, 0x80};

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

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_KEY_USAGE_NINE_BITS_ALL_SET.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_NINE_BITS_ALL_SET, got);
}

TEST(KeyUsageTest, KeyUsageSixteenBitsAllSetEncoding) {
    n20_x509_ext_key_usage_t key_usage = {.key_usage_mask = {0xff, 0xff}};

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_ext_key_usage_content(&s, &key_usage);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_KEY_USAGE_NINE_BITS_ALL_SET.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_KEY_USAGE_NINE_BITS_ALL_SET, got);
}

class CertTBSTest : public testing::Test {};

std::vector<uint8_t> const ENCODED_CERT_TBS_NULL = {0x30, 0x00};

// Test the encoding of a null tbs structure.
TEST(CertTBSTest, CertTBSNullEncoding) {
    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert_tbs(&s, nullptr);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_CERT_TBS_NULL.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_CERT_TBS_NULL, got);
}

std::vector<uint8_t> const ENCODED_CERT_TBS_ZERO = {
    0x30,
    0x3d,
    // version
    0xa0,
    0x03,
    0x02,
    0x01,
    0x02,
    // serialNumber
    0x02,
    0x01,
    0x00,
    // signature
    0x30,
    0x02,
    0x05,
    0x00,
    // issuer
    0x30,
    0x00,
    // validity
    0x30,
    0x22,
    0x18,
    0x0f,
    0x31,
    0x39,
    0x37,
    0x30,
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
    0x5a,
    0x18,
    0x0f,
    0x39,
    0x39,
    0x39,
    0x39,
    0x31,
    0x32,
    0x33,
    0x31,
    0x32,
    0x33,
    0x35,
    0x39,
    0x35,
    0x39,
    0x5a,
    // subject
    0x30,
    0x00,
    // subjectPublicKeyInfo,
    0x30,
    0x07,
    0x30,
    0x02,
    0x05,
    0x00,
    0x03,
    0x01,
    0x00,
};

// Test the encoding of a zero tbs structure.
TEST(CertTBSTest, CertTBSZeroEncoding) {
    n20_x509_tbs_t tbs = {0};

    n20_asn1_stream_t s;
    uint8_t buffer[128];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_CERT_TBS_ZERO.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    ASSERT_EQ(ENCODED_CERT_TBS_ZERO, got);
}

std::vector<uint8_t> const ENCODED_CERT_TBS_NONZERO = {
    0x30,
    0x81,
    0xe1,
    // version
    0xa0,
    0x03,
    0x02,
    0x01,
    0x02,
    // serialNumber
    0x02,
    0x01,
    0x01,
    // signature
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x70,
    // issuer
    0x30,
    0x35,
    0x31,
    0x0b,
    0x30,
    0x09,
    0x06,
    0x03,
    0x55,
    0x04,
    0x06,
    0x13,
    0x02,
    0x49,
    0x54,
    0x31,
    0x0f,
    0x30,
    0x0d,
    0x06,
    0x03,
    0x55,
    0x04,
    0x07,
    0x13,
    0x06,
    0x4d,
    0x69,
    0x6c,
    0x61,
    0x6e,
    0x6f,
    0x31,
    0x15,
    0x30,
    0x13,
    0x06,
    0x03,
    0x55,
    0x04,
    0x03,
    0x13,
    0x0c,
    0x54,
    0x65,
    0x73,
    0x74,
    0x20,
    0x65,
    0x64,
    0x32,
    0x35,
    0x35,
    0x31,
    0x39,
    // validity
    0x30,
    0x22,
    0x18,
    0x0f,
    0x32,
    0x30,
    0x32,
    0x30,
    0x30,
    0x39,
    0x30,
    0x32,
    0x31,
    0x33,
    0x32,
    0x35,
    0x32,
    0x36,
    0x5a,
    0x18,
    0x0f,
    0x32,
    0x30,
    0x32,
    0x30,
    0x30,
    0x39,
    0x30,
    0x32,
    0x31,
    0x33,
    0x32,
    0x35,
    0x32,
    0x36,
    0x5a,
    // subject
    0x30,
    0x35,
    0x31,
    0x0b,
    0x30,
    0x09,
    0x06,
    0x03,
    0x55,
    0x04,
    0x06,
    0x13,
    0x02,
    0x49,
    0x54,
    0x31,
    0x0f,
    0x30,
    0x0d,
    0x06,
    0x03,
    0x55,
    0x04,
    0x07,
    0x13,
    0x06,
    0x4d,
    0x69,
    0x6c,
    0x61,
    0x6e,
    0x6f,
    0x31,
    0x15,
    0x30,
    0x13,
    0x06,
    0x03,
    0x55,
    0x04,
    0x03,
    0x13,
    0x0c,
    0x54,
    0x65,
    0x73,
    0x74,
    0x20,
    0x65,
    0x64,
    0x32,
    0x35,
    0x35,
    0x31,
    0x39,
    // subjectPublicKeyInfo,
    0x30,
    0x2a,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x70,
    0x03,
    0x21,
    0x00,
    0x3b,
    0xa9,
    0x2f,
    0xfd,
    0xcb,
    0x17,
    0x66,
    0xde,
    0x40,
    0xa2,
    0x92,
    0xf7,
    0x93,
    0xde,
    0x30,
    0xf8,
    0x0a,
    0x23,
    0xa8,
    0x31,
    0x21,
    0x5d,
    0xd0,
    0x07,
    0xd8,
    0x63,
    0x24,
    0x2e,
    0xff,
    0x68,
    0x21,
    0x85,
    // extensions
    0xa3,
    0x12,
    0x30,
    0x10,
    0x30,
    0x0e,
    0x06,
    0x03,
    0x55,
    0x1d,
    0x0f,
    0x01,
    0x01,
    0xff,
    0x04,
    0x04,
    0x03,
    0x02,
    0x05,
    0x00,
};

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
        .issuer_name = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "IT"),
                                     N20_X509_RDN(&OID_LOCALITY_NAME, "Milano"),
                                     N20_X509_RDN(&OID_COMMON_NAME, "Test ed25519")),
        .validity = {.not_before = "20200902132526Z", .not_after = "20200902132526Z"},
        .subject_name = N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "IT"),
                                      N20_X509_RDN(&OID_LOCALITY_NAME, "Milano"),
                                      N20_X509_RDN(&OID_COMMON_NAME, "Test ed25519")),
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

    n20_asn1_stream_t s;
    uint8_t buffer[256];
    n20_asn1_stream_init(&s, buffer, sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_EQ(n20_asn1_stream_data_written(&s), ENCODED_CERT_TBS_NONZERO.size());
    std::vector<uint8_t> got = std::vector<uint8_t>(
        n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
    for (int i = 0; i < got.size(); i++) {
        if (got[i] != ENCODED_CERT_TBS_NONZERO[i]) {
            std::cout << "FDSFSDFSD: " << i << std::endl;
        }
    }
    ASSERT_EQ(ENCODED_CERT_TBS_NONZERO, got);
}

class CryptoTest : public testing::TestWithParam<std::tuple<int>> {};

INSTANTIATE_TEST_CASE_P(CryptoTestInstance,
                        CryptoTest,
                        testing::Values(std::tuple(EVP_PKEY_RSA),
                                        std::tuple(EVP_PKEY_EC),
                                        std::tuple(EVP_PKEY_ED25519)));

TEST_P(CryptoTest, KeyGenSignVerify) {
    auto [key_type] = GetParam();

    std::string message("the message");
    auto message_v =
        std::vector<uint8_t>(reinterpret_cast<uint8_t const*>(message.c_str()),
                             reinterpret_cast<uint8_t const*>(message.c_str() + message.size()));

    auto key = generate_key(key_type, 2048, "KeyGenSignVerify");
    ASSERT_TRUE(!!key);

    auto signature = sign(key, message_v);
    ASSERT_TRUE(!!signature);

    ASSERT_TRUE(verify(key, message_v, *signature));
}

class X509Test : public testing::Test {};

struct BoringsslDeleter {
    void operator()(void* p) { OPENSSL_free(p); }
};

TEST_F(X509Test, Inittest) {

    n20_x509_tbs_t tbs = {0};

    ASSERT_EQ(tbs.serial_number, 0);
    ASSERT_EQ(tbs.signature_algorithm.oid, nullptr);
    ASSERT_EQ(tbs.validity.not_after, nullptr);
    ASSERT_EQ(tbs.validity.not_before, nullptr);
    ASSERT_EQ(tbs.issuer_name.element_count, 0);
    ASSERT_EQ(tbs.subject_name.element_count, 0);
    ASSERT_EQ(tbs.extensions.extensions_count, 0);
    ASSERT_EQ(tbs.subject_public_key_info.public_key_bits, 0);
    ASSERT_EQ(tbs.subject_public_key_info.algorithm_identifier.oid, nullptr);
}

class CertIssueTest : public testing::TestWithParam<std::tuple<int,
                                                               int,
                                                               size_t,
                                                               n20_asn1_object_identifier_t*,
                                                               n20_asn1_object_identifier_t*,
                                                               size_t,
                                                               n20_x509_algorithm_parameters_t,
                                                               bool>> {};

std::optional<std::vector<uint8_t>> get_public_key_bits(EVP_PKEY_PTR_t const& key) {
    auto key_type = EVP_PKEY_id(key.get());

    switch (key_type) {
        case EVP_PKEY_EC:
        case EVP_PKEY_RSA: {
            uint8_t* der_key_info = NULL;
            int rc_der_len = i2d_PublicKey(key.get(), &der_key_info);
            EXPECT_TRUE(!!rc_der_len);
            if (!rc_der_len) return std::nullopt;
            auto der_key_info_guard = std::unique_ptr<uint8_t, BoringsslDeleter>(der_key_info);
            return std::vector<uint8_t>(der_key_info, der_key_info + rc_der_len);
        }
        case EVP_PKEY_ED25519: {
            std::vector<uint8_t> result(32);
            size_t key_buffer_size = 32;
            auto rc = EVP_PKEY_get_raw_public_key(key.get(), result.data(), &key_buffer_size);
            EXPECT_TRUE(!!rc);
            EXPECT_EQ(key_buffer_size, 32);
            if (!rc || key_buffer_size != 32) return std::nullopt;
            return result;
        }
        default:
            return std::nullopt;
    }
}

INSTANTIATE_TEST_CASE_P(
    X509Test,
    CertIssueTest,
    testing::Values(std::tuple(EVP_PKEY_RSA,
                               2048,
                               256,
                               &OID_SHA256_WITH_RSA_ENC,
                               &OID_RSA_ENCRYPTION,
                               673,
                               n20_x509_algorithm_parameters_t{.variant = n20_x509_pv_null_e},
                               true),
                    std::tuple(EVP_PKEY_EC,
                               secp256r1,
                               72,
                               &OID_ECDSA_WITH_SHA256,
                               &OID_EC_PUBLIC_KEY,
                               469,
                               n20_x509_algorithm_parameters_t{.variant = n20_x509_pv_ec_curve_e,
                                                               .ec_curve = &OID_SECP256R1},
                               true),
                    std::tuple(EVP_PKEY_EC,
                               secp384r1,
                               104,
                               &OID_ECDSA_WITH_SHA256,
                               &OID_EC_PUBLIC_KEY,
                               498,
                               n20_x509_algorithm_parameters_t{.variant = n20_x509_pv_ec_curve_e,
                                                               .ec_curve = &OID_SECP384R1},
                               true),
                    std::tuple(EVP_PKEY_ED25519,
                               0,
                               64,
                               &OID_ED25519,
                               &OID_ED25519,
                               417,
                               n20_x509_algorithm_parameters_t{.variant = n20_x509_pv_none_e},
                               true),
                    std::tuple(EVP_PKEY_ED25519,
                               0,
                               64,
                               &OID_ED25519,
                               &OID_ED25519,
                               414,
                               n20_x509_algorithm_parameters_t{.variant = n20_x509_pv_none_e},
                               false)));

std::vector<uint8_t> from_stream(n20_asn1_stream_t const* s) {
    if (n20_asn1_stream_is_data_good(s)) {
        return std::vector<uint8_t>(n20_asn1_stream_data(s),
                                    n20_asn1_stream_data(s) + n20_asn1_stream_data_written(s));
    }
    return {};
}

TEST_P(CertIssueTest, CertIssue) {
    auto [key_type,
          key_bits_curve,
          sig_size,
          signature_algorithm,
          publickey_algorithm,
          want_tbs_size,
          want_params,
          has_path_length] = GetParam();

    auto key = generate_key(key_type, key_bits_curve, "CertIssueTest1");
    ASSERT_TRUE(!!key);

    auto key_bits = get_public_key_bits(key);
    ASSERT_TRUE(!!key_bits);

    // Assemble the to-be-signed information of the certificate.
    n20_x509_tbs_t tbs = {};
    tbs.serial_number = 1;
    tbs.signature_algorithm.oid = signature_algorithm;
    tbs.signature_algorithm.params.variant = n20_x509_pv_none_e;
    tbs.issuer_name =
        N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                      N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"),
                      N20_X509_RDN(&OID_ORGANIZATION_NAME, "Aurora Innovation Inc"),
                      N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Aurora Information Security"),
                      N20_X509_RDN(&OID_COMMON_NAME, "Aurora DICE Authority"), );
    tbs.validity = {.not_before = NULL, .not_after = NULL};
    tbs.subject_name =
        N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                      N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"),
                      N20_X509_RDN(&OID_ORGANIZATION_NAME, "Aurora Innovation Inc"),
                      N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Aurora Information Security"),
                      N20_X509_RDN(&OID_COMMON_NAME, "Aurora DICE Authority"), );
    tbs.subject_public_key_info = {
        .algorithm_identifier = {.oid = publickey_algorithm, .params = want_params},
        .public_key_bits = key_bits->size() * 8,
        .public_key = key_bits->data(),
    };

    n20_x509_ext_key_usage_t key_usage = {0};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_x509_ext_basic_constraints_t basic_constraints = {
        .is_ca = 1,
        .has_path_length = has_path_length,
        .path_length = 1,
    };

    n20_x509_extension_t exts[] = {
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

    tbs.extensions = {
        .extensions_count = 2,
        .extensions = exts,
    };

    // DER encode the to-be-signed part of the certificate.
    // First run the formatting function with NULL stream buffer
    // to compute the length of the tbs part.
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);
    n20_x509_cert_tbs(&s, &tbs);
    auto tbs_size = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    EXPECT_EQ(want_tbs_size, tbs_size);

    // Now allocate a buffer large enough to hold the tbs part,
    // reinitialize the asn1_stream and write the tbs part again.
    uint8_t buffer[2000] = {};
    n20_asn1_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    tbs_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    ASSERT_EQ(want_tbs_size, tbs_size) << hexdump(from_stream(&s));

    // Sign the TBS part.
    auto sig = sign(
        key, std::vector<uint8_t>(n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + tbs_size));
    ASSERT_TRUE(!!sig);

    ASSERT_LE(sig->size(), sig_size);

    // Combine the tbs info with the signature algorithm,
    // reinitialize the asn1 stream and write out the entire
    // certificate.
    n20_x509_t x509 = {
        .tbs = &tbs,
        .signature_algorithm = {.oid = signature_algorithm,
                                .params = {.variant = n20_x509_pv_none_e}},
        .signature_bits = sig->size() * 8,
        .signature = sig->data(),
    };
    n20_asn1_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_cert(&s, &x509);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));
    auto x509_size = n20_asn1_stream_data_written(&s);

    // Now verify the signature on the Certificate.
    uint8_t const* p = n20_asn1_stream_data(&s);

    auto x509i = X509_PTR_t(d2i_X509(nullptr, &p, (long)x509_size));
    ASSERT_TRUE(!!x509i) << BsslError() << "\n"
                         << hexdump(std::vector<uint8_t>(n20_asn1_stream_data(&s),
                                                         n20_asn1_stream_data(&s) + x509_size));
    X509_print_ex_fp(stdout, x509i.get(), 0, X509V3_EXT_DUMP_UNKNOWN);
    auto rc = X509_verify(x509i.get(), key.get());
    ASSERT_EQ(rc, 1) << BsslError();

    bssl::CertificateVerifyOptions cert_opts{};
    bssl::VerifyError v_error{};
    bssl::CertificateVerifyStatus v_status{};
    std::unique_ptr<bssl::VerifyTrustStore> trust_store;

    // The validation code in boringssl's pki library does not understand
    // ED25519, so we have to skip this test for now.
    if (key_type != EVP_PKEY_ED25519) {

        // Validate the self signed certificate.
        std::string diag;
        auto cert_string_view =
            std::string_view(reinterpret_cast<char const*>(n20_asn1_stream_data(&s)), x509_size);
        trust_store = bssl::VerifyTrustStore::FromDER(cert_string_view, &diag);
        ASSERT_TRUE(!!trust_store) << "Diag: " << diag;
        cert_opts.leaf_cert = cert_string_view;
        cert_opts.trust_store = trust_store.get();
        auto verify_result = bssl::CertificateVerify(cert_opts, &v_error, &v_status);
        ASSERT_TRUE(!!verify_result);
        ASSERT_EQ(v_error.Code(), bssl::VerifyError::StatusCode::PATH_VERIFIED)
            << "Diag: " << v_error.DiagnosticString();
    }
    // Now create a certificate signed with a different key.
    // It is expected to fail the verification.

    // Allocate a new buffer for the new certificate.
    uint8_t buffer2[2000] = {};
    n20_asn1_stream_init(&s, &buffer2[0], sizeof(buffer2));
    n20_x509_cert_tbs(&s, &tbs);
    tbs_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));

    ASSERT_EQ(want_tbs_size, tbs_size);

    auto key2 = generate_key(key_type, key_bits_curve, "CertIssueTest2");

    // Sign the TBS part.
    auto sig2 = sign(
        key2, std::vector<uint8_t>(n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + tbs_size));
    ASSERT_TRUE(!!sig);

    // Combine the tbs info with the signature algorithm,
    // reinitialize the asn1 stream and write out the entire
    // certificate.
    n20_x509_t x5092 = {
        .tbs = &tbs,
        .signature_algorithm = {.oid = signature_algorithm,
                                .params = {.variant = n20_x509_pv_none_e}},
        .signature_bits = sig2->size() * 8,
        .signature = sig2->data(),
    };
    n20_asn1_stream_init(&s, &buffer2[0], sizeof(buffer2));
    n20_x509_cert(&s, &x5092);
    auto x5092_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_data_good(&s));
    ASSERT_TRUE(n20_asn1_stream_is_data_written_good(&s));

    p = n20_asn1_stream_data(&s);

    x509i = X509_PTR_t(d2i_X509(nullptr, &p, (long)x5092_size));
    ASSERT_TRUE(!!x509i) << BsslError() << "\n"
                         << hexdump(std::vector<uint8_t>(n20_asn1_stream_data(&s),
                                                         n20_asn1_stream_data(&s) + x509_size));
    X509_print_ex_fp(stdout, x509i.get(), 0, X509V3_EXT_DUMP_UNKNOWN);
    rc = X509_verify(x509i.get(), key.get());
    ASSERT_EQ(rc, 0);

    // The validation code in boringssl's pki library does not understand
    // ED25519, so we have to skip this test for now.
    if (key_type != EVP_PKEY_ED25519) {

        auto cert2_string_view =
            std::string_view(reinterpret_cast<char const*>(n20_asn1_stream_data(&s)), x5092_size);

        cert_opts.leaf_cert = cert2_string_view;
        auto verify_result = bssl::CertificateVerify(cert_opts, &v_error, &v_status);
        ASSERT_FALSE(!!verify_result)
            << "raw cert:\n"
            << hexdump(std::vector<uint8_t>(n20_asn1_stream_data(&s),
                                            n20_asn1_stream_data(&s) + x5092_size))
            << std::endl;
        ASSERT_EQ(v_error.Code(), bssl::VerifyError::StatusCode::CERTIFICATE_INVALID_SIGNATURE)
            << "Diag: " << v_error.DiagnosticString();
    }
}

TEST_F(X509Test, KeyDerivation) {
    std::vector<uint8_t> out_key(64);
    char const* info = "the info";
    int rc = HKDF_expand(out_key.data(),
                         out_key.size(),
                         EVP_sha256(),
                         test_uds,
                         sizeof(test_uds),
                         reinterpret_cast<uint8_t const*>(info),
                         strlen(info));

    ASSERT_EQ(rc, 1);

    std::cout << "Key:\n" << hexdump(out_key) << std::endl;
}
