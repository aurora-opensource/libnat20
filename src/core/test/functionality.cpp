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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nat20/asn1.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/functionality.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <tuple>

#include "nat20/stream.h"
#include "nat20/types.h"

// // Mock structures and functions
// class MockCryptoContext : public n20_crypto_context_t {
// public:
//     MOCK_METHOD(n20_crypto_error_t, digest_impl, (n20_crypto_digest_algorithm_t,
//     n20_crypto_gather_list_t const *, uint8_t *, size_t *), ()); MOCK_METHOD(n20_crypto_error_t,
//     kdf_impl, (n20_crypto_key_t, n20_crypto_key_type_t, n20_crypto_gather_list_t const *,
//     n20_crypto_key_t *), ()); MOCK_METHOD(n20_crypto_error_t, key_get_public_key_impl,
//     (n20_crypto_key_t, uint8_t *, size_t *), ()); MOCK_METHOD(n20_crypto_error_t, key_free_impl,
//     (n20_crypto_key_t), ());

// };

// extern "C" {
//     n20_crypto_error_t mock_digest(n20_crypto_context_t *ctx, n20_crypto_digest_algorithm_t algo,
//     n20_crypto_gather_list_t const *input, uint8_t *digest, size_t *digest_size) {
//         auto crypto_ctx = reinterpret_cast<MockCryptoContext *>(ctx);
//         return crypto_ctx->digest(algo, input, digest, digest_size);
//     }

//     n20_crypto_error_t mock_kdf(n20_crypto_context_t *ctx, n20_crypto_key_t secret,
//     n20_crypto_key_type_t key_type, n20_crypto_gather_list_t const *context, n20_crypto_key_t
//     *derived) {
//         auto crypto_ctx = reinterpret_cast<MockCryptoContext *>(ctx);
//         return crypto_ctx->kdf(secret, key_type, context, derived);
//     }

//     n20_crypto_error_t mock_key_get_public_key(n20_crypto_context_t *ctx, n20_crypto_key_t key,
//     uint8_t *buffer, size_t *size) {
//         auto crypto_ctx = reinterpret_cast<MockCryptoContext *>(ctx);
//         return crypto_ctx->key_get_public_key(key, buffer, size);
//     }

//     n20_crypto_error_t mock_key_free(n20_crypto_context_t *ctx, n20_crypto_key_t key) {
//         auto crypto_ctx = reinterpret_cast<MockCryptoContext *>(ctx);
//         return crypto_ctx->key_free(key);
//     }
// }

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

// Test fixture
class FunctionalityTest : public ::testing::Test {
   protected:
    n20_crypto_context_t* crypto_ctx;

    void SetUp() override { EXPECT_EQ(n20_error_ok_e, n20_crypto_boringssl_open(&crypto_ctx)); }

    void TearDown() override { EXPECT_EQ(n20_error_ok_e, n20_crypto_boringssl_close(crypto_ctx)); }

    n20_crypto_key_t GetCdi() {
        n20_slice_t cdi_slice = {sizeof(test_cdi), const_cast<uint8_t*>(&test_cdi[0])};
        n20_crypto_key_t cdi_key = nullptr;
        EXPECT_EQ(n20_error_ok_e,
                  n20_crypto_boringssl_make_secret(crypto_ctx, &cdi_slice, &cdi_key));
        return cdi_key;
    }
};

static std::string hexdump(std::vector<uint8_t> const& data) {
    std::stringstream s;
    int i;
    for (i = 0; i < data.size() - 1; ++i) {
        s << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << ",";
        if (i % 16 == 15) {
            s << "\n";
        } else if (i % 16 == 7) {
            s << "  ";
        } else {
            s << " ";
        }
    }
    if (i < data.size()) {
        s << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

std::vector<uint8_t> test_cert = {
    0x30, 0x82, 0x02, 0x34, 0x30, 0x82, 0x01, 0xe6, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
    0x08, 0x53, 0x63, 0x72, 0x61, 0x6e, 0x74, 0x6f, 0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x49, 0x43, 0x45, 0x20, 0x43, 0x41,
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x44, 0x49, 0x43, 0x45, 0x20,
    0x4c, 0x61, 0x79, 0x65, 0x72, 0x20, 0x30, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30,
    0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39,
    0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x4e, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x07, 0x13, 0x08, 0x53, 0x63, 0x72, 0x61, 0x6e, 0x74, 0x6f, 0x6e, 0x31, 0x15, 0x30,
    0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x49, 0x43,
    0x45, 0x20, 0x43, 0x41, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x44,
    0x49, 0x43, 0x45, 0x20, 0x4c, 0x61, 0x79, 0x65, 0x72, 0x20, 0x31, 0x30, 0x2a, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x33, 0x02, 0xa2, 0x47, 0xe8, 0xb2, 0xaf, 0xb7, 0x84,
    0xd5, 0x31, 0x78, 0x9b, 0x6f, 0x2c, 0x03, 0x85, 0xe7, 0xc3, 0x24, 0x68, 0xe6, 0x90, 0x0b, 0xee,
    0x18, 0xb4, 0xb0, 0x90, 0x2a, 0x8d, 0x6f, 0xa3, 0x81, 0xe4, 0x30, 0x81, 0xe1, 0x30, 0x81, 0xbd,
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x18, 0x01, 0x01, 0xff, 0x04,
    0x81, 0xab, 0x30, 0x81, 0xa8, 0xa0, 0x22, 0x04, 0x20, 0xce, 0xdb, 0x7b, 0x98, 0x1c, 0x5c, 0x16,
    0xa9, 0x14, 0x5f, 0x3c, 0xbb, 0x69, 0x31, 0xfb, 0xc9, 0xab, 0x42, 0x52, 0x08, 0xd5, 0xab, 0x8d,
    0xb8, 0x2d, 0x4d, 0x6f, 0xc1, 0xff, 0x52, 0xfa, 0x98, 0xa1, 0x36, 0x04, 0x34, 0x30, 0x32, 0x0c,
    0x09, 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x49, 0x43, 0x45, 0x0c, 0x03, 0x31, 0x2e, 0x30, 0x04,
    0x20, 0xcf, 0x48, 0x17, 0xd9, 0x79, 0x3e, 0x92, 0xa0, 0xb0, 0x0b, 0x0a, 0xfc, 0x24, 0x13, 0x54,
    0xf9, 0xa6, 0x49, 0x86, 0x6d, 0xa1, 0xd8, 0x83, 0xc6, 0x04, 0xc0, 0x58, 0x5e, 0xf4, 0x12, 0x9b,
    0x82, 0xa2, 0x22, 0x04, 0x20, 0x18, 0x11, 0x30, 0xb8, 0x01, 0x27, 0xa6, 0x5a, 0xfc, 0xdd, 0xe4,
    0xc0, 0xf9, 0x0c, 0xaf, 0x6e, 0x69, 0x1a, 0xcf, 0xc7, 0x19, 0x9e, 0x83, 0xc0, 0x3e, 0x49, 0x4e,
    0x8f, 0xc8, 0x54, 0xc1, 0xaf, 0xa3, 0x15, 0x04, 0x13, 0x30, 0x11, 0x02, 0x01, 0x01, 0x01, 0x01,
    0xff, 0x0c, 0x09, 0x74, 0x68, 0x65, 0x79, 0x2f, 0x74, 0x68, 0x65, 0x6d, 0xa6, 0x03, 0x02, 0x01,
    0x02, 0xa7, 0x0a, 0x0c, 0x08, 0x4f, 0x70, 0x65, 0x6e, 0x44, 0x49, 0x43, 0x45, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x04, 0x30, 0x0f, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0x03, 0x25, 0x61, 0xdf, 0x52, 0x85, 0x02, 0xcf,
    0xae, 0xe3, 0xac, 0x8a, 0x66, 0xed, 0x4b, 0x06, 0x80, 0x18, 0x74, 0xf2, 0x34, 0x16, 0xfe, 0x1f,
    0x29, 0x8a, 0x3a, 0x2b, 0x25, 0xd5, 0x73, 0x0f, 0x6d, 0x10, 0x74, 0xb9, 0x39, 0xc2, 0xe1, 0x3d,
    0x65, 0x8d, 0xa7, 0x9d, 0xdb, 0x90, 0x40, 0x57, 0x67, 0xfe, 0xda, 0xc4, 0x0a, 0x65, 0x1d, 0x44,
    0x23, 0xda, 0xd6, 0x54, 0xa8, 0x59, 0x36, 0x08};

/* Sha256 digest of "test code". */
std::vector<uint8_t> test_code_hash = {
    0xcf, 0x48, 0x17, 0xd9, 0x79, 0x3e, 0x92, 0xa0, 0xb0, 0x0b, 0x0a, 0xfc, 0x24, 0x13, 0x54, 0xf9,
    0xa6, 0x49, 0x86, 0x6d, 0xa1, 0xd8, 0x83, 0xc6, 0x04, 0xc0, 0x58, 0x5e, 0xf4, 0x12, 0x9b, 0x82};

/*
 * This function creates an example code descriptor.
 * It is an ASN1 sequence of a name string a version string,
 * both encoded as UTF-8 strings and a digest encoded as octetstring.
 */
std::vector<uint8_t> make_code_descriptor(std::string const& name,
                                          std::string const& version,
                                          std::vector<uint8_t> const& code_hash) {
    n20_stream_t s;
    uint8_t buffer[1024];
    n20_stream_init(&s, buffer, sizeof(buffer));

    auto context = std::make_tuple(name, version, code_hash);

    auto cb = [](n20_stream_t* s, void* ctx) -> void {
        auto [name, version, code_hash] = *reinterpret_cast<decltype(context)*>(ctx);
        n20_slice_t code_hash_slice = {.size = code_hash.size(),
                                       .buffer = (uint8_t*)code_hash.data()};

        n20_string_slice_t version_slice = {.size = version.length(), .buffer = version.c_str()};
        n20_string_slice_t name_slice = {.size = name.length(), .buffer = name.c_str()};
        n20_asn1_octetstring(s, &code_hash_slice, n20_asn1_tag_info_no_override());
        n20_asn1_utf8_string(s, &version_slice, n20_asn1_tag_info_no_override());
        n20_asn1_utf8_string(s, &name_slice, n20_asn1_tag_info_no_override());
    };

    n20_asn1_sequence(&s, cb, &context, n20_asn1_tag_info_no_override());

    EXPECT_FALSE(n20_stream_has_buffer_overflow(&s));

    return std::vector<uint8_t>(n20_stream_data(&s),
                                n20_stream_data(&s) + n20_stream_byte_count(&s));
}

/*
 * This function creates an example configuration descriptor.
 * The configuration is made up of a frobnication level integer
 * a hardcore mode boolean and a preferred pronouns string
 * encoded a an ASN1 sequence of integer, boolean, and UTF-8 string.
 */
std::vector<uint8_t> make_configuration_descriptor(int frobnication_level,
                                                   bool hardcore_mode,
                                                   std::string const& preferred_pronouns) {
    n20_stream_t s;
    uint8_t buffer[1024];
    n20_stream_init(&s, buffer, sizeof(buffer));

    auto context = std::make_tuple(frobnication_level, hardcore_mode, preferred_pronouns);

    auto cb = [](n20_stream_t* s, void* ctx) -> void {
        auto [frobnication_level, hardcore_mode, preferred_pronouns] =
            *reinterpret_cast<decltype(context)*>(ctx);
        n20_string_slice_t preferred_pronouns_slice = {
            .size = preferred_pronouns.length(),
            .buffer = preferred_pronouns.c_str(),
        };
        n20_asn1_utf8_string(s, &preferred_pronouns_slice, n20_asn1_tag_info_no_override());
        n20_asn1_boolean(s, hardcore_mode, n20_asn1_tag_info_no_override());
        n20_asn1_int64(s, (int64_t)frobnication_level, n20_asn1_tag_info_no_override());
    };

    n20_asn1_sequence(&s, cb, &context, n20_asn1_tag_info_no_override());

    EXPECT_FALSE(n20_stream_has_buffer_overflow(&s));

    return std::vector<uint8_t>(n20_stream_data(&s),
                                n20_stream_data(&s) + n20_stream_byte_count(&s));
}

n20_slice_t slice_of_vec(std::vector<uint8_t> const& vec) {
    return n20_slice_t{.size = vec.size(), .buffer = vec.data()};
}

TEST_F(FunctionalityTest, TestOpenDiceAttestationCertificate) {
    auto key_deleter = [this](void* key) { crypto_ctx->key_free(crypto_ctx, key); };

    n20_crypto_key_t parent_secret = this->GetCdi();
    auto parent_secret_guard =
        std::unique_ptr<void, decltype(key_deleter)>(parent_secret, key_deleter);

    n20_crypto_key_t parent_attestation_key = nullptr;
    ASSERT_NE(parent_secret, nullptr);
    auto parent_attestation_key_guard =
        std::unique_ptr<void, decltype(key_deleter)>(parent_attestation_key, key_deleter);

    ASSERT_EQ(
        n20_error_ok_e,
        n20_derive_attestation_key(
            crypto_ctx, parent_secret, &parent_attestation_key, n20_crypto_key_type_ed25519_e));
    ASSERT_NE(parent_attestation_key, nullptr);

    auto code_descriptor = make_code_descriptor("Test DICE", "1.0", test_code_hash);

    n20_slice_t code_descriptor_slice = {.size = code_descriptor.size(),
                                         .buffer = const_cast<uint8_t*>(code_descriptor.data())};

    n20_crypto_gather_list_t code_descriptor_gather_list = {1, &code_descriptor_slice};

    std::vector<uint8_t> code_descriptor_hash(32);
    size_t code_descriptor_hash_size = code_descriptor_hash.size();
    ASSERT_EQ(n20_error_ok_e,
              crypto_ctx->digest(crypto_ctx,
                                 n20_crypto_digest_algorithm_sha2_256_e,
                                 &code_descriptor_gather_list,
                                 code_descriptor_hash.data(),
                                 &code_descriptor_hash_size));

    auto configuration_descriptor = make_configuration_descriptor(1, true, "they/them");
    n20_slice_t configuration_descriptor_slice = {
        .size = configuration_descriptor.size(),
        .buffer = const_cast<uint8_t*>(configuration_descriptor.data()),
    };
    n20_crypto_gather_list_t configuration_descriptor_gather_list = {
        1, &configuration_descriptor_slice};

    std::vector<uint8_t> configuration_descriptor_hash(32);
    size_t configuration_descriptor_hash_size = configuration_descriptor_hash.size();
    ASSERT_EQ(n20_error_ok_e,
              crypto_ctx->digest(crypto_ctx,
                                 n20_crypto_digest_algorithm_sha2_256_e,
                                 &configuration_descriptor_gather_list,
                                 configuration_descriptor_hash.data(),
                                 &configuration_descriptor_hash_size));
    ASSERT_EQ(configuration_descriptor_hash_size, 32);
    n20_crypto_key_type_t parent_key_type = n20_crypto_key_type_ed25519_e;
    n20_crypto_key_type_t key_type = n20_crypto_key_type_ed25519_e;

    n20_open_dice_input_t context = {
        .code_hash = slice_of_vec(code_descriptor_hash),
        .code_descriptor = slice_of_vec(code_descriptor),
        .configuration_hash = slice_of_vec(configuration_descriptor_hash),
        .configuration_descriptor = slice_of_vec(configuration_descriptor),
        .authority_hash = {0, nullptr},
        .authority_descriptor = {0, nullptr},
        .mode = n20_open_dice_mode_debug_e,
        .profile_name = N20_STR_C("OpenDICE"),
    };
    uint8_t attestation_certificate[2048] = {};
    size_t attestation_certificate_size = sizeof(attestation_certificate);
    ASSERT_EQ(n20_error_ok_e,
              n20_opendice_attestation_key_and_certificate(crypto_ctx,
                                                           parent_secret,
                                                           parent_attestation_key,
                                                           parent_key_type,
                                                           key_type,
                                                           &context,
                                                           attestation_certificate,
                                                           &attestation_certificate_size))
        << "Expected buffer size: " << attestation_certificate_size;

    auto got_cert = std::vector<uint8_t>(
        &attestation_certificate[sizeof(attestation_certificate) - attestation_certificate_size],
        &attestation_certificate[sizeof(attestation_certificate)]);
    ASSERT_EQ(test_cert, got_cert) << hexdump(got_cert);
    ASSERT_EQ(test_cert.size(), attestation_certificate_size);
    // Verify the certificate
}

// // Test cases
// TEST_F(FunctionalityTest, DigestInput_Success) {
//     n20_open_dice_input_t context = {};
//     uint8_t digest[64];
//     size_t digest_size = sizeof(digest);

//     EXPECT_CALL(*crypto_ctx, digest(&crypto_ctx, n20_crypto_digest_algorithm_sha2_512_e,
//     testing::_, digest, &digest_size))
//         .WillOnce(testing::Return(n20_error_ok_e));

//     n20_error_t result = n20_digest_input(&crypto_ctx, &context, digest, &digest_size);
//     EXPECT_EQ(result, n20_error_ok_e);
// }

// TEST_F(FunctionalityTest, DigestInput_NullCryptoContext) {
//     n20_open_dice_input_t context = {};
//     uint8_t digest[64];
//     size_t digest_size = sizeof(digest);

//     n20_error_t result = n20_digest_input(nullptr, &context, digest, &digest_size);
//     EXPECT_EQ(result, n20_error_missing_crypto_context_e);
// }

// TEST_F(FunctionalityTest, DeriveKey_Success) {
//     n20_crypto_key_t cdi_secret = reinterpret_cast<n20_crypto_key_t>(0x1234);
//     n20_crypto_key_t derived_key = nullptr;
//     n20_slice_t salt = {10, reinterpret_cast<const uint8_t *>("salt")};
//     n20_slice_t tag = {10, reinterpret_cast<const uint8_t *>("tag")};

//     EXPECT_CALL(*crypto_ctx, kdf(&crypto_ctx, cdi_secret, n20_crypto_key_type_cdi_e, testing::_,
//     &derived_key))
//         .WillOnce(testing::Return(n20_error_ok_e));

//     n20_error_t result = n20_derive_key(&crypto_ctx, cdi_secret, &derived_key,
//     n20_crypto_key_type_cdi_e, salt, tag); EXPECT_EQ(result, n20_error_ok_e);
// }

// TEST_F(FunctionalityTest, DeriveKey_NullCryptoContext) {
//     n20_crypto_key_t cdi_secret = reinterpret_cast<n20_crypto_key_t>(0x1234);
//     n20_crypto_key_t derived_key = nullptr;
//     n20_slice_t salt = {10, reinterpret_cast<const uint8_t *>("salt")};
//     n20_slice_t tag = {10, reinterpret_cast<const uint8_t *>("tag")};

//     n20_error_t result = n20_derive_key(nullptr, cdi_secret, &derived_key,
//     n20_crypto_key_type_cdi_e, salt, tag); EXPECT_EQ(result, n20_error_missing_crypto_context_e);
// }

// TEST_F(FunctionalityTest, InitAlgorithmIdentifier_Success) {
//     n20_x509_algorithm_identifier_t algorithm_identifier = {};
//     n20_error_t result = n20_init_algorithm_identifier(&algorithm_identifier,
//     n20_crypto_key_type_ed25519_e); EXPECT_EQ(result, n20_error_ok_e);
//     EXPECT_EQ(algorithm_identifier.oid, &OID_ED25519);
// }

// TEST_F(FunctionalityTest, InitAlgorithmIdentifier_UnsupportedKeyType) {
//     n20_x509_algorithm_identifier_t algorithm_identifier = {};
//     n20_error_t result = n20_init_algorithm_identifier(&algorithm_identifier,
//     static_cast<n20_crypto_key_type_t>(999)); EXPECT_EQ(result, n20_error_crypto_backend_e);
// }

// TEST_F(FunctionalityTest, PrepareX509Cert_Success) {
//     n20_open_dice_input_t context = {};
//     n20_signer_t signer = {&crypto_ctx, reinterpret_cast<n20_crypto_key_t>(0x1234), nullptr};
//     uint8_t public_key[64] = {};
//     uint8_t attestation_certificate[256] = {};
//     size_t attestation_certificate_size = sizeof(attestation_certificate);

//     EXPECT_CALL(*crypto_ctx, key_get_public_key(&crypto_ctx, testing::_, testing::_, testing::_))
//         .WillOnce(testing::Return(n20_error_ok_e));

//     n20_error_t result = n20_prepare_x509_cert(&context, &signer, n20_crypto_key_type_ed25519_e,
//     nullptr, n20_crypto_key_type_ed25519_e, nullptr, public_key, sizeof(public_key),
//     attestation_certificate, &attestation_certificate_size); EXPECT_EQ(result, n20_error_ok_e);
// }
