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
#include <nat20/functionality.h>
#include <nat20/testing/test_utils.h>
#include <sys/types.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <tuple>

#include "nat20/stream.h"
#include "nat20/types.h"
#include "test_vectors.h"

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

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

// Test fixture
class FunctionalityTest : public ::testing::TestWithParam<std::tuple<std::string,
                                                                     n20_crypto_key_type_t,
                                                                     n20_crypto_key_type_t,
                                                                     n20_certificate_format_t,
                                                                     std::vector<uint8_t>>> {
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

INSTANTIATE_TEST_SUITE_P(FunctionalityTestInstance,
                         FunctionalityTest,
                         ::testing::ValuesIn(attestationCertificateTestVectors),
                         [](testing::TestParamInfo<FunctionalityTest::ParamType> const& info) {
                             return std::get<0>(info.param);
                         });

TEST_P(FunctionalityTest, TestOpenDiceAttestationCertificate) {
    auto [_, parent_key_type, key_type, certificate_format, want_cert] = GetParam();

    auto key_deleter = [this](void* key) { crypto_ctx->key_free(crypto_ctx, key); };

    n20_crypto_key_t parent_secret = this->GetCdi();
    auto parent_secret_guard =
        std::unique_ptr<void, decltype(key_deleter)>(parent_secret, key_deleter);

    n20_crypto_key_t parent_attestation_key = nullptr;
    ASSERT_NE(parent_secret, nullptr);
    auto parent_attestation_key_guard =
        std::unique_ptr<void, decltype(key_deleter)>(parent_attestation_key, key_deleter);

    ASSERT_EQ(n20_error_ok_e,
              n20_derive_attestation_key(
                  crypto_ctx, parent_secret, &parent_attestation_key, parent_key_type));
    ASSERT_NE(parent_attestation_key, nullptr);

    auto code_descriptor = make_code_descriptor("Test DICE", "1.0", test_code_hash);

    n20_slice_t code_descriptor_slice = {.size = code_descriptor.size(),
                                         .buffer = const_cast<uint8_t*>(code_descriptor.data())};

    n20_crypto_gather_list_t code_descriptor_gather_list = {1, &code_descriptor_slice};

    std::vector<uint8_t> code_descriptor_hash(32);
    size_t code_descriptor_hash_size = code_descriptor_hash.size();
    ASSERT_EQ(n20_error_ok_e,
              crypto_ctx->digest_ctx.digest(&crypto_ctx->digest_ctx,
                                            n20_crypto_digest_algorithm_sha2_256_e,
                                            &code_descriptor_gather_list,
                                            1,
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
              crypto_ctx->digest_ctx.digest(&crypto_ctx->digest_ctx,
                                            n20_crypto_digest_algorithm_sha2_256_e,
                                            &configuration_descriptor_gather_list,
                                            1,
                                            configuration_descriptor_hash.data(),
                                            &configuration_descriptor_hash_size));
    ASSERT_EQ(configuration_descriptor_hash_size, 32);

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
                                                           certificate_format,
                                                           attestation_certificate,
                                                           &attestation_certificate_size))
        << "Expected buffer size: " << attestation_certificate_size;

    auto got_cert = std::vector<uint8_t>(
        &attestation_certificate[sizeof(attestation_certificate) - attestation_certificate_size],
        &attestation_certificate[sizeof(attestation_certificate)]);

    // Currently we are using ECDSA with random nonce (k) for signing with
    // secp256r1 and secp384r1 keys, so the signature will not match the
    // one in the test vectors.
    // We can only compare the certificate content without the signature
    // in these cases. For ed25519, the signature is deterministic
    // and will match the one in the test vectors.
    auto comp_want_cert = want_cert;
    auto comp_got_cert = got_cert;
    uint8_t signature_offset = 0;
    switch (parent_key_type) {
        case n20_crypto_key_type_secp256r1_e:
            signature_offset = 64;
            break;
        case n20_crypto_key_type_secp384r1_e:
            signature_offset = 96;
            break;
        default:
            break;
    }
    comp_want_cert.resize(want_cert.size() >= signature_offset ? want_cert.size() - signature_offset
                                                               : 0);
    comp_got_cert.resize(got_cert.size() >= signature_offset ? got_cert.size() - signature_offset
                                                             : 0);

    ASSERT_EQ(comp_want_cert, comp_got_cert) << "\nExpected: \n"
                                             << hexdump(want_cert) << "\n Got: \n"
                                             << hexdump(got_cert);
    ASSERT_EQ(want_cert.size(), got_cert.size());
    // Verify the certificate
}
