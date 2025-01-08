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

#include <memory>
#include <vector>

#include "gtest/gtest.h"
#include "nat20/crypto.h"

#define MAKE_PTR(name) using name##_PTR_t = bssl::UniquePtr<name>

MAKE_PTR(EVP_PKEY);
MAKE_PTR(EVP_PKEY_CTX);
MAKE_PTR(EVP_MD_CTX);
MAKE_PTR(BIO);
MAKE_PTR(X509);
MAKE_PTR(EC_KEY);

// These definitions help with disambiguating the inner test loop by
// printing the test variant name on failure.
#define N20_ASSERT_EQ(val1, val2) ASSERT_EQ(val1, val2) << "Test variant: " << n20_test_name << " "
#define N20_ASSERT_LE(val1, val2) ASSERT_LE(val1, val2) << "Test variant: " << n20_test_name << " "
#define N20_ASSERT_TRUE(val1) ASSERT_TRUE(val1) << "Test variant: " << n20_test_name << " "
#define N20_ASSERT_FALSE(val1) ASSERT_FALSE(val1) << "Test variant: " << n20_test_name << " "

template <typename T>
class CryptoTestFixture : public ::testing::Test {
   protected:
    n20_crypto_context_t* ctx = nullptr;

   public:
    using impl = T;

    void SetUp() override { ASSERT_EQ(n20_crypto_error_ok_e, impl::open(&ctx)); }

    void TearDown() override {
        ASSERT_EQ(n20_crypto_error_ok_e, impl::close(ctx));
        ctx = nullptr;
    }
};

TYPED_TEST_SUITE_P(CryptoTestFixture);

TYPED_TEST_P(CryptoTestFixture, OpenClose) {

    // If this point is reached the fixture has already successfully
    // Opened the implementation. So let's close it.
    ASSERT_EQ(n20_crypto_error_ok_e, TypeParam::close(this->ctx));

    // Does the implementation correctly return n20_crypto_error_unexpected_null_e
    // if passed a nullptr?
    ASSERT_EQ(n20_crypto_error_unexpected_null_e, TypeParam::open(nullptr));
    ASSERT_EQ(n20_crypto_error_unexpected_null_e, TypeParam::close(nullptr));

    // Okay, let's open it again to restore the invariant of the fixture.
    ASSERT_EQ(n20_crypto_error_ok_e, TypeParam::open(&this->ctx));
}

constexpr uint8_t test_vector_sha224_abc[] = {
    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
    0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7};

constexpr uint8_t test_vector_sha256_abc[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
constexpr uint8_t test_vector_sha384_abc[] = {
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
    0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
    0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
constexpr uint8_t test_vector_sha3512_abc[] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};

struct DigestTestCase {
    n20_crypto_digest_algorithm_t alg;
    std::string name;
    std::string preimage;
    std::vector<uint8_t> want;
};

DigestTestCase digest_test_cases[] = {
    {n20_crypto_digest_algorithm_sha2_224_e,
     "sha224_<empty>",
     "",
     {0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82,
      0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f}},
    {n20_crypto_digest_algorithm_sha2_256_e,
     "sha256_<empty>",
     "",
     {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
      0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
      0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}},
    {n20_crypto_digest_algorithm_sha2_384_e,
     "sha384_<empty>",
     "",
     {0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
      0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
      0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
      0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b}},
    {n20_crypto_digest_algorithm_sha2_512_e,
     "sha512_<empty>",
     "",
     {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6,
      0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4,
      0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2,
      0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd,
      0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e}},
    {n20_crypto_digest_algorithm_sha2_224_e,
     "sha224_abc",
     "abc",
     {0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
      0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7}},
    {n20_crypto_digest_algorithm_sha2_256_e,
     "sha256_abc",
     "abc",
     {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}},
    {n20_crypto_digest_algorithm_sha2_384_e,
     "sha384_abc",
     "abc",
     {0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
      0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
      0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
      0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7}},
    {n20_crypto_digest_algorithm_sha2_512_e,
     "sha512_abc",
     "abc",
     {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae,
      0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e,
      0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1,
      0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23,
      0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f}},
};

TYPED_TEST_P(CryptoTestFixture, DigestTestVectorTest) {
    for (auto test_case : digest_test_cases) {
        n20_crypto_slice_t buffers[]{
            {test_case.preimage.size(),
             const_cast<uint8_t*>(reinterpret_cast<uint8_t const*>(test_case.preimage.c_str()))}};
        n20_crypto_gather_list_t msg = {1, buffers};
        std::vector<uint8_t> digest(test_case.want.size());
        size_t buffer_size = digest.size();
        ASSERT_EQ(n20_crypto_error_ok_e,
                  this->ctx->digest(this->ctx, test_case.alg, &msg, digest.data(), &buffer_size))
            << test_case.name;
        ASSERT_EQ(digest.size(), buffer_size) << test_case.name;
        ASSERT_EQ(test_case.want, digest) << test_case.name;
    }
}

TYPED_TEST_P(CryptoTestFixture, DigestBufferSizeTest) {

    size_t got_size = 0;
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t, size_t>;

    for (auto [n20_test_name, alg, want_size] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e, 28},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e, 32},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e, 48},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e, 64},
         }) {

        // If null is given as output buffer, the function must return
        // the required buffer size for the algorithm.
        // It must also tolerate that nullptr is passed as msg.
        N20_ASSERT_EQ(n20_crypto_error_insufficient_buffer_size_e,
                      this->ctx->digest(this->ctx, alg, nullptr, nullptr, &got_size));
        N20_ASSERT_EQ(want_size, got_size);

        // If the output buffer given is too small, the correct
        // buffer size must be returned in digest_size_in_out, and the buffer
        // must not be touched.
        got_size = 4;
        std::vector<uint8_t> const want_buffer = {0xde, 0xad, 0xbe, 0xef};
        std::vector<uint8_t> buffer = want_buffer;
        N20_ASSERT_EQ(n20_crypto_error_insufficient_buffer_size_e,
                      this->ctx->digest(this->ctx, alg, nullptr, buffer.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);
        N20_ASSERT_EQ(want_buffer, buffer);

        // This part of the test ensures that the output buffer size
        // is as expected for the given algorithm even if the original buffer
        // is larger than required.
        buffer = std::vector<uint8_t>(80);
        got_size = buffer.size();
        N20_ASSERT_EQ(80, got_size);

        n20_crypto_slice_t buffers[]{{0, nullptr}};
        n20_crypto_gather_list_t msg = {1, buffers};

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->digest(this->ctx, alg, &msg, buffer.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);
    }
}

TYPED_TEST_P(CryptoTestFixture, InvalidContext) {

    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        // Digest must return invalid context if nullptr is given as context.
        N20_ASSERT_EQ(n20_crypto_error_invalid_context_e,
                      this->ctx->digest(nullptr, alg, nullptr, nullptr, nullptr));
    }

    // KDF must return invalid context if nullptr is given as context.
    ASSERT_EQ(n20_crypto_error_invalid_context_e,
              this->ctx->kdf(nullptr, nullptr, n20_crypto_key_type_cdi_e, nullptr, nullptr));

    // Sign must return invalid context if nullptr is given as context.
    ASSERT_EQ(n20_crypto_error_invalid_context_e,
              this->ctx->sign(nullptr, nullptr, nullptr, nullptr, nullptr));

    // Key_get_public_key must return invalid context if nullptr is given as context.
    ASSERT_EQ(n20_crypto_error_invalid_context_e,
              this->ctx->key_get_public_key(nullptr, nullptr, nullptr, nullptr));

    // Key_free must return invalid context if nullptr is given as context.
    ASSERT_EQ(n20_crypto_error_invalid_context_e, this->ctx->key_free(nullptr, nullptr));

    // Get_cdi must return invalid context if nullptr is given as context.
    ASSERT_EQ(n20_crypto_error_invalid_context_e, this->ctx->get_cdi(nullptr, nullptr));
}

TYPED_TEST_P(CryptoTestFixture, DigestErrorsTest) {

    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        // Must return n20_crypto_error_unexpected_null_size_e if a valid context
        // was given but no digest_size_in_out.
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_size_e,
                      this->ctx->digest(this->ctx, alg, nullptr, nullptr, nullptr));

        // Must return n20_crypto_error_unexpected_null_data_e if sufficient
        // buffer given, but no message.
        auto buffer = std::vector<uint8_t>(80);
        size_t got_size = buffer.size();
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_data_e,
                      this->ctx->digest(this->ctx, alg, nullptr, buffer.data(), &got_size));

        // Must return n20_crypto_error_unexpected_null_list_e if
        // the gatherlist buffer count is not 0 but the list is NULL.
        n20_crypto_gather_list_t msg = {1, nullptr};
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_list_e,
                      this->ctx->digest(this->ctx, alg, &msg, buffer.data(), &got_size));

        // Must return n20_crypto_error_unexpected_null_slice_e if a buffer in
        // the message has a size but nullptr buffer.
        n20_crypto_slice_t buffers[]{{3, nullptr}};
        msg.list = buffers;
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_slice_e,
                      this->ctx->digest(this->ctx, alg, &msg, buffer.data(), &got_size));
    }
}

TYPED_TEST_P(CryptoTestFixture, DigestSkipEmpty) {

    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t, size_t>;
    for (auto [n20_test_name, alg, want_size] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e, 28},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e, 32},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e, 48},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e, 64},
         }) {

        uint8_t msg1[] = {'f', 'o', 'o'};
        uint8_t msg2[] = {'b', 'a', 'r'};

        std::vector<uint8_t> got_digest(want_size);
        size_t got_digest_size = want_size;

        // We are digesting the message "foobar" in a roundabout way.
        // First we split it up into {"foo", "bar", ""}.
        n20_crypto_slice_t buffers[3]{{sizeof msg1, msg1}, {sizeof msg2, msg2}, {0, nullptr}};
        n20_crypto_gather_list_t msg = {3, buffers};

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->digest(this->ctx, alg, &msg, got_digest.data(), &got_digest_size));

        // Safe the first result to compare it with the following computations.
        auto want_digest = got_digest;

        // Change the message gather list to {"foo", "", "bar"}.
        buffers[2] = buffers[1];
        buffers[1] = {0, nullptr};

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->digest(this->ctx, alg, &msg, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);

        // Change the message gather list to {"", "foo", "bar"}.
        buffers[1] = buffers[0];
        buffers[0] = {0, nullptr};

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->digest(this->ctx, alg, &msg, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);

        // This test checks that the buffer pointer has no impact if size is 0
        // even if not null.
        buffers[0] = {0, msg2};

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->digest(this->ctx, alg, &msg, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);
    }
}

static std::vector<uint8_t> signature_2_asn1_sequence(std::vector<uint8_t> const& sig) {
    size_t integer_size = sig.size() / 2;

    uint8_t buffer[104];
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, &buffer[0], 104);

    auto mark = n20_asn1_stream_data_written(&s);
    // Write S
    n20_asn1_integer(&s, sig.data() + integer_size, integer_size, false, false);
    // Write R
    n20_asn1_integer(&s, sig.data(), integer_size, false, false);

    n20_asn1_header(&s,
                    N20_ASN1_CLASS_UNIVERSAL,
                    /*constructed=*/true,
                    N20_ASN1_TAG_SEQUENCE,
                    n20_asn1_stream_data_written(&s) - mark);

    EXPECT_TRUE(n20_asn1_stream_is_data_good(&s));
    return std::vector<uint8_t>(n20_asn1_stream_data(&s),
                                n20_asn1_stream_data(&s) + n20_asn1_stream_data_written(&s));
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

        auto sig = signature_2_asn1_sequence(signature);

        if (1 != EVP_DigestVerifyFinal(md_ctx.get(), sig.data(), sig.size())) {
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
            return false;
        }
    }
    return true;
}

// This test exercises most positive code paths of the entire crypto implementation.
// It derives multiple keys which are used for signing. It then gets the public key
// of one of the derived keys for signature verification.
// The test tries to establish, indirectly, that the key derivation is deterministic.
// For each key type it performs tree key derivations. The first two are
// derived using the same context. These keys are used for signing and
// verification respectively. If the key derivation is in deed deterministic.
// signatures issued with the first key must verify against the public key of
// the second.
// The third key uses a different context. The signature generated with this
// key must not verify against the second.
TYPED_TEST_P(CryptoTestFixture, KDFTest) {
    n20_crypto_key_t cdi;

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->get_cdi(this->ctx, &cdi));

    using tc = std::tuple<std::string, n20_crypto_key_type_t>;
    for (auto [n20_test_name, key_type] : {
             tc{"ed25519", n20_crypto_key_type_ed25519_e},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e},
         }) {

        n20_crypto_slice_t context_buffers[] = {
            {15, (uint8_t*)"this context is "},
            {4, (uint8_t*)"not "},
            {10, (uint8_t*)"the other"},
        };

        n20_crypto_gather_list_t context = {3, context_buffers};

        // Derive two keys with using the same context.
        // The implementation must generate the same key.
        // So we use one for signing and the other for verification.
        // If the signature verifies successfully we can be reasonably
        // certain that the derived keys were indeed the same.
        n20_crypto_key_t derived_key_sign;
        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &context, &derived_key_sign));

        n20_crypto_key_t derived_key_verify;
        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &context, &derived_key_verify));

        // ##### Sign the message. #########
        n20_crypto_slice_t message_buffers[] = {
            {10, (uint8_t*)"my message"},
        };
        n20_crypto_gather_list_t message = {1, message_buffers};

        // Get the maximal signature size and allocate the buffer.
        size_t sig_size = 0;
        N20_ASSERT_EQ(n20_crypto_error_insufficient_buffer_size_e,
                      this->ctx->sign(this->ctx, derived_key_sign, &message, nullptr, &sig_size));
        std::vector<uint8_t> signature(sig_size);

        // Do the actual signing.
        N20_ASSERT_EQ(
            n20_crypto_error_ok_e,
            this->ctx->sign(this->ctx, derived_key_sign, &message, signature.data(), &sig_size));
        N20_ASSERT_LE(sig_size, signature.size());
        signature.resize(sig_size);

        // ##### Sign the message with another key #########

        // Derive a different key for a negative check.
        // This turns the context into "this context is the other".
        context.list[1].size = 0;
        n20_crypto_key_t derived_key_other;
        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &context, &derived_key_other));

        // 96 is large enough for all implemented algorithms. So
        // no need to do the query dance again.
        sig_size = 96;
        std::vector<uint8_t> other_signature(sig_size);
        N20_ASSERT_EQ(
            n20_crypto_error_ok_e,
            this->ctx->sign(
                this->ctx, derived_key_other, &message, other_signature.data(), &sig_size));
        N20_ASSERT_LE(sig_size, other_signature.size());
        other_signature.resize(sig_size);

        // ###### Verification ##########

        // Now get the public key from derived_key_verify.
        size_t pub_key_size = 0;
        N20_ASSERT_EQ(
            n20_crypto_error_insufficient_buffer_size_e,
            this->ctx->key_get_public_key(this->ctx, derived_key_verify, nullptr, &pub_key_size));
        std::vector<uint8_t> pub_key(pub_key_size);
        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->key_get_public_key(
                          this->ctx, derived_key_verify, pub_key.data(), &pub_key_size));
        N20_ASSERT_EQ(pub_key.size(), pub_key_size);
        EVP_PKEY_PTR_t evp_pub_key;
        if (key_type == n20_crypto_key_type_ed25519_e) {
            evp_pub_key = EVP_PKEY_PTR_t(EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519, nullptr, pub_key.data(), pub_key.size()));
            N20_ASSERT_TRUE(!!evp_pub_key);
        } else {
            uint8_t const* p = pub_key.data();

            int ec_curve;
            switch (key_type) {
                case n20_crypto_key_type_secp256r1_e:
                    ec_curve = NID_X9_62_prime256v1;
                    break;
                case n20_crypto_key_type_secp384r1_e:
                    ec_curve = NID_secp384r1;
                    break;
                default:
                    N20_ASSERT_TRUE(false) << "unknown key type";
            }
            auto ec_key = EC_KEY_PTR_t(EC_KEY_new_by_curve_name(ec_curve));
            N20_ASSERT_TRUE(!!ec_key);
            auto ec_key_p = ec_key.get();
            N20_ASSERT_TRUE(o2i_ECPublicKey(&ec_key_p, &p, pub_key.size()));
            evp_pub_key = EVP_PKEY_PTR_t(EVP_PKEY_new());
            N20_ASSERT_TRUE(!!evp_pub_key);
            N20_ASSERT_TRUE(EVP_PKEY_assign_EC_KEY(evp_pub_key.get(), ec_key.release()));
        }

        auto message_vector = std::vector<uint8_t>(
            message_buffers[0].buffer, message_buffers[0].buffer + message_buffers[0].size);

        // Verify the signature.
        N20_ASSERT_TRUE(verify(evp_pub_key, message_vector, signature));

        // The signature made with the other key must not verify
        // showing that the key in fact differed.
        N20_ASSERT_FALSE(verify(evp_pub_key, message_vector, other_signature));

        // Cleanup derived keys.
        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, derived_key_sign));
        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, derived_key_verify));
        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, derived_key_other));
    }
    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, cdi));
}

TYPED_TEST_P(CryptoTestFixture, GetCDIErrorsTest) {

    ASSERT_EQ(n20_crypto_error_invalid_context_e, this->ctx->get_cdi(nullptr, nullptr));

    ASSERT_EQ(n20_crypto_error_unexpected_null_key_out_e, this->ctx->get_cdi(this->ctx, nullptr));
}

TYPED_TEST_P(CryptoTestFixture, KDFErrorsTest) {
    n20_crypto_key_t cdi;

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->get_cdi(this->ctx, &cdi));

    using tc = std::tuple<std::string, n20_crypto_key_type_t>;
    for (auto [n20_test_name, key_type] : {
             tc{"cdi", n20_crypto_key_type_cdi_e},
             tc{"ed25519", n20_crypto_key_type_ed25519_e},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e},
         }) {

        N20_ASSERT_EQ(n20_crypto_error_invalid_context_e,
                      this->ctx->kdf(nullptr, nullptr, key_type, nullptr, nullptr));

        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_key_in_e,
                      this->ctx->kdf(this->ctx, nullptr, key_type, nullptr, nullptr));

        // Derive each key type that would be ineligible to derive a key from
        // and use it as in key for the KDF. The kdf must diagnose it
        // as n20_crypto_error_invalid_key_e.
        n20_crypto_slice_t context_buffers[] = {
            {3, (uint8_t*)"foo"},
        };
        n20_crypto_gather_list_t context = {1, context_buffers};
        n20_crypto_key_t invalid_key = nullptr;
        N20_ASSERT_EQ(
            n20_crypto_error_ok_e,
            this->ctx->kdf(this->ctx, cdi, n20_crypto_key_type_ed25519_e, &context, &invalid_key));
        N20_ASSERT_EQ(n20_crypto_error_invalid_key_e,
                      this->ctx->kdf(this->ctx, invalid_key, key_type, nullptr, nullptr));
        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, invalid_key));

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(
                          this->ctx, cdi, n20_crypto_key_type_secp256r1_e, &context, &invalid_key));
        N20_ASSERT_EQ(n20_crypto_error_invalid_key_e,
                      this->ctx->kdf(this->ctx, invalid_key, key_type, nullptr, nullptr));
        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, invalid_key));

        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(
                          this->ctx, cdi, n20_crypto_key_type_secp384r1_e, &context, &invalid_key));
        N20_ASSERT_EQ(n20_crypto_error_invalid_key_e,
                      this->ctx->kdf(this->ctx, invalid_key, key_type, nullptr, nullptr));
        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, invalid_key));

        // Must return n20_crypto_error_unexpected_null_key_out_e if no buffer is
        // given to return the derived key.
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_key_out_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, nullptr, nullptr));

        n20_crypto_key_t key_out = nullptr;
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_data_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, nullptr, &key_out));

        // Must return n20_crypto_error_unexpected_null_list_e if the gather list
        // pointer is NULL.
        n20_crypto_gather_list_t invalid_context = {1, nullptr};
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_list_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &invalid_context, &key_out));

        n20_crypto_slice_t invalid_context_buffers[] = {
            {3, nullptr},
        };
        invalid_context.list = invalid_context_buffers;
        N20_ASSERT_EQ(n20_crypto_error_unexpected_null_slice_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &invalid_context, &key_out));
    }

    n20_crypto_key_t out_key = nullptr;
    n20_crypto_slice_t context_buffers[] = {
        {3, (uint8_t*)"foo"},
    };
    n20_crypto_gather_list_t context = {1, context_buffers};

    ASSERT_EQ(n20_crypto_error_invalid_key_type_e,
              this->ctx->kdf(this->ctx, cdi, (n20_crypto_key_type_t)-1, &context, &out_key));

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, cdi));
}

TYPED_TEST_P(CryptoTestFixture, SignErrorsTest) {
    n20_crypto_key_t cdi;

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->get_cdi(this->ctx, &cdi));

    ASSERT_EQ(n20_crypto_error_invalid_context_e,
              this->ctx->sign(nullptr, nullptr, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_crypto_error_unexpected_null_key_in_e,
              this->ctx->sign(this->ctx, nullptr, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_crypto_error_unexpected_null_size_e,
              this->ctx->sign(this->ctx, cdi, nullptr, nullptr, nullptr));

    size_t signature_size = 0;
    ASSERT_EQ(n20_crypto_error_invalid_key_e,
              this->ctx->sign(this->ctx, cdi, nullptr, nullptr, &signature_size));

    using tc = std::tuple<std::string, n20_crypto_key_type_t, size_t>;
    for (auto [n20_test_name, key_type, want_signature_size] : {
             tc{"ed25519", n20_crypto_key_type_ed25519_e, 64},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e, 64},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e, 96},
         }) {

        n20_crypto_slice_t context_buffers[] = {
            {19, (uint8_t*)"sign error test key"},
        };
        n20_crypto_gather_list_t context = {1, context_buffers};
        n20_crypto_key_t signing_key = nullptr;
        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &context, &signing_key));

        // Must return n20_crypto_error_insufficient_buffer_size_e if out buffer is NULL.
        signature_size = 30000;
        N20_ASSERT_EQ(n20_crypto_error_insufficient_buffer_size_e,
                      this->ctx->sign(this->ctx, signing_key, nullptr, nullptr, &signature_size));

        // Must return the correct expected signature size.
        N20_ASSERT_EQ(want_signature_size, signature_size);

        // Must return n20_crypto_error_insufficient_buffer_size_e if buffer given but
        // size is too small.
        uint8_t signature_buffer[104];
        signature_size = want_signature_size - 1;
        N20_ASSERT_EQ(
            n20_crypto_error_insufficient_buffer_size_e,
            this->ctx->sign(this->ctx, signing_key, nullptr, signature_buffer, &signature_size));

        // Must return the correct expected signature size.
        N20_ASSERT_EQ(want_signature_size, signature_size);

        N20_ASSERT_EQ(
            n20_crypto_error_unexpected_null_data_e,
            this->ctx->sign(this->ctx, signing_key, nullptr, signature_buffer, &signature_size));

        n20_crypto_gather_list_t message = {1, nullptr};
        N20_ASSERT_EQ(
            n20_crypto_error_unexpected_null_list_e,
            this->ctx->sign(this->ctx, signing_key, &message, signature_buffer, &signature_size));

        char const* msg = "my message";
        n20_crypto_slice_t msg_buffers[] = {{strlen(msg), nullptr}};
        message.list = msg_buffers;
        N20_ASSERT_EQ(
            n20_crypto_error_unexpected_null_slice_e,
            this->ctx->sign(this->ctx, signing_key, &message, signature_buffer, &signature_size));
        msg_buffers[0].buffer = (uint8_t const*)msg;
    }

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, cdi));
}

TYPED_TEST_P(CryptoTestFixture, GetPublicKeyErrorsTest) {
    n20_crypto_key_t cdi;

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->get_cdi(this->ctx, &cdi));

    ASSERT_EQ(n20_crypto_error_invalid_context_e,
              this->ctx->key_get_public_key(nullptr, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_crypto_error_unexpected_null_key_in_e,
              this->ctx->key_get_public_key(this->ctx, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_crypto_error_unexpected_null_size_e,
              this->ctx->key_get_public_key(this->ctx, cdi, nullptr, nullptr));

    size_t public_key_size = 0;
    ASSERT_EQ(n20_crypto_error_invalid_key_e,
              this->ctx->key_get_public_key(this->ctx, cdi, nullptr, &public_key_size));

    using tc = std::tuple<std::string, n20_crypto_key_type_t, size_t>;
    for (auto [n20_test_name, key_type, want_key_size] : {
             tc{"ed25519", n20_crypto_key_type_ed25519_e, 32},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e, 65},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e, 97},
         }) {

        n20_crypto_key_t key = nullptr;
        char const context_str[] = "public key errors test context";
        n20_crypto_slice_t context_buffers[] = {sizeof(context_str) - 1,
                                                (uint8_t* const)&context_str[0]};
        n20_crypto_gather_list_t context = {1, context_buffers};
        N20_ASSERT_EQ(n20_crypto_error_ok_e,
                      this->ctx->kdf(this->ctx, cdi, key_type, &context, &key));

        // Must return n20_crypto_error_insufficient_buffer_size_e if public_key_out
        // is nullptr.
        public_key_size = 100;
        N20_ASSERT_EQ(n20_crypto_error_insufficient_buffer_size_e,
                      this->ctx->key_get_public_key(this->ctx, key, nullptr, &public_key_size));
        // If n20_crypto_error_insufficient_buffer_size_e was returned public_key_size
        // must contain the correct maximal required buffer size.
        N20_ASSERT_EQ(want_key_size, public_key_size);

        // Must return n20_crypto_error_insufficient_buffer_size_e if
        // *public_key_size_in_out is too small even if a buffer was given.
        public_key_size = want_key_size - 1;
        uint8_t public_key_buffer[100];
        N20_ASSERT_EQ(
            n20_crypto_error_insufficient_buffer_size_e,
            this->ctx->key_get_public_key(this->ctx, key, public_key_buffer, &public_key_size));

        // If n20_crypto_error_insufficient_buffer_size_e was returned public_key_size
        // must contain the correct maximal required buffer size.
        N20_ASSERT_EQ(want_key_size, public_key_size);

        N20_ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, key));
    }

    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, cdi));
}

TYPED_TEST_P(CryptoTestFixture, KeyFreeErrorsTest) {
    ASSERT_EQ(n20_crypto_error_invalid_context_e, this->ctx->key_free(nullptr, nullptr));
    ASSERT_EQ(n20_crypto_error_ok_e, this->ctx->key_free(this->ctx, nullptr));
}

REGISTER_TYPED_TEST_SUITE_P(CryptoTestFixture,
                            OpenClose,
                            DigestTestVectorTest,
                            DigestBufferSizeTest,
                            InvalidContext,
                            DigestErrorsTest,
                            DigestSkipEmpty,
                            KDFTest,
                            GetCDIErrorsTest,
                            KDFErrorsTest,
                            SignErrorsTest,
                            GetPublicKeyErrorsTest,
                            KeyFreeErrorsTest);

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

struct CryptoImplBSSL {
    static n20_crypto_error_t open(n20_crypto_context_t** ctx) {
        n20_crypto_slice_t cdi = {sizeof(test_cdi), const_cast<uint8_t*>(&test_cdi[0])};
        return n20_crypto_open_boringssl(ctx, &cdi);
    }
    static n20_crypto_error_t close(n20_crypto_context_t* ctx) {
        return n20_crypto_close_boringssl(ctx);
    }
};

using CryptoImpls = ::testing::Types<CryptoImplBSSL>;

INSTANTIATE_TYPED_TEST_SUITE_P(BSSLCrypto, CryptoTestFixture, CryptoImpls);
