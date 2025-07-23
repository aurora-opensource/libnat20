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
#include <nat20/oid.h>
#include <nat20/testing/test_utils.h>
#include <nat20/types.h>
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

#include "crypto_implementations_to_test.h"
#include "nat20/error.h"
#include "test_vectors.h"

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
#define N20_ASSERT_GE(val1, val2) ASSERT_GE(val1, val2) << "Test variant: " << n20_test_name << " "
#define N20_ASSERT_TRUE(val1) ASSERT_TRUE(val1) << "Test variant: " << n20_test_name << " "
#define N20_ASSERT_FALSE(val1) ASSERT_FALSE(val1) << "Test variant: " << n20_test_name << " "

template <typename T>
class CryptoDigestFixture : public ::testing::Test {
   protected:
    n20_crypto_context_t* ctx = nullptr;
    n20_crypto_digest_context_t* digest_ctx = nullptr;

   public:
    using impl = T;

    template <typename U>
    std::enable_if_t<std::is_same_v<n20_error_t(n20_crypto_digest_context_t**), decltype(U::open)>,
                     n20_error_t>
    open_digest_impl() {
        return U::open(&digest_ctx);
    }

    template <typename U>
    std::enable_if_t<std::is_same_v<n20_error_t(n20_crypto_context_t**), decltype(U::open)>,
                     n20_error_t>
    open_digest_impl() {
        auto rc = U::open(&ctx);
        if (rc != n20_error_ok_e) {
            return rc;
        }
        digest_ctx = &ctx->digest_ctx;
        return n20_error_ok_e;
    }

    template <typename U>
    std::enable_if_t<std::is_same_v<n20_error_t(n20_crypto_digest_context_t**), decltype(U::open)>,
                     n20_error_t>
    close_digest_impl() {
        auto rc = U::close(digest_ctx);
        digest_ctx = nullptr;
        return rc;
    }

    template <typename U>
    std::enable_if_t<std::is_same_v<n20_error_t(n20_crypto_context_t**), decltype(U::open)>,
                     n20_error_t>
    close_digest_impl() {
        auto rc = U::close(ctx);
        ctx = nullptr;
        digest_ctx = nullptr;
        return rc;
    }

    void SetUp() override { ASSERT_EQ(n20_error_ok_e, open_digest_impl<T>()); }

    void TearDown() override { ASSERT_EQ(n20_error_ok_e, close_digest_impl<T>()); }
};

TYPED_TEST_SUITE_P(CryptoDigestFixture);

template <typename T>
class CryptoTestFixture : public ::testing::Test {
   protected:
    n20_crypto_context_t* ctx = nullptr;
    n20_crypto_key_t cdi = nullptr;

   public:
    using impl = T;

    void SetUp() override {
        ASSERT_EQ(n20_error_ok_e, impl::open(&ctx));
        ASSERT_EQ(n20_error_ok_e, impl::get_cdi(ctx, &cdi));
    }

    void TearDown() override {
        ASSERT_EQ(n20_error_ok_e, ctx->key_free(ctx, cdi));
        ASSERT_EQ(n20_error_ok_e, impl::close(ctx));
        ctx = nullptr;
        cdi = nullptr;
    }
};

TYPED_TEST_SUITE_P(CryptoTestFixture);

TYPED_TEST_P(CryptoTestFixture, OpenClose) {
    // If this point is reached the fixture has already successfully
    // Opened the implementation. So let's close it.
    ASSERT_EQ(n20_error_ok_e, TypeParam::close(this->ctx));

    // Does the implementation correctly return n20_error_crypto_unexpected_null_e
    // if passed a nullptr?
    ASSERT_EQ(n20_error_crypto_unexpected_null_e, TypeParam::open(nullptr));
    ASSERT_EQ(n20_error_crypto_unexpected_null_e, TypeParam::close(nullptr));

    // Okay, let's open it again to restore the invariant of the fixture.
    ASSERT_EQ(n20_error_ok_e, TypeParam::open(&this->ctx));
}

TYPED_TEST_P(CryptoDigestFixture, SHA2TestVectorTest) {
    for (auto [n20_test_name, alg, msg, want_digest] : sha2TestVectors) {
        n20_slice_t buffers[]{N20_SLICE_NULL};
        if (msg.size() > 0) {
            buffers[0] = {msg.size(), const_cast<uint8_t*>(msg.data())};
        }
        n20_crypto_gather_list_t gather_list = {1, buffers};

        std::vector<uint8_t> got_digest(want_digest.size());
        size_t got_size = got_digest.size();
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, &gather_list, 1, got_digest.data(), &got_size));
        N20_ASSERT_EQ(want_digest.size(), got_size);
        N20_ASSERT_EQ(want_digest, got_digest);
    }
}

TYPED_TEST_P(CryptoDigestFixture, HmacTest) {
    for (auto [n20_test_name, alg, key, msg, want_hmac] : hmacTestVectors) {

        n20_slice_t key_slice = {key.size(), key.data()};
        n20_slice_t msg_slice = {msg.size(), msg.data()};

        n20_crypto_gather_list_t msg_list = {1, &msg_slice};

        std::vector<uint8_t> got_hmac(64);
        size_t got_hmac_size = got_hmac.size();

        auto rc = this->digest_ctx->hmac(
            this->digest_ctx, alg, key_slice, &msg_list, got_hmac.data(), &got_hmac_size);

        N20_ASSERT_EQ(rc, n20_error_ok_e);
        N20_ASSERT_GE(got_hmac_size, want_hmac.size());
        got_hmac.resize(want_hmac.size());
        N20_ASSERT_EQ(want_hmac, got_hmac) << "Expected HMAC: " << hex(want_hmac) << std::endl
                                           << "Actual HMAC: " << hex(got_hmac) << std::endl;
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfTest) {
    for (auto [n20_test_name, alg, ikm, salt, info, unused_prk, want_key] : hkdfTestVectors) {

        n20_slice_t ikm_slice = {ikm.size(), ikm.data()};
        n20_slice_t salt_slice = {salt.size(), salt.data()};
        n20_slice_t info_slice = {info.size(), info.data()};

        std::vector<uint8_t> got_key(want_key.size());

        auto rc = this->digest_ctx->hkdf(this->digest_ctx,
                                         alg,
                                         ikm_slice,
                                         salt_slice,
                                         info_slice,
                                         got_key.size(),
                                         got_key.data());

        N20_ASSERT_EQ(rc, n20_error_ok_e);
        N20_ASSERT_EQ(want_key, got_key) << "Expected key: " << hex(want_key) << std::endl
                                         << "Actual key: " << hex(got_key) << std::endl;
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfExtractTest) {
    for (auto [n20_test_name, alg, ikm, salt, unused_info, want_prk, _want_key] : hkdfTestVectors) {

        n20_slice_t ikm_slice = {ikm.size(), ikm.data()};
        n20_slice_t salt_slice = {salt.size(), salt.data()};

        std::vector<uint8_t> got_prk(want_prk.size());

        size_t got_size = want_prk.size();

        auto rc = this->digest_ctx->hkdf_extract(
            this->digest_ctx, alg, ikm_slice, salt_slice, got_prk.data(), &got_size);

        N20_ASSERT_EQ(rc, n20_error_ok_e);
        N20_ASSERT_EQ(want_prk, got_prk) << "Expected PRK: " << hex(want_prk) << std::endl
                                         << "Actual PRK: " << hex(got_prk) << std::endl;
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfExpandTest) {
    for (auto [n20_test_name, alg, unused_ikm, unused_salt, info, prk, want_key] :
         hkdfTestVectors) {

        n20_slice_t info_slice = {info.size(), info.data()};
        n20_slice_t prk_slice = {prk.size(), prk.data()};

        std::vector<uint8_t> got_key(want_key.size());

        auto rc = this->digest_ctx->hkdf_expand(
            this->digest_ctx, alg, prk_slice, info_slice, want_key.size(), got_key.data());

        N20_ASSERT_EQ(rc, n20_error_ok_e);
        N20_ASSERT_EQ(want_key, got_key) << "Expected key: " << hex(want_key) << std::endl
                                         << "Actual key: " << hex(got_key) << std::endl;
    }
}

TYPED_TEST_P(CryptoDigestFixture, DigestBufferSizeTest) {
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
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->digest(this->digest_ctx, alg, nullptr, 0, nullptr, &got_size));
        N20_ASSERT_EQ(want_size, got_size);

        // If the output buffer given is too small, the correct
        // buffer size must be returned in digest_size_in_out, and the buffer
        // must not be touched.
        got_size = 4;
        std::vector<uint8_t> const want_buffer = {0xde, 0xad, 0xbe, 0xef};
        std::vector<uint8_t> buffer = want_buffer;
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->digest(this->digest_ctx, alg, nullptr, 0, buffer.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);
        N20_ASSERT_EQ(want_buffer, buffer);

        // This part of the test ensures that the output buffer size
        // is as expected for the given algorithm even if the original buffer
        // is larger than required.
        buffer = std::vector<uint8_t>(80);
        got_size = buffer.size();
        N20_ASSERT_EQ(80, got_size);

        n20_slice_t buffers[]{N20_SLICE_NULL};
        n20_crypto_gather_list_t msg = {1, buffers};

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->digest_ctx->digest(this->digest_ctx, alg, &msg, 1, buffer.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);
    }
}

TYPED_TEST_P(CryptoDigestFixture, DigestErrorsTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        // Digest must return invalid context if nullptr is given as context.
        N20_ASSERT_EQ(n20_error_crypto_invalid_context_e,
                      this->digest_ctx->digest(nullptr, alg, nullptr, 0, nullptr, nullptr));

        // Must return n20_error_crypto_unknown_algorithm_e if an unknown
        // algorithm is given.
        N20_ASSERT_EQ(
            n20_error_crypto_unknown_algorithm_e,
            this->digest_ctx->digest(
                this->digest_ctx, (n20_crypto_digest_algorithm_t)-1, nullptr, 0, nullptr, nullptr));

        // Must return n20_error_crypto_unexpected_null_size_e if a valid context
        // was given but no digest_size_in_out.
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_size_e,
            this->digest_ctx->digest(this->digest_ctx, alg, nullptr, 0, nullptr, nullptr));

        // Must return n20_error_crypto_insufficient_buffer_size_e if a valid context,
        // algorithm, and size pointer was given, but digest_out is NULL.
        size_t got_size = 1000;
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->digest(this->digest_ctx, alg, nullptr, 0, nullptr, &got_size));

        // Must return n20_error_crypto_insufficient_buffer_size_e if a valid context,
        // algorithm, size, and out buffer was given but the size was too small.
        auto buffer = std::vector<uint8_t>(80);
        got_size = 4;
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->digest(this->digest_ctx, alg, nullptr, 0, buffer.data(), &got_size));

        got_size = buffer.size();
        // Must return n20_error_crypto_unexpected_null_data_e if sufficient
        // buffer given, but no message.
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_data_e,
            this->digest_ctx->digest(this->digest_ctx, alg, nullptr, 0, buffer.data(), &got_size));

        // Must return n20_error_crypto_unexpected_null_list_e if
        // the gatherlist buffer count is not 0 but the list is NULL.
        n20_crypto_gather_list_t msg = {1, nullptr};
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_list_e,
            this->digest_ctx->digest(this->digest_ctx, alg, &msg, 1, buffer.data(), &got_size));

        // Must return n20_error_crypto_unexpected_null_slice_e if a buffer in
        // the message has a size but nullptr buffer.
        n20_slice_t buffers[]{3, nullptr};
        msg.list = buffers;
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_e,
            this->digest_ctx->digest(this->digest_ctx, alg, &msg, 1, buffer.data(), &got_size));
    }
}

TYPED_TEST_P(CryptoDigestFixture, DigestSkipEmpty) {
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
        n20_slice_t buffers[3]{{sizeof msg1, msg1}, {sizeof msg2, msg2}, N20_SLICE_NULL};
        n20_crypto_gather_list_t msg[2] = {{3, buffers}, {0, nullptr}};

        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, msg, 1, got_digest.data(), &got_digest_size));

        // Save the first result to compare it with the following computations.
        auto want_digest = std::move(got_digest);
        got_digest.resize(want_size);

        // Change the message gather list to {"foo", "", "bar"}.
        buffers[2] = buffers[1];
        buffers[1] = N20_SLICE_NULL;

        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, msg, 1, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed digest.
        got_digest.assign(want_size, 0);

        // Change the message gather list to {"", "foo", "bar"}.
        buffers[1] = buffers[0];
        buffers[0] = N20_SLICE_NULL;

        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, msg, 1, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed digest.
        got_digest.assign(want_size, 0);

        // This test checks that the buffer pointer has no impact if size is 0
        // even if not null.
        buffers[0] = {0, (uint8_t*)"snafu"};

        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, msg, 1, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed digest.
        got_digest.assign(want_size, 0);

        // This test checks that the second gather list element
        // is skipped if it has a size of 0.
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, msg, 2, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed digest.
        got_digest.assign(want_size, 0);

        // This test checks that the first gather list element
        // is skipped if it has a size of 0.
        msg[1] = msg[0];
        msg[0].list = nullptr;
        msg[0].count = 0;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->digest(
                          this->digest_ctx, alg, msg, 2, got_digest.data(), &got_digest_size));

        // Must result in the same digest as the first computation.
        N20_ASSERT_EQ(want_digest, got_digest);
    }
}

// This test checks that the digest function correctly concatenates multiple
// gather lists and computes the digest over the concatenated data.
TYPED_TEST_P(CryptoDigestFixture, DigestMultipleGatherLists) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t, size_t>;
    for (auto [n20_test_name, alg, want_size] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e, 28},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e, 32},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e, 48},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e, 64},
         }) {

        // This test checks that the digest function correctly concatenates multiple
        // gather lists and computes the digest over the concatenated data.
        n20_slice_t buffers1[2] = {
            {3, (uint8_t*)"foo"},
            {3, (uint8_t*)"bar"},
        };

        n20_slice_t buffers2[2] = {
            {0, (uint8_t*)"foo"},
            {0, (uint8_t*)"bar"},
        };

        n20_crypto_gather_list_t msg[2] = {
            {2, buffers1},  // First gather list with "foobar"
            {2, buffers2},  // Second gather list with empty slices
        };

        std::vector<uint8_t> got_digest(want_size);
        size_t got_size = want_size;

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->digest_ctx->digest(this->digest_ctx, alg, msg, 2, got_digest.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);

        auto want_digest = std::move(got_digest);
        got_digest.resize(want_size);

        // Now we change the second gather list to {"foo", "bar"}.
        // and the first to {"", ""}.
        buffers1[0].size = 0;
        buffers1[1].size = 0;
        buffers2[0].size = 3;
        buffers2[1].size = 3;

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->digest_ctx->digest(this->digest_ctx, alg, msg, 2, got_digest.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);

        // The digest must be the same as if we had concatenated the two gather lists.
        N20_ASSERT_EQ(want_digest, got_digest);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed digest.
        got_digest.assign(want_size, 0);

        // This test checks that the digest function correctly concatenates multiple
        // gather lists and computes the digest over the concatenated data.
        buffers2[0].size = 0;
        buffers1[0].size = 3;

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->digest_ctx->digest(this->digest_ctx, alg, msg, 2, got_digest.data(), &got_size));
        N20_ASSERT_EQ(want_size, got_size);

        // The digest must be the same as if we had concatenated the two gather lists.
        N20_ASSERT_EQ(want_digest, got_digest);
    }
}

TYPED_TEST_P(CryptoDigestFixture, HmacErrorsTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        n20_slice_t key = {0, nullptr};
        n20_crypto_gather_list_t msg = {1, nullptr};
        std::vector<uint8_t> buffer(80);
        size_t mac_size = buffer.size();

        // Invalid context
        N20_ASSERT_EQ(n20_error_crypto_invalid_context_e,
                      this->digest_ctx->hmac(nullptr, alg, key, nullptr, nullptr, nullptr));

        // Unexpected null size
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_size_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, nullptr, nullptr, nullptr));

        // Unknown algorithm
        N20_ASSERT_EQ(n20_error_crypto_unknown_algorithm_e,
                      this->digest_ctx->hmac(this->digest_ctx,
                                             (n20_crypto_digest_algorithm_t)-1,
                                             key,
                                             nullptr,
                                             nullptr,
                                             &mac_size));

        // Unexpected null slice key
        n20_slice_t bad_key = {4, nullptr};
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_key_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, bad_key, nullptr, nullptr, &mac_size));

        // Insufficient buffer size (mac_out is NULL)
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, nullptr, nullptr, &mac_size));

        // Insufficient buffer size (mac_size_in_out too small)
        mac_size = 4;
        std::vector<uint8_t> want_buffer = {0xde, 0xad, 0xbe, 0xef};
        std::vector<uint8_t> mac_buffer = want_buffer;
        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->digest_ctx->hmac(
                          this->digest_ctx, alg, key, nullptr, mac_buffer.data(), &mac_size));
        N20_ASSERT_EQ(want_buffer, mac_buffer);

        // Unexpected null data (msg_in is NULL, not querying size)
        mac_size = buffer.size();
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_data_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, nullptr, buffer.data(), &mac_size));

        // Unexpected null list
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_list_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, &msg, buffer.data(), &mac_size));

        // Unexpected null slice in gather list
        n20_slice_t msg_buffers[] = {{3, nullptr}};
        msg.list = msg_buffers;
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, &msg, buffer.data(), &mac_size));
    }
}

TYPED_TEST_P(CryptoDigestFixture, HmacSkipEmpty) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t, size_t>;
    for (auto [n20_test_name, alg, want_size] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e, 28},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e, 32},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e, 48},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e, 64},
         }) {

        uint8_t key_bytes[] = {'k', 'e', 'y'};
        n20_slice_t key = {sizeof key_bytes, key_bytes};

        uint8_t msg1[] = {'f', 'o', 'o'};
        uint8_t msg2[] = {'b', 'a', 'r'};

        std::vector<uint8_t> got_mac(want_size);
        size_t got_mac_size = want_size;

        // HMAC over "foobar" split as {"foo", "bar", ""}
        n20_slice_t buffers[3]{{sizeof msg1, msg1}, {sizeof msg2, msg2}, N20_SLICE_NULL};
        n20_crypto_gather_list_t msg = {3, buffers};

        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->hmac(
                          this->digest_ctx, alg, key, &msg, got_mac.data(), &got_mac_size));

        // Save the first result to compare it with the following computations.
        auto want_mac = std::move(got_mac);
        got_mac.resize(want_size);

        // Change gather list to {"foo", "", "bar"}
        buffers[2] = buffers[1];
        buffers[1] = N20_SLICE_NULL;

        got_mac_size = want_size;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->hmac(
                          this->digest_ctx, alg, key, &msg, got_mac.data(), &got_mac_size));
        N20_ASSERT_EQ(want_mac, got_mac);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed HMAC.
        got_mac.assign(want_size, 0);
        // Change gather list to {"", "foo", "bar"}
        buffers[1] = buffers[0];
        buffers[0] = N20_SLICE_NULL;

        got_mac_size = want_size;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->hmac(
                          this->digest_ctx, alg, key, &msg, got_mac.data(), &got_mac_size));
        N20_ASSERT_EQ(want_mac, got_mac);

        // Zero result buffer to make sure the function actually writes to
        // it and does not just return the previously computed HMAC.
        got_mac.assign(want_size, 0);

        // Test that buffer pointer is ignored if size is 0, even if not null
        buffers[0] = {0, (uint8_t*)"snafu"};

        got_mac_size = want_size;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->hmac(
                          this->digest_ctx, alg, key, &msg, got_mac.data(), &got_mac_size));
        N20_ASSERT_EQ(want_mac, got_mac);
    }
}

TYPED_TEST_P(CryptoDigestFixture, HmacBufferSizeTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t, size_t>;

    for (auto [n20_test_name, alg, want_size] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e, 28},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e, 32},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e, 48},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e, 64},
         }) {

        uint8_t key_bytes[] = {'k', 'e', 'y'};
        n20_slice_t key = {sizeof key_bytes, key_bytes};

        uint8_t msg_bytes[] = {'f', 'o', 'o', 'b', 'a', 'r'};
        n20_slice_t buffers[] = {{sizeof msg_bytes, msg_bytes}};
        n20_crypto_gather_list_t msg = {1, buffers};

        // Make the buffer larger than required.
        std::vector<uint8_t> mac(want_size + 4);
        size_t mac_size = want_size + 4;

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, &msg, mac.data(), &mac_size));
        // The output buffer must be truncated to the required size.
        N20_ASSERT_EQ(want_size, mac_size);

        mac_size -= 4;  // Make the buffer too small.
        mac.assign(want_size + 4, 0);

        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->hmac(this->digest_ctx, alg, key, &msg, mac.data(), &mac_size));
        // The output buffer must be set to the required size.
        N20_ASSERT_EQ(want_size, mac_size);
        // The output buffer remains unchanged.
        N20_ASSERT_EQ(std::vector<uint8_t>(want_size + 4, 0), mac);

        mac_size = 0;

        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->digest_ctx->hmac(this->digest_ctx, alg, key, &msg, nullptr, &mac_size));
        // The output buffer must be set to the required size.
        N20_ASSERT_EQ(want_size, mac_size);
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfErrorsTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        n20_slice_t ikm = {0, nullptr};
        n20_slice_t salt = {0, nullptr};
        n20_slice_t info = {0, nullptr};
        std::vector<uint8_t> buffer(80);

        // Invalid context
        N20_ASSERT_EQ(
            n20_error_crypto_invalid_context_e,
            this->digest_ctx->hkdf(nullptr, alg, ikm, salt, info, buffer.size(), buffer.data()));

        // Unknown algorithm
        N20_ASSERT_EQ(n20_error_crypto_unknown_algorithm_e,
                      this->digest_ctx->hkdf(this->digest_ctx,
                                             (n20_crypto_digest_algorithm_t)-1,
                                             ikm,
                                             salt,
                                             info,
                                             buffer.size(),
                                             buffer.data()));

        // Unexpected null slice ikm
        n20_slice_t bad_ikm = {4, nullptr};
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_ikm_e,
            this->digest_ctx->hkdf(
                this->digest_ctx, alg, bad_ikm, salt, info, buffer.size(), buffer.data()));

        // Unexpected null slice salt
        n20_slice_t bad_salt = {4, nullptr};
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_salt_e,
            this->digest_ctx->hkdf(
                this->digest_ctx, alg, ikm, bad_salt, info, buffer.size(), buffer.data()));

        // Unexpected null slice info
        n20_slice_t bad_info = {4, nullptr};
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_info_e,
            this->digest_ctx->hkdf(
                this->digest_ctx, alg, ikm, salt, bad_info, buffer.size(), buffer.data()));

        // Insufficient buffer size (key_out is NULL and key_octets_in != 0)
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->hkdf(this->digest_ctx, alg, ikm, salt, info, buffer.size(), nullptr));
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfExtractErrorsTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        n20_slice_t ikm = {0, nullptr};
        n20_slice_t salt = {0, nullptr};
        std::vector<uint8_t> buffer(80);
        size_t prk_size = buffer.size();

        // Invalid context
        N20_ASSERT_EQ(
            n20_error_crypto_invalid_context_e,
            this->digest_ctx->hkdf_extract(nullptr, alg, ikm, salt, buffer.data(), &prk_size));

        // Unknown algorithm
        N20_ASSERT_EQ(n20_error_crypto_unknown_algorithm_e,
                      this->digest_ctx->hkdf_extract(this->digest_ctx,
                                                     (n20_crypto_digest_algorithm_t)-1,
                                                     ikm,
                                                     salt,
                                                     buffer.data(),
                                                     &prk_size));

        // Unexpected null slice ikm
        n20_slice_t bad_ikm = {4, nullptr};
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_slice_ikm_e,
                      this->digest_ctx->hkdf_extract(
                          this->digest_ctx, alg, bad_ikm, salt, buffer.data(), &prk_size));

        // Unexpected null slice salt
        n20_slice_t bad_salt = {4, nullptr};
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_slice_salt_e,
                      this->digest_ctx->hkdf_extract(
                          this->digest_ctx, alg, ikm, bad_salt, buffer.data(), &prk_size));

        // Insufficient buffer size (prk_out is NULL)
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->hkdf_extract(this->digest_ctx, alg, ikm, salt, nullptr, &prk_size));

        // Insufficient buffer size (prk_size_in_out too small)
        prk_size = 4;
        std::vector<uint8_t> want_buffer = {0xde, 0xad, 0xbe, 0xef};
        std::vector<uint8_t> prk_buffer = want_buffer;
        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->digest_ctx->hkdf_extract(
                          this->digest_ctx, alg, ikm, salt, prk_buffer.data(), &prk_size));
        N20_ASSERT_EQ(want_buffer, prk_buffer);
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfExtractBufferSizeTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t, size_t>;

    for (auto [n20_test_name, alg, want_size] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e, 28},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e, 32},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e, 48},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e, 64},
         }) {

        uint8_t key_bytes[] = {'k', 'e', 'y'};
        n20_slice_t key = {sizeof key_bytes, key_bytes};

        uint8_t salt_bytes[] = {'f', 'o', 'o', 'b', 'a', 'r'};
        n20_slice_t salt = {sizeof salt_bytes, salt_bytes};

        // Make the buffer larger than required.
        std::vector<uint8_t> prk(want_size + 4);
        size_t prk_size = want_size + 4;

        N20_ASSERT_EQ(n20_error_ok_e,
                      this->digest_ctx->hkdf_extract(
                          this->digest_ctx, alg, key, salt, prk.data(), &prk_size));
        // The output buffer must be truncated to the required size.
        N20_ASSERT_EQ(want_size, prk_size);

        prk_size -= 4;  // Make the buffer too small.
        prk.assign(want_size + 4, 0);

        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->digest_ctx->hkdf_extract(
                          this->digest_ctx, alg, key, salt, prk.data(), &prk_size));
        // The output buffer must be set to the required size.
        N20_ASSERT_EQ(want_size, prk_size);
        // The output buffer remains unchanged.
        N20_ASSERT_EQ(std::vector<uint8_t>(want_size + 4, 0), prk);

        prk_size = 0;

        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->digest_ctx->hkdf_extract(this->digest_ctx, alg, key, salt, nullptr, &prk_size));
        // The output buffer must be set to the required size.
        N20_ASSERT_EQ(want_size, prk_size);
    }
}

TYPED_TEST_P(CryptoDigestFixture, HkdfExpandErrorsTest) {
    using tc = std::tuple<std::string, n20_crypto_digest_algorithm_t>;
    for (auto [n20_test_name, alg] : {
             tc{"sha224", n20_crypto_digest_algorithm_sha2_224_e},
             tc{"sha256", n20_crypto_digest_algorithm_sha2_256_e},
             tc{"sha384", n20_crypto_digest_algorithm_sha2_384_e},
             tc{"sha512", n20_crypto_digest_algorithm_sha2_512_e},
         }) {
        n20_slice_t prk = {0, nullptr};
        n20_slice_t info = {0, nullptr};
        std::vector<uint8_t> buffer(80);

        // Invalid context
        N20_ASSERT_EQ(
            n20_error_crypto_invalid_context_e,
            this->digest_ctx->hkdf_expand(nullptr, alg, prk, info, buffer.size(), buffer.data()));

        // Unknown algorithm
        N20_ASSERT_EQ(n20_error_crypto_unknown_algorithm_e,
                      this->digest_ctx->hkdf_expand(this->digest_ctx,
                                                    (n20_crypto_digest_algorithm_t)-1,
                                                    prk,
                                                    info,
                                                    buffer.size(),
                                                    buffer.data()));

        // Unexpected null slice prk
        n20_slice_t bad_prk = {4, nullptr};
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_slice_prk_e,
                      this->digest_ctx->hkdf_expand(
                          this->digest_ctx, alg, bad_prk, info, buffer.size(), buffer.data()));

        // Unexpected null slice info
        n20_slice_t bad_info = {4, nullptr};
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_slice_info_e,
                      this->digest_ctx->hkdf_expand(
                          this->digest_ctx, alg, prk, bad_info, buffer.size(), buffer.data()));

        // Insufficient buffer size (key_out is NULL and key_octets_in != 0)
        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->digest_ctx->hkdf_expand(
                          this->digest_ctx, alg, prk, info, buffer.size(), nullptr));
    }
}

static std::vector<uint8_t> signature_2_asn1_sequence(std::vector<uint8_t> const& sig) {
    size_t integer_size = sig.size() / 2;

    uint8_t buffer[104];
    n20_stream_t s;
    n20_stream_init(&s, &buffer[0], 104);

    auto mark = n20_stream_byte_count(&s);
    // Write S
    n20_asn1_integer(
        &s, sig.data() + integer_size, integer_size, false, false, n20_asn1_tag_info_no_override());
    // Write R
    n20_asn1_integer(&s, sig.data(), integer_size, false, false, n20_asn1_tag_info_no_override());

    n20_asn1_header(&s,
                    N20_ASN1_CLASS_UNIVERSAL,
                    /*constructed=*/true,
                    N20_ASN1_TAG_SEQUENCE,
                    n20_stream_byte_count(&s) - mark);

    EXPECT_FALSE(n20_stream_has_buffer_overflow(&s));
    return std::vector<uint8_t>(n20_stream_data(&s),
                                n20_stream_data(&s) + n20_stream_byte_count(&s));
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
        auto ec_key = EVP_PKEY_get0_EC_KEY(key.get());
        if (ec_key == nullptr) {
            ADD_FAILURE();
            return false;
        }
        auto ec_group = EC_KEY_get0_group(ec_key);
        if (ec_group == nullptr) {
            ADD_FAILURE();
            return false;
        }
        auto ec_curve_nid = EC_GROUP_get_curve_name(ec_group);

        EVP_MD const* md = nullptr;
        if (ec_curve_nid == NID_X9_62_prime256v1) {
            md = EVP_sha256();
        } else {
            md = EVP_sha384();
        }

        if (1 != EVP_DigestVerifyInit(md_ctx.get(), NULL, md, NULL, key.get())) {
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
// For each key type it performs three key derivations. The first two are
// derived using the same context. These keys are used for signing and
// verification respectively. If the key derivation is in deed deterministic.
// signatures issued with the first key must verify against the public key of
// the second.
// The third key uses a different context. The signature generated with this
// key must not verify against the second.
TYPED_TEST_P(CryptoTestFixture, KDFTest) {
    using tc = std::tuple<std::string, n20_crypto_key_type_t>;
    for (auto [n20_test_name, key_type] : {
             tc{"ed25519", n20_crypto_key_type_ed25519_e},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e},
         }) {

        n20_slice_t context_buffers[] = {
            {15, (uint8_t*)"this context is "},
            {4, (uint8_t*)"not "},
            {10, (uint8_t*)"the other"},
        };

        n20_crypto_gather_list_t context = {3, context_buffers};

        // Derive two keys using the same context.
        // The implementation must generate the same key.
        // So we use one for signing and the other for verification.
        // If the signature verifies successfully we can be reasonably
        // certain that the derived keys were indeed the same.
        n20_crypto_key_t derived_key_sign;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, &context, &derived_key_sign));

        n20_crypto_key_t derived_key_verify;
        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->ctx->kdf(this->ctx, this->cdi, key_type, &context, &derived_key_verify));

        // ##### Sign the message. #########
        n20_slice_t message_buffers[] = {
            {10, (uint8_t*)"my message"},
        };
        n20_crypto_gather_list_t message = {1, message_buffers};

        // Get the maximal signature size and allocate the buffer.
        size_t sig_size = 0;
        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->ctx->sign(this->ctx, derived_key_sign, &message, nullptr, &sig_size));
        std::vector<uint8_t> signature(sig_size);

        // Do the actual signing.
        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->ctx->sign(this->ctx, derived_key_sign, &message, signature.data(), &sig_size));
        N20_ASSERT_LE(sig_size, signature.size());
        signature.resize(sig_size);

        // ##### Sign the message with another key #########

        // Derive a different key for a negative check.
        // This turns the context into "this context is the other".
        context_buffers[1].size = 0;
        n20_crypto_key_t derived_key_other;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, &context, &derived_key_other));

        // 96 is large enough for all implemented algorithms. So
        // no need to do the query dance again.
        sig_size = 96;
        std::vector<uint8_t> other_signature(sig_size);
        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->ctx->sign(
                this->ctx, derived_key_other, &message, other_signature.data(), &sig_size));
        N20_ASSERT_LE(sig_size, other_signature.size());
        other_signature.resize(sig_size);

        // ###### Verification ##########

        // Now get the public key from derived_key_verify.
        size_t pub_key_size = 0;
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->ctx->key_get_public_key(this->ctx, derived_key_verify, nullptr, &pub_key_size));
        std::vector<uint8_t> pub_key(pub_key_size);
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->ctx->key_get_public_key(
                          this->ctx, derived_key_verify, pub_key.data(), &pub_key_size));
        N20_ASSERT_EQ(pub_key.size(), pub_key_size);
        EVP_PKEY_PTR_t evp_pub_key;
        if (key_type == n20_crypto_key_type_ed25519_e) {
            evp_pub_key = EVP_PKEY_PTR_t(EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519, nullptr, pub_key.data(), pub_key.size()));
            N20_ASSERT_TRUE(!!evp_pub_key);
        } else {
            // The nat20 crypto library always returns an uncompressed point
            // as public key. But boringssl expects the uncompressed header byte
            // 0x04 to be prefixed to this point representation.
            pub_key.insert(pub_key.begin(), 0x04);
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
        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, derived_key_sign));
        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, derived_key_verify));
        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, derived_key_other));
    }
}

TYPED_TEST_P(CryptoTestFixture, KDFErrorsTest) {
    using tc = std::tuple<std::string, n20_crypto_key_type_t>;
    for (auto [n20_test_name, key_type] : {
             tc{"cdi", n20_crypto_key_type_cdi_e},
             tc{"ed25519", n20_crypto_key_type_ed25519_e},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e},
         }) {

        N20_ASSERT_EQ(n20_error_crypto_invalid_context_e,
                      this->ctx->kdf(nullptr, nullptr, key_type, nullptr, nullptr));

        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_key_in_e,
                      this->ctx->kdf(this->ctx, nullptr, key_type, nullptr, nullptr));

        // Derive each key type that would be ineligible to derive a key from
        // and use it as `key_in` for the KDF. The kdf must diagnose it
        // as n20_error_crypto_invalid_key_e.
        n20_slice_t context_buffers[] = {
            {3, (uint8_t*)"foo"},
        };
        n20_crypto_gather_list_t context = {1, context_buffers};
        n20_crypto_key_t invalid_key = nullptr;
        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->ctx->kdf(
                this->ctx, this->cdi, n20_crypto_key_type_ed25519_e, &context, &invalid_key));
        N20_ASSERT_EQ(n20_error_crypto_invalid_key_e,
                      this->ctx->kdf(this->ctx, invalid_key, key_type, nullptr, nullptr));
        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, invalid_key));

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->ctx->kdf(
                this->ctx, this->cdi, n20_crypto_key_type_secp256r1_e, &context, &invalid_key));
        N20_ASSERT_EQ(n20_error_crypto_invalid_key_e,
                      this->ctx->kdf(this->ctx, invalid_key, key_type, nullptr, nullptr));
        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, invalid_key));

        N20_ASSERT_EQ(
            n20_error_ok_e,
            this->ctx->kdf(
                this->ctx, this->cdi, n20_crypto_key_type_secp384r1_e, &context, &invalid_key));
        N20_ASSERT_EQ(n20_error_crypto_invalid_key_e,
                      this->ctx->kdf(this->ctx, invalid_key, key_type, nullptr, nullptr));
        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, invalid_key));

        // Must return n20_error_crypto_unexpected_null_key_out_e if no buffer is
        // given to return the derived key.
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_key_out_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, nullptr, nullptr));

        n20_crypto_key_t key_out = nullptr;
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_data_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, nullptr, &key_out));

        // Must return n20_error_crypto_unexpected_null_list_e if the gather list
        // pointer is NULL.
        n20_crypto_gather_list_t invalid_context = {1, nullptr};
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_list_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, &invalid_context, &key_out));

        n20_slice_t invalid_context_buffers[] = {
            {3, nullptr},
        };
        invalid_context.list = invalid_context_buffers;
        N20_ASSERT_EQ(n20_error_crypto_unexpected_null_slice_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, &invalid_context, &key_out));
    }

    n20_crypto_key_t out_key = nullptr;
    n20_slice_t context_buffers[] = {
        {3, (uint8_t*)"foo"},
    };
    n20_crypto_gather_list_t context = {1, context_buffers};

    ASSERT_EQ(n20_error_crypto_invalid_key_type_e,
              this->ctx->kdf(this->ctx, this->cdi, (n20_crypto_key_type_t)-1, &context, &out_key));
}

TYPED_TEST_P(CryptoTestFixture, SignErrorsTest) {
    ASSERT_EQ(n20_error_crypto_invalid_context_e,
              this->ctx->sign(nullptr, nullptr, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_error_crypto_unexpected_null_key_in_e,
              this->ctx->sign(this->ctx, nullptr, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_error_crypto_unexpected_null_size_e,
              this->ctx->sign(this->ctx, this->cdi, nullptr, nullptr, nullptr));

    size_t signature_size = 0;
    ASSERT_EQ(n20_error_crypto_invalid_key_e,
              this->ctx->sign(this->ctx, this->cdi, nullptr, nullptr, &signature_size));

    using tc = std::tuple<std::string, n20_crypto_key_type_t, size_t>;
    for (auto [n20_test_name, key_type, want_signature_size] : {
             tc{"ed25519", n20_crypto_key_type_ed25519_e, 64},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e, 64},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e, 96},
         }) {

        n20_slice_t context_buffers[] = {
            {19, (uint8_t*)"sign error test key"},
        };
        n20_crypto_gather_list_t context = {1, context_buffers};
        n20_crypto_key_t signing_key = nullptr;
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, &context, &signing_key));

        // Must return n20_error_crypto_insufficient_buffer_size_e if out buffer is NULL.
        signature_size = 30000;
        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->ctx->sign(this->ctx, signing_key, nullptr, nullptr, &signature_size));

        // Must return the correct expected signature size.
        N20_ASSERT_EQ(want_signature_size, signature_size);

        // Must return n20_error_crypto_insufficient_buffer_size_e if buffer given but
        // size is too small.
        uint8_t signature_buffer[104];
        signature_size = want_signature_size - 1;
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->ctx->sign(this->ctx, signing_key, nullptr, signature_buffer, &signature_size));

        // Must return the correct expected signature size.
        N20_ASSERT_EQ(want_signature_size, signature_size);

        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_data_e,
            this->ctx->sign(this->ctx, signing_key, nullptr, signature_buffer, &signature_size));

        n20_crypto_gather_list_t message = {1, nullptr};
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_list_e,
            this->ctx->sign(this->ctx, signing_key, &message, signature_buffer, &signature_size));

        n20_slice_t msg_buffers[] = {{5, nullptr}};
        message.list = msg_buffers;
        N20_ASSERT_EQ(
            n20_error_crypto_unexpected_null_slice_e,
            this->ctx->sign(this->ctx, signing_key, &message, signature_buffer, &signature_size));
    }
}

TYPED_TEST_P(CryptoTestFixture, GetPublicKeyErrorsTest) {
    ASSERT_EQ(n20_error_crypto_invalid_context_e,
              this->ctx->key_get_public_key(nullptr, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_error_crypto_unexpected_null_key_in_e,
              this->ctx->key_get_public_key(this->ctx, nullptr, nullptr, nullptr));

    ASSERT_EQ(n20_error_crypto_unexpected_null_size_e,
              this->ctx->key_get_public_key(this->ctx, this->cdi, nullptr, nullptr));

    size_t public_key_size = 0;
    ASSERT_EQ(n20_error_crypto_invalid_key_e,
              this->ctx->key_get_public_key(this->ctx, this->cdi, nullptr, &public_key_size));

    using tc = std::tuple<std::string, n20_crypto_key_type_t, size_t>;
    for (auto [n20_test_name, key_type, want_key_size] : {
             tc{"ed25519", n20_crypto_key_type_ed25519_e, 32},
             tc{"secp256r1", n20_crypto_key_type_secp256r1_e, 64},
             tc{"secp384r1", n20_crypto_key_type_secp384r1_e, 96},
         }) {

        n20_crypto_key_t key = nullptr;
        char const context_str[] = "public key errors test context";
        n20_slice_t context_buffers[] = {sizeof(context_str) - 1, (uint8_t* const)&context_str[0]};
        n20_crypto_gather_list_t context = {1, context_buffers};
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->ctx->kdf(this->ctx, this->cdi, key_type, &context, &key));

        // Must return n20_error_crypto_insufficient_buffer_size_e if public_key_out
        // is nullptr.
        public_key_size = 100;
        N20_ASSERT_EQ(n20_error_crypto_insufficient_buffer_size_e,
                      this->ctx->key_get_public_key(this->ctx, key, nullptr, &public_key_size));
        // If n20_error_crypto_insufficient_buffer_size_e was returned public_key_size
        // must contain the correct maximal required buffer size.
        N20_ASSERT_EQ(want_key_size, public_key_size);

        // Must return n20_error_crypto_insufficient_buffer_size_e if
        // *public_key_size_in_out is too small even if a buffer was given.
        public_key_size = want_key_size - 1;
        uint8_t public_key_buffer[100];
        N20_ASSERT_EQ(
            n20_error_crypto_insufficient_buffer_size_e,
            this->ctx->key_get_public_key(this->ctx, key, public_key_buffer, &public_key_size));

        // If n20_error_crypto_insufficient_buffer_size_e was returned public_key_size
        // must contain the correct maximal required buffer size.
        N20_ASSERT_EQ(want_key_size, public_key_size);

        // Must return n20_error_ok_e if the the buffer size is sufficient.
        uint8_t large_public_key_buffer[256];
        public_key_size = sizeof(large_public_key_buffer);
        N20_ASSERT_EQ(n20_error_ok_e,
                      this->ctx->key_get_public_key(
                          this->ctx, key, large_public_key_buffer, &public_key_size));

        // If n20_error_ok_e was returned public_key_size must contain the correct maximal
        // required buffer size.
        N20_ASSERT_EQ(want_key_size, public_key_size);

        N20_ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, key));
    }
}

TYPED_TEST_P(CryptoTestFixture, KeyFreeErrorsTest) {
    ASSERT_EQ(n20_error_crypto_invalid_context_e, this->ctx->key_free(nullptr, nullptr));
    ASSERT_EQ(n20_error_ok_e, this->ctx->key_free(this->ctx, nullptr));
}

REGISTER_TYPED_TEST_SUITE_P(CryptoDigestFixture,
                            DigestBufferSizeTest,
                            DigestErrorsTest,
                            DigestSkipEmpty,
                            DigestMultipleGatherLists,
                            SHA2TestVectorTest,
                            HmacTest,
                            HkdfTest,
                            HkdfExtractTest,
                            HkdfExpandTest,
                            HmacErrorsTest,
                            HmacSkipEmpty,
                            HmacBufferSizeTest,
                            HkdfErrorsTest,
                            HkdfExtractErrorsTest,
                            HkdfExtractBufferSizeTest,
                            HkdfExpandErrorsTest);

REGISTER_TYPED_TEST_SUITE_P(CryptoTestFixture,
                            OpenClose,
                            KDFTest,
                            KDFErrorsTest,
                            SignErrorsTest,
                            GetPublicKeyErrorsTest,
                            KeyFreeErrorsTest);

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(CryptoDigestFixture);
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(CryptoTestFixture);

using DigestCryptoImplementationsToTest =
    ConcatenateTestLists<FullCryptoImplementationsToTest,
                         DigestOnlyCryptoImplementationsToTest>::type;

#ifdef N20_CONFIG_ENABLE_CRYPTO_TEST_IMPL

INSTANTIATE_TYPED_TEST_SUITE_P(CryptoTest, CryptoTestFixture, FullCryptoImplementationsToTest);

INSTANTIATE_TYPED_TEST_SUITE_P(DigestCryptoTest,
                               CryptoDigestFixture,
                               DigestCryptoImplementationsToTest);

#endif
