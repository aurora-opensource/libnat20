/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
 *
 * This work is dual licensed.
 * You may use it under Apache-2.0 or GPL-2.0 at your option.
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
 *
 * OR
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#include <gtest/gtest.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/oid.h>
#include <nat20/open_dice.h>
#include <nat20/testing/test_bssl_utils.h>
#include <nat20/testing/test_utils.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <type_traits>

#include "nat20/constants.h"
#include "test_vectors.h"

uint8_t const test_cdi[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};

/* Test code "hash" 32 repetitions of 0x0c */
std::vector<uint8_t> const TEST_CODE_HASH = {
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
};

/* Test authority "hash" 32 repetitions of 0x1a */
std::vector<uint8_t> const TEST_AUTHORITY_HASH = {
    0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10,
    0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10, 0x1a, 0x1a, 0x1a, 0x10,
};

/* Test configuration "hash" 32 repetitions of 0x2d */
std::vector<uint8_t> const TEST_CONFIGURATION_HASH = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
};

std::vector<uint8_t> const TEST_CODE_DESCRIPTOR = {
    'C', 'o', 'd', 'e', ' ', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r'};

std::vector<uint8_t> const TEST_CONFIGURATION_DESCRIPTOR = {
    'C', 'o', 'n', 'f', 'i', 'g', ' ', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r'};

std::vector<uint8_t> const TEST_AUTHORITY_DESCRIPTOR = {'A', 'u', 't', 'h', 'o', 'r', 'i',
                                                        't', 'y', ' ', 'D', 'e', 's', 'c',
                                                        'r', 'i', 'p', 't', 'o', 'r'};

/* Test hidden data 32 repetitions of  0x04 */
std::vector<uint8_t> const TEST_HIDDEN = {
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
};

std::vector<uint8_t> const TEST_NONCE = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
};

n20_slice_t vec2slice(std::vector<uint8_t> const& vec) {
    return n20_slice_t{.size = vec.size(), .buffer = vec.data()};
}

n20_open_dice_input_t const TEST_OPEN_DICE_INPUT = {
    .code_hash = vec2slice(TEST_CODE_HASH),
    .code_descriptor = vec2slice(TEST_CODE_DESCRIPTOR),
    .configuration_hash = vec2slice(TEST_CONFIGURATION_HASH),
    .configuration_descriptor = vec2slice(TEST_CONFIGURATION_DESCRIPTOR),
    .authority_hash = vec2slice(TEST_AUTHORITY_HASH),
    .authority_descriptor = vec2slice(TEST_AUTHORITY_DESCRIPTOR),
    .mode = n20_open_dice_mode_normal_e,
    .profile_name = N20_STR_C("OpenDICE"),
    .hidden = vec2slice(TEST_HIDDEN),
};

// Implement container_of macro
#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))

struct BsslTestFixtureCryptoContext : public n20_crypto_context_t {
    template <typename T>
    static T* GetTestContext(n20_crypto_context_t* ctx) {
        return reinterpret_cast<T*>(reinterpret_cast<BsslTestFixtureCryptoContext*>(ctx)->test_ctx);
    }

    template <typename T>
    static T* GetTestContext(n20_crypto_digest_context_t* ctx) {
        n20_crypto_context_t* base_ctx = container_of(ctx, n20_crypto_context_t, digest_ctx);
        return GetTestContext<T>(base_ctx);
    }

    BsslTestFixtureCryptoContext() {
        memset(this, 0, sizeof(n20_crypto_context_t));
        PatchFunctions();
    }

    BsslTestFixtureCryptoContext(n20_crypto_context_t const& ctx) {
        memcpy(this, &ctx, sizeof(n20_crypto_context_t));
        PatchFunctions();
    }

    BsslTestFixtureCryptoContext& operator=(n20_crypto_context_t const& ctx) {
        memcpy(this, &ctx, sizeof(n20_crypto_context_t));
        PatchFunctions();
        return *this;
    }

    void PatchFunctions() {
        backup.kdf = this->kdf;

        this->kdf = [](n20_crypto_context_t* ctx,
                       n20_crypto_key_t key_in,
                       n20_crypto_key_type_t key_type,
                       n20_crypto_gather_list_t const* context_in,
                       n20_crypto_key_t* key_out) -> n20_error_t {
            BsslTestFixtureCryptoContext* bctx =
                reinterpret_cast<BsslTestFixtureCryptoContext*>(ctx);
            n20_error_t err = bctx->backup.kdf(ctx, key_in, key_type, context_in, key_out);
            if (err == n20_error_ok_e) {
                bctx->active_key_handles++;
                bctx->max_active_key_handles =
                    std::max(bctx->max_active_key_handles, bctx->active_key_handles);
            }
            return err;
        };

        backup.key_free = this->key_free;
        this->key_free = [](n20_crypto_context_t* ctx, n20_crypto_key_t key) -> n20_error_t {
            BsslTestFixtureCryptoContext* bctx =
                reinterpret_cast<BsslTestFixtureCryptoContext*>(ctx);
            n20_error_t err = bctx->backup.key_free(ctx, key);
            if (err == n20_error_ok_e) {
                bctx->active_key_handles--;
            }
            return err;
        };
    }

    n20_crypto_context_t backup;
    void* test_ctx = nullptr;
    size_t active_key_handles = 0;
    size_t max_active_key_handles = 0;
};
class BsslTestFixtureBase : public ::testing::Test {
   private:
    n20_crypto_context_t* private_crypto_ctx = nullptr;
    BsslTestFixtureCryptoContext crypto_ctx_copy = {};

   protected:
    BsslTestFixtureCryptoContext* crypto_ctx;

    void SetUp() override {
        EXPECT_EQ(n20_error_ok_e, n20_crypto_boringssl_open(&private_crypto_ctx));
        crypto_ctx_copy = *private_crypto_ctx;
        crypto_ctx = &crypto_ctx_copy;
    }

    void TearDown() override {
        EXPECT_EQ(n20_error_ok_e, n20_crypto_boringssl_close(private_crypto_ctx));
        EXPECT_EQ(0, crypto_ctx->active_key_handles) << "There are leaked key handles";
        EXPECT_GE(3, crypto_ctx->max_active_key_handles)
            << "There should never be more than 3 active key handles at any time";
    }

    void SetTestContext(void* ctx) { crypto_ctx->test_ctx = ctx; }

   public:
    n20_crypto_key_t GetCdi() {
        n20_slice_t cdi_slice = {sizeof(test_cdi), &test_cdi[0]};
        n20_crypto_key_t cdi_key = nullptr;
        auto err = n20_crypto_boringssl_make_secret(private_crypto_ctx, &cdi_slice, &cdi_key);
        EXPECT_EQ(err, n20_error_ok_e);
        if (err == n20_error_ok_e) {
            crypto_ctx->active_key_handles++;
            crypto_ctx->max_active_key_handles =
                std::max(crypto_ctx->max_active_key_handles, crypto_ctx->active_key_handles);
        }
        return cdi_key;
    }
};

// Test fixture
class FunctionalityX509Test
    : public BsslTestFixtureBase,
      public ::testing::WithParamInterface<std::tuple<std::string,
                                                      n20_crypto_key_type_t,
                                                      n20_crypto_key_type_t,
                                                      n20_cert_type_t,
                                                      std::vector<uint8_t>>> {};

INSTANTIATE_TEST_SUITE_P(FunctionalityTestInstance,
                         FunctionalityX509Test,
                         ::testing::ValuesIn(x509_test_vectors),
                         [](testing::TestParamInfo<FunctionalityX509Test::ParamType> const& info) {
                             return std::get<0>(info.param);
                         });

template <typename T, typename F>
std::unique_ptr<T, F> make_unique_ptr(T* ptr, F deleter) {
    return std::unique_ptr<std::remove_reference_t<T>, F>(ptr, deleter);
}

#define KEY_HANDLE_GUARD(key) \
    auto key##_guard =        \
        make_unique_ptr(key, [this](void* k) { crypto_ctx->key_free(crypto_ctx, k); });

TEST_P(FunctionalityX509Test, IssueX509CertificateTest) {
    auto [test_name, issuer_key_type, subject_key_type, cert_type, want_cert] = GetParam();

    auto key_deleter = [this](void* key) { crypto_ctx->key_free(crypto_ctx, key); };

    // Get the root CDI from the crypto backend.
    n20_crypto_key_t issuer_secret = this->GetCdi();
    KEY_HANDLE_GUARD(issuer_secret);

    // Assemble certificate info.

    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = cert_type;
    switch (cert_info.cert_type) {
        case n20_cert_type_self_signed_e:
            break;
        case n20_cert_type_cdi_e:
            cert_info.open_dice_input = TEST_OPEN_DICE_INPUT;
            break;
        case n20_cert_type_eca_e:
            cert_info.eca.nonce = vec2slice(TEST_NONCE);
            break;
        case n20_cert_type_eca_ee_e:
            cert_info.eca_ee.nonce = vec2slice(TEST_NONCE);
            cert_info.eca_ee.name = N20_STR_C("Test EE");
            break;
        default:
            GTEST_FAIL() << "Unsupported certificate type: " << cert_info.cert_type;
            return;
    }
    uint8_t certificate[2048] = {};
    size_t certificate_size = sizeof(certificate);

    ASSERT_EQ(n20_error_ok_e,
              n20_issue_certificate(crypto_ctx,
                                    issuer_secret,
                                    issuer_key_type,
                                    subject_key_type,
                                    &cert_info,
                                    n20_certificate_format_x509_e,
                                    certificate,
                                    &certificate_size))
        << "Expected buffer size: " << certificate_size;

    auto got_cert = std::vector<uint8_t>(&certificate[sizeof(certificate) - certificate_size],
                                         &certificate[sizeof(certificate)]);

    // Currently we are using ECDSA with random nonce (k) for signing with
    // secp256r1 and secp384r1 keys, so the signature will not match the
    // one in the test vectors.
    // We can only compare the certificate content without the signature
    // in these cases. For ed25519, the signature is deterministic
    // and will match the one in the test vectors.
    // The test vectors for secp256r1 and secp384r1 are truncated right
    // before the signature bitstring header.
    auto comp_got_cert = got_cert;

    if (issuer_key_type == n20_crypto_key_type_secp256r1_e ||
        issuer_key_type == n20_crypto_key_type_secp384r1_e) {
        comp_got_cert.resize(got_cert.size() > want_cert.size() ? want_cert.size()
                                                                : got_cert.size());
        // In the case of X.509 certificates we also have to adjust the
        // length in the sequence header, because the signature length
        // is not deterministic either.
        if (want_cert.size() > 3 && comp_got_cert.size() > 3) {
            comp_got_cert[3] = want_cert[3];
        }
    }

    ASSERT_EQ(want_cert, comp_got_cert)
        << hexdump_side_by_side("Expected:", want_cert, "Got:", got_cert) << hex(got_cert);
    ASSERT_EQ(want_cert.size(), comp_got_cert.size());

    // Check the signature on the certificate.
    // Derive the issuer key.
    n20_crypto_key_t issuer_key = nullptr;
    ASSERT_NE(issuer_secret, nullptr);

    if (cert_type == n20_cert_type_eca_ee_e) {
        ASSERT_EQ(n20_error_ok_e,
                  n20_derive_eca_key(crypto_ctx, issuer_secret, &issuer_key, issuer_key_type));
        ASSERT_NE(issuer_key, nullptr);

    } else {
        ASSERT_EQ(n20_error_ok_e,
                  n20_derive_cdi_attestation_key(
                      crypto_ctx, issuer_secret, &issuer_key, issuer_key_type));
        ASSERT_NE(issuer_key, nullptr);
    }
    KEY_HANDLE_GUARD(issuer_key);

    size_t public_key_size = 0;
    crypto_ctx->key_get_public_key(crypto_ctx, issuer_key, nullptr, &public_key_size);

    std::vector<uint8_t> public_key_buffer(public_key_size + 1);
    uint8_t* public_key = public_key_buffer.data() + 1;
    crypto_ctx->key_get_public_key(crypto_ctx, issuer_key, public_key, &public_key_size);

    if (issuer_key_type == n20_crypto_key_type_secp256r1_e ||
        issuer_key_type == n20_crypto_key_type_secp384r1_e) {
        public_key_buffer[0] = 0x04;
        public_key = public_key_buffer.data();
        public_key_size += 1;
    }

    uint8_t const* p = got_cert.data();
    auto x509i = X509_PTR_t(d2i_X509(nullptr, &p, got_cert.size()));
    ASSERT_TRUE(!!x509i) << BsslError();
    X509_print_ex_fp(stdout, x509i.get(), 0, X509V3_EXT_DUMP_UNKNOWN);

    auto key = n20_crypto_key_to_evp_pkey_ptr(issuer_key_type, public_key, public_key_size);
    auto rc = X509_verify(x509i.get(), key.get());
    ASSERT_EQ(rc, 1) << BsslError();
}

extern "C" n20_error_t n20_issue_x509_cert(n20_open_dice_cert_info_t const* cert_info,
                                           n20_signer_t* signer,
                                           n20_crypto_key_type_t issuer_key_type,
                                           uint8_t* certificate,
                                           size_t* certificate_size);

TEST_F(FunctionalityX509Test, IssueX509CertificateUnsupportedCertificateType) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = (n20_cert_type_t)0xFF;
    uint8_t certificate[2048] = {};
    size_t certificate_size = sizeof(certificate);

    n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    ASSERT_EQ(
        n20_error_unsupported_certificate_type_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));
}

TEST_F(FunctionalityX509Test, IssueX509CertificateInvalidIssuerKeyType) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    uint8_t certificate[2048] = {};
    size_t certificate_size = sizeof(certificate);

    n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    ASSERT_EQ(
        n20_error_crypto_invalid_key_type_e,
        n20_issue_x509_cert(
            &cert_info, &signer, (n20_crypto_key_type_t)0xff, certificate, &certificate_size));
}

TEST_F(FunctionalityX509Test, IssueX509CertificateInvalidSubjectKeyType) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.subject_public_key.algorithm = (n20_crypto_key_type_t)0xFF;
    uint8_t certificate[2048] = {};
    size_t certificate_size = sizeof(certificate);

    n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    ASSERT_EQ(
        n20_error_crypto_invalid_key_type_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));
}

TEST_F(FunctionalityX509Test, IssueX509CertificateInvalidInsufficientBufferSize) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.subject_public_key.algorithm = n20_crypto_key_type_ed25519_e;
    uint8_t certificate[12] = {};
    size_t certificate_size = 12;

    n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    ASSERT_EQ(
        n20_error_insufficient_buffer_size_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));
}

TEST_F(FunctionalityX509Test, IssueX509CertificateInvalidWritePositionOverflow) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.subject_public_key.algorithm = n20_crypto_key_type_ed25519_e;
    cert_info.open_dice_input.configuration_hash.buffer = (uint8_t*)1;
    cert_info.open_dice_input.configuration_hash.size = SIZE_MAX;  // Will cause overflow
    uint8_t certificate[12] = {};
    size_t certificate_size = 12;

    n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    ASSERT_EQ(
        n20_error_write_position_overflow_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));
}

TEST_F(FunctionalityX509Test, IssueX509CertificateInvalidWriteSignerError) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.subject_public_key.algorithm = n20_crypto_key_type_ed25519_e;
    // The lambda below cannot capture this because it needs to have C linkage.
    // So we use a static variable with appropriate prefix so as not to clash
    // with other tests.
    static uint8_t IssueX509CertificateInvalidWriteSignerError_certificate[2000] = {};
    size_t certificate_size = sizeof(IssueX509CertificateInvalidWriteSignerError_certificate);

    static n20_signer_t IssueX509CertificateInvalidWriteSignerError_signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    auto signer_cb = [](void* ctx, n20_slice_t tbs, uint8_t* signature, size_t* signature_size) {
        EXPECT_EQ((uintptr_t)&IssueX509CertificateInvalidWriteSignerError_signer, (uintptr_t)ctx);
        EXPECT_GT(tbs.size, 0);
        EXPECT_GE(tbs.buffer, &IssueX509CertificateInvalidWriteSignerError_certificate[0]);
        EXPECT_LT(tbs.buffer,
                  &IssueX509CertificateInvalidWriteSignerError_certificate[sizeof(
                      IssueX509CertificateInvalidWriteSignerError_certificate)]);
        return n20_error_crypto_implementation_specific_e;
    };

    IssueX509CertificateInvalidWriteSignerError_signer.cb = signer_cb;

    ASSERT_EQ(n20_error_crypto_implementation_specific_e,
              n20_issue_x509_cert(&cert_info,
                                  &IssueX509CertificateInvalidWriteSignerError_signer,
                                  n20_crypto_key_type_ed25519_e,
                                  IssueX509CertificateInvalidWriteSignerError_certificate,
                                  &certificate_size));
}

TEST_F(FunctionalityX509Test, IssueX509CertificateWriteBufferOverflowAfterSigning) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.subject_public_key.algorithm = n20_crypto_key_type_ed25519_e;
    // The lambda below cannot capture this because it needs to have C linkage.
    // So we use a static variable with appropriate prefix so as not to clash
    // with other tests.
    uint8_t certificate[154] = {};
    size_t certificate_size = sizeof(certificate);

    static n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    auto signer_cb = [](void* ctx, n20_slice_t tbs, uint8_t* signature, size_t* signature_size) {
        EXPECT_TRUE(!!signature_size);
        EXPECT_EQ(tbs.size, 154);
        return n20_error_ok_e;
    };

    signer.cb = signer_cb;

    ASSERT_EQ(
        n20_error_insufficient_buffer_size_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));
    ASSERT_EQ(certificate_size, 264);
}

std::vector<uint8_t> TEST_ECA_CERT = {
    0x30, 0x81, 0xed, 0x30, 0x81, 0x80, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x05,
    0x13, 0x00, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
    0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04,
    0x05, 0x13, 0x00, 0x30, 0x0a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x01, 0x00, 0xa3,
    0x25, 0x30, 0x23, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x03, 0x03,
    0x01, 0x00, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06,
    0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x61, 0x00,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

TEST_F(FunctionalityX509Test, IssueX509CertificateWriteEcaCertRendering) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_e;
    cert_info.subject_public_key.algorithm = n20_crypto_key_type_ed25519_e;
    // The lambda below cannot capture this because it needs to have C linkage.
    // So we use a static variable with appropriate prefix so as not to clash
    // with other tests.
    uint8_t certificate[300] = {};
    size_t certificate_size = sizeof(certificate);

    static n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    auto signer_cb = [](void* ctx, n20_slice_t tbs, uint8_t* signature, size_t* signature_size) {
        memset(signature, 0x55, *signature_size);
        return n20_error_ok_e;
    };

    signer.cb = signer_cb;

    ASSERT_EQ(
        n20_error_ok_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));

    auto got_cert = std::vector<uint8_t>(&certificate[sizeof(certificate) - certificate_size],
                                         &certificate[sizeof(certificate)]);
    ASSERT_EQ(TEST_ECA_CERT, got_cert)
        << hexdump_side_by_side("Expected:", TEST_ECA_CERT, "Got:", got_cert)
        << hex_as_c_array(got_cert);
}

std::vector<uint8_t> TEST_ECA_EE_CERT = {
    0x30, 0x81, 0xe6, 0x30, 0x7a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13,
    0x00, 0x30, 0x22, 0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
    0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x05,
    0x13, 0x00, 0x30, 0x0a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x01, 0x00, 0xa3, 0x1f,
    0x30, 0x1d, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x03, 0x03, 0x01,
    0x00, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30,
    0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x61, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

TEST_F(FunctionalityX509Test, IssueX509CertificateWriteEcaEeCertRendering) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    cert_info.subject_public_key.algorithm = n20_crypto_key_type_ed25519_e;
    // The lambda below cannot capture this because it needs to have C linkage.
    // So we use a static variable with appropriate prefix so as not to clash
    // with other tests.
    uint8_t certificate[300] = {};
    size_t certificate_size = sizeof(certificate);

    static n20_signer_t signer = {
        .crypto_ctx = nullptr,
        .signing_key = nullptr,
        .cb = nullptr,
    };

    auto signer_cb = [](void* ctx, n20_slice_t tbs, uint8_t* signature, size_t* signature_size) {
        memset(signature, 0x55, *signature_size);
        return n20_error_ok_e;
    };

    signer.cb = signer_cb;

    ASSERT_EQ(
        n20_error_ok_e,
        n20_issue_x509_cert(
            &cert_info, &signer, n20_crypto_key_type_ed25519_e, certificate, &certificate_size));

    auto got_cert = std::vector<uint8_t>(&certificate[sizeof(certificate) - certificate_size],
                                         &certificate[sizeof(certificate)]);
    ASSERT_EQ(TEST_ECA_EE_CERT, got_cert)
        << hexdump_side_by_side("Expected:", TEST_ECA_EE_CERT, "Got:", got_cert)
        << hex_as_c_array(got_cert);
}

class CompressedInputTestFixture : public BsslTestFixtureBase {};

TEST_F(CompressedInputTestFixture, CompressInputNullCryptoContext) {
    n20_compressed_input_t output;

    auto err = n20_compress_input(nullptr, nullptr, output);
    ASSERT_EQ(err, n20_error_missing_crypto_context_e);
}

TEST_F(CompressedInputTestFixture, CompressInputNullCertInfo) {
    n20_compressed_input_t output;

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, nullptr, output);
    ASSERT_EQ(err, n20_error_unexpected_null_certificate_info_e);
}

uint8_t const TEST_COMPRESSED_INPUT_CDI[] = {
    0xe4, 0xfb, 0x97, 0x93, 0xc4, 0x05, 0xa1, 0x13, 0x28, 0x34, 0x5b, 0xf0, 0x57, 0x62, 0x72, 0xa6,
    0x70, 0x8d, 0x15, 0xff, 0x04, 0x9e, 0xc4, 0xf9, 0xa0, 0xdd, 0x01, 0xc7, 0x0c, 0x9c, 0xc7, 0x7c,
    0x20, 0x64, 0x5a, 0x19, 0x23, 0x12, 0xaa, 0x61, 0xb5, 0x53, 0x7e, 0xa7, 0x19, 0xa0, 0xd0, 0x18,
    0xf3, 0x4d, 0x80, 0x2c, 0x9d, 0x07, 0x65, 0x1b, 0x92, 0x2f, 0xe4, 0x58, 0x30, 0x2c, 0x59, 0x80};

TEST_F(CompressedInputTestFixture, CompressInputCdi) {
    n20_compressed_input_t output;
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input = TEST_OPEN_DICE_INPUT;

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, output);
    ASSERT_EQ(err, n20_error_ok_e);

    std::vector<uint8_t> got(output, output + sizeof(output));
    std::vector<uint8_t> want(TEST_COMPRESSED_INPUT_CDI,
                              TEST_COMPRESSED_INPUT_CDI + sizeof(TEST_COMPRESSED_INPUT_CDI));
    ASSERT_EQ(want, got) << hexdump_side_by_side("Expected:", want, "Got:", got) << "\n"
                         << hex_as_c_array(got) << std::endl;
}

uint8_t const TEST_COMPRESSED_INPUT_CDI_NO_CONFIG_HASH[] = {
    0x0f, 0xf7, 0x41, 0x37, 0x55, 0x84, 0xb9, 0x11, 0x6c, 0xe3, 0x2a, 0x3a, 0xe9, 0x3f, 0xc5, 0x78,
    0xdd, 0xbb, 0x1f, 0x46, 0x4b, 0x9f, 0x33, 0xe8, 0x1f, 0x30, 0x94, 0x39, 0x09, 0x00, 0x75, 0x72,
    0x46, 0xd7, 0xf5, 0xda, 0x7a, 0xbd, 0x09, 0x9b, 0xb2, 0x13, 0x18, 0x52, 0x78, 0x57, 0xd2, 0x29,
    0x4e, 0x11, 0x30, 0x0b, 0x6a, 0x4a, 0x74, 0x7a, 0x3b, 0x0b, 0xdc, 0x68, 0x48, 0x98, 0x2b, 0x32};

TEST_F(CompressedInputTestFixture, CompressInputCdiNoConfigHash) {
    n20_compressed_input_t output;
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input = TEST_OPEN_DICE_INPUT;
    cert_info.open_dice_input.configuration_hash = N20_SLICE_NULL;

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, output);
    ASSERT_EQ(err, n20_error_ok_e);

    std::vector<uint8_t> got(output, output + sizeof(output));
    std::vector<uint8_t> want(TEST_COMPRESSED_INPUT_CDI_NO_CONFIG_HASH,
                              TEST_COMPRESSED_INPUT_CDI_NO_CONFIG_HASH +
                                  sizeof(TEST_COMPRESSED_INPUT_CDI_NO_CONFIG_HASH));
    ASSERT_EQ(want, got) << hexdump_side_by_side("Expected:", want, "Got:", got) << "\n"
                         << hex_as_c_array(got) << std::endl;
}

uint8_t TEST_COMPRESSED_INPUT_SELF_SIGNED[] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};

TEST_F(CompressedInputTestFixture, CompressInputSelfSigned) {
    n20_compressed_input_t output;
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_self_signed_e;

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, output);
    std::vector<uint8_t> got(output, output + sizeof(output));
    std::vector<uint8_t> want(
        TEST_COMPRESSED_INPUT_SELF_SIGNED,
        TEST_COMPRESSED_INPUT_SELF_SIGNED + sizeof(TEST_COMPRESSED_INPUT_SELF_SIGNED));
    ASSERT_EQ(want, got) << hexdump_side_by_side("Expected:", want, "Got:", got) << "\n"
                         << hex_as_c_array(got) << std::endl;
}

TEST_F(CompressedInputTestFixture, CompressInputEca) {
    n20_compressed_input_t output;
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_e;

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, output);
    std::vector<uint8_t> got(output, output + sizeof(output));
    // Produces the same output as selfsigned.
    std::vector<uint8_t> want(
        TEST_COMPRESSED_INPUT_SELF_SIGNED,
        TEST_COMPRESSED_INPUT_SELF_SIGNED + sizeof(TEST_COMPRESSED_INPUT_SELF_SIGNED));
    ASSERT_EQ(want, got) << hexdump_side_by_side("Expected:", want, "Got:", got) << "\n"
                         << hex_as_c_array(got) << std::endl;
}

uint8_t TEST_COMPRESSED_INPUT_ECA_EE[] = {
    0x7a, 0xc0, 0xf2, 0x34, 0xbf, 0x63, 0x49, 0x6a, 0x64, 0x58, 0x67, 0x3e, 0xad, 0xd4, 0x28, 0xbc,
    0xaa, 0xbd, 0x14, 0x60, 0x86, 0x4e, 0xb1, 0x10, 0xfe, 0xee, 0x32, 0xca, 0x40, 0xa2, 0x0a, 0x79,
    0xdf, 0xf4, 0x1f, 0xeb, 0xd6, 0x3b, 0xa1, 0x26, 0x21, 0x00, 0x0c, 0xb0, 0x4f, 0x9b, 0x1f, 0x9b,
    0xa6, 0x49, 0xb1, 0x9d, 0x15, 0x8a, 0x1a, 0xd2, 0x6c, 0xfd, 0xcc, 0x71, 0xfa, 0x61, 0x39, 0x0e};

TEST_F(CompressedInputTestFixture, CompressInputEcaEe) {
    n20_compressed_input_t output;
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    cert_info.eca_ee.nonce = vec2slice(TEST_NONCE);
    cert_info.eca_ee.name = N20_STR_C("Test EE");

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, output);
    std::vector<uint8_t> got(output, output + sizeof(output));
    // Produces the same output as selfsigned.
    std::vector<uint8_t> want(TEST_COMPRESSED_INPUT_ECA_EE,
                              TEST_COMPRESSED_INPUT_ECA_EE + sizeof(TEST_COMPRESSED_INPUT_ECA_EE));
    ASSERT_EQ(want, got) << hexdump_side_by_side("Expected:", want, "Got:", got) << "\n"
                         << hex_as_c_array(got) << std::endl;
}

TEST_F(CompressedInputTestFixture, CompressInputDigestFail) {
    n20_compressed_input_t output;
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input = TEST_OPEN_DICE_INPUT;

    auto fail_digest = [](n20_crypto_digest_context_t*,
                          n20_crypto_digest_algorithm_t,
                          n20_crypto_gather_list_t const*,
                          size_t,
                          uint8_t*,
                          size_t*) -> n20_error_t {
        return n20_error_crypto_implementation_specific_e;
    };

    // Corrupt the digest context to force a failure.
    crypto_ctx->digest_ctx.digest = fail_digest;

    auto err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, output);
    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
}

class DeriveKeyTestFixture : public BsslTestFixtureBase {};

TEST_F(DeriveKeyTestFixture, DeriveKeyNullCryptoContext) {
    n20_crypto_key_t derived_key = nullptr;

    auto err = n20_derive_cdi_attestation_key(
        nullptr, nullptr, &derived_key, n20_crypto_key_type_ed25519_e);
    ASSERT_EQ(err, n20_error_missing_crypto_context_e);
    ASSERT_EQ(derived_key, nullptr);
}

TEST_F(DeriveKeyTestFixture, DeriveKeyNullDerivedKey) {
    n20_crypto_key_t parent_key = this->GetCdi();
    KEY_HANDLE_GUARD(parent_key);

    auto err = n20_derive_cdi_attestation_key(
        crypto_ctx, parent_key, nullptr, n20_crypto_key_type_ed25519_e);
    ASSERT_EQ(err, n20_error_unexpected_null_key_handle_e);
}

TEST_F(DeriveKeyTestFixture, DeriveKeyNullParentKey) {
    n20_crypto_key_t derived_key = nullptr;

    auto err = n20_derive_cdi_attestation_key(
        crypto_ctx, nullptr, &derived_key, n20_crypto_key_type_ed25519_e);
    ASSERT_EQ(err, n20_error_crypto_unexpected_null_key_in_e);
}

class InitKeyInfoTestFixture : public BsslTestFixtureBase {};

TEST_F(InitKeyInfoTestFixture, InitKeyInfoUnsupportedKeyType) {
    n20_x509_public_key_info_t key_info = {};
    auto null_slice = N20_SLICE_NULL;
    auto err = n20_init_key_info(&key_info, n20_crypto_key_type_cdi_e, &null_slice);
    ASSERT_EQ(err, n20_error_crypto_invalid_key_type_e);
}

TEST_F(InitKeyInfoTestFixture, InitKeyInfoNullKeyInfo) {
    auto null_slice = N20_SLICE_NULL;
    auto err = n20_init_key_info(nullptr, n20_crypto_key_type_cdi_e, &null_slice);
    ASSERT_EQ(err, n20_error_unexpected_null_key_info_e);
}

TEST_F(InitKeyInfoTestFixture, InitKeyInfoNullKeyData) {
    n20_x509_public_key_info_t key_info = {};
    auto err = n20_init_key_info(&key_info, n20_crypto_key_type_ed25519_e, nullptr);
    ASSERT_EQ(err, n20_error_unexpected_null_public_key_e);
}

extern "C" void n20_func_key_usage_open_dice_to_x509(n20_open_dice_cert_info_t const* cert_info,
                                                     n20_x509_ext_key_usage_t* key_usage);

TEST(OpenDiceToX509Tests, KeyUsageOpenDiceToX509NoOp) {
    // Just a no-op, should not crash.
    n20_x509_ext_key_usage_t key_usage = {};
    n20_func_key_usage_open_dice_to_x509(nullptr, &key_usage);
    n20_func_key_usage_open_dice_to_x509(nullptr, nullptr);
    n20_open_dice_cert_info_t cert_info = {};
    n20_func_key_usage_open_dice_to_x509(&cert_info, nullptr);
}
class InitAlgorithmIdentifierFixture
    : public BsslTestFixtureBase,
      public ::testing::WithParamInterface<std::tuple<std::string,
                                                      n20_crypto_key_type_t,
                                                      n20_asn1_object_identifier_t*,
                                                      n20_error_t>> {};

INSTANTIATE_TEST_SUITE_P(
    InitAlgorithmIdentifierTestInstance,
    InitAlgorithmIdentifierFixture,
    ::testing::Values(
        std::make_tuple("ed25519", n20_crypto_key_type_ed25519_e, &OID_ED25519, n20_error_ok_e),
        std::make_tuple(
            "secp256r1", n20_crypto_key_type_secp256r1_e, &OID_ECDSA_WITH_SHA256, n20_error_ok_e),
        std::make_tuple(
            "secp384r1", n20_crypto_key_type_secp384r1_e, &OID_ECDSA_WITH_SHA384, n20_error_ok_e),
        std::make_tuple("unsupported",
                        n20_crypto_key_type_cdi_e,
                        nullptr,
                        n20_error_crypto_invalid_key_type_e)),
    [](testing::TestParamInfo<InitAlgorithmIdentifierFixture::ParamType> const& info) {
        return std::get<0>(info.param);
    });

TEST_P(InitAlgorithmIdentifierFixture, InitAlgorithmIdentifierTest) {
    auto [_, key_type, want_oid, want_err] = GetParam();

    n20_x509_algorithm_identifier_t algorithm_identifier = {};
    auto err = n20_init_algorithm_identifier(&algorithm_identifier, key_type);
    ASSERT_EQ(err, want_err);

    if (err == n20_error_ok_e) {
        ASSERT_NE(algorithm_identifier.oid, nullptr);
        ASSERT_EQ(algorithm_identifier.oid, want_oid);
    }
}

class EeSignMessageTestFixture
    : public BsslTestFixtureBase,
      public ::testing::WithParamInterface<std::tuple<std::string,
                                                      n20_error_t,
                                                      std::vector<uint8_t>,
                                                      n20_crypto_key_type_t,
                                                      std::vector<uint8_t>>> {};

INSTANTIATE_TEST_SUITE_P(
    EeSignMessageTestFixtureInstance,
    EeSignMessageTestFixture,
    ::testing::Values(
        std::make_tuple(std::string("empty_key_usage"),
                        n20_error_ok_e,
                        std::vector<uint8_t>{},
                        n20_crypto_key_type_ed25519_e,
                        std::vector<uint8_t>{
                            0x7d, 0x15, 0x5f, 0x72, 0x3b, 0xad, 0x11, 0xd9, 0x5f, 0x04, 0x25,
                            0xd7, 0xa4, 0x00, 0x05, 0x1e, 0xbb, 0x18, 0xaf, 0xf5, 0x3b, 0xef,
                            0xbf, 0xa7, 0x30, 0xa8, 0x98, 0xe0, 0xbe, 0x90, 0xf8, 0x08, 0xd4,
                            0x26, 0xb9, 0x76, 0x81, 0xc7, 0x45, 0x9a, 0x1b, 0x31, 0xe2, 0x6f,
                            0x57, 0x0a, 0x2d, 0xd8, 0x52, 0x2a, 0xaf, 0x3f, 0xec, 0xae, 0xdf,
                            0x20, 0x45, 0x4c, 0x82, 0x3d, 0xd3, 0x04, 0x5d, 0x0e}),
        std::make_tuple(std::string("one_byte_key_usage"),
                        n20_error_ok_e,
                        std::vector<uint8_t>{0x01},
                        n20_crypto_key_type_ed25519_e,
                        std::vector<uint8_t>{
                            0x2d, 0x73, 0x3d, 0xaa, 0xc5, 0xb8, 0x72, 0x03, 0xc6, 0xfe, 0x99,
                            0x1a, 0x29, 0x25, 0xec, 0x30, 0xb9, 0x0d, 0xb9, 0x32, 0x72, 0x1f,
                            0x8e, 0x76, 0x36, 0x7e, 0xa9, 0x2a, 0xbf, 0x14, 0xc0, 0xe7, 0x4f,
                            0x6b, 0x4d, 0x40, 0x42, 0x47, 0xbc, 0x71, 0x1b, 0x8c, 0x2a, 0x96,
                            0xf0, 0x37, 0x84, 0xa3, 0xb8, 0x5e, 0xc0, 0x8b, 0x0e, 0xdb, 0xa4,
                            0x1a, 0xc3, 0xd5, 0xe8, 0x61, 0x12, 0x9a, 0xf1, 0x02}),
        std::make_tuple(std::string("multiple_byte_key_usage"),
                        n20_error_ok_e,
                        std::vector<uint8_t>{0x01, 0x02, 0x03},
                        n20_crypto_key_type_ed25519_e,
                        std::vector<uint8_t>{
                            0x41, 0x0b, 0x8b, 0x2b, 0x16, 0x98, 0x88, 0x8b, 0x22, 0x29, 0xa2,
                            0x80, 0xdd, 0x7c, 0x13, 0xa9, 0x33, 0x42, 0x91, 0x7c, 0xf6, 0x49,
                            0x35, 0xf8, 0x9e, 0x65, 0x1e, 0xe4, 0x9f, 0x86, 0x74, 0xb3, 0x99,
                            0xeb, 0xe7, 0xea, 0xbe, 0x05, 0x54, 0xf0, 0x4d, 0xba, 0x10, 0xbc,
                            0xa9, 0xe2, 0xb3, 0x6f, 0x92, 0x59, 0x3e, 0xb6, 0xd8, 0xff, 0x5e,
                            0x31, 0x51, 0xdf, 0xf9, 0xfe, 0xf0, 0x2c, 0x27, 0x04}),
        std::make_tuple(std::string("invalid_key_type"),
                        n20_error_crypto_invalid_key_type_e,
                        std::vector<uint8_t>{0x01, 0x02, 0x03},
                        (n20_crypto_key_type_t)0xFF,
                        std::vector<uint8_t>{})),
    [](testing::TestParamInfo<EeSignMessageTestFixture::ParamType> const& info) {
        return std::get<0>(info.param);
    });

char const TEST_MESSAGE[] = "Test message for EE signing";

TEST_P(EeSignMessageTestFixture, EeSignMessageTest) {
    auto [_, want_error, key_usage, key_type, want_signature] = GetParam();

    n20_crypto_key_t parent_secret = GetCdi();
    KEY_HANDLE_GUARD(parent_secret);

    n20_slice_t message = {.size = sizeof(TEST_MESSAGE) - 1,
                           .buffer = (uint8_t const*)TEST_MESSAGE};
    uint8_t signature[100] = {};
    size_t signature_size = sizeof(signature);

    struct test_context {
        n20_slice_t message;
        uint8_t* signature;
        size_t signature_buffer_size;
        size_t want_signature_size;
        n20_error_t (*sign)(struct n20_crypto_context_s* ctx,
                            n20_crypto_key_t key_in,
                            n20_crypto_gather_list_t const* msg_in,
                            uint8_t* signature_out,
                            size_t* signature_size_in_out);
        unsigned int call_count = 0;
    } test_ctx = {
        .message = message,
        .signature = &signature[sizeof(signature) - want_signature.size()],
        .signature_buffer_size = sizeof(signature),
        .want_signature_size = want_signature.size(),
        .sign = crypto_ctx->sign,
    };

    SetTestContext(&test_ctx);
    crypto_ctx->sign = [](n20_crypto_context_t* ctx,
                          n20_crypto_key_t key,
                          n20_crypto_gather_list_t const* gather_list,
                          uint8_t* signature,
                          size_t* size) -> n20_error_t {
        auto test_ctx = BsslTestFixtureCryptoContext::GetTestContext<test_context>(ctx);
        EXPECT_NE(key, nullptr);
        EXPECT_EQ(gather_list->count, 1);
        EXPECT_EQ(gather_list->list[0].size, test_ctx->message.size);
        EXPECT_EQ(gather_list->list[0].buffer, test_ctx->message.buffer);
        // sign is called twice, first to get the signature size and second to get the signature.
        if (test_ctx->call_count == 0) {
            test_ctx->call_count++;
            EXPECT_NE(size, nullptr);
            EXPECT_EQ(*size, 0u);
            EXPECT_EQ(signature, nullptr);
        } else {
            EXPECT_NE(size, nullptr);
            EXPECT_EQ(*size, test_ctx->want_signature_size);
            EXPECT_EQ(signature, test_ctx->signature);
        }
        auto err = test_ctx->sign(ctx, key, gather_list, signature, size);
        EXPECT_EQ(*size, test_ctx->want_signature_size);
        return err;
    };

    n20_string_slice_t name = N20_STR_C("Test EE");
    n20_slice_t key_usage_slice = vec2slice(key_usage);

    ASSERT_EQ(want_error,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      key_type,
                                      name,
                                      key_usage_slice,
                                      message,
                                      signature,
                                      &signature_size));

    if (want_error != n20_error_ok_e) {
        return;
    }

    auto signature_vect = std::vector<uint8_t>(signature + sizeof(signature) - signature_size,
                                               signature + sizeof(signature));
    EXPECT_EQ(want_signature, signature_vect) << "Signature mismatch" << std::endl
                                              << hex_as_c_array(signature_vect);
}

TEST(EeSignMessageTest, EeSignMessageMissingCryptoContextTest) {
    ASSERT_EQ(n20_error_missing_crypto_context_e,
              n20_eca_ee_sign_message(nullptr,
                                      nullptr,
                                      n20_crypto_key_type_ed25519_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      nullptr));
}

class EcaEeSignMessageFixture : public BsslTestFixtureBase {};

TEST_F(EcaEeSignMessageFixture, EeSignMessageUnexpectedNullBufferSizeTest) {
    n20_crypto_key_t parent_secret = nullptr;
    ASSERT_EQ(n20_error_unexpected_null_buffer_size_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      n20_crypto_key_type_ed25519_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      nullptr));
}

TEST_F(EcaEeSignMessageFixture, EeSignMessageUnexpectedInsufficientBufferSizeTest) {
    n20_crypto_key_t parent_secret = GetCdi();
    KEY_HANDLE_GUARD(parent_secret);
    size_t signature_size = 0;
    ASSERT_EQ(n20_error_insufficient_buffer_size_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      n20_crypto_key_type_ed25519_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      &signature_size));
    EXPECT_EQ(signature_size, 64u);  // Ed25519 signature size

    signature_size = 0;
    ASSERT_EQ(n20_error_insufficient_buffer_size_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      n20_crypto_key_type_secp256r1_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      &signature_size));
    EXPECT_EQ(signature_size, 64u);  // Secp256r1 signature size

    signature_size = 0;
    ASSERT_EQ(n20_error_insufficient_buffer_size_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      n20_crypto_key_type_secp384r1_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      &signature_size));
    EXPECT_EQ(signature_size, 96u);  // Secp384r1 signature size
}

TEST_F(EcaEeSignMessageFixture, EeSignMessageDigestErrorForwardingTest) {
    crypto_ctx->digest_ctx.digest = [](n20_crypto_digest_context_t* ctx,
                                       n20_crypto_digest_algorithm_t algorithm,
                                       n20_crypto_gather_list_t const* gather_list,
                                       size_t msg_count,
                                       uint8_t* digest,
                                       size_t* digest_size) -> n20_error_t {
        return n20_error_crypto_implementation_specific_e;
    };

    n20_crypto_key_t parent_secret = GetCdi();
    KEY_HANDLE_GUARD(parent_secret);

    n20_slice_t message = {.size = sizeof(TEST_MESSAGE) - 1,
                           .buffer = (uint8_t const*)TEST_MESSAGE};
    uint8_t signature[100] = {};
    size_t signature_size = sizeof(signature);
    std::vector<uint8_t> key_usage = {0x01, 0x02, 0x03};
    n20_crypto_key_type_t key_type = n20_crypto_key_type_ed25519_e;

    n20_string_slice_t name = N20_STR_C("Test EE");
    n20_slice_t key_usage_slice = vec2slice(key_usage);

    ASSERT_EQ(n20_error_crypto_implementation_specific_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      key_type,
                                      name,
                                      key_usage_slice,
                                      message,
                                      signature,
                                      &signature_size));
}

TEST_F(EcaEeSignMessageFixture, EeSignMessageSignErrorForwardingTest) {

    struct test_context {
        n20_error_t (*sign)(struct n20_crypto_context_s* ctx,
                            n20_crypto_key_t key_in,
                            n20_crypto_gather_list_t const* msg_in,
                            uint8_t* signature_out,
                            size_t* signature_size_in_out);
        unsigned int fail_on = 0;
    } test_ctx = {
        .sign = crypto_ctx->sign,
    };

    SetTestContext(&test_ctx);
    crypto_ctx->sign = [](n20_crypto_context_t* ctx,
                          n20_crypto_key_t key,
                          n20_crypto_gather_list_t const* gather_list,
                          uint8_t* signature,
                          size_t* size) -> n20_error_t {
        auto test_ctx = BsslTestFixtureCryptoContext::GetTestContext<test_context>(ctx);
        if (test_ctx->fail_on-- == 0) {
            return n20_error_crypto_implementation_specific_e;
        }
        return test_ctx->sign(ctx, key, gather_list, signature, size);
    };

    n20_crypto_key_t parent_secret = GetCdi();
    KEY_HANDLE_GUARD(parent_secret);
    size_t signature_size = 0;
    ASSERT_EQ(n20_error_crypto_implementation_specific_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      n20_crypto_key_type_ed25519_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      &signature_size));

    test_ctx.fail_on = 1;
    signature_size = 64;
    ASSERT_EQ(n20_error_crypto_implementation_specific_e,
              n20_eca_ee_sign_message(crypto_ctx,
                                      parent_secret,
                                      n20_crypto_key_type_ed25519_e,
                                      N20_STR_C("Test EE"),
                                      N20_SLICE_NULL,
                                      N20_SLICE_NULL,
                                      nullptr,
                                      &signature_size));
}

class ComputeCertificateContextTest : public BsslTestFixtureBase {};

TEST_F(ComputeCertificateContextTest, NullCryptoContext) {
    auto err = n20_compute_certificate_context(nullptr,
                                               nullptr,
                                               nullptr,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               nullptr);
    ASSERT_EQ(err, n20_error_missing_crypto_context_e);
}

TEST_F(ComputeCertificateContextTest, NullPublicKeyBuffer) {
    auto err = n20_compute_certificate_context(crypto_ctx,
                                               nullptr,
                                               nullptr,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               nullptr);
    ASSERT_EQ(err, n20_error_unexpected_null_public_key_buffer_e);
}

TEST_F(ComputeCertificateContextTest, NullPublicKeySizeBuffer) {
    uint8_t public_key[32] = {};
    auto err = n20_compute_certificate_context(crypto_ctx,
                                               nullptr,
                                               nullptr,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               nullptr);
    ASSERT_EQ(err, n20_error_unexpected_null_buffer_size_e);
}

TEST_F(ComputeCertificateContextTest, NullCertificateInfo) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    auto err = n20_compute_certificate_context(crypto_ctx,
                                               nullptr,
                                               nullptr,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);
    ASSERT_EQ(err, n20_error_unexpected_null_certificate_info_e);
}

TEST_F(ComputeCertificateContextTest, ForwardDigestError) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;

    crypto_ctx->digest_ctx.digest = [](n20_crypto_digest_context_t* ctx,
                                       n20_crypto_digest_algorithm_t algorithm,
                                       n20_crypto_gather_list_t const* gather_list,
                                       size_t msg_count,
                                       uint8_t* digest,
                                       size_t* digest_size) -> n20_error_t {
        return n20_error_crypto_implementation_specific_e;
    };

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               nullptr,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);
    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
}

TEST_F(ComputeCertificateContextTest, UnexpectedNullKeyError) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_cdi_e;

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               nullptr,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);
    ASSERT_EQ(err, n20_error_crypto_unexpected_null_key_in_e);
}

TEST_F(ComputeCertificateContextTest, UnsupportedCertificateType) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = (n20_cert_type_t)0xFF;

    n20_crypto_key_t parent_key = GetCdi();
    KEY_HANDLE_GUARD(parent_key);

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               parent_key,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);

    ASSERT_EQ(err, n20_error_unsupported_certificate_type_e);
}

TEST_F(ComputeCertificateContextTest, ForwardKdfIssuerKeyError) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_crypto_key_t issuer_cdi = GetCdi();
    KEY_HANDLE_GUARD(issuer_cdi);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;

    struct test_context {
        n20_error_t (*kdf)(struct n20_crypto_context_s* ctx,
                           n20_crypto_key_t key_in,
                           n20_crypto_key_type_t key_type_in,
                           n20_crypto_gather_list_t const* context_in,
                           n20_crypto_key_t* key_out);
        size_t invocations_until_failure = 1;
    } test_ctx = {
        .kdf = crypto_ctx->kdf,
    };

    SetTestContext(&test_ctx);

    crypto_ctx->kdf = [](struct n20_crypto_context_s* ctx,
                         n20_crypto_key_t key_in,
                         n20_crypto_key_type_t key_type_in,
                         n20_crypto_gather_list_t const* context_in,
                         n20_crypto_key_t* key_out) -> n20_error_t {
        auto test_ctx = BsslTestFixtureCryptoContext::GetTestContext<test_context>(ctx);
        if (test_ctx->invocations_until_failure > 0) {
            test_ctx->invocations_until_failure--;
            return test_ctx->kdf(ctx, key_in, key_type_in, context_in, key_out);
        }
        return n20_error_crypto_implementation_specific_e;
    };

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               issuer_cdi,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);

    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);
}

TEST_F(ComputeCertificateContextTest, ForwardGetPublicKeyError) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_crypto_key_t issuer_cdi = GetCdi();
    KEY_HANDLE_GUARD(issuer_cdi);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    n20_cdi_id_t issuer_serial_number = {};
    n20_cdi_id_t subject_serial_number = {};

    struct test_context {
        n20_error_t (*key_get_public_key)(struct n20_crypto_context_s* ctx,
                                          n20_crypto_key_t key_in,
                                          uint8_t* public_key_out,
                                          size_t* public_key_size_in_out);
        size_t invocations_until_failure = 0;
    } test_ctx = {
        .key_get_public_key = crypto_ctx->key_get_public_key,
    };

    SetTestContext(&test_ctx);

    crypto_ctx->key_get_public_key = [](struct n20_crypto_context_s* ctx,
                                        n20_crypto_key_t key_in,
                                        uint8_t* public_key_out,
                                        size_t* public_key_size_in_out) -> n20_error_t {
        auto test_ctx = BsslTestFixtureCryptoContext::GetTestContext<test_context>(ctx);
        if (test_ctx->invocations_until_failure > 0) {
            test_ctx->invocations_until_failure--;
            return test_ctx->key_get_public_key(
                ctx, key_in, public_key_out, public_key_size_in_out);
        }
        return n20_error_crypto_implementation_specific_e;
    };

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               issuer_cdi,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               issuer_serial_number,
                                               subject_serial_number,
                                               &public_key[0],
                                               &public_key_size);

    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);

    // Now allow the first call to succeed, and fail the second call.
    test_ctx.invocations_until_failure = 1;
    err = n20_compute_certificate_context(crypto_ctx,
                                          issuer_cdi,
                                          &cert_info,
                                          n20_crypto_key_type_ed25519_e,
                                          n20_crypto_key_type_ed25519_e,
                                          nullptr,
                                          issuer_serial_number,
                                          subject_serial_number,
                                          &public_key[0],
                                          &public_key_size);

    n20_cdi_id_t TEST_CDI_ID = {0x14, 0xed, 0x91, 0xf1, 0x5d, 0xaa, 0x4f, 0xff, 0x3b, 0x38,
                                0xfe, 0x53, 0x74, 0x47, 0x89, 0xeb, 0x7a, 0x05, 0x30, 0x11};

    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
    ASSERT_EQ(0, memcmp(issuer_serial_number, TEST_CDI_ID, sizeof(issuer_serial_number)))
        << hex_as_c_array(std::vector<uint8_t>(
               issuer_serial_number, issuer_serial_number + sizeof(issuer_serial_number)));
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);
}

TEST_F(ComputeCertificateContextTest, ForwardCdiIDError) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_crypto_key_t issuer_cdi = GetCdi();
    KEY_HANDLE_GUARD(issuer_cdi);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    n20_cdi_id_t issuer_serial_number = {};
    n20_cdi_id_t subject_serial_number = {};

    // CDI ID derivation uses kdf, so we simulate an error there.
    struct test_context {
        n20_error_t (*hkdf)(struct n20_crypto_digest_context_s* ctx,
                            n20_crypto_digest_algorithm_t alg_in,
                            n20_slice_t ikm_in,
                            n20_slice_t salt_in,
                            n20_slice_t info_in,
                            size_t key_octets_in,
                            uint8_t* key_out);
        size_t invocations_until_failure = 0;
    } test_ctx = {
        .hkdf = crypto_ctx->digest_ctx.hkdf,
    };

    SetTestContext(&test_ctx);

    crypto_ctx->digest_ctx.hkdf = [](struct n20_crypto_digest_context_s* ctx,
                                     n20_crypto_digest_algorithm_t alg_in,
                                     n20_slice_t ikm_in,
                                     n20_slice_t salt_in,
                                     n20_slice_t info_in,
                                     size_t key_octets_in,
                                     uint8_t* key_out) -> n20_error_t {
        auto test_ctx = BsslTestFixtureCryptoContext::GetTestContext<test_context>(ctx);
        if (test_ctx->invocations_until_failure > 0) {
            test_ctx->invocations_until_failure--;
            return test_ctx->hkdf(ctx, alg_in, ikm_in, salt_in, info_in, key_octets_in, key_out);
        }
        return n20_error_crypto_implementation_specific_e;
    };

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               issuer_cdi,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               issuer_serial_number,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);

    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);

    // Now allow the first call to succeed, and fail the second call.
    test_ctx.invocations_until_failure = 1;
    err = n20_compute_certificate_context(crypto_ctx,
                                          issuer_cdi,
                                          &cert_info,
                                          n20_crypto_key_type_ed25519_e,
                                          n20_crypto_key_type_ed25519_e,
                                          nullptr,
                                          issuer_serial_number,
                                          subject_serial_number,
                                          &public_key[0],
                                          &public_key_size);

    n20_cdi_id_t TEST_CDI_ID = {0x14, 0xed, 0x91, 0xf1, 0x5d, 0xaa, 0x4f, 0xff, 0x3b, 0x38,
                                0xfe, 0x53, 0x74, 0x47, 0x89, 0xeb, 0x7a, 0x05, 0x30, 0x11};

    ASSERT_EQ(err, n20_error_crypto_implementation_specific_e);
    ASSERT_EQ(0, memcmp(issuer_serial_number, TEST_CDI_ID, sizeof(issuer_serial_number)))
        << hex_as_c_array(std::vector<uint8_t>(
               issuer_serial_number, issuer_serial_number + sizeof(issuer_serial_number)));
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);
}

TEST_F(ComputeCertificateContextTest, NoIssuerKeyHandleLeakOnNullIssuerKeyHandle) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_crypto_key_t issuer_cdi = GetCdi();
    KEY_HANDLE_GUARD(issuer_cdi);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    n20_cdi_id_t issuer_serial_number = {};
    n20_cdi_id_t subject_serial_number = {};

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               issuer_cdi,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               issuer_serial_number,
                                               subject_serial_number,
                                               &public_key[0],
                                               &public_key_size);

    ASSERT_EQ(err, n20_error_ok_e);
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);
    n20_cdi_id_t TEST_ISSUER_CDI_ID = {0x14, 0xed, 0x91, 0xf1, 0x5d, 0xaa, 0x4f, 0xff, 0x3b, 0x38,
                                       0xfe, 0x53, 0x74, 0x47, 0x89, 0xeb, 0x7a, 0x05, 0x30, 0x11};
    ASSERT_EQ(0, memcmp(issuer_serial_number, TEST_ISSUER_CDI_ID, sizeof(issuer_serial_number)))
        << hex_as_c_array(std::vector<uint8_t>(
               issuer_serial_number, issuer_serial_number + sizeof(issuer_serial_number)));
    n20_cdi_id_t TEST_SUBJECT_CDI_ID = {0x08, 0x7a, 0x55, 0x80, 0x22, 0x5c, 0x38, 0x3c, 0x1a, 0x66,
                                        0xce, 0x8b, 0xaa, 0xd5, 0x5f, 0x0a, 0x0f, 0x8d, 0x31, 0x90};
    ASSERT_EQ(0, memcmp(subject_serial_number, TEST_SUBJECT_CDI_ID, sizeof(subject_serial_number)))
        << hex_as_c_array(std::vector<uint8_t>(
               subject_serial_number, subject_serial_number + sizeof(subject_serial_number)));

    n20_crypto_key_t issuer_key_handle = nullptr;

    err = n20_compute_certificate_context(crypto_ctx,
                                          issuer_cdi,
                                          &cert_info,
                                          n20_crypto_key_type_ed25519_e,
                                          n20_crypto_key_type_ed25519_e,
                                          &issuer_key_handle,
                                          issuer_serial_number,
                                          subject_serial_number,
                                          &public_key[0],
                                          &public_key_size);

    KEY_HANDLE_GUARD(issuer_key_handle);

    ASSERT_EQ(err, n20_error_ok_e);
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    // Now we have the issuer key handle, so there should be 2 active key handles.
    ASSERT_EQ(crypto_ctx->active_key_handles, 2U);
    ASSERT_EQ(0, memcmp(issuer_serial_number, TEST_ISSUER_CDI_ID, sizeof(issuer_serial_number)))
        << hex_as_c_array(std::vector<uint8_t>(
               issuer_serial_number, issuer_serial_number + sizeof(issuer_serial_number)));
    ASSERT_EQ(0, memcmp(subject_serial_number, TEST_SUBJECT_CDI_ID, sizeof(subject_serial_number)))
        << hex_as_c_array(std::vector<uint8_t>(
               subject_serial_number, subject_serial_number + sizeof(subject_serial_number)));
}

TEST_F(ComputeCertificateContextTest, NoRequestSerialNumberComputation) {
    uint8_t public_key[32] = {};
    size_t public_key_size = sizeof(public_key);
    n20_crypto_key_t issuer_cdi = GetCdi();
    KEY_HANDLE_GUARD(issuer_cdi);
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;

    auto err = n20_compute_certificate_context(crypto_ctx,
                                               issuer_cdi,
                                               &cert_info,
                                               n20_crypto_key_type_ed25519_e,
                                               n20_crypto_key_type_ed25519_e,
                                               nullptr,
                                               nullptr,
                                               nullptr,
                                               &public_key[0],
                                               &public_key_size);

    ASSERT_EQ(err, n20_error_ok_e);
    ASSERT_EQ(crypto_ctx->max_active_key_handles, 3U);
    ASSERT_EQ(crypto_ctx->active_key_handles, 1U);
}

class IssueCertificateTestFixture : public BsslTestFixtureBase {};

TEST_F(IssueCertificateTestFixture, NullCryptoContext) {
    auto err = n20_issue_certificate(nullptr,
                                     nullptr,
                                     n20_crypto_key_type_ed25519_e,
                                     n20_crypto_key_type_ed25519_e,
                                     nullptr,
                                     n20_certificate_format_x509_e,
                                     nullptr,
                                     nullptr);
    ASSERT_EQ(err, n20_error_missing_crypto_context_e);
}

TEST_F(IssueCertificateTestFixture, NullCertInfo) {
    auto err = n20_issue_certificate(crypto_ctx,
                                     nullptr,
                                     n20_crypto_key_type_ed25519_e,
                                     n20_crypto_key_type_ed25519_e,
                                     nullptr,
                                     n20_certificate_format_x509_e,
                                     nullptr,
                                     nullptr);
    ASSERT_EQ(err, n20_error_unexpected_null_certificate_info_e);
}

TEST_F(IssueCertificateTestFixture, UnsupportedCertificateType) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = (n20_cert_type_t)0xFF;

    auto err = n20_issue_certificate(crypto_ctx,
                                     nullptr,
                                     n20_crypto_key_type_ed25519_e,
                                     n20_crypto_key_type_ed25519_e,
                                     &cert_info,
                                     n20_certificate_format_x509_e,
                                     nullptr,
                                     nullptr);
    ASSERT_EQ(err, n20_error_unsupported_certificate_type_e);
}

TEST_F(IssueCertificateTestFixture, ForwardComputeCertificateContextError) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;

    auto err = n20_issue_certificate(crypto_ctx,
                                     nullptr,
                                     n20_crypto_key_type_ed25519_e,
                                     n20_crypto_key_type_ed25519_e,
                                     &cert_info,
                                     n20_certificate_format_x509_e,
                                     nullptr,
                                     nullptr);
    ASSERT_EQ(err, n20_error_crypto_unexpected_null_key_in_e);
}

TEST_F(IssueCertificateTestFixture, UnsupportedCertificateFormat) {
    n20_open_dice_cert_info_t cert_info = {};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    n20_crypto_key_t issuer_cdi = GetCdi();
    KEY_HANDLE_GUARD(issuer_cdi);
    uint8_t certificate[512] = {};
    size_t certificate_size = sizeof(certificate);

    auto err = n20_issue_certificate(crypto_ctx,
                                     issuer_cdi,
                                     n20_crypto_key_type_ed25519_e,
                                     n20_crypto_key_type_ed25519_e,
                                     &cert_info,
                                     (n20_certificate_format_t)0xFF,
                                     certificate,
                                     &certificate_size);
    ASSERT_EQ(err, n20_error_unsupported_certificate_format_e);
}
