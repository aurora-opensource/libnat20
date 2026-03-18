/*
 * Copyright 2026 Aurora Operations, Inc.
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
#include <nat20/constants.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {

// 32-byte all-zeros UDS / test CDI secret – content is irrelevant for these tests.
static constexpr std::array<uint8_t, 32> kTestSecret{};

struct MockCryptoContext : public n20_crypto_context_t {
    uint32_t err_on_zero_kdf = std::numeric_limits<uint32_t>::max();
    n20_error_t kdf_error = n20_error_ok_e;
    uint32_t err_on_zero_digest = std::numeric_limits<uint32_t>::max();
    n20_error_t digest_error = n20_error_ok_e;
    n20_error_t (*kdf_fn)(struct n20_crypto_context_s* ctx,
                          n20_crypto_key_t key_in,
                          n20_crypto_key_type_t key_type_in,
                          n20_crypto_gather_list_t const* context_in,
                          n20_crypto_key_t* key_out);
    n20_error_t (*digest_fn)(n20_crypto_digest_context_t* ctx,
                             n20_crypto_digest_algorithm_t alg,
                             n20_crypto_gather_list_t const* data,
                             size_t msg_count,
                             uint8_t* out,
                             size_t* out_len);
    n20_error_t (*key_free_fn)(n20_crypto_context_t* ctx, n20_crypto_key_t key);

    uint32_t free_key_calls = 0;
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

#define container_of(ptr, type, member) ((type*)((char*)(ptr)-offsetof(type, member)))

class GnosticNodeTest : public testing::Test {
   protected:
    void SetUp() override {
        ASSERT_EQ(n20_error_ok_e, n20_crypto_boringssl_open(&crypto_context_));

        *static_cast<n20_crypto_context_t*>(&mock_crypto_context_) = *crypto_context_;
        mock_crypto_context_.kdf_fn = crypto_context_->kdf;
        mock_crypto_context_.digest_fn = crypto_context_->digest_ctx.digest;
        mock_crypto_context_.key_free_fn = crypto_context_->key_free;
        mock_crypto_context_.kdf = [](n20_crypto_context_t* ctx,
                                      n20_crypto_key_t key_in,
                                      n20_crypto_key_type_t key_type_in,
                                      n20_crypto_gather_list_t const* context_in,
                                      n20_crypto_key_t* key_out) -> n20_error_t {
            MockCryptoContext* mock_ctx = reinterpret_cast<MockCryptoContext*>(ctx);
            if (!mock_ctx->err_on_zero_kdf--) {
                return mock_ctx->kdf_error;
            }
            return mock_ctx->kdf_fn(ctx, key_in, key_type_in, context_in, key_out);
        };

        mock_crypto_context_.digest_ctx.digest = [](n20_crypto_digest_context_t* ctx,
                                                    n20_crypto_digest_algorithm_t alg,
                                                    n20_crypto_gather_list_t const* data,
                                                    size_t msg_count,
                                                    uint8_t* out,
                                                    size_t* out_len) -> n20_error_t {
            MockCryptoContext* mock_ctx = reinterpret_cast<MockCryptoContext*>(
                container_of(ctx, n20_crypto_context_t, digest_ctx));
            if (!mock_ctx->err_on_zero_digest--) {
                return mock_ctx->digest_error;
            }
            return mock_ctx->digest_fn(ctx, alg, data, msg_count, out, out_len);
        };

        mock_crypto_context_.key_free = [](n20_crypto_context_t* ctx,
                                           n20_crypto_key_t key) -> n20_error_t {
            MockCryptoContext* mock_ctx = reinterpret_cast<MockCryptoContext*>(ctx);
            mock_ctx->free_key_calls++;
            return mock_ctx->key_free_fn(ctx, key);
        };

        n20_slice_t const secret{kTestSecret.size(), const_cast<uint8_t*>(kTestSecret.data())};
        ASSERT_EQ(n20_error_ok_e,
                  n20_crypto_boringssl_make_secret(crypto_context_, &secret, &state_.min_cdi));
        state_.crypto_context = &mock_crypto_context_;

        // Initialize parent path elements to distinct values for easier debugging.
        for (size_t i = 0; i < parent_path_elements_.size(); ++i) {
            parent_path_elements_[i].fill(static_cast<uint8_t>(0x11 * i));
            parent_path_elements_slices_[i] = {sizeof(n20_compressed_input_t),
                                               parent_path_elements_[i].data()};
        }
    }

    void TearDown() override {
        // Free whatever CDI the state currently holds (may be a derived key after promote).
        if (crypto_context_ != nullptr && state_.min_cdi != nullptr) {
            crypto_context_->key_free(crypto_context_, state_.min_cdi);
            state_.min_cdi = nullptr;
        }
        n20_crypto_boringssl_close(crypto_context_);
        crypto_context_ = nullptr;
    }

    // Convenience: a path element of exactly the right size filled with 0x11.
    n20_slice_t valid_path_element() {
        path_element_.fill(0x11);
        return {sizeof(n20_compressed_input_t), const_cast<uint8_t*>(path_element_.data())};
    }

    // Convenience: a compressed context of exactly the right size filled with 0x33.
    n20_slice_t valid_compressed_context() {
        compressed_context_.fill(0x33);
        return {sizeof(n20_compressed_input_t), const_cast<uint8_t*>(compressed_context_.data())};
    }

    n20_parent_path_t valid_path() {
        return {.length = 2, .is_encoded = false, .decoded = parent_path_elements_slices_.data()};
    }

    n20_crypto_context_t* crypto_context_ = nullptr;
    MockCryptoContext mock_crypto_context_;
    n20_gnostic_node_state_t state_{};

    std::array<uint8_t, sizeof(n20_compressed_input_t)> path_element_{};
    std::array<uint8_t, sizeof(n20_compressed_input_t)> compressed_context_{};
    std::array<uint8_t, 4096> cert_buffer_{};
    std::array<uint8_t, 256> sign_buffer_{};
    std::array<std::array<uint8_t, sizeof(n20_compressed_input_t)>, 4> parent_path_elements_{};
    std::array<n20_slice_t, 4> parent_path_elements_slices_{};
};

// ---------------------------------------------------------------------------
// check_node_state: NULL ctx
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, NullCtxAllOpsReturnUnexpectedNullServiceState) {
    n20_msg_promote_request_t promote_req{.compressed_context = valid_compressed_context()};
    EXPECT_EQ(n20_error_unexpected_null_service_state_e,
              n20_gnostic_service_ops.n20_srv_promote(nullptr, &promote_req));

    n20_msg_issue_cdi_cert_request_t cdi_req{};
    size_t cdi_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_state_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  nullptr, &cdi_req, cert_buffer_.data(), &cdi_sz));

    n20_msg_issue_eca_cert_request_t eca_req{};
    size_t eca_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_state_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  nullptr, &eca_req, cert_buffer_.data(), &eca_sz));

    n20_msg_issue_eca_ee_cert_request_t ee_req{};
    size_t ee_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_state_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  nullptr, &ee_req, cert_buffer_.data(), &ee_sz));

    n20_msg_eca_ee_sign_request_t sign_req{};
    size_t sig_sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_state_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(
                  nullptr, &sign_req, sign_buffer_.data(), &sig_sz));
}

// ---------------------------------------------------------------------------
// check_node_state: NULL crypto_context
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, NullCryptoContextAllOpsReturnMissingCryptoContext) {
    n20_gnostic_node_state_t bad{.crypto_context = nullptr, .min_cdi = state_.min_cdi};

    n20_msg_promote_request_t promote_req{.compressed_context = valid_compressed_context()};
    EXPECT_EQ(n20_error_missing_crypto_context_e,
              n20_gnostic_service_ops.n20_srv_promote(&bad, &promote_req));

    n20_msg_issue_cdi_cert_request_t cdi_req{};
    size_t cdi_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_missing_crypto_context_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &bad, &cdi_req, cert_buffer_.data(), &cdi_sz));

    n20_msg_issue_eca_cert_request_t eca_req{};
    size_t eca_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_missing_crypto_context_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  &bad, &eca_req, cert_buffer_.data(), &eca_sz));

    n20_msg_issue_eca_ee_cert_request_t ee_req{};
    size_t ee_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_missing_crypto_context_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &bad, &ee_req, cert_buffer_.data(), &ee_sz));

    n20_msg_eca_ee_sign_request_t sign_req{};
    size_t sig_sz = sign_buffer_.size();
    EXPECT_EQ(
        n20_error_missing_crypto_context_e,
        n20_gnostic_service_ops.n20_srv_eca_ee_sign(&bad, &sign_req, sign_buffer_.data(), &sig_sz));
}

// ---------------------------------------------------------------------------
// check_node_state: NULL min_cdi (service disabled)
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, NullMinCdiAllOpsReturnServiceDisabled) {
    // Use a separate state so the fixture's valid state_ is unaffected.
    n20_gnostic_node_state_t bad{.crypto_context = crypto_context_, .min_cdi = nullptr};

    n20_msg_promote_request_t promote_req{.compressed_context = valid_compressed_context()};
    EXPECT_EQ(n20_error_service_disabled_e,
              n20_gnostic_service_ops.n20_srv_promote(&bad, &promote_req));

    n20_msg_issue_cdi_cert_request_t cdi_req{};
    size_t cdi_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_service_disabled_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &bad, &cdi_req, cert_buffer_.data(), &cdi_sz));

    n20_msg_issue_eca_cert_request_t eca_req{};
    size_t eca_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_service_disabled_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  &bad, &eca_req, cert_buffer_.data(), &eca_sz));

    n20_msg_issue_eca_ee_cert_request_t ee_req{};
    size_t ee_sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_service_disabled_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &bad, &ee_req, cert_buffer_.data(), &ee_sz));

    n20_msg_eca_ee_sign_request_t sign_req{};
    size_t sig_sz = sign_buffer_.size();
    EXPECT_EQ(
        n20_error_service_disabled_e,
        n20_gnostic_service_ops.n20_srv_eca_ee_sign(&bad, &sign_req, sign_buffer_.data(), &sig_sz));
}

// ---------------------------------------------------------------------------
// NULL request
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, NullRequestAllOpsReturnUnexpectedNullServiceRequest) {
    EXPECT_EQ(n20_error_unexpected_null_service_request_e,
              n20_gnostic_service_ops.n20_srv_promote(&state_, nullptr));

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_request_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, nullptr, cert_buffer_.data(), &sz));

    sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_request_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  &state_, nullptr, cert_buffer_.data(), &sz));

    sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_null_service_request_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, nullptr, cert_buffer_.data(), &sz));

    sz = sign_buffer_.size();
    EXPECT_EQ(
        n20_error_unexpected_null_service_request_e,
        n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, nullptr, sign_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, ForwardPromoteCryptoErrors) {
    // Set the mock context to return an error on the next KDF call, which will be made during
    // promote.
    mock_crypto_context_.err_on_zero_kdf = 0;
    mock_crypto_context_.kdf_error = n20_error_crypto_implementation_specific_e;

    n20_msg_promote_request_t req{.compressed_context = valid_compressed_context()};

    EXPECT_EQ(n20_error_crypto_implementation_specific_e,
              n20_gnostic_service_ops.n20_srv_promote(&state_, &req));
}

TEST_F(GnosticNodeTest, ForwardCdiCertCryptoErrors) {
    n20_msg_issue_cdi_cert_request_t req{.parent_path = valid_path()};
    req.parent_path.length = 2;

    // Set the mock context to return an error on the next kdf call, which will be made during
    // CDI derivation.
    mock_crypto_context_.err_on_zero_kdf = 0;
    mock_crypto_context_.kdf_error = n20_error_crypto_implementation_specific_e;

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_crypto_implementation_specific_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, ForwardEcaCertCryptoErrors) {
    n20_msg_issue_eca_cert_request_t req{.parent_path = valid_path()};
    req.parent_path.length = 2;

    // Set the mock context to return an error on the next kdf call, which will be made during
    // CDI derivation.
    mock_crypto_context_.err_on_zero_kdf = 0;
    mock_crypto_context_.kdf_error = n20_error_crypto_implementation_specific_e;

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_crypto_implementation_specific_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

// ---------------------------------------------------------------------------
// ECA EE cert: unsupported key usage
//
// key_usage validation: first byte must be 0x00 or 0x01;
// any subsequent byte must be 0x00.
// Uses parent_path_length=0 so n20_resolve_path is a trivial pass-through.
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, IssueEcaEECertEmptyKeyUsageProducesUnusableKey) {
    n20_msg_issue_eca_ee_cert_request_t req{
        .issuer_key_type = n20_crypto_key_type_ed25519_e,
        .subject_key_type = n20_crypto_key_type_ed25519_e,
        .certificate_format = n20_certificate_format_x509_e,
    };
    req.key_usage = {0, nullptr};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, IssueEcaEECertLongEmptyKeyUsageProducesUnusableKey) {
    std::array<uint8_t, 3> const long_usage = {0, 0, 0};
    n20_msg_issue_eca_ee_cert_request_t req{
        .issuer_key_type = n20_crypto_key_type_ed25519_e,
        .subject_key_type = n20_crypto_key_type_ed25519_e,
        .certificate_format = n20_certificate_format_x509_e,
    };
    req.key_usage = {long_usage.size(), const_cast<uint8_t*>(long_usage.data())};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, IssueEcaEECertLongNonEmptyKeyUsageReturnsError) {
    std::array<uint8_t, 3> const long_usage = {0, 0, 1};
    n20_msg_issue_eca_ee_cert_request_t req{};
    req.key_usage = {long_usage.size(), const_cast<uint8_t*>(long_usage.data())};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unsupported_key_usage_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, IssueEcaEeCertUnsupportedKeyUsageBitReturnsError) {
    std::array<uint8_t, 1> const bad_usage = {0x02};  // bit 1 set – not allowed
    n20_msg_issue_eca_ee_cert_request_t req{};
    req.key_usage = {bad_usage.size(), const_cast<uint8_t*>(bad_usage.data())};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unsupported_key_usage_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, IssueEcaEeCertUnsupportedKeyUsageNonzeroSecondByteReturnsError) {
    std::array<uint8_t, 2> const bad_usage = {0x01, 0x01};  // second byte non-zero
    n20_msg_issue_eca_ee_cert_request_t req{};
    req.key_usage = {bad_usage.size(), const_cast<uint8_t*>(bad_usage.data())};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unsupported_key_usage_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, ForwardEcaEECertCryptoErrors) {
    n20_msg_issue_eca_ee_cert_request_t req{.parent_path = valid_path()};
    req.parent_path.length = 2;
    req.key_usage = {0, nullptr};  // valid but empty key usage

    // Set the mock context to return an error on the next kdf call, which will be made during
    // ECA signing.
    mock_crypto_context_.err_on_zero_kdf = 0;
    mock_crypto_context_.kdf_error = n20_error_crypto_implementation_specific_e;

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_crypto_implementation_specific_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
}

// ---------------------------------------------------------------------------
// ECA EE sign: unsupported key usage
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, EcaSignEmptyKeyUsageReturnsError) {
    std::array<uint8_t, 1> const bad_usage = {0x04};  // bit 2 set – not allowed
    std::array<uint8_t, 4> const msg = {0x01, 0x02, 0x03, 0x04};
    n20_msg_eca_ee_sign_request_t req{};
    req.key_usage = {0, nullptr};  // empty key usage is not allowed
    req.message = {msg.size(), const_cast<uint8_t*>(msg.data())};

    size_t sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_key_usage_not_permitted_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, EcaSignUnsupportedKeyUsageBitReturnsError) {
    std::array<uint8_t, 1> const bad_usage = {0x04};  // bit 2 set – not allowed
    std::array<uint8_t, 4> const msg = {0x01, 0x02, 0x03, 0x04};
    n20_msg_eca_ee_sign_request_t req{};
    req.key_usage = {bad_usage.size(), const_cast<uint8_t*>(bad_usage.data())};
    req.message = {msg.size(), const_cast<uint8_t*>(msg.data())};

    size_t sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_key_usage_not_permitted_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, EcaSignUnsupportedKeyUsageNonzeroSecondByteReturnsError) {
    std::array<uint8_t, 3> const bad_usage = {0x00, 0x00, 0x01};  // third byte non-zero
    std::array<uint8_t, 4> const msg = {0xAA, 0xBB, 0xCC, 0xDD};
    n20_msg_eca_ee_sign_request_t req{};
    req.key_usage = {bad_usage.size(), const_cast<uint8_t*>(bad_usage.data())};
    req.message = {msg.size(), const_cast<uint8_t*>(msg.data())};

    size_t sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_key_usage_not_permitted_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));
}

TEST_F(GnosticNodeTest, ForwardEcaSignCryptoErrors) {
    std::array<uint8_t, 4> const msg = {0xDE, 0xAD, 0xBE, 0xEF};
    n20_msg_eca_ee_sign_request_t req{.parent_path = valid_path()};
    req.parent_path.length = 2;
    req.key_usage = {0, nullptr};  // valid but empty key usage
    req.message = {msg.size(), const_cast<uint8_t*>(msg.data())};

    // Set the mock context to return an error on the next kdf call, which will be made during
    // ECA signing.
    mock_crypto_context_.err_on_zero_kdf = 0;
    mock_crypto_context_.kdf_error = n20_error_crypto_implementation_specific_e;

    size_t sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_crypto_implementation_specific_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));

    // Set the mock context to return an error on the next key free call, which will be made during
    // ECA signing.
    mock_crypto_context_.err_on_zero_kdf = 1;
    mock_crypto_context_.kdf_error = n20_error_crypto_implementation_specific_e;

    sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_crypto_implementation_specific_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));
}

// ---------------------------------------------------------------------------
// Success paths
// ---------------------------------------------------------------------------

TEST_F(GnosticNodeTest, PromoteSuccess) {
    n20_msg_promote_request_t req{.compressed_context = valid_compressed_context()};
    EXPECT_EQ(n20_error_ok_e, n20_gnostic_service_ops.n20_srv_promote(&state_, &req));
    // After a successful promote, state_.min_cdi holds the new derived key.
    EXPECT_NE(nullptr, state_.min_cdi);
}

TEST_F(GnosticNodeTest, IssueCdiCertSuccess) {
    n20_msg_issue_cdi_cert_request_t req{.parent_path = valid_path()};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 0;
    req.certificate_format = n20_certificate_format_x509_e;
    // next_context left zero-initialised; open dice input is optional.

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);

    // exercise path processing (derivation and freeing of intermediates)
    req.parent_path.length = 2;

    sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);
}

TEST_F(GnosticNodeTest, IssueEcaCertSuccess) {
    n20_msg_issue_eca_cert_request_t req{.parent_path = valid_path()};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 0;
    req.certificate_format = n20_certificate_format_x509_e;
    req.challenge = {0, nullptr};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);

    // exercise path processing (derivation and freeing of intermediates)
    req.parent_path.length = 2;

    sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);
}

TEST_F(GnosticNodeTest, IssueEcaEeCertSuccess) {
    std::array<uint8_t, 1> const key_usage_data = {0x01};  // digital signature
    n20_msg_issue_eca_ee_cert_request_t req{.parent_path = valid_path()};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 0;
    req.certificate_format = n20_certificate_format_x509_e;
    req.name = {3, "key"};
    req.key_usage = {key_usage_data.size(), const_cast<uint8_t*>(key_usage_data.data())};
    req.challenge = {0, nullptr};

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);

    // exercise path processing (derivation and freeing of intermediates)
    req.parent_path.length = 2;

    sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_eca_ee_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);
}

TEST_F(GnosticNodeTest, EcaSignSuccess) {
    std::array<uint8_t, 1> const key_usage_data = {0x01};  // digital signature
    std::array<uint8_t, 8> const message_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    n20_msg_eca_ee_sign_request_t req{.parent_path = valid_path()};
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 0;
    req.name = {3, "key"};
    req.key_usage = {key_usage_data.size(), const_cast<uint8_t*>(key_usage_data.data())};
    req.message = {message_data.size(), const_cast<uint8_t*>(message_data.data())};

    size_t sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);

    // exercise path processing (derivation and freeing of intermediates)
    req.parent_path.length = 2;

    sz = sign_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_eca_ee_sign(&state_, &req, sign_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);
}

// ---------------------------------------------------------------------------
// n20_resolve_path: exercised through the cert ops via parent_path_length > 0.
//
// Code paths covered:
//   depth=1  the straight-line derivation branch (while-loop not entered)
//   depth=2  the while-loop body runs once, freeing the intermediate key
//   different output  a derived issuer key produces a cert distinct from the
//                     root-issuer cert (confirms path is actually applied)
//   determinism       the same path yields byte-identical certificates
// ---------------------------------------------------------------------------

// A depth-1 path exercises the straight-line derivation in n20_resolve_path
// (the while-loop condition evaluates to false immediately).
TEST_F(GnosticNodeTest, ResolvePathDepth1IssuesCertSuccessfully) {
    n20_msg_issue_cdi_cert_request_t req{.parent_path = valid_path()};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 1;
    req.certificate_format = n20_certificate_format_x509_e;

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);
}

// A depth-2 path exercises the while-loop body in n20_resolve_path, which
// frees the intermediate derived key before proceeding.
TEST_F(GnosticNodeTest, ResolvePathDepth2IssuesCertSuccessfully) {
    n20_msg_issue_cdi_cert_request_t req{.parent_path = valid_path()};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 2;
    req.certificate_format = n20_certificate_format_x509_e;

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);
}

// A non-trivial path must yield a certificate different from the one produced
// with no path (different issuer key => different cert).
TEST_F(GnosticNodeTest, ResolvePathProducesDifferentCertThanNullPath) {
    n20_msg_issue_cdi_cert_request_t req_no_path{};
    req_no_path.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req_no_path.subject_key_type = n20_crypto_key_type_ed25519_e;
    req_no_path.certificate_format = n20_certificate_format_x509_e;

    std::array<uint8_t, 4096> cert_no_path{};
    size_t sz_no_path = cert_no_path.size();
    ASSERT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req_no_path, cert_no_path.data(), &sz_no_path));

    n20_msg_issue_cdi_cert_request_t req_with_path{.parent_path = valid_path()};
    req_with_path.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req_with_path.subject_key_type = n20_crypto_key_type_ed25519_e;
    req_with_path.parent_path.length = 1;
    req_with_path.certificate_format = n20_certificate_format_x509_e;

    size_t sz_with_path = cert_buffer_.size();
    ASSERT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req_with_path, cert_buffer_.data(), &sz_with_path));

    // The two certificates must differ (different issuer key, different signature).
    EXPECT_FALSE(sz_no_path == sz_with_path &&
                 std::memcmp(cert_no_path.data() + cert_no_path.size() - sz_no_path,
                             cert_buffer_.data() + cert_buffer_.size() - sz_with_path,
                             sz_no_path) == 0);
}

// Key derivation is deterministic: two identical requests must produce
// byte-for-byte identical certificates.
TEST_F(GnosticNodeTest, ResolvePathIsDeterministic) {
    n20_msg_issue_cdi_cert_request_t req{.parent_path = valid_path()};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.parent_path.length = 1;
    req.certificate_format = n20_certificate_format_x509_e;

    std::array<uint8_t, 4096> first_cert{};
    size_t sz_first = first_cert.size();
    ASSERT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, first_cert.data(), &sz_first));

    size_t sz_second = cert_buffer_.size();
    ASSERT_EQ(n20_error_ok_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz_second));

    ASSERT_EQ(sz_first, sz_second);
    EXPECT_EQ(0,
              std::memcmp(first_cert.data() + first_cert.size() - sz_first,
                          cert_buffer_.data() + cert_buffer_.size() - sz_second,
                          sz_first));
}

TEST_F(GnosticNodeTest, ResolvePathFreesIntermediateDerivedKeyIfPathParsingErrorsOut) {
    // A depth-2 path requires one intermediate key to be derived and freed
    // even if the path fails to parse (in this case due to length mismatch in the encoded path).
    uint8_t invalid_encoded_path[] = {
        0x82, 0x41, 0xaa,  // length=2, but only 1 element provided.
    };
    n20_msg_issue_cdi_cert_request_t req{
        .parent_path = {.length = 2,
                        .is_encoded = true,
                        .encoded = {sizeof(invalid_encoded_path), invalid_encoded_path}}};
    req.issuer_key_type = n20_crypto_key_type_ed25519_e;
    req.subject_key_type = n20_crypto_key_type_ed25519_e;
    req.certificate_format = n20_certificate_format_x509_e;

    size_t sz = cert_buffer_.size();
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_gnostic_service_ops.n20_srv_issue_cdi_certificate(
                  &state_, &req, cert_buffer_.data(), &sz));
    EXPECT_GT(sz, 0u);

    // The intermediate key must have been freed (1 call for the intermediate, 1 for the final
    // cert key).
    EXPECT_EQ(1u, mock_crypto_context_.free_key_calls);
}

}  // namespace
