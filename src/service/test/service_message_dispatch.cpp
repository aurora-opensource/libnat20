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
#include <nat20/cbor.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/service/service_message_dispatch.h>
#include <nat20/stream.h>
#include <nat20/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <tuple>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Test double state
// ---------------------------------------------------------------------------

struct StubState {
    // Configurable return codes for each op.
    n20_error_t promote_rc = n20_error_ok_e;
    n20_error_t issue_cdi_cert_rc = n20_error_ok_e;
    n20_error_t issue_eca_cert_rc = n20_error_ok_e;
    n20_error_t issue_eca_ee_cert_rc = n20_error_ok_e;
    n20_error_t sign_rc = n20_error_ok_e;

    // Call counters.
    size_t promote_calls = 0;
    size_t issue_cdi_cert_calls = 0;
    size_t issue_eca_cert_calls = 0;
    size_t issue_eca_ee_cert_calls = 0;
    size_t sign_calls = 0;

    // Payload written back to the caller for cert/sign ops.
    n20_slice_t cert_payload = {0, nullptr};
    n20_slice_t sign_payload = {0, nullptr};

    // Insanely large payloads.
    bool oversized_payloads = false;
};

// Write stub payload into the back of [buffer, buffer + *size_in_out).
static n20_error_t write_stub_payload(uint8_t* buffer, size_t* size_in_out, n20_slice_t payload) {
    if (payload.size > *size_in_out) {
        *size_in_out = payload.size;
        return n20_error_insufficient_buffer_size_e;
    }
    memcpy(buffer + (*size_in_out - payload.size), payload.buffer, payload.size);
    *size_in_out = payload.size;
    return n20_error_ok_e;
}

// ---------------------------------------------------------------------------
// C-linkage stubs
// ---------------------------------------------------------------------------

extern "C" {

static n20_error_t stub_promote(void* ctx, n20_msg_promote_request_t* /*request*/) {
    auto* s = static_cast<StubState*>(ctx);
    s->promote_calls++;
    return s->promote_rc;
}

static n20_error_t stub_issue_cdi_certificate(void* ctx,
                                              n20_msg_issue_cdi_cert_request_t* /*request*/,
                                              uint8_t* certificate,
                                              size_t* certificate_size) {
    auto* s = static_cast<StubState*>(ctx);
    s->issue_cdi_cert_calls++;
    if (s->issue_cdi_cert_rc != n20_error_ok_e) {
        return s->issue_cdi_cert_rc;
    }
    if (s->oversized_payloads) {
        *certificate_size = std::numeric_limits<size_t>::max();
        return n20_error_ok_e;
    }
    return write_stub_payload(certificate, certificate_size, s->cert_payload);
}

static n20_error_t stub_issue_eca_certificate(void* ctx,
                                              n20_msg_issue_eca_cert_request_t* /*request*/,
                                              uint8_t* certificate,
                                              size_t* certificate_size) {
    auto* s = static_cast<StubState*>(ctx);
    s->issue_eca_cert_calls++;
    if (s->issue_eca_cert_rc != n20_error_ok_e) {
        return s->issue_eca_cert_rc;
    }
    if (s->oversized_payloads) {
        *certificate_size = std::numeric_limits<size_t>::max();
        return n20_error_ok_e;
    }
    return write_stub_payload(certificate, certificate_size, s->cert_payload);
}

static n20_error_t stub_issue_eca_ee_certificate(void* ctx,
                                                 n20_msg_issue_eca_ee_cert_request_t* /*request*/,
                                                 uint8_t* certificate,
                                                 size_t* certificate_size) {
    auto* s = static_cast<StubState*>(ctx);
    s->issue_eca_ee_cert_calls++;
    if (s->issue_eca_ee_cert_rc != n20_error_ok_e) {
        return s->issue_eca_ee_cert_rc;
    }
    if (s->oversized_payloads) {
        *certificate_size = std::numeric_limits<size_t>::max();
        return n20_error_ok_e;
    }
    return write_stub_payload(certificate, certificate_size, s->cert_payload);
}

static n20_error_t stub_eca_sign(void* ctx,
                                 n20_msg_eca_ee_sign_request_t* /*request*/,
                                 uint8_t* signature,
                                 size_t* signature_size) {
    auto* s = static_cast<StubState*>(ctx);
    s->sign_calls++;
    if (s->sign_rc != n20_error_ok_e) {
        return s->sign_rc;
    }
    if (s->oversized_payloads) {
        *signature_size = std::numeric_limits<size_t>::max();
        return n20_error_ok_e;
    }
    return write_stub_payload(signature, signature_size, s->sign_payload);
}

}  // extern "C"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ServiceMessageDispatchTest : public testing::Test {
   protected:
    // Sizes of fake cert and signature payloads.
    static constexpr size_t kCertSize = 32;
    static constexpr size_t kSignSize = 16;

    void SetUp() override {
        ops_.n20_srv_promote = stub_promote;
        ops_.n20_srv_issue_cdi_certificate = stub_issue_cdi_certificate;
        ops_.n20_srv_issue_eca_certificate = stub_issue_eca_certificate;
        ops_.n20_srv_issue_eca_ee_certificate = stub_issue_eca_ee_certificate;
        ops_.n20_srv_eca_ee_sign = stub_eca_sign;

        ctx_.ops = &ops_;
        ctx_.ctx = &state_;

        // Fill payloads with recognisable patterns.
        cert_payload_data_.fill(0xCC);
        sign_payload_data_.fill(0xDD);

        state_.cert_payload = {cert_payload_data_.size(), cert_payload_data_.data()};
        state_.sign_payload = {sign_payload_data_.size(), sign_payload_data_.data()};

        // A valid compressed-context element is exactly sizeof(n20_compressed_input_t) bytes.
        valid_path_element_data_.fill(0x11);
        valid_context_data_.fill(0x22);
        key_usage_data_.fill(0x03);
        parent_path_elements_ = {
            {{valid_path_element_data_.size(), valid_path_element_data_.data()}}};

        state_.oversized_payloads = false;
        response_buffer_.resize(1024);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    // Encode a request to the end of request_buffer_ and return its slice.
    n20_slice_t encode_request(n20_msg_request_t const& req) {
        size_t sz = request_buffer_.size();
        EXPECT_EQ(n20_error_ok_e, n20_msg_request_write(&req, request_buffer_.data(), &sz));
        return {sz, request_buffer_.data() + (request_buffer_.size() - sz)};
    }

    // Run the dispatcher; return the return code and the response slice.
    std::tuple<n20_error_t, n20_slice_t> dispatch(n20_slice_t message) {
        size_t sz = response_buffer_.size();
        n20_error_t rc = n20_service_message_dispatch(&ctx_, response_buffer_.data(), &sz, message);
        n20_slice_t response = {sz,
                                sz <= response_buffer_.size()
                                    ? response_buffer_.data() + (response_buffer_.size() - sz)
                                    : nullptr};
        return {rc, response};
    }

    // Parse a success response body: CBOR map{1}{ uint(label) => bytes }.
    // Returns true and populates *bytes_out on success.
    static bool parse_labelled_bytes(n20_slice_t response,
                                     uint64_t expected_label,
                                     n20_slice_t* bytes_out) {
        n20_istream_t s;
        n20_istream_init(&s, response.buffer, response.size);

        n20_cbor_type_t type{};
        uint64_t value{};

        if (!n20_cbor_read_header(&s, &type, &value)) return false;
        if (type != n20_cbor_type_map_e || value != 1) return false;

        if (!n20_cbor_read_header(&s, &type, &value)) return false;
        if (type != n20_cbor_type_uint_e || value != expected_label) return false;

        if (!n20_cbor_read_header(&s, &type, &value)) return false;
        if (type != n20_cbor_type_bytes_e) return false;

        return n20_istream_get_slice(&s, bytes_out, static_cast<size_t>(value)) &&
               !n20_istream_has_buffer_underrun(&s);
    }

    // Parse an error response and return the embedded error code.
    static n20_error_t parse_error_response(n20_slice_t response) {
        n20_msg_error_response_t r{};
        EXPECT_EQ(n20_error_ok_e, n20_msg_error_response_read(&r, response));
        return r.error_code;
    }

    n20_slice_t valid_path_element() const {
        return {valid_path_element_data_.size(),
                const_cast<uint8_t*>(valid_path_element_data_.data())};
    }

    n20_parent_path_t valid_path() const {
        return {.length = 1, .is_encoded = false, .decoded = parent_path_elements_.data()};
    }

    n20_slice_t valid_context() const {
        return {valid_context_data_.size(), const_cast<uint8_t*>(valid_context_data_.data())};
    }

    n20_slice_t key_usage() const {
        return {key_usage_data_.size(), const_cast<uint8_t*>(key_usage_data_.data())};
    }

    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------

    StubState state_{};
    n20_service_ops_t ops_{};
    n20_service_message_dispatch_ctx_t ctx_{};

    std::array<uint8_t, 1024> request_buffer_{};
    std::vector<uint8_t> response_buffer_;
    std::array<uint8_t, kCertSize> cert_payload_data_{};
    std::array<uint8_t, kSignSize> sign_payload_data_{};
    std::array<uint8_t, sizeof(n20_compressed_input_t)> valid_path_element_data_{};
    std::array<uint8_t, sizeof(n20_compressed_input_t)> valid_context_data_{};
    std::array<uint8_t, 2> key_usage_data_{};
    std::array<n20_slice_t, 1> parent_path_elements_{};
};

// ---------------------------------------------------------------------------
// Malformed / unknown request tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, MalformedCborProducesErrorResponse) {
    // A single CBOR integer is not a valid request; the dispatcher must still
    // write an error response and return n20_error_ok_e to its caller.
    std::array<uint8_t, 1> const bad = {0x00};
    n20_slice_t const message = {bad.size(), const_cast<uint8_t*>(bad.data())};

    auto const [rc, response] = dispatch(message);

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_NE(n20_error_ok_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, UnknownRequestTypeProducesUnknownTypeErrorResponse) {
    // CBOR [99, {}] — a two-element array with an unrecognised request-type value.
    // Encode manually: 0x82 (array 2), 0x18 0x63 (uint 99), 0xa0 (map 0).
    std::array<uint8_t, 4> const raw = {0x82, 0x18, 0x63, 0xa0};
    n20_slice_t const message = {raw.size(), const_cast<uint8_t*>(raw.data())};

    auto const [rc, response] = dispatch(message);

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_request_type_unknown_e, parse_error_response(response));
    // None of the service ops should have been invoked.
    EXPECT_EQ(0u, state_.promote_calls);
    EXPECT_EQ(0u, state_.issue_cdi_cert_calls);
}

// ---------------------------------------------------------------------------
// Promote tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, PromoteSuccess) {
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_promote_e,
        .payload = {.promote = {.compressed_context = valid_context()}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.promote_calls);
    EXPECT_EQ(n20_error_ok_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, PromoteForwardsServiceError) {
    state_.promote_rc = n20_error_crypto_invalid_context_e;

    n20_msg_request_t req{
        .request_type = n20_msg_request_type_promote_e,
        .payload = {.promote = {.compressed_context = valid_context()}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.promote_calls);
    EXPECT_EQ(n20_error_crypto_invalid_context_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, PromoteInsufficientBufferSize) {
    // Set the response buffer size to 0 so that even the error response cannot be written.
    size_t const original_size = response_buffer_.size();
    size_t response_size = 0;

    n20_msg_request_t req{
        .request_type = n20_msg_request_type_promote_e,
        .payload = {.promote = {.compressed_context = valid_context()}},
    };

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.promote_calls);
    EXPECT_EQ(original_size, response_buffer_.size());
}

// ---------------------------------------------------------------------------
// Issue CDI certificate tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, IssueCdiCertSuccessWrapsCertificate) {
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_cdi_cert_e,
        .payload = {.issue_cdi_cert = {.issuer_key_type = n20_crypto_key_type_ed25519_e,
                                       .subject_key_type = n20_crypto_key_type_ed25519_e,
                                       .next_context = {},
                                       .parent_path = valid_path(),
                                       .certificate_format = n20_certificate_format_x509_e}},
    };

    response_buffer_.resize(0);

    auto [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.issue_cdi_cert_calls);

    response_buffer_.resize(response.size);

    std::tie(rc, response) = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(2u, state_.issue_cdi_cert_calls);
    EXPECT_EQ(response_buffer_.size(), response.size);

    n20_slice_t cert{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_CERTIFICATE, &cert));
    ASSERT_EQ(kCertSize, cert.size);
    EXPECT_EQ(0, memcmp(cert_payload_data_.data(), cert.buffer, kCertSize));
}

TEST_F(ServiceMessageDispatchTest, IssueCdiCertForwardsServiceError) {
    state_.issue_cdi_cert_rc = n20_error_crypto_invalid_context_e;
    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_cdi_cert_e;
    req.payload.issue_cdi_cert = {};
    req.payload.issue_cdi_cert.parent_path = valid_path();

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_cdi_cert_calls);
    EXPECT_EQ(n20_error_crypto_invalid_context_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, IssueCdiCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // test payload but not for the response header.
    size_t response_size = state_.cert_payload.size;

    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_cdi_cert_e;
    req.payload.issue_cdi_cert = {};
    req.payload.issue_cdi_cert.parent_path = valid_path();

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.issue_cdi_cert_calls);
}

// ---------------------------------------------------------------------------
// Issue ECA certificate tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, IssueEcaCertSuccessWrapsCertificate) {
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_cert_e,
        .payload = {.issue_eca_cert = {.issuer_key_type = n20_crypto_key_type_ed25519_e,
                                       .subject_key_type = n20_crypto_key_type_ed25519_e,
                                       .parent_path = valid_path(),
                                       .certificate_format = n20_certificate_format_x509_e,
                                       .challenge = {}}},
    };

    response_buffer_.resize(0);
    auto [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_cert_calls);

    response_buffer_.resize(response.size);
    std::tie(rc, response) = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(2u, state_.issue_eca_cert_calls);
    EXPECT_EQ(response_buffer_.size(), response.size);

    n20_slice_t cert{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_CERTIFICATE, &cert));
    ASSERT_EQ(kCertSize, cert.size);
    EXPECT_EQ(0, memcmp(cert_payload_data_.data(), cert.buffer, kCertSize));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaCertForwardsServiceError) {
    state_.issue_eca_cert_rc = n20_error_missing_crypto_context_e;

    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_eca_cert_e;
    req.payload.issue_eca_cert = {};
    req.payload.issue_eca_cert.parent_path = valid_path();

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_cert_calls);
    EXPECT_EQ(n20_error_missing_crypto_context_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, IssueEcaCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // test payload but not for the response header.
    size_t response_size = state_.cert_payload.size;

    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_eca_cert_e;
    req.payload.issue_eca_cert = {};
    req.payload.issue_eca_cert.parent_path = valid_path();

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_cert_calls);
}

// ---------------------------------------------------------------------------
// Issue ECA EE certificate tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertSuccessWrapsCertificate) {
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_ee_cert_e,
        .payload = {.issue_eca_ee_cert = {.issuer_key_type = n20_crypto_key_type_ed25519_e,
                                          .subject_key_type = n20_crypto_key_type_ed25519_e,
                                          .parent_path = valid_path(),
                                          .certificate_format = n20_certificate_format_x509_e,
                                          .name = {4, "test"},
                                          .key_usage = key_usage(),
                                          .challenge = {}}},
    };

    response_buffer_.resize(0);

    auto [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_ee_cert_calls);
    response_buffer_.resize(response.size);

    std::tie(rc, response) = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(2u, state_.issue_eca_ee_cert_calls);

    n20_slice_t cert{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_CERTIFICATE, &cert));
    ASSERT_EQ(kCertSize, cert.size);
    EXPECT_EQ(0, memcmp(cert_payload_data_.data(), cert.buffer, kCertSize));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertForwardsServiceError) {
    state_.issue_eca_ee_cert_rc = n20_error_unsupported_certificate_format_e;
    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_eca_ee_cert_e;
    req.payload.issue_eca_ee_cert = {};
    req.payload.issue_eca_ee_cert.parent_path = valid_path();

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_ee_cert_calls);
    EXPECT_EQ(n20_error_unsupported_certificate_format_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // test payload but not for the response header.
    size_t response_size = state_.cert_payload.size;

    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_eca_ee_cert_e;
    req.payload.issue_eca_ee_cert = {};
    req.payload.issue_eca_ee_cert.parent_path = valid_path();

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_ee_cert_calls);
}

// ---------------------------------------------------------------------------
// ECA EE sign tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, EcaIllInitializedContext) {
    n20_msg_request_t req{};

    ctx_.ops->n20_srv_promote = nullptr;
    req.request_type = n20_msg_request_type_promote_e;
    auto [rc, response] = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_request_type_not_implemented_e, parse_error_response(response));

    ctx_.ops->n20_srv_issue_cdi_certificate = nullptr;
    req.request_type = n20_msg_request_type_issue_cdi_cert_e;
    std::tie(rc, response) = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_request_type_not_implemented_e, parse_error_response(response));

    ctx_.ops->n20_srv_issue_eca_certificate = nullptr;
    req.request_type = n20_msg_request_type_issue_eca_cert_e;
    std::tie(rc, response) = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_request_type_not_implemented_e, parse_error_response(response));

    ctx_.ops->n20_srv_issue_eca_ee_certificate = nullptr;
    req.request_type = n20_msg_request_type_issue_eca_ee_cert_e;
    std::tie(rc, response) = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_request_type_not_implemented_e, parse_error_response(response));

    ctx_.ops->n20_srv_eca_ee_sign = nullptr;
    req.request_type = n20_msg_request_type_eca_ee_sign_e;
    std::tie(rc, response) = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_request_type_not_implemented_e, parse_error_response(response));

    ctx_.ops = nullptr;

    std::tie(rc, response) = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_unexpected_null_service_ops_e, rc);

    size_t response_size = response_buffer_.size();
    rc = n20_service_message_dispatch(
        nullptr, response_buffer_.data(), &response_size, encode_request(req));
    ASSERT_EQ(n20_error_unexpected_null_dispatch_context_e, rc);
}

TEST_F(ServiceMessageDispatchTest, DispatchWithNullResponseBufferSize) {
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_promote_e,
        .payload = {.promote = {.compressed_context = valid_context()}},
    };

    n20_error_t rc = n20_service_message_dispatch(&ctx_, nullptr, nullptr, encode_request(req));

    ASSERT_EQ(n20_error_unexpected_null_buffer_size_e, rc);
}

TEST_F(ServiceMessageDispatchTest, EcaEeSignSuccessWrapsSignature) {
    std::array<uint8_t, 4> const msg_bytes = {0x01, 0x02, 0x03, 0x04};
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_eca_ee_sign_e,
        .payload = {.eca_ee_sign = {.subject_key_type = n20_crypto_key_type_ed25519_e,
                                    .parent_path = valid_path(),
                                    .name = {6, "signer"},
                                    .key_usage = key_usage(),
                                    .message = {msg_bytes.size(),
                                                const_cast<uint8_t*>(msg_bytes.data())}}},
    };

    response_buffer_.resize(1);

    auto [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
    EXPECT_EQ(1u, state_.sign_calls);

    response_buffer_.resize(response.size);

    std::tie(rc, response) = dispatch(encode_request(req));
    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(2u, state_.sign_calls);
    EXPECT_EQ(response_buffer_.size(), response.size);

    n20_slice_t sig{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_SIGNATURE, &sig));
    ASSERT_EQ(kSignSize, sig.size);
    EXPECT_EQ(0, memcmp(sign_payload_data_.data(), sig.buffer, kSignSize));
}

TEST_F(ServiceMessageDispatchTest, EcaEeSignForwardsServiceError) {
    state_.sign_rc = n20_error_missing_crypto_context_e;
    std::array<uint8_t, 2> const msg_bytes = {0xAA, 0xBB};
    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_eca_ee_sign_e;
    req.payload.eca_ee_sign = {};
    req.payload.eca_ee_sign.parent_path = valid_path();
    req.payload.eca_ee_sign.name = {3, "key"};
    req.payload.eca_ee_sign.key_usage = key_usage();
    req.payload.eca_ee_sign.message = {msg_bytes.size(),
                                       const_cast<uint8_t*>(msg_bytes.data())};

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.sign_calls);
    EXPECT_EQ(n20_error_missing_crypto_context_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, EcaEeSignInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // test payload but not for the response header.
    size_t response_size = state_.sign_payload.size;

    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_eca_ee_sign_e;
    req.payload.eca_ee_sign = {};
    req.payload.eca_ee_sign.parent_path = valid_path();

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_insufficient_buffer_size_e, rc);
}

TEST_F(ServiceMessageDispatchTest, WritePositionOverflow) {
    // This test covers the case where the service writes so large of a response
    // that it doesn't just overflow the provided buffer but the write position
    // counter.
    n20_msg_request_t req{};
    req.request_type = n20_msg_request_type_issue_cdi_cert_e;

    state_.oversized_payloads = true;

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(n20_error_write_position_overflow_e, parse_error_response(response));
}

}  // namespace
