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
};

// Write stub payload into the back of [buffer, buffer + *size_in_out).
static n20_error_t write_stub_payload(uint8_t* buffer, size_t* size_in_out, n20_slice_t payload) {
    if (payload.size > *size_in_out) {
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
        ops_.n20_srv_eca_sign = stub_eca_sign;

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
    struct DispatchResult {
        n20_error_t rc;
        n20_slice_t response;  // Points into response_buffer_.
    };

    DispatchResult dispatch(n20_slice_t message) {
        size_t sz = response_buffer_.size();
        n20_error_t rc = n20_service_message_dispatch(&ctx_, response_buffer_.data(), &sz, message);
        n20_slice_t response = {sz, response_buffer_.data() + (response_buffer_.size() - sz)};
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
    std::array<uint8_t, 1024> response_buffer_{};
    std::array<uint8_t, kCertSize> cert_payload_data_{};
    std::array<uint8_t, kSignSize> sign_payload_data_{};
    std::array<uint8_t, sizeof(n20_compressed_input_t)> valid_path_element_data_{};
    std::array<uint8_t, sizeof(n20_compressed_input_t)> valid_context_data_{};
    std::array<uint8_t, 2> key_usage_data_{};
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

TEST_F(ServiceMessageDispatchTest, PromoteRejectsWrongContextSize) {
    // Trim the context by one byte so it does not match sizeof(n20_compressed_input_t).
    n20_slice_t bad_context = valid_context();
    bad_context.size -= 1;

    n20_msg_request_t req{
        .request_type = n20_msg_request_type_promote_e,
        .payload = {.promote = {.compressed_context = bad_context}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.promote_calls);
    EXPECT_EQ(n20_error_incompatible_compressed_input_size_e, parse_error_response(response));
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
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_cdi_cert_e,
        .payload = {.issue_cdi_cert = {.issuer_key_type = n20_crypto_key_type_ed25519_e,
                                       .subject_key_type = n20_crypto_key_type_ed25519_e,
                                       .next_context = {},
                                       .parent_path_length = 1,
                                       .parent_path = {path},
                                       .certificate_format = n20_certificate_format_x509_e}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_cdi_cert_calls);

    n20_slice_t cert{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_CERTIFICATE, &cert));
    ASSERT_EQ(kCertSize, cert.size);
    EXPECT_EQ(0, memcmp(cert_payload_data_.data(), cert.buffer, kCertSize));
}

TEST_F(ServiceMessageDispatchTest, IssueCdiCertRejectsPathTooLong) {
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_cdi_cert_e,
        .payload = {.issue_cdi_cert = {.parent_path_length = N20_STATELESS_MAX_PATH_LENGTH + 1,
                                       .parent_path = {path}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.issue_cdi_cert_calls);
    EXPECT_EQ(n20_error_parent_path_size_exceeds_max_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, IssueCdiCertRejectsPathElementWithWrongSize) {
    // Path element one byte too short.
    n20_slice_t bad_element = valid_path_element();
    bad_element.size -= 1;

    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_cdi_cert_e,
        .payload = {.issue_cdi_cert = {.parent_path_length = 1, .parent_path = {bad_element}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.issue_cdi_cert_calls);
    EXPECT_EQ(n20_error_incompatible_compressed_input_size_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, IssueCdiCertForwardsServiceError) {
    state_.issue_cdi_cert_rc = n20_error_crypto_invalid_context_e;
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_cdi_cert_e,
        .payload = {.issue_cdi_cert = {.parent_path_length = 1, .parent_path = {path}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_cdi_cert_calls);
    EXPECT_EQ(n20_error_crypto_invalid_context_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of buffer response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, IssueCdiCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // thest payload not not for the response header.
    size_t const original_size = response_buffer_.size();
    size_t response_size = state_.cert_payload.size;

    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_cdi_cert_e,
        .payload = {.issue_cdi_cert = {.parent_path_length = 1, .parent_path = {path}}},
    };

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_cdi_cert_calls);
    EXPECT_EQ(
        n20_error_insufficient_buffer_size_e,
        parse_error_response(
            {response_size, response_buffer_.data() + state_.cert_payload.size - response_size}));
}

// ---------------------------------------------------------------------------
// Issue ECA certificate tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, IssueEcaCertSuccessWrapsCertificate) {
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_cert_e,
        .payload = {.issue_eca_cert = {.issuer_key_type = n20_crypto_key_type_ed25519_e,
                                       .subject_key_type = n20_crypto_key_type_ed25519_e,
                                       .parent_path_length = 1,
                                       .parent_path = {path},
                                       .certificate_format = n20_certificate_format_x509_e,
                                       .challenge = {}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_cert_calls);

    n20_slice_t cert{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_CERTIFICATE, &cert));
    ASSERT_EQ(kCertSize, cert.size);
    EXPECT_EQ(0, memcmp(cert_payload_data_.data(), cert.buffer, kCertSize));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaCertRejectsPathElementWithWrongSize) {
    n20_slice_t bad_element = valid_path_element();
    bad_element.size += 1;  // One byte too long.

    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_cert_e,
        .payload = {.issue_eca_cert = {.parent_path_length = 1, .parent_path = {bad_element}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.issue_eca_cert_calls);
    EXPECT_EQ(n20_error_incompatible_compressed_input_size_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaCertRejectsPathTooLong) {
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_cert_e,
        .payload = {.issue_eca_cert = {.parent_path_length = N20_STATELESS_MAX_PATH_LENGTH + 1,
                                       .parent_path = {path}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.issue_eca_cert_calls);
    EXPECT_EQ(n20_error_parent_path_size_exceeds_max_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaCertForwardsServiceError) {
    state_.issue_eca_cert_rc = n20_error_missing_crypto_context_e;
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_cert_e,
        .payload = {.issue_eca_cert = {.parent_path_length = 1, .parent_path = {path}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_cert_calls);
    EXPECT_EQ(n20_error_missing_crypto_context_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of buffer response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, IssueEcaCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // thest payload not not for the response header.
    size_t const original_size = response_buffer_.size();
    size_t response_size = state_.cert_payload.size;

    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_cert_e,
        .payload = {.issue_eca_cert = {.parent_path_length = 1, .parent_path = {path}}},
    };

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_cert_calls);
    EXPECT_EQ(
        n20_error_insufficient_buffer_size_e,
        parse_error_response(
            {response_size, response_buffer_.data() + state_.cert_payload.size - response_size}));
}

// ---------------------------------------------------------------------------
// Issue ECA EE certificate tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertSuccessWrapsCertificate) {
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_ee_cert_e,
        .payload = {.issue_eca_ee_cert = {.issuer_key_type = n20_crypto_key_type_ed25519_e,
                                          .subject_key_type = n20_crypto_key_type_ed25519_e,
                                          .parent_path_length = 1,
                                          .parent_path = {path},
                                          .certificate_format = n20_certificate_format_x509_e,
                                          .name = {4, "test"},
                                          .key_usage = key_usage(),
                                          .challenge = {}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_ee_cert_calls);

    n20_slice_t cert{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_CERTIFICATE, &cert));
    ASSERT_EQ(kCertSize, cert.size);
    EXPECT_EQ(0, memcmp(cert_payload_data_.data(), cert.buffer, kCertSize));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertRejectsPathTooLong) {
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_ee_cert_e,
        .payload = {.issue_eca_ee_cert = {.parent_path_length = N20_STATELESS_MAX_PATH_LENGTH + 1,
                                          .parent_path = {path}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.issue_eca_ee_cert_calls);
    EXPECT_EQ(n20_error_parent_path_size_exceeds_max_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertRejectsPathElementWithWrongSize) {
    n20_slice_t bad_element = valid_path_element();
    bad_element.size += 1;  // One byte too long.

    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_ee_cert_e,
        .payload = {.issue_eca_ee_cert = {.parent_path_length = 1, .parent_path = {bad_element}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.issue_eca_ee_cert_calls);
    EXPECT_EQ(n20_error_incompatible_compressed_input_size_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertForwardsServiceError) {
    state_.issue_eca_ee_cert_rc = n20_error_unsupported_certificate_format_e;
    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_ee_cert_e,
        .payload = {.issue_eca_ee_cert = {.parent_path_length = 1, .parent_path = {path}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_ee_cert_calls);
    EXPECT_EQ(n20_error_unsupported_certificate_format_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of buffer response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, IssueEcaEeCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // thest payload not not for the response header.
    size_t const original_size = response_buffer_.size();
    size_t response_size = state_.cert_payload.size;

    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_issue_eca_ee_cert_e,
        .payload = {.issue_eca_ee_cert = {.parent_path_length = 1, .parent_path = {path}}},
    };

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.issue_eca_ee_cert_calls);
    EXPECT_EQ(
        n20_error_insufficient_buffer_size_e,
        parse_error_response(
            {response_size, response_buffer_.data() + state_.cert_payload.size - response_size}));
}

// ---------------------------------------------------------------------------
// ECA EE sign tests
// ---------------------------------------------------------------------------

TEST_F(ServiceMessageDispatchTest, EcaEeSignSuccessWrapsSignature) {
    n20_slice_t const path = valid_path_element();
    std::array<uint8_t, 4> const msg_bytes = {0x01, 0x02, 0x03, 0x04};
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_eca_ee_sign_e,
        .payload = {.eca_ee_sign = {.subject_key_type = n20_crypto_key_type_ed25519_e,
                                    .parent_path_length = 1,
                                    .parent_path = {path},
                                    .name = {6, "signer"},
                                    .key_usage = key_usage(),
                                    .message = {msg_bytes.size(),
                                                const_cast<uint8_t*>(msg_bytes.data())}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.sign_calls);

    n20_slice_t sig{};
    ASSERT_TRUE(parse_labelled_bytes(response, N20_MSG_LABEL_SIGNATURE, &sig));
    ASSERT_EQ(kSignSize, sig.size);
    EXPECT_EQ(0, memcmp(sign_payload_data_.data(), sig.buffer, kSignSize));
}

TEST_F(ServiceMessageDispatchTest, EcaEeSignRejectsPathTooLong) {
    n20_slice_t const path = valid_path_element();
    std::array<uint8_t, 1> const msg_bytes = {0x42};
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_eca_ee_sign_e,
        .payload = {.eca_ee_sign = {.parent_path_length = N20_STATELESS_MAX_PATH_LENGTH + 1,
                                    .parent_path = {path},
                                    .name = {3, "key"},
                                    .key_usage = key_usage(),
                                    .message = {msg_bytes.size(),
                                                const_cast<uint8_t*>(msg_bytes.data())}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.sign_calls);
    EXPECT_EQ(n20_error_parent_path_size_exceeds_max_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, EcaEeSignRejectsPathElementWithWrongSize) {
    n20_slice_t bad_element = valid_path_element();
    bad_element.size -= 1;
    std::array<uint8_t, 1> const msg_bytes = {0xFF};
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_eca_ee_sign_e,
        .payload = {.eca_ee_sign = {.parent_path_length = 1,
                                    .parent_path = {bad_element},
                                    .name = {3, "key"},
                                    .key_usage = key_usage(),
                                    .message = {msg_bytes.size(),
                                                const_cast<uint8_t*>(msg_bytes.data())}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(0u, state_.sign_calls);
    EXPECT_EQ(n20_error_incompatible_compressed_input_size_e, parse_error_response(response));
}

TEST_F(ServiceMessageDispatchTest, EcaEeSignForwardsServiceError) {
    state_.sign_rc = n20_error_missing_crypto_context_e;
    n20_slice_t const path = valid_path_element();
    std::array<uint8_t, 2> const msg_bytes = {0xAA, 0xBB};
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_eca_ee_sign_e,
        .payload = {.eca_ee_sign = {.parent_path_length = 1,
                                    .parent_path = {path},
                                    .name = {3, "key"},
                                    .key_usage = key_usage(),
                                    .message = {msg_bytes.size(),
                                                const_cast<uint8_t*>(msg_bytes.data())}}},
    };

    auto const [rc, response] = dispatch(encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.sign_calls);
    EXPECT_EQ(n20_error_missing_crypto_context_e, parse_error_response(response));
}

// This test covers the case where the dispatcher runs out of buffer response buffer
// while rendering the response prefix.
TEST_F(ServiceMessageDispatchTest, EcaEeSignEeCertInsufficientBufferSize) {
    // Set the response buffer size to the payload size so that there enough space for the
    // thest payload not not for the response header.
    size_t const original_size = response_buffer_.size();
    size_t response_size = state_.sign_payload.size;

    n20_slice_t const path = valid_path_element();
    n20_msg_request_t req{
        .request_type = n20_msg_request_type_eca_ee_sign_e,
        .payload = {.eca_ee_sign = {.parent_path_length = 1, .parent_path = {path}}},
    };

    n20_error_t rc = n20_service_message_dispatch(
        &ctx_, response_buffer_.data(), &response_size, encode_request(req));

    ASSERT_EQ(n20_error_ok_e, rc);
    EXPECT_EQ(1u, state_.sign_calls);
    EXPECT_EQ(
        n20_error_insufficient_buffer_size_e,
        parse_error_response(
            {response_size, response_buffer_.data() + state_.sign_payload.size - response_size}));
}

}  // namespace
