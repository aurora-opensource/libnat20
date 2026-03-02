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
#include <nat20/cbor.h>
#include <nat20/error.h>
#include <nat20/service/messages.h>
#include <nat20/stream.h>
#include <nat20/types.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "nat20/testing/test_utils.h"

template <size_t N, typename T>
constexpr auto make_array(T initializer) {
    std::array<T, N> arr{};
    for (size_t i = 0; i < N; ++i) {
        arr[i] = initializer;
    }
    return arr;
}

constexpr auto TEST_PATH_ELEMENT1_DATA = make_array<32, uint8_t>(0x66);
constexpr auto TEST_PATH_ELEMENT2_DATA = make_array<32, uint8_t>(0x77);

n20_slice_t const TEST_PATH_ELEMENT1 = {TEST_PATH_ELEMENT1_DATA.size(),
                                        TEST_PATH_ELEMENT1_DATA.data()};
n20_slice_t const TEST_PATH_ELEMENT2 = {TEST_PATH_ELEMENT2_DATA.size(),
                                        TEST_PATH_ELEMENT2_DATA.data()};

class MessagesTest : public testing::Test {
   protected:
    void SetUp() override {  // Initialize common test data
        test_buffer.resize(8192);

        // Set up common test values
        test_compressed_context = {4, (uint8_t*)"test"};
        test_code_hash = {sizeof(test_hash_data), test_hash_data};
        test_cert_data = {sizeof(test_cert_buffer), test_cert_buffer};
        test_signature_data = {sizeof(test_signature_buffer), test_signature_buffer};

        // Fill hash data with pattern
        for (size_t i = 0; i < sizeof(test_hash_data); ++i) {
            test_hash_data[i] = static_cast<uint8_t>(i % 256);
        }

        // Fill cert buffer with pattern
        for (size_t i = 0; i < sizeof(test_cert_buffer); ++i) {
            test_cert_buffer[i] = static_cast<uint8_t>((i + 100) % 256);
        }

        // Fill signature buffer with pattern
        for (size_t i = 0; i < sizeof(test_signature_buffer); ++i) {
            test_signature_buffer[i] = static_cast<uint8_t>((i + 200) % 256);
        }
    }

    // Helper to create a CBOR message manually for testing read functions
    void WriteTestCborMessage(std::vector<uint8_t> const& data) {
        std::copy(data.begin(), data.end(), test_buffer.begin());
        test_slice = {data.size(), test_buffer.data()};
    }

    // Helper to get the CBOR data after a write operation
    n20_slice_t GetCborDataFromWrite(size_t original_buffer_size, size_t bytes_written) {
        uint8_t* cbor_start = test_buffer.data() + (original_buffer_size - bytes_written);
        return {bytes_written, cbor_start};
    }

    std::vector<uint8_t> test_buffer;
    n20_slice_t test_slice;
    n20_slice_t test_compressed_context;
    n20_slice_t test_code_hash;
    n20_slice_t test_cert_data;
    n20_slice_t test_signature_data;

    uint8_t test_hash_data[32];
    uint8_t test_cert_buffer[100];
    uint8_t test_signature_buffer[64];
};

// Test promote request read/write
TEST_F(MessagesTest, PromoteRequestRoundTrip) {
    n20_msg_promote_request_t original_request = {.compressed_context = test_compressed_context};

    n20_msg_request_t request = {.request_type = n20_msg_request_type_promote_e,
                                 .payload = {.promote = original_request}};

    // Write the request
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&request, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    // Verify
    EXPECT_EQ(n20_msg_request_type_promote_e, read_request.request_type);
    EXPECT_EQ(test_compressed_context.size, read_request.payload.promote.compressed_context.size);
    EXPECT_EQ(0,
              memcmp(test_compressed_context.buffer,
                     read_request.payload.promote.compressed_context.buffer,
                     test_compressed_context.size));
}

// Test CDI cert request read/write
TEST_F(MessagesTest, CdiCertRequestRoundTrip) {
    n20_msg_issue_cdi_cert_request_t original_request = {
        .issuer_key_type = n20_crypto_key_type_ed25519_e,
        .subject_key_type = n20_crypto_key_type_secp256r1_e,
        .next_context = {.code_hash = test_code_hash,
                         .mode = n20_open_dice_mode_normal_e,
                         .profile_name = {8, "testprof"}},
        .parent_path_length = 2,
        .parent_path = {TEST_PATH_ELEMENT1, TEST_PATH_ELEMENT2},
        .certificate_format = n20_certificate_format_x509_e};

    n20_msg_request_t request = {.request_type = n20_msg_request_type_issue_cdi_cert_e,
                                 .payload = {.issue_cdi_cert = original_request}};

    // Write the request
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&request, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    // Verify
    EXPECT_EQ(n20_msg_request_type_issue_cdi_cert_e, read_request.request_type);
    EXPECT_EQ(n20_crypto_key_type_ed25519_e, read_request.payload.issue_cdi_cert.issuer_key_type);
    EXPECT_EQ(n20_crypto_key_type_secp256r1_e,
              read_request.payload.issue_cdi_cert.subject_key_type);
    EXPECT_EQ(n20_certificate_format_x509_e,
              read_request.payload.issue_cdi_cert.certificate_format);
    EXPECT_EQ(2, read_request.payload.issue_cdi_cert.parent_path_length);
    EXPECT_EQ(n20_open_dice_mode_normal_e, read_request.payload.issue_cdi_cert.next_context.mode);
    EXPECT_EQ(original_request.parent_path[0].size,
              read_request.payload.issue_cdi_cert.parent_path[0].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[0].buffer,
                     read_request.payload.issue_cdi_cert.parent_path[0].buffer,
                     original_request.parent_path[0].size));
    EXPECT_EQ(original_request.parent_path[1].size,
              read_request.payload.issue_cdi_cert.parent_path[1].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[1].buffer,
                     read_request.payload.issue_cdi_cert.parent_path[1].buffer,
                     original_request.parent_path[1].size));
}

// Test ECA cert request read/write
TEST_F(MessagesTest, EcaCertRequestRoundTrip) {
    n20_msg_issue_eca_cert_request_t original_request = {
        .issuer_key_type = n20_crypto_key_type_secp256r1_e,
        .subject_key_type = n20_crypto_key_type_ed25519_e,
        .parent_path_length = 2,
        .parent_path = {TEST_PATH_ELEMENT1, TEST_PATH_ELEMENT2},
        .certificate_format = n20_certificate_format_x509_e,
        .challenge = {8, (uint8_t*)"challeng"}};

    n20_msg_request_t request = {.request_type = n20_msg_request_type_issue_eca_cert_e,
                                 .payload = {.issue_eca_cert = original_request}};

    // Write the request
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&request, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    // Verify
    EXPECT_EQ(n20_msg_request_type_issue_eca_cert_e, read_request.request_type);
    EXPECT_EQ(n20_crypto_key_type_secp256r1_e, read_request.payload.issue_eca_cert.issuer_key_type);
    EXPECT_EQ(n20_crypto_key_type_ed25519_e, read_request.payload.issue_eca_cert.subject_key_type);
    EXPECT_EQ(n20_certificate_format_x509_e,
              read_request.payload.issue_eca_cert.certificate_format);
    EXPECT_EQ(2, read_request.payload.issue_eca_cert.parent_path_length);
    EXPECT_EQ(8, read_request.payload.issue_eca_cert.challenge.size);
    EXPECT_EQ(original_request.parent_path[0].size,
              read_request.payload.issue_eca_cert.parent_path[0].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[0].buffer,
                     read_request.payload.issue_eca_cert.parent_path[0].buffer,
                     original_request.parent_path[0].size));
    EXPECT_EQ(original_request.parent_path[1].size,
              read_request.payload.issue_eca_cert.parent_path[1].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[1].buffer,
                     read_request.payload.issue_eca_cert.parent_path[1].buffer,
                     original_request.parent_path[1].size));
}

// Test ECA End-Entity cert request read/write
TEST_F(MessagesTest, EcaEeCertRequestRoundTrip) {
    uint8_t key_usage_data[] = {0x01, 0x02};

    n20_msg_issue_eca_ee_cert_request_t original_request = {
        .issuer_key_type = n20_crypto_key_type_ed25519_e,
        .subject_key_type = n20_crypto_key_type_secp384r1_e,
        .parent_path_length = 2,
        .parent_path = {TEST_PATH_ELEMENT1, TEST_PATH_ELEMENT2},
        .certificate_format = n20_certificate_format_x509_e,
        .name = {7, "testkey"},
        .key_usage = {2, key_usage_data},
        .challenge = {4, (uint8_t*)"abcd"}};

    n20_msg_request_t request = {.request_type = n20_msg_request_type_issue_eca_ee_cert_e,
                                 .payload = {.issue_eca_ee_cert = original_request}};

    // Write the request
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&request, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    // Verify
    EXPECT_EQ(n20_msg_request_type_issue_eca_ee_cert_e, read_request.request_type);
    EXPECT_EQ(n20_crypto_key_type_ed25519_e,
              read_request.payload.issue_eca_ee_cert.issuer_key_type);
    EXPECT_EQ(n20_crypto_key_type_secp384r1_e,
              read_request.payload.issue_eca_ee_cert.subject_key_type);
    EXPECT_EQ(7, read_request.payload.issue_eca_ee_cert.name.size);
    EXPECT_EQ(0, memcmp("testkey", read_request.payload.issue_eca_ee_cert.name.buffer, 7));
    EXPECT_EQ(2, read_request.payload.issue_eca_ee_cert.key_usage.size);
    EXPECT_EQ(0x01, read_request.payload.issue_eca_ee_cert.key_usage.buffer[0]);
    EXPECT_EQ(0x02, read_request.payload.issue_eca_ee_cert.key_usage.buffer[1]);
    EXPECT_EQ(2, read_request.payload.issue_eca_ee_cert.parent_path_length);
    EXPECT_EQ(original_request.parent_path[0].size,
              read_request.payload.issue_eca_ee_cert.parent_path[0].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[0].buffer,
                     read_request.payload.issue_eca_ee_cert.parent_path[0].buffer,
                     original_request.parent_path[0].size));
    EXPECT_EQ(original_request.parent_path[1].size,
              read_request.payload.issue_eca_ee_cert.parent_path[1].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[1].buffer,
                     read_request.payload.issue_eca_ee_cert.parent_path[1].buffer,
                     original_request.parent_path[1].size));
    EXPECT_EQ(0, memcmp("abcd", read_request.payload.issue_eca_ee_cert.challenge.buffer, 4));
}

// Test ECA End-Entity sign request read/write
TEST_F(MessagesTest, EcaEeSignRequestRoundTrip) {
    uint8_t message_data[] = "Hello, World!";
    uint8_t key_usage_data[] = {0x01};

    n20_msg_eca_ee_sign_request_t original_request = {
        .subject_key_type = n20_crypto_key_type_ed25519_e,
        .parent_path_length = 2,
        .parent_path = {TEST_PATH_ELEMENT1, TEST_PATH_ELEMENT2},
        .name = {6, "signer"},
        .key_usage = {1, key_usage_data},
        .message = {13, message_data}};

    n20_msg_request_t request = {.request_type = n20_msg_request_type_eca_ee_sign_e,
                                 .payload = {.eca_ee_sign = original_request}};

    // Write the request
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&request, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    // Verify
    EXPECT_EQ(n20_msg_request_type_eca_ee_sign_e, read_request.request_type);
    EXPECT_EQ(n20_crypto_key_type_ed25519_e, read_request.payload.eca_ee_sign.subject_key_type);
    EXPECT_EQ(6, read_request.payload.eca_ee_sign.name.size);
    EXPECT_EQ(0, memcmp("signer", read_request.payload.eca_ee_sign.name.buffer, 6));
    EXPECT_EQ(13, read_request.payload.eca_ee_sign.message.size);
    EXPECT_EQ(0, memcmp("Hello, World!", read_request.payload.eca_ee_sign.message.buffer, 13));
    EXPECT_EQ(1, read_request.payload.eca_ee_sign.key_usage.size);
    EXPECT_EQ(0x01, read_request.payload.eca_ee_sign.key_usage.buffer[0]);
    EXPECT_EQ(2, read_request.payload.eca_ee_sign.parent_path_length);
    EXPECT_EQ(original_request.parent_path[0].size,
              read_request.payload.eca_ee_sign.parent_path[0].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[0].buffer,
                     read_request.payload.eca_ee_sign.parent_path[0].buffer,
                     original_request.parent_path[0].size));
    EXPECT_EQ(original_request.parent_path[1].size,
              read_request.payload.eca_ee_sign.parent_path[1].size);
    EXPECT_EQ(0,
              memcmp(original_request.parent_path[1].buffer,
                     read_request.payload.eca_ee_sign.parent_path[1].buffer,
                     original_request.parent_path[1].size));
}

// Test error response read/write
TEST_F(MessagesTest, ErrorResponseRoundTrip) {
    n20_msg_error_response_t original_response = {.error_code = n20_error_crypto_invalid_key_e};

    // Write the response
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e,
              n20_msg_error_response_write(&original_response, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_error_response_t read_response = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_error_response_read(&read_response, msg_buffer));

    // Verify
    EXPECT_EQ(n20_error_crypto_invalid_key_e, read_response.error_code);
}

// Test success error response (no error code written)
TEST_F(MessagesTest, SuccessErrorResponse) {
    n20_msg_error_response_t original_response = {.error_code = n20_error_ok_e};

    // Write the response
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e,
              n20_msg_error_response_write(&original_response, test_buffer.data(), &buffer_size));

    // Should write some data for success case
    EXPECT_GT(buffer_size, 0);

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_error_response_t read_response = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_error_response_read(&read_response, msg_buffer));

    // Should default to success
    EXPECT_EQ(n20_error_ok_e, read_response.error_code);
}

// Test certificate response read/write with success
TEST_F(MessagesTest, CertResponseSuccessRoundTrip) {
    n20_msg_issue_cert_response_t original_response = {.error_code = n20_error_ok_e,
                                                       .certificate = test_cert_data};

    // Write the response
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(
        n20_error_ok_e,
        n20_msg_issue_cert_response_write(&original_response, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_issue_cert_response_t read_response = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_issue_cert_response_read(&read_response, msg_buffer));

    // Verify
    EXPECT_EQ(n20_error_ok_e, read_response.error_code);
    EXPECT_EQ(test_cert_data.size, read_response.certificate.size);
    EXPECT_EQ(0,
              memcmp(test_cert_data.buffer, read_response.certificate.buffer, test_cert_data.size));
}

// Test certificate response read/write with error
TEST_F(MessagesTest, CertResponseErrorRoundTrip) {
    n20_msg_issue_cert_response_t original_response = {
        .error_code = n20_error_crypto_invalid_context_e, .certificate = {0, nullptr}};

    // Write the response
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(
        n20_error_ok_e,
        n20_msg_issue_cert_response_write(&original_response, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_issue_cert_response_t read_response = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_issue_cert_response_read(&read_response, msg_buffer));

    // Verify
    EXPECT_EQ(n20_error_crypto_invalid_context_e, read_response.error_code);
    EXPECT_EQ(0, read_response.certificate.size);
    EXPECT_EQ(nullptr, read_response.certificate.buffer);
}

// Test signing response read/write with success
TEST_F(MessagesTest, SignResponseSuccessRoundTrip) {
    n20_msg_eca_ee_sign_response_t original_response = {.error_code = n20_error_ok_e,
                                                        .signature = test_signature_data};

    // Write the response
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(
        n20_error_ok_e,
        n20_msg_eca_ee_sign_response_write(&original_response, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_eca_ee_sign_response_t read_response = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_eca_ee_sign_response_read(&read_response, msg_buffer));

    // Verify
    EXPECT_EQ(n20_error_ok_e, read_response.error_code);
    EXPECT_EQ(test_signature_data.size, read_response.signature.size);
    EXPECT_EQ(
        0,
        memcmp(
            test_signature_data.buffer, read_response.signature.buffer, test_signature_data.size));
}

// Test signing response read/write with error
TEST_F(MessagesTest, SignResponseErrorRoundTrip) {
    n20_msg_eca_ee_sign_response_t original_response = {
        .error_code = n20_error_crypto_invalid_key_e, .signature = {0, nullptr}};

    // Write the response
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(
        n20_error_ok_e,
        n20_msg_eca_ee_sign_response_write(&original_response, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_eca_ee_sign_response_t read_response = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_eca_ee_sign_response_read(&read_response, msg_buffer));

    // Verify
    EXPECT_EQ(n20_error_crypto_invalid_key_e, read_response.error_code);
    EXPECT_EQ(0, read_response.signature.size);
    EXPECT_EQ(nullptr, read_response.signature.buffer);
}

// Test invalid request type
TEST_F(MessagesTest, InvalidRequestType) {
    // Create a manually crafted invalid request
    WriteTestCborMessage({
        0x82,  // Array of 2 items
        0x18,
        0xFF,  // Invalid request type (255)
        0xA0   // Empty map
    });

    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_request_type_unknown_e, n20_msg_request_read(&request, test_slice));
}

// Test malformed CBOR
TEST_F(MessagesTest, MalformedCbor) {
    WriteTestCborMessage({
        0x81,  // Array of 1 item (should be 2)
        0x01   // Request type 1
    });

    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

// Test buffer overflow protection
TEST_F(MessagesTest, BufferOverflow) {
    n20_msg_promote_request_t request = {.compressed_context = test_compressed_context};

    n20_msg_request_t msg = {.request_type = n20_msg_request_type_promote_e,
                             .payload = {.promote = request}};

    // Try to write to a buffer that's too small
    uint8_t small_buffer[4];
    size_t buffer_size = sizeof(small_buffer);

    EXPECT_EQ(n20_error_insufficient_buffer_size_e,
              n20_msg_request_write(&msg, small_buffer, &buffer_size));
}

TEST_F(MessagesTest, RequestWriteRequestTypeUnknown) {
    n20_msg_request_t msg = {.request_type = static_cast<n20_msg_request_type_t>(255)};

    size_t buffer_size = test_buffer.size();
    EXPECT_EQ(n20_error_request_type_unknown_e,
              n20_msg_request_write(&msg, test_buffer.data(), &buffer_size));
}

TEST_F(MessagesTest, RequestWriteWritePositionOverflow) {
    // Create a request that would cause size_t overflow when calculating write position.
    n20_msg_request_t msg = {
        .request_type = n20_msg_request_type_promote_e,
        .payload = {.promote = {.compressed_context = {SIZE_MAX, (uint8_t const*)1}}}};

    size_t buffer_size = 0;  // Zero size to trigger overflow
    EXPECT_EQ(n20_error_write_position_overflow_e,
              n20_msg_request_write(&msg, test_buffer.data(), &buffer_size));
}

// Test null pointer handling
TEST_F(MessagesTest, RequestReadNullPointerHandling) {
    n20_msg_request_t request = {};
    n20_msg_error_response_t error_response = {};
    size_t buffer_size = test_buffer.size();

    // Test null request pointer
    EXPECT_EQ(n20_error_unexpected_null_request_e, n20_msg_request_read(nullptr, test_slice));
}

// Test maximum path length
TEST_F(MessagesTest, MaxPathLength) {
    n20_msg_issue_cdi_cert_request_t request = {
        .issuer_key_type = n20_crypto_key_type_ed25519_e,
        .subject_key_type = n20_crypto_key_type_ed25519_e,
        .parent_path_length = N20_STATELESS_MAX_PATH_LENGTH,
        .certificate_format = n20_certificate_format_x509_e};

    // Fill parent path to maximum
    for (size_t i = 0; i < N20_STATELESS_MAX_PATH_LENGTH; ++i) {
        request.parent_path[i] = {4, (uint8_t*)"path"};
    }

    n20_msg_request_t msg = {.request_type = n20_msg_request_type_issue_cdi_cert_e,
                             .payload = {.issue_cdi_cert = request}};

    // Should succeed with maximum path length
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&msg, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    // Read it back
    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    EXPECT_EQ(N20_STATELESS_MAX_PATH_LENGTH,
              read_request.payload.issue_cdi_cert.parent_path_length);
}

// Test OpenDICE input with all fields
TEST_F(MessagesTest, OpenDiceInputAllFields) {
    n20_open_dice_input_t dice_input = {
        .code_hash = test_code_hash,
        .code_descriptor = {4, (uint8_t*)"code"},
        .configuration_hash = {32, test_hash_data},
        .configuration_descriptor = {4, (uint8_t*)"conf"},
        .authority_hash = {32, test_hash_data},
        .authority_descriptor = {4, (uint8_t*)"auth"},
        .mode = n20_open_dice_mode_debug_e,
        .profile_name = {4, "prof"},
        .hidden = {4, (uint8_t*)"hide"},
    };

    n20_msg_issue_cdi_cert_request_t request = {
        .issuer_key_type = n20_crypto_key_type_ed25519_e,
        .subject_key_type = n20_crypto_key_type_ed25519_e,
        .next_context = dice_input,
        .parent_path_length = 0,
        .certificate_format = n20_certificate_format_x509_e};

    n20_msg_request_t msg = {.request_type = n20_msg_request_type_issue_cdi_cert_e,
                             .payload = {.issue_cdi_cert = request}};

    // Write and read back
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&msg, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    // Verify all fields
    auto const& read_dice = read_request.payload.issue_cdi_cert.next_context;
    ASSERT_EQ(test_code_hash.size, read_dice.code_hash.size);
    ASSERT_EQ(4, read_dice.code_descriptor.size);
    ASSERT_EQ(32, read_dice.configuration_hash.size);
    ASSERT_EQ(4, read_dice.configuration_descriptor.size);
    ASSERT_EQ(32, read_dice.authority_hash.size);
    ASSERT_EQ(4, read_dice.authority_descriptor.size);
    ASSERT_EQ(n20_open_dice_mode_debug_e, read_dice.mode);
    ASSERT_EQ(4, read_dice.hidden.size);
    ASSERT_EQ(4, read_dice.profile_name.size);
    EXPECT_EQ(0, memcmp(test_code_hash.buffer, read_dice.code_hash.buffer, test_code_hash.size));
    EXPECT_EQ(0, memcmp("code", read_dice.code_descriptor.buffer, 4));
    EXPECT_EQ(0,
              memcmp(test_hash_data, read_dice.configuration_hash.buffer, sizeof(test_hash_data)));
    EXPECT_EQ(0, memcmp("conf", read_dice.configuration_descriptor.buffer, 4));
    EXPECT_EQ(0, memcmp(test_hash_data, read_dice.authority_hash.buffer, sizeof(test_hash_data)));
    EXPECT_EQ(0, memcmp("auth", read_dice.authority_descriptor.buffer, 4));
    EXPECT_EQ(0, memcmp("prof", read_dice.profile_name.buffer, 4));
    EXPECT_EQ(0, memcmp("hide", read_dice.hidden.buffer, 4));
}

// Parameterized test for different request types
class RequestTypeTest : public MessagesTest,
                        public testing::WithParamInterface<n20_msg_request_type_t> {};

TEST_P(RequestTypeTest, BasicRequestTypeHandling) {
    n20_msg_request_type_t request_type = GetParam();

    // Skip invalid types
    if (request_type == n20_msg_request_type_none_e ||
        request_type >= n20_msg_request_type_count_e) {
        return;
    }

    n20_msg_request_t request = {};
    request.request_type = request_type;

    // Initialize minimal valid payload based on type
    switch (request_type) {
        case n20_msg_request_type_promote_e:
            request.payload.promote.compressed_context = test_compressed_context;
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            request.payload.issue_cdi_cert.issuer_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.issue_cdi_cert.subject_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.issue_cdi_cert.certificate_format = n20_certificate_format_x509_e;
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            request.payload.issue_eca_cert.issuer_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.issue_eca_cert.subject_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.issue_eca_cert.certificate_format = n20_certificate_format_x509_e;
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            request.payload.issue_eca_ee_cert.issuer_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.issue_eca_ee_cert.subject_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.issue_eca_ee_cert.certificate_format = n20_certificate_format_x509_e;
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            request.payload.eca_ee_sign.subject_key_type = n20_crypto_key_type_ed25519_e;
            request.payload.eca_ee_sign.message = test_compressed_context;
            break;
        default:
            break;
    }

    // Test write/read roundtrip
    size_t original_buffer_size = test_buffer.size();
    size_t buffer_size = original_buffer_size;
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_write(&request, test_buffer.data(), &buffer_size));

    // Get the CBOR data from the end of the buffer
    n20_slice_t msg_buffer = GetCborDataFromWrite(original_buffer_size, buffer_size);

    n20_msg_request_t read_request = {};
    ASSERT_EQ(n20_error_ok_e, n20_msg_request_read(&read_request, msg_buffer));

    EXPECT_EQ(request_type, read_request.request_type);
}

INSTANTIATE_TEST_SUITE_P(AllRequestTypes,
                         RequestTypeTest,
                         testing::Values(n20_msg_request_type_promote_e,
                                         n20_msg_request_type_issue_cdi_cert_e,
                                         n20_msg_request_type_issue_eca_cert_e,
                                         n20_msg_request_type_issue_eca_ee_cert_e,
                                         n20_msg_request_type_eca_ee_sign_e));

namespace std {

std::string to_string(n20_msg_request_type_t type) {
    switch (type) {
        case n20_msg_request_type_none_e:
            return "none";
        case n20_msg_request_type_promote_e:
            return "promote";
        case n20_msg_request_type_issue_cdi_cert_e:
            return "issue_cdi_cert";
        case n20_msg_request_type_issue_eca_cert_e:
            return "issue_eca_cert";
        case n20_msg_request_type_issue_eca_ee_cert_e:
            return "issue_eca_ee_cert";
        case n20_msg_request_type_eca_ee_sign_e:
            return "eca_ee_sign";
        default:
            return "unknown";
    }
}

}  // namespace std
class ReadMalformedRequestTestFixture
    : public MessagesTest,
      public testing::WithParamInterface<std::tuple<n20_msg_request_type_t, uint64_t>> {};

INSTANTIATE_TEST_SUITE_P(
    ReadMalformedRequestTestInstance,
    ReadMalformedRequestTestFixture,
    testing::Combine(testing::Values(n20_msg_request_type_promote_e,
                                     n20_msg_request_type_issue_cdi_cert_e,
                                     n20_msg_request_type_issue_eca_cert_e,
                                     n20_msg_request_type_issue_eca_ee_cert_e,
                                     n20_msg_request_type_eca_ee_sign_e),
                     testing::Values(1, 2, 3, 4, 5, 6, 7, 8, 9, 19)),
    [](testing::TestParamInfo<ReadMalformedRequestTestFixture::ParamType> const& info) {
        return std::to_string(std::get<0>(info.param)) + "_" +
               std::to_string(std::get<1>(info.param));
    });

TEST_P(ReadMalformedRequestTestFixture, MalformedRequestHandling) {
    auto [request_type, field] = GetParam();

    std::vector<uint8_t> cbor_data = {};
    n20_msg_request_t request = {};

    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data = {
        0xA2,  // Map of 3 items
    };

    // Not an array
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data = {
        0x82,  // Array of 2 items
    };

    // Missing request type
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data = {
        0x82,  // Array of 2 items
        0xF7,  // Invalid request type (undefined)
    };

    // Request type not an integer
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data = {
        0x82,                                // Array of 2 items
        static_cast<uint8_t>(request_type),  // Request type
        0xA1,                                // Map with one element
    };

    // Missing field key
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Unexpected field key failing to skip due to lack of value.
    cbor_data.push_back(0xf7);  // Add "undefined" value as map key
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Successfully skip an unexpected field.
    cbor_data.push_back(0xf7);  // Add "undefined" value as map value
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_ok_e, n20_msg_request_read(&request, test_slice));

    cbor_data.pop_back();
    cbor_data.pop_back();
    cbor_data.push_back(0x20);  // Add -1 as map key
    cbor_data.push_back(0xf7);  // Add "undefined" value as map value

    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_ok_e, n20_msg_request_read(&request, test_slice));

    cbor_data.pop_back();
    cbor_data.pop_back();
    cbor_data.push_back(static_cast<uint8_t>(field));  // Field key

    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    n20_error_t wanted_error = n20_error_unexpected_message_structure_e;

    // Some fields are unexpected by certain request types and will be ignored.
    // In those cases n20_error_ok_e is expected.
    switch (request_type) {
        case n20_msg_request_type_promote_e:
            if (field != 19) wanted_error = n20_error_ok_e;
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            switch (field) {
                case 6:
                case 7:
                case 8:
                case 9:
                case 19:
                    wanted_error = n20_error_ok_e;
                    break;
                default:
                    break;
            }
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            switch (field) {
                case 3:
                case 6:
                case 7:
                case 9:
                case 19:
                    wanted_error = n20_error_ok_e;
                    break;
                default:
                    break;
            }
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            switch (field) {
                case 3:
                case 9:
                case 19:
                    wanted_error = n20_error_ok_e;
                    break;
                default:
                    break;
            }
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            switch (field) {
                case 1:
                case 3:
                case 5:
                case 8:
                case 19:
                    wanted_error = n20_error_ok_e;
                    break;
                default:
                    break;
            }
            break;
            break;
        default:
            break;
    }

    // Add "undefined" to make it a valid CBOR item that is never expected.
    cbor_data.push_back(0xf7);
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(wanted_error, n20_msg_request_read(&request, test_slice));
}

TEST_F(MessagesTest, ReadTruncatedSliceInPromoteRequest) {
    // Truncated Compressed Context field 19
    WriteTestCborMessage({0x82, 0x01, 0xA1, 0x13, 0x42, 'a'});

    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

TEST_F(MessagesTest, ReadTruncatedSliceInIssueEcaCertRequest) {
    // Truncated Challenge field 8
    WriteTestCborMessage({0x82, 0x03, 0xA1, 0x08, 0x42, 'a'});

    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

TEST_F(MessagesTest, ReadTruncatedSliceInIssueEcaEeCertRequest) {
    // Truncated Label field 6
    WriteTestCborMessage({0x82, 0x04, 0xA1, 0x06, 0x62, 'a'});

    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Truncated Key Usage field 7
    WriteTestCborMessage({0x82, 0x04, 0xA1, 0x07, 0x42, 'a'});

    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Truncated Challenge field 8
    WriteTestCborMessage({0x82, 0x04, 0xA1, 0x08, 0x42, 'a'});

    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

TEST_F(MessagesTest, ReadTruncatedSliceInEcaEeSignRequest) {
    // Truncated Label field 6
    WriteTestCborMessage({0x82, 0x05, 0xA1, 0x06, 0x62, 'a'});

    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Truncated Key Usage field 7
    WriteTestCborMessage({0x82, 0x05, 0xA1, 0x07, 0x42, 'a'});

    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Truncated Message field 9
    WriteTestCborMessage({0x82, 0x05, 0xA1, 0x09, 0x42, 'a'});

    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

class ReadMalformedDiceInputTestFixture : public MessagesTest,
                                          public testing::WithParamInterface<uint64_t> {};

INSTANTIATE_TEST_SUITE_P(ReadMalformedDiceInputTestInstance,
                         ReadMalformedDiceInputTestFixture,
                         testing::Values(10, 11, 12, 13, 14, 15, 16, 17, 18));

TEST_P(ReadMalformedDiceInputTestFixture, MalformedDiceInputHandling) {
    auto field = GetParam();

    std::vector<uint8_t> cbor_data = {
        0x82,                                   // Array of 2 items
        n20_msg_request_type_issue_cdi_cert_e,  // Request type
        0xA1,                                   // Map with one element
        0x03,                                   // Field 3 (open dice input)
        0xA1,                                   // Map with one element
        static_cast<uint8_t>(field)  // Field number (all fields are in the simple positive range)
    };

    WriteTestCborMessage(cbor_data);
    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data.push_back(
        0xf7);  // Add "undefined" to make it a valid CBOR item that is never expected.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data.pop_back();
    if (field == 16 /* mode */) {
        cbor_data.push_back(0x0f);  // Invalid mode value
    } else if (field == 18) {
        cbor_data.push_back(0x62);  // Add a truncated text string
    } else {
        cbor_data.push_back(0x42);  // Add a truncated byte string
    }
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

TEST_F(MessagesTest, ReadDiceInputWithUnknownField) {
    std::vector<uint8_t> cbor_data = {
        0x82,                                   // Array of 2 items
        n20_msg_request_type_issue_cdi_cert_e,  // Request type
        0xA1,                                   // Map with one element
        0x03,                                   // Field 3 (open dice input)
        0xA1,                                   // Map with one element
        0x18,                                   // Unknown field
        0xFF                                    // Field number (255)
    };

    // The unknown field is truncated and fails to be skipped.
    WriteTestCborMessage(cbor_data);
    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data.push_back(0xf6);  // Add "null" to make it a valid CBOR item that is ignored.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_ok_e, n20_msg_request_read(&request, test_slice));
}

class CompressedContextPathTestFixture
    : public MessagesTest,
      public testing::WithParamInterface<n20_msg_request_type_t> {};

INSTANTIATE_TEST_SUITE_P(CompressedContextPathTooLongTestInstance,
                         CompressedContextPathTestFixture,
                         testing::Values(n20_msg_request_type_issue_cdi_cert_e,
                                         n20_msg_request_type_issue_eca_cert_e,
                                         n20_msg_request_type_issue_eca_ee_cert_e,
                                         n20_msg_request_type_eca_ee_sign_e));

TEST_P(CompressedContextPathTestFixture, CompressedContextPathTooLong) {
    auto request_type = GetParam();
    // Create a promote request with a compressed context that is too long

    // If this ASSERTION fails, the N20_STATELESS_MAX_PATH_LENGTH constant
    // was set larger than the maximum simple integer value that can be
    // encoded in a single byte (23). The test code below would need to be updated
    // to handle multi-byte integer encoding.
    ASSERT_LE(N20_STATELESS_MAX_PATH_LENGTH + 1, 23);

    std::vector<uint8_t> cbor_data = {
        0x82,                                        // Array of 2 items
        static_cast<uint8_t>(request_type),          // Request type
        0xA1,                                        // Map with one element
        0x04,                                        // Field 4 parent path
        0x80 | (N20_STATELESS_MAX_PATH_LENGTH + 1),  // Array of max path length + 1
    };

    WriteTestCborMessage(cbor_data);
    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_parent_path_size_exceeds_max_e, n20_msg_request_read(&request, test_slice));
}

TEST_P(CompressedContextPathTestFixture, CompressedContextMalformed) {
    auto request_type = GetParam();
    // Create a promote request with a compressed context that is too long

    // If this ASSERTION fails, the N20_STATELESS_MAX_PATH_LENGTH constant
    // was set less then 2. The test code below would need to be updated to handle that case.
    ASSERT_GE(N20_STATELESS_MAX_PATH_LENGTH, 2);

    std::vector<uint8_t> cbor_data = {
        0x82,                                // Array of 2 items
        static_cast<uint8_t>(request_type),  // Request type
        0xA1,                                // Map with one element
        0x04,                                // Field 4 parent path
        0x82,                                // Array of size 2
        0x01,                                // Not a byte string
    };

    WriteTestCborMessage(cbor_data);
    n20_msg_request_t request = {};
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    // Missing array item
    cbor_data.pop_back();
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));

    cbor_data.push_back(0x42);  // Truncated byte string of size 2
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e, n20_msg_request_read(&request, test_slice));
}

TEST_F(MessagesTest, IssueCertResponseReadNullPointerHandling) {
    n20_msg_issue_cert_response_t response = {};
    size_t buffer_size = test_buffer.size();

    // Test null response pointer
    EXPECT_EQ(n20_error_unexpected_null_response_e,
              n20_msg_issue_cert_response_read(nullptr, test_slice));
}

TEST_F(MessagesTest, MalformedIssueCertResponseHandling) {
    std::vector<uint8_t> cbor_data = {0xA1, 0x14};
    n20_msg_issue_cert_response_t response = {};

    // Error code missing value.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_issue_cert_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x14, 0x20};
    // Error code is not an unsigned integer.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_issue_cert_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x15};
    // Certificate missing value.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_issue_cert_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x15, 0x20};
    // Certificate Not a byte string.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_issue_cert_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x15, 0x42, 'a'};
    // Certificate is truncated 0x42 has length 2 but only one byte follows.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_issue_cert_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x17, 0xF7};
    // Unknown field key. Skipped successfully.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_ok_e, n20_msg_issue_cert_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x17, 0xFF};
    // Unknown field key. Not a valid CBOR item.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_issue_cert_response_read(&response, test_slice));
}

TEST_F(MessagesTest, WriteIssueCertResponseNullPointerHandling) {
    n20_msg_issue_cert_response_t response = {};
    size_t buffer_size = test_buffer.size();

    // Test null response pointer
    EXPECT_EQ(n20_error_unexpected_null_response_e,
              n20_msg_issue_cert_response_write(nullptr, test_buffer.data(), &buffer_size));

    // Test null buffer size pointer
    EXPECT_EQ(n20_error_unexpected_null_buffer_size_e,
              n20_msg_issue_cert_response_write(&response, test_buffer.data(), nullptr));
}

TEST_F(MessagesTest, WriteIssueCertResponseWritePositionOverflow) {
    n20_msg_issue_cert_response_t response = {.certificate = {SIZE_MAX, (uint8_t const*)1}};
    size_t buffer_size = test_buffer.size();

    EXPECT_EQ(n20_error_write_position_overflow_e,
              n20_msg_issue_cert_response_write(&response, test_buffer.data(), &buffer_size));
}

TEST_F(MessagesTest, WriteIssueCertResponseBufferOverflow) {
    n20_msg_issue_cert_response_t response = {.certificate = test_cert_data};
    uint8_t small_buffer[4];
    size_t buffer_size = sizeof(small_buffer);

    EXPECT_EQ(n20_error_insufficient_buffer_size_e,
              n20_msg_issue_cert_response_write(&response, small_buffer, &buffer_size));
    EXPECT_EQ(buffer_size, 104);
}

TEST_F(MessagesTest, ErrorResponseReadNullPointerHandling) {
    n20_msg_issue_cert_response_t response = {};
    size_t buffer_size = test_buffer.size();

    // Test null response pointer
    EXPECT_EQ(n20_error_unexpected_null_response_e,
              n20_msg_error_response_read(nullptr, test_slice));
}

TEST_F(MessagesTest, MalformedErrorResponseReadHandling) {
    std::vector<uint8_t> cbor_data = {0xA1, 0x14};
    n20_msg_error_response_t response = {};

    // Error code missing value.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_error_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x14, 0x20};
    // Error code is not an unsigned integer.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_error_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x17, 0xF7};
    // Unknown field key. Skipped successfully.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_ok_e, n20_msg_error_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x17, 0xFF};
    // Unknown field key. Not a valid CBOR item.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_error_response_read(&response, test_slice));
}

TEST_F(MessagesTest, ErrorResponseWriteNullPointerHandling) {
    n20_msg_error_response_t response = {};
    size_t buffer_size = test_buffer.size();

    // Test null response pointer
    EXPECT_EQ(n20_error_unexpected_null_response_e,
              n20_msg_error_response_write(nullptr, test_buffer.data(), &buffer_size));

    // Test null buffer size pointer
    EXPECT_EQ(n20_error_unexpected_null_buffer_size_e,
              n20_msg_error_response_write(&response, test_buffer.data(), nullptr));
}

TEST_F(MessagesTest, ErrorResponseWriteBufferOverflow) {
    n20_msg_error_response_t response = {.error_code = n20_error_crypto_invalid_key_e};
    uint8_t small_buffer[1];
    size_t buffer_size = sizeof(small_buffer);

    EXPECT_EQ(n20_error_insufficient_buffer_size_e,
              n20_msg_error_response_write(&response, small_buffer, &buffer_size));
    EXPECT_EQ(buffer_size, 5);
}

TEST_F(MessagesTest, EcaEeSignResponseReadNullPointerHandling) {
    n20_msg_issue_cert_response_t response = {};
    size_t buffer_size = test_buffer.size();

    // Test null response pointer
    EXPECT_EQ(n20_error_unexpected_null_response_e,
              n20_msg_eca_ee_sign_response_read(nullptr, test_slice));
}

TEST_F(MessagesTest, MalformedEcaEeSignResponseHandling) {
    std::vector<uint8_t> cbor_data = {0xA1, 0x14};
    n20_msg_eca_ee_sign_response_t response = {};

    // Error code missing value.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_eca_ee_sign_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x14, 0x20};
    // Error code is not an unsigned integer.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_eca_ee_sign_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x16};
    // Signature missing value.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_eca_ee_sign_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x16, 0x20};
    // Signature not a byte string.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_eca_ee_sign_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x16, 0x42, 'a'};
    // Signature is truncated 0x42 has length 2 but only one byte follows.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_eca_ee_sign_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x17, 0xF7};
    // Unknown field key. Skipped successfully.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_ok_e, n20_msg_eca_ee_sign_response_read(&response, test_slice));

    cbor_data = {0xA1, 0x17, 0xFF};
    // Unknown field key. Not a valid CBOR item.
    WriteTestCborMessage(cbor_data);
    EXPECT_EQ(n20_error_unexpected_message_structure_e,
              n20_msg_eca_ee_sign_response_read(&response, test_slice));
}

TEST_F(MessagesTest, EcaEeSignResponseWriteNullPointerHandling) {
    n20_msg_eca_ee_sign_response_t response = {};
    size_t buffer_size = test_buffer.size();

    // Test null response pointer
    EXPECT_EQ(n20_error_unexpected_null_response_e,
              n20_msg_eca_ee_sign_response_write(nullptr, test_buffer.data(), &buffer_size));

    // Test null buffer size pointer
    EXPECT_EQ(n20_error_unexpected_null_buffer_size_e,
              n20_msg_eca_ee_sign_response_write(&response, test_buffer.data(), nullptr));
}

TEST_F(MessagesTest, EcaEeSignResponseWritePositionOverflow) {
    n20_msg_eca_ee_sign_response_t response = {.signature = {SIZE_MAX, (uint8_t const*)1}};
    uint8_t small_buffer[4];
    size_t buffer_size = sizeof(small_buffer);

    EXPECT_EQ(n20_error_write_position_overflow_e,
              n20_msg_eca_ee_sign_response_write(&response, small_buffer, &buffer_size));
}

TEST_F(MessagesTest, EcaEeSignResponseWriteBufferOverflow) {
    n20_msg_eca_ee_sign_response_t response = {.signature = test_signature_data};
    uint8_t small_buffer[4];
    size_t buffer_size = sizeof(small_buffer);

    EXPECT_EQ(n20_error_insufficient_buffer_size_e,
              n20_msg_eca_ee_sign_response_write(&response, small_buffer, &buffer_size));
    EXPECT_EQ(buffer_size, 68);
}
