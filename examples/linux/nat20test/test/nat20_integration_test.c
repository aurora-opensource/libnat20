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

#include <fcntl.h>
#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/service/messages.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_helpers.h"

#define DEVICE_PATH "/dev/nat200"
#define DICE_CHAIN_PATH "/sys/kernel/security/nat200/dice_chain"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Start a test case. Call once at the beginning of each test function.
 * Usage: TEST_BEGIN("descriptive test name"); */
#define TEST_BEGIN(name)                   \
    do {                                   \
        tests_run++;                       \
        printf("  TEST: %s ... ", (name)); \
        fflush(stdout);                    \
    } while (0)

/* Mark the current test as passed. Call once at the end of a successful test.
 * Usage: TEST_PASS(); */
#define TEST_PASS()       \
    do {                  \
        tests_passed++;   \
        printf("PASS\n"); \
        fflush(stdout);   \
    } while (0)

/* Mark the current test as failed and print a diagnostic message.
 * The first variadic argument is a printf format string; subsequent
 * arguments are format parameters.
 * Usage: TEST_FAIL("expected %d, got %d", expected, actual); */
#define TEST_FAIL(...)                       \
    do {                                     \
        tests_failed++;                      \
        printf("FAIL\n");                    \
        fprintf(stderr, "    " __VA_ARGS__); \
        fprintf(stderr, "\n");               \
        fflush(stderr);                      \
    } while (0)

/* Assert a condition. On failure, prints a diagnostic and returns from
 * the enclosing function (marking the test as failed).
 * The first argument is the condition; the remaining variadic arguments
 * form a printf-style diagnostic message.
 * Usage: ASSERT(ptr != NULL, "allocation failed for size %zu", size); */
#define ASSERT(cond, ...)           \
    do {                            \
        if (!(cond)) {              \
            TEST_FAIL(__VA_ARGS__); \
            return;                 \
        }                           \
    } while (0)

/* Assert equality. Convenience wrapper around ASSERT for comparing two values.
 * Usage: ASSERT_EQ(err, n20_error_ok_e, "unexpected error: 0x%x", err); */
#define ASSERT_EQ(a, b, ...) ASSERT((a) == (b), __VA_ARGS__)

static ssize_t dispatch_request(uint8_t const* request,
                                size_t request_size,
                                uint8_t* response,
                                size_t response_size) {
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("open " DEVICE_PATH);
        return -1;
    }

    ssize_t written = write(fd, request, request_size);
    if (written < 0) {
        perror("write");
        close(fd);
        return -1;
    }

    ssize_t received = read(fd, response, response_size);
    if (received < 0) {
        perror("read");
        close(fd);
        return -1;
    }

    close(fd);
    return received;
}

static n20_error_t send_request(n20_msg_request_t const* request,
                                uint8_t* response_buffer,
                                size_t response_buffer_size,
                                n20_slice_t* response_out) {
    uint8_t msg_buffer[1024];
    size_t msg_size = sizeof(msg_buffer);

    n20_error_t err = n20_msg_request_write(request, msg_buffer, &msg_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    ssize_t received = dispatch_request(msg_buffer + (sizeof(msg_buffer) - msg_size),
                                        msg_size,
                                        response_buffer,
                                        response_buffer_size);
    if (received < 0) {
        return n20_error_crypto_implementation_specific_e;
    }

    response_out->buffer = response_buffer;
    response_out->size = (size_t)received;
    return n20_error_ok_e;
}

static void test_dice_chain_readable(void) {
    TEST_BEGIN("dice_chain is readable from securityfs");

    int fd = open(DICE_CHAIN_PATH, O_RDONLY);
    ASSERT(fd >= 0, "Cannot open %s", DICE_CHAIN_PATH);

    uint8_t buffer[4096];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    close(fd);

    ASSERT(bytes_read > 0, "dice_chain is empty");
    ASSERT_EQ(
        buffer[0], 0x9f, "Expected CBOR indefinite array start (0x9f), got 0x%02x", buffer[0]);
    ASSERT_EQ(buffer[bytes_read - 1],
              0xff,
              "Expected CBOR break (0xff) at end, got 0x%02x",
              buffer[bytes_read - 1]);

    TEST_PASS();
}

static void test_cdi_cert_x509_p256(void) {
    TEST_BEGIN("cdi-cert X.509 P-256");

    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_cdi_cert_e;
    request.payload.issue_cdi_cert.issuer_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_cdi_cert.subject_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_cdi_cert.certificate_format = n20_certificate_format_x509_e;

    uint8_t response_buffer[2048];
    n20_slice_t response;
    n20_error_t err = send_request(&request, response_buffer, sizeof(response_buffer), &response);
    ASSERT_EQ(err, n20_error_ok_e, "send_request failed: 0x%x", err);

    n20_msg_issue_cert_response_t cert_response;
    err = n20_msg_issue_cert_response_read(&cert_response, response);
    ASSERT_EQ(err, n20_error_ok_e, "Failed to parse cert response: 0x%x", err);
    ASSERT_EQ(cert_response.error_code,
              n20_error_ok_e,
              "Service returned error: 0x%x",
              cert_response.error_code);
    ASSERT(cert_response.certificate.size > 0, "Certificate is empty");
    ASSERT_EQ(cert_response.certificate.buffer[0],
              0x30,
              "Expected DER SEQUENCE tag (0x30), got 0x%02x",
              cert_response.certificate.buffer[0]);

    TEST_PASS();
}

#if N20_WITH_COSE == 1
static void test_cdi_cert_cose_p256(void) {
    TEST_BEGIN("cdi-cert COSE P-256");

    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_cdi_cert_e;
    request.payload.issue_cdi_cert.issuer_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_cdi_cert.subject_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_cdi_cert.certificate_format = n20_certificate_format_cose_e;

    uint8_t response_buffer[2048];
    n20_slice_t response;
    n20_error_t err = send_request(&request, response_buffer, sizeof(response_buffer), &response);
    ASSERT_EQ(err, n20_error_ok_e, "send_request failed: 0x%x", err);

    n20_msg_issue_cert_response_t cert_response;
    err = n20_msg_issue_cert_response_read(&cert_response, response);
    ASSERT_EQ(err, n20_error_ok_e, "Failed to parse cert response: 0x%x", err);
    ASSERT_EQ(cert_response.error_code,
              n20_error_ok_e,
              "Service returned error: 0x%x",
              cert_response.error_code);
    ASSERT(cert_response.certificate.size > 0, "Certificate is empty");

    n20_istream_t istream;
    n20_istream_init(&istream, cert_response.certificate.buffer, cert_response.certificate.size);
    n20_cbor_type_t type;
    uint64_t value;
    bool ok = n20_cbor_read_header(&istream, &type, &value);
    ASSERT(ok, "Failed to parse COSE_Sign1 CBOR header");
    ASSERT_EQ(type, n20_cbor_type_array_e, "Expected CBOR array, got type %d", (int)type);
    ASSERT_EQ(value, 4u, "COSE_Sign1 must have 4 elements, got %llu", (unsigned long long)value);

    TEST_PASS();
}
#endif

static void test_eca_cert_x509_p256(void) {
    TEST_BEGIN("eca-cert X.509 P-256");

    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_eca_cert_e;
    request.payload.issue_eca_cert.issuer_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_eca_cert.subject_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_eca_cert.certificate_format = n20_certificate_format_x509_e;

    uint8_t response_buffer[2048];
    n20_slice_t response;
    n20_error_t err = send_request(&request, response_buffer, sizeof(response_buffer), &response);
    ASSERT_EQ(err, n20_error_ok_e, "send_request failed: 0x%x", err);

    n20_msg_issue_cert_response_t cert_response;
    err = n20_msg_issue_cert_response_read(&cert_response, response);
    ASSERT_EQ(err, n20_error_ok_e, "Failed to parse cert response: 0x%x", err);
    ASSERT_EQ(cert_response.error_code,
              n20_error_ok_e,
              "Service returned error: 0x%x",
              cert_response.error_code);
    ASSERT(cert_response.certificate.size > 0, "ECA certificate is empty");
    ASSERT_EQ(cert_response.certificate.buffer[0],
              0x30,
              "Expected DER SEQUENCE tag (0x30), got 0x%02x",
              cert_response.certificate.buffer[0]);

    TEST_PASS();
}

static void test_eca_ee_cert_x509_p256(void) {
    TEST_BEGIN("eca-ee-cert X.509 P-256");

    uint8_t key_usage[] = {0x01};
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_eca_ee_cert_e;
    request.payload.issue_eca_ee_cert.issuer_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_eca_ee_cert.subject_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.issue_eca_ee_cert.certificate_format = n20_certificate_format_x509_e;
    request.payload.issue_eca_ee_cert.name = (n20_string_slice_t){.size = 4, .buffer = "test"};
    request.payload.issue_eca_ee_cert.key_usage =
        (n20_slice_t){.size = sizeof(key_usage), .buffer = key_usage};

    uint8_t response_buffer[2048];
    n20_slice_t response;
    n20_error_t err = send_request(&request, response_buffer, sizeof(response_buffer), &response);
    ASSERT_EQ(err, n20_error_ok_e, "send_request failed: 0x%x", err);

    n20_msg_issue_cert_response_t cert_response;
    err = n20_msg_issue_cert_response_read(&cert_response, response);
    ASSERT_EQ(err, n20_error_ok_e, "Failed to parse cert response: 0x%x", err);
    ASSERT_EQ(cert_response.error_code,
              n20_error_ok_e,
              "Service returned error: 0x%x",
              cert_response.error_code);
    ASSERT(cert_response.certificate.size > 0, "ECA EE certificate is empty");
    ASSERT_EQ(cert_response.certificate.buffer[0],
              0x30,
              "Expected DER SEQUENCE tag (0x30), got 0x%02x",
              cert_response.certificate.buffer[0]);

    TEST_PASS();
}

static void test_eca_ee_sign_p256(void) {
    TEST_BEGIN("eca-ee-sign P-256");

    uint8_t key_usage[] = {0x01};
    uint8_t message[] = "test message to sign";
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_eca_ee_sign_e;
    request.payload.eca_ee_sign.subject_key_type = n20_crypto_key_type_secp256r1_e;
    request.payload.eca_ee_sign.name = (n20_string_slice_t){.size = 4, .buffer = "test"};
    request.payload.eca_ee_sign.key_usage =
        (n20_slice_t){.size = sizeof(key_usage), .buffer = key_usage};
    request.payload.eca_ee_sign.message =
        (n20_slice_t){.size = sizeof(message) - 1, .buffer = message};

    uint8_t response_buffer[1024];
    n20_slice_t response;
    n20_error_t err = send_request(&request, response_buffer, sizeof(response_buffer), &response);
    ASSERT_EQ(err, n20_error_ok_e, "send_request failed: 0x%x", err);

    n20_msg_eca_ee_sign_response_t sign_response;
    err = n20_msg_eca_ee_sign_response_read(&sign_response, response);
    ASSERT_EQ(err, n20_error_ok_e, "Failed to parse sign response: 0x%x", err);
    ASSERT_EQ(sign_response.error_code,
              n20_error_ok_e,
              "Service returned error: 0x%x",
              sign_response.error_code);
    ASSERT_EQ(sign_response.signature.size,
              64u,
              "P-256 signature should be 64 bytes, got %zu",
              sign_response.signature.size);

    TEST_PASS();
}

static uint8_t const TEST_CODE_HASH[32] = {
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
};
static uint8_t const TEST_CONFIG_HASH[32] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
};
static uint8_t const TEST_AUTHORITY_HASH[32] = {
    0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
    0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a,
};
static uint8_t const TEST_HIDDEN[32] = {
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
};

/*
 * Full chain generation and verification test.
 *
 * The test exercises the full DICE certificate chain across all supported
 * key type and format permutations. Since promote is irreversible, all
 * certificates at a given level must be generated before promoting.
 *
 * Structure:
 *   - At each level, generate CDI/ECA/ECA_EE/sign for all key_type × format combos
 *   - Also generate ECA/ECA_EE/sign via parent_path from earlier levels
 *   - After all promotes, verify chains and check parent_path equivalence
 */

typedef struct {
    uint8_t data[2048];
    size_t size;
} cert_buffer_t;

typedef struct {
    uint8_t data[128];
    size_t size;
} sig_buffer_t;

static bool issue_cdi_cert(n20_crypto_key_type_t issuer_key_type,
                           n20_crypto_key_type_t subject_key_type,
                           n20_certificate_format_t format,
                           n20_parent_path_t parent_path,
                           cert_buffer_t* out) {
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_cdi_cert_e;
    request.payload.issue_cdi_cert.issuer_key_type = issuer_key_type;
    request.payload.issue_cdi_cert.subject_key_type = subject_key_type;
    request.payload.issue_cdi_cert.certificate_format = format;
    request.payload.issue_cdi_cert.parent_path = parent_path;
    request.payload.issue_cdi_cert.next_context.code_hash =
        (n20_slice_t){.size = sizeof(TEST_CODE_HASH), .buffer = TEST_CODE_HASH};
    request.payload.issue_cdi_cert.next_context.configuration_hash =
        (n20_slice_t){.size = sizeof(TEST_CONFIG_HASH), .buffer = TEST_CONFIG_HASH};
    request.payload.issue_cdi_cert.next_context.authority_hash =
        (n20_slice_t){.size = sizeof(TEST_AUTHORITY_HASH), .buffer = TEST_AUTHORITY_HASH};
    request.payload.issue_cdi_cert.next_context.mode = n20_open_dice_mode_normal_e;
    request.payload.issue_cdi_cert.next_context.hidden =
        (n20_slice_t){.size = sizeof(TEST_HIDDEN), .buffer = TEST_HIDDEN};

    uint8_t response_buffer[2048];
    n20_slice_t response;
    if (send_request(&request, response_buffer, sizeof(response_buffer), &response) !=
        n20_error_ok_e) {
        return false;
    }

    n20_msg_issue_cert_response_t cert_response;
    if (n20_msg_issue_cert_response_read(&cert_response, response) != n20_error_ok_e) {
        return false;
    }
    if (cert_response.error_code != n20_error_ok_e) {
        fprintf(stderr, "    cdi-cert error: 0x%x\n", cert_response.error_code);
        return false;
    }
    if (cert_response.certificate.size > sizeof(out->data)) return false;
    memcpy(out->data, cert_response.certificate.buffer, cert_response.certificate.size);
    out->size = cert_response.certificate.size;
    return true;
}

static bool issue_eca_cert(n20_crypto_key_type_t issuer_key_type,
                           n20_crypto_key_type_t subject_key_type,
                           n20_certificate_format_t format,
                           n20_parent_path_t parent_path,
                           cert_buffer_t* out) {
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_eca_cert_e;
    request.payload.issue_eca_cert.issuer_key_type = issuer_key_type;
    request.payload.issue_eca_cert.subject_key_type = subject_key_type;
    request.payload.issue_eca_cert.certificate_format = format;
    request.payload.issue_eca_cert.parent_path = parent_path;

    uint8_t response_buffer[2048];
    n20_slice_t response;
    if (send_request(&request, response_buffer, sizeof(response_buffer), &response) !=
        n20_error_ok_e) {
        return false;
    }

    n20_msg_issue_cert_response_t cert_response;
    if (n20_msg_issue_cert_response_read(&cert_response, response) != n20_error_ok_e) {
        return false;
    }
    if (cert_response.error_code != n20_error_ok_e) {
        fprintf(stderr, "    eca-cert error: 0x%x\n", cert_response.error_code);
        return false;
    }
    if (cert_response.certificate.size > sizeof(out->data)) return false;
    memcpy(out->data, cert_response.certificate.buffer, cert_response.certificate.size);
    out->size = cert_response.certificate.size;
    return true;
}

static bool issue_eca_ee_cert(n20_crypto_key_type_t issuer_key_type,
                              n20_crypto_key_type_t subject_key_type,
                              n20_certificate_format_t format,
                              n20_parent_path_t parent_path,
                              cert_buffer_t* out) {
    uint8_t key_usage[] = {0x01};
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_issue_eca_ee_cert_e;
    request.payload.issue_eca_ee_cert.issuer_key_type = issuer_key_type;
    request.payload.issue_eca_ee_cert.subject_key_type = subject_key_type;
    request.payload.issue_eca_ee_cert.certificate_format = format;
    request.payload.issue_eca_ee_cert.parent_path = parent_path;
    request.payload.issue_eca_ee_cert.name = (n20_string_slice_t){.size = 7, .buffer = "testkey"};
    request.payload.issue_eca_ee_cert.key_usage =
        (n20_slice_t){.size = sizeof(key_usage), .buffer = key_usage};

    uint8_t response_buffer[2048];
    n20_slice_t response;
    if (send_request(&request, response_buffer, sizeof(response_buffer), &response) !=
        n20_error_ok_e) {
        return false;
    }

    n20_msg_issue_cert_response_t cert_response;
    if (n20_msg_issue_cert_response_read(&cert_response, response) != n20_error_ok_e) {
        return false;
    }
    if (cert_response.error_code != n20_error_ok_e) {
        fprintf(stderr, "    eca-ee-cert error: 0x%x\n", cert_response.error_code);
        return false;
    }
    if (cert_response.certificate.size > sizeof(out->data)) return false;
    memcpy(out->data, cert_response.certificate.buffer, cert_response.certificate.size);
    out->size = cert_response.certificate.size;
    return true;
}

static bool eca_ee_sign(n20_crypto_key_type_t key_type,
                        n20_parent_path_t parent_path,
                        uint8_t const* message,
                        size_t message_size,
                        sig_buffer_t* out) {
    uint8_t key_usage[] = {0x01};
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_eca_ee_sign_e;
    request.payload.eca_ee_sign.subject_key_type = key_type;
    request.payload.eca_ee_sign.parent_path = parent_path;
    request.payload.eca_ee_sign.name = (n20_string_slice_t){.size = 7, .buffer = "testkey"};
    request.payload.eca_ee_sign.key_usage =
        (n20_slice_t){.size = sizeof(key_usage), .buffer = key_usage};
    request.payload.eca_ee_sign.message = (n20_slice_t){.size = message_size, .buffer = message};

    uint8_t response_buffer[1024];
    n20_slice_t response;
    if (send_request(&request, response_buffer, sizeof(response_buffer), &response) !=
        n20_error_ok_e) {
        return false;
    }

    n20_msg_eca_ee_sign_response_t sign_response;
    if (n20_msg_eca_ee_sign_response_read(&sign_response, response) != n20_error_ok_e) {
        return false;
    }
    if (sign_response.error_code != n20_error_ok_e) {
        fprintf(stderr, "    eca-ee-sign error: 0x%x\n", sign_response.error_code);
        return false;
    }
    if (sign_response.signature.size > sizeof(out->data)) return false;
    memcpy(out->data, sign_response.signature.buffer, sign_response.signature.size);
    out->size = sign_response.signature.size;
    return true;
}

static bool do_promote(uint8_t const* compressed_input, size_t compressed_input_size) {
    n20_msg_request_t request = {0};
    request.request_type = n20_msg_request_type_promote_e;
    request.payload.promote.compressed_context =
        (n20_slice_t){.size = compressed_input_size, .buffer = compressed_input};

    uint8_t response_buffer[1024];
    n20_slice_t response;
    if (send_request(&request, response_buffer, sizeof(response_buffer), &response) !=
        n20_error_ok_e) {
        return false;
    }

    n20_msg_error_response_t promote_resp;
    if (n20_msg_error_response_read(&promote_resp, response) != n20_error_ok_e) {
        return false;
    }
    if (promote_resp.error_code != n20_error_ok_e) {
        fprintf(stderr, "    promote error: 0x%x\n", promote_resp.error_code);
        return false;
    }
    return true;
}

static bool read_uds_cert(cert_buffer_t* out) {
    int fd = open(DICE_CHAIN_PATH, O_RDONLY);
    if (fd < 0) return false;
    uint8_t dice_chain_buf[4096];
    ssize_t dc_size = read(fd, dice_chain_buf, sizeof(dice_chain_buf));
    close(fd);
    if (dc_size <= 10) return false;

    n20_istream_t dc_stream;
    n20_istream_init(&dc_stream, dice_chain_buf, (size_t)dc_size);
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    n20_cbor_read_header(&dc_stream, &cbor_type, &cbor_value);
    n20_cbor_read_header(&dc_stream, &cbor_type, &cbor_value);
    n20_cbor_read_header(&dc_stream, &cbor_type, &cbor_value);
    n20_slice_t uds_cert_slice;
    if (!n20_istream_get_slice(&dc_stream, &uds_cert_slice, cbor_value)) return false;
    if (uds_cert_slice.size > sizeof(out->data)) return false;
    memcpy(out->data, uds_cert_slice.buffer, uds_cert_slice.size);
    out->size = uds_cert_slice.size;
    return true;
}

/* Key types to test. */
static n20_crypto_key_type_t const KEY_TYPES[] = {
    n20_crypto_key_type_secp256r1_e,
    n20_crypto_key_type_secp384r1_e,
};
#define NUM_KEY_TYPES (sizeof(KEY_TYPES) / sizeof(KEY_TYPES[0]))

/* Certificate format variants for CDI certs. ECA/ECA_EE are X.509 only. */
static n20_certificate_format_t const CDI_FORMATS[] = {
    n20_certificate_format_x509_e,
#if N20_WITH_COSE == 1
    n20_certificate_format_cose_e,
#endif
};
#define NUM_CDI_FORMATS (sizeof(CDI_FORMATS) / sizeof(CDI_FORMATS[0]))

/*
 * Data structure to hold all artifacts generated at level 1 (before any promote).
 *
 * CDI1: issued at level 0 with no parent path.
 *   Dimensions: subject_key_type[NUM_KEY_TYPES] × format[NUM_CDI_FORMATS]
 *   Issuer key type is always P-256 (the UDS key type).
 *
 * CDI2: issued at level 0 with parent_path depth 1.
 *   Dimensions: issuer_key_type[NUM_KEY_TYPES] × subject_key_type[NUM_KEY_TYPES]
 *               × format[NUM_CDI_FORMATS]
 *   The issuer_key_type selects the signing key derivation path from the
 *   parent CDI.
 *
 * ECA: issued at level 0 with parent_path depth 2.
 *   Dimensions: issuer_key_type[NUM_KEY_TYPES] × subject_key_type[NUM_KEY_TYPES]
 *   Format is always X.509.
 *
 * ECA_EE: issued at level 0 with parent_path depth 2.
 *   The issuer key for ECA_EE is the ECA's subject key.
 *   Dimensions: eca_key_type[NUM_KEY_TYPES] × ee_subject_key_type[NUM_KEY_TYPES]
 *   Format is always X.509.
 *
 * Signature: issued at level 0 with parent_path depth 2.
 *   The signing key type is the ECA_EE's subject key type.
 *   Dimensions: ee_subject_key_type[NUM_KEY_TYPES]
 */

typedef struct {
    /* CDI1 certs: indexed by [subject_key_type_idx][format_idx] */
    cert_buffer_t cdi1[NUM_KEY_TYPES][NUM_CDI_FORMATS];
    bool cdi1_valid[NUM_KEY_TYPES][NUM_CDI_FORMATS];

    /* CDI2 certs (via parent path depth 1): indexed by
     * [issuer_key_type_idx][subject_key_type_idx][format_idx] */
    cert_buffer_t cdi2[NUM_KEY_TYPES][NUM_KEY_TYPES][NUM_CDI_FORMATS];
    bool cdi2_valid[NUM_KEY_TYPES][NUM_KEY_TYPES][NUM_CDI_FORMATS];

    /* ECA certs (via parent path depth 2): indexed by [issuer_key_type_idx][subject_key_type_idx]
     */
    cert_buffer_t eca[NUM_KEY_TYPES][NUM_KEY_TYPES];
    bool eca_valid[NUM_KEY_TYPES][NUM_KEY_TYPES];

    /* ECA_EE certs (via parent path depth 2):
     * indexed by [eca_subject_key_type_idx][ee_subject_key_type_idx]
     * The ECA_EE issuer_key_type = ECA's subject_key_type. */
    cert_buffer_t eca_ee[NUM_KEY_TYPES][NUM_KEY_TYPES];
    bool eca_ee_valid[NUM_KEY_TYPES][NUM_KEY_TYPES];

    /* Signatures (via parent path depth 2):
     * indexed by [ee_subject_key_type_idx] */
    sig_buffer_t signature[NUM_KEY_TYPES];
    bool signature_valid[NUM_KEY_TYPES];
} level_artifacts_t;

static level_artifacts_t level1_artifacts;
static cert_buffer_t uds_cert;
static uint8_t compressed_input[N20_FUNC_COMPRESSED_INPUT_SIZE];
static uint8_t const test_message[] = "DICE chain integration test message";

static void test_level1(void) {
    TEST_BEGIN("Level 1: generate all certs at UDS level");

    n20_parent_path_t no_path = N20_MSG_PARENT_PATH_EMPTY;
    n20_slice_t path_elements[2] = {
        {.size = sizeof(compressed_input), .buffer = compressed_input},
        {.size = sizeof(compressed_input), .buffer = compressed_input},
    };
    n20_parent_path_t path_depth1 = {
        .length = 1, .is_encoded = false, .decoded = &path_elements[0]};
    n20_parent_path_t path_depth2 = {
        .length = 2, .is_encoded = false, .decoded = &path_elements[0]};

    n20_error_t err = test_compress_cdi_input(TEST_CODE_HASH,
                                              sizeof(TEST_CODE_HASH),
                                              TEST_CONFIG_HASH,
                                              sizeof(TEST_CONFIG_HASH),
                                              TEST_AUTHORITY_HASH,
                                              sizeof(TEST_AUTHORITY_HASH),
                                              (uint8_t)n20_open_dice_mode_normal_e,
                                              TEST_HIDDEN,
                                              sizeof(TEST_HIDDEN),
                                              compressed_input,
                                              sizeof(compressed_input));
    ASSERT_EQ(err, n20_error_ok_e, "compress_cdi_input failed: 0x%x", err);

    ASSERT(read_uds_cert(&uds_cert), "Failed to read UDS cert");

    /* CDI1: subject_key_type × format, issuer = P-256, no parent path */
    for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
        for (size_t fi = 0; fi < NUM_CDI_FORMATS; fi++) {
            level1_artifacts.cdi1_valid[si][fi] = issue_cdi_cert(n20_crypto_key_type_secp256r1_e,
                                                                 KEY_TYPES[si],
                                                                 CDI_FORMATS[fi],
                                                                 no_path,
                                                                 &level1_artifacts.cdi1[si][fi]);
        }
    }

    /* CDI2: issuer_key_type × subject_key_type × format, parent_path depth 1 */
    for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            for (size_t fi = 0; fi < NUM_CDI_FORMATS; fi++) {
                level1_artifacts.cdi2_valid[ii][si][fi] =
                    issue_cdi_cert(KEY_TYPES[ii],
                                   KEY_TYPES[si],
                                   CDI_FORMATS[fi],
                                   path_depth1,
                                   &level1_artifacts.cdi2[ii][si][fi]);
            }
        }
    }

    /* ECA: issuer_key_type × subject_key_type, parent_path depth 2 */
    for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            level1_artifacts.eca_valid[ii][si] = issue_eca_cert(KEY_TYPES[ii],
                                                                KEY_TYPES[si],
                                                                n20_certificate_format_x509_e,
                                                                path_depth2,
                                                                &level1_artifacts.eca[ii][si]);
        }
    }

    /* ECA_EE: eca_subject_key_type × ee_subject_key_type, parent_path depth 2.
     * The ECA_EE issuer key type = ECA subject key type. */
    for (size_t ei = 0; ei < NUM_KEY_TYPES; ei++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            level1_artifacts.eca_ee_valid[ei][si] =
                issue_eca_ee_cert(KEY_TYPES[ei],
                                  KEY_TYPES[si],
                                  n20_certificate_format_x509_e,
                                  path_depth2,
                                  &level1_artifacts.eca_ee[ei][si]);
        }
    }

    /* Signature: ee_subject_key_type, parent_path depth 2 */
    for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
        level1_artifacts.signature_valid[si] = eca_ee_sign(KEY_TYPES[si],
                                                           path_depth2,
                                                           test_message,
                                                           sizeof(test_message) - 1,
                                                           &level1_artifacts.signature[si]);
    }

    /* Verification: check X.509 chains where applicable */
    uint8_t uds_pubkey[97];
    size_t uds_pubkey_size = sizeof(uds_pubkey);
    ASSERT(test_extract_x509_pubkey(uds_cert.data, uds_cert.size, uds_pubkey, &uds_pubkey_size),
           "Failed to extract UDS public key");
    ASSERT(test_verify_x509_signature(uds_cert.data,
                                      uds_cert.size,
                                      uds_pubkey,
                                      uds_pubkey_size,
                                      n20_crypto_key_type_secp256r1_e),
           "UDS self-signed verification failed");

    /* Verify CDI1 X.509 certs against UDS key */
    for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
        if (!level1_artifacts.cdi1_valid[si][0]) continue; /* X.509 is index 0 */
        ASSERT(test_verify_x509_signature(level1_artifacts.cdi1[si][0].data,
                                          level1_artifacts.cdi1[si][0].size,
                                          uds_pubkey,
                                          uds_pubkey_size,
                                          n20_crypto_key_type_secp256r1_e),
               "CDI1 X.509 (sub=%d) verification against UDS failed",
               KEY_TYPES[si]);
        if (NUM_CDI_FORMATS > 1 && level1_artifacts.cdi1_valid[si][1]) {
            /* If COSE format also generated, verify signature using same UDS key */
            test_cose_sign1_t cose_sign1 = {0};
            ASSERT(test_parse_cose_sign1(level1_artifacts.cdi1[si][1].data,
                                         level1_artifacts.cdi1[si][1].size,
                                         &cose_sign1),
                   "Failed to parse CDI1 COSE_Sign1 cert (sub=%d)",
                   KEY_TYPES[si]);
            ASSERT(test_verify_cose_sign1(&cose_sign1,
                                          uds_pubkey + 1,
                                          uds_pubkey_size - 1,
                                          n20_crypto_key_type_secp256r1_e),
                   "CDI1 COSE (sub=%d) verification against UDS failed",
                   KEY_TYPES[si]);
        }
    }

    /* Verify CDI2 X.509 against CDI1 subject key (P-256 CDI1 -> CDI2) */
    for (size_t issfi = 0; issfi < NUM_CDI_FORMATS; issfi++) {
        for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
            /* CDI 1 subject key is the issuer for the CDI2 certs.
             * So use issuer index ii as subject index of the CDI1 matrix. */
            if (level1_artifacts.cdi1_valid[ii][issfi]) {
                uint8_t cdi1_pubkey[97];
                size_t cdi1_pubkey_size = sizeof(cdi1_pubkey);
                if (issfi == 0) {
                    /* X.509 format: extract pubkey from cert */
                    ASSERT(test_extract_x509_pubkey(level1_artifacts.cdi1[ii][issfi].data,
                                                    level1_artifacts.cdi1[ii][issfi].size,
                                                    cdi1_pubkey,
                                                    &cdi1_pubkey_size),
                           "Failed to extract CDI1 public key");
                } else {
                    /* COSE format: pubkey is the COSE_Sign1 payload */
                    n20_crypto_key_type_t got_key_type;
                    ASSERT(test_extract_cose_pubkey(level1_artifacts.cdi1[ii][issfi].data,
                                                    level1_artifacts.cdi1[ii][issfi].size,
                                                    cdi1_pubkey,
                                                    &cdi1_pubkey_size,
                                                    &got_key_type),
                           "Failed to extract CDI1 COSE_Sign1 cert (sub=%d)",
                           KEY_TYPES[ii]);
                    ASSERT_EQ(got_key_type,
                              KEY_TYPES[ii],
                              "Unexpected key type extracted from CDI1 COSE_Sign1 cert (sub=%d)",
                              KEY_TYPES[ii]);
                }
                for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
                    if (!level1_artifacts.cdi2_valid[ii][si][0]) continue;
                    ASSERT(test_verify_x509_signature(level1_artifacts.cdi2[ii][si][0].data,
                                                      level1_artifacts.cdi2[ii][si][0].size,
                                                      cdi1_pubkey,
                                                      cdi1_pubkey_size,
                                                      KEY_TYPES[ii]),
                           "CDI2 X.509 (issf=%zu, iss=%d, sub=%d) verification against CDI1 failed",
                           issfi,
                           KEY_TYPES[ii],
                           KEY_TYPES[si]);
                    if (NUM_CDI_FORMATS > 1 && level1_artifacts.cdi2_valid[ii][si][1]) {
                        /* If COSE format also generated, verify signature using CDI1 key */
                        test_cose_sign1_t cose_sign1 = {0};
                        ASSERT(test_parse_cose_sign1(level1_artifacts.cdi2[ii][si][1].data,
                                                     level1_artifacts.cdi2[ii][si][1].size,
                                                     &cose_sign1),
                               "Failed to parse CDI2 COSE_Sign1 cert (sub=%d)",
                               KEY_TYPES[si]);
                        ASSERT(
                            test_verify_cose_sign1(
                                &cose_sign1, cdi1_pubkey + 1, cdi1_pubkey_size - 1, KEY_TYPES[ii]),
                            "CDI2 COSE (issf=%zu, iss=%d, sub=%d) verification against CDI1 failed",
                            issfi,
                            KEY_TYPES[ii],
                            KEY_TYPES[si]);
                    }
                }
            }
        }
    }

    /* Verify ECA certificates against CDI2 keys */
    for (size_t issfi = 0; issfi < NUM_CDI_FORMATS; issfi++) {
        for (size_t ii2 = 0; ii2 < NUM_KEY_TYPES; ii2++) {
            for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
                /* Get CDI2 public key for this issuer key type.
                 * Use the issuer index ii as the subject index of the CDI2 matrix.
                 * The issuer index ii2 corresponds to the CDI2 issuer key type. */
                if (!level1_artifacts.cdi2_valid[ii2][ii][issfi]) continue;
                uint8_t cdi2_pubkey[97];
                size_t cdi2_pubkey_size = sizeof(cdi2_pubkey);
                if (issfi == 0) {
                    /* X.509 format: extract pubkey from cert */
                    ASSERT(test_extract_x509_pubkey(level1_artifacts.cdi2[ii2][ii][issfi].data,
                                                    level1_artifacts.cdi2[ii2][ii][issfi].size,
                                                    cdi2_pubkey,
                                                    &cdi2_pubkey_size),
                           "Failed to extract public key from CDI2 X.509 cert (iss=%d, sub=%d)",
                           KEY_TYPES[ii2],
                           KEY_TYPES[ii]);
                } else {
                    /* COSE format: pubkey is the COSE_Sign1 payload */
                    n20_crypto_key_type_t got_key_type;
                    ASSERT(
                        test_extract_cose_pubkey(level1_artifacts.cdi2[ii2][ii][issfi].data,
                                                 level1_artifacts.cdi2[ii2][ii][issfi].size,
                                                 cdi2_pubkey,
                                                 &cdi2_pubkey_size,
                                                 &got_key_type),
                        "Failed to extract public key from CDI2 COSE_Sign1 cert (iss=%d, sub=%d)",
                        KEY_TYPES[ii2],
                        KEY_TYPES[ii]);
                    ASSERT_EQ(
                        got_key_type,
                        KEY_TYPES[ii],
                        "Unexpected key type extracted from CDI2 COSE_Sign1 cert (iss=%d, sub=%d)",
                        KEY_TYPES[ii2],
                        KEY_TYPES[ii]);
                }

                for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
                    if (!level1_artifacts.eca_valid[ii][si]) continue;

                    /* ECA signed by CDI2's subject key (type = KEY_TYPES[ii]) */
                    ASSERT(test_verify_x509_signature(level1_artifacts.eca[ii][si].data,
                                                      level1_artifacts.eca[ii][si].size,
                                                      cdi2_pubkey,
                                                      cdi2_pubkey_size,
                                                      KEY_TYPES[ii]),
                           "ECA (cdi2.iss = %d, eca.iss=%d, eca.sub=%d) verification failed",
                           KEY_TYPES[ii2],
                           KEY_TYPES[ii],
                           KEY_TYPES[si]);
                }
            }
        }
    }
    /* Verify ECA_EE certificates against ECA keys */
    for (size_t ii2 = 0; ii2 < NUM_KEY_TYPES; ii2++) {
        for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
            /* Get ECA public key for this issuer key type.
             * Use the issuer index ii as the subject index of the CDI2 matrix. */
            if (!level1_artifacts.eca_valid[ii2][ii]) continue;
            uint8_t eca_pubkey[97];
            size_t eca_pubkey_size = sizeof(eca_pubkey);
            if (!test_extract_x509_pubkey(level1_artifacts.eca[ii2][ii].data,
                                          level1_artifacts.eca[ii2][ii].size,
                                          eca_pubkey,
                                          &eca_pubkey_size))
                continue;

            for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
                if (!level1_artifacts.eca_ee_valid[ii][si]) continue;

                /* ECA_EE signed by ECA's subject key (type = KEY_TYPES[ii]) */
                ASSERT(test_verify_x509_signature(level1_artifacts.eca_ee[ii][si].data,
                                                  level1_artifacts.eca_ee[ii][si].size,
                                                  eca_pubkey,
                                                  eca_pubkey_size,
                                                  KEY_TYPES[ii]),
                       "ECA_EE (eca.iss = %d, eca.sub=%d, ee.sub=%d) verification failed",
                       KEY_TYPES[ii2],
                       KEY_TYPES[ii],
                       KEY_TYPES[si]);
            }
        }
    }

    /* Verify ECA_EE Signatures against ECA_EE keys */
    for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            if (!level1_artifacts.eca_ee_valid[ii][si]) continue;
            uint8_t eca_ee_pubkey[97];
            size_t eca_ee_pubkey_size = sizeof(eca_ee_pubkey);
            if (!test_extract_x509_pubkey(level1_artifacts.eca_ee[ii][si].data,
                                          level1_artifacts.eca_ee[ii][si].size,
                                          eca_ee_pubkey,
                                          &eca_ee_pubkey_size))
                continue;

            if (!level1_artifacts.signature_valid[si]) continue;
            /* Verify signature against ECA_EE key */
            ASSERT(test_verify_raw_signature(eca_ee_pubkey + 1,
                                             eca_ee_pubkey_size - 1,
                                             test_message,
                                             sizeof(test_message) - 1,
                                             level1_artifacts.signature[si].data,
                                             level1_artifacts.signature[si].size,
                                             KEY_TYPES[si]),
                   "Signature verification failed (ee.iss=%d, ee.sub=%d)",
                   KEY_TYPES[ii],
                   KEY_TYPES[si]);
        }
    }

    TEST_PASS();
}

/*
 * This test is run after test_level1 and one promote step.
 * At this point we are at CDI1 level. Generate:
 *   - CDI2: issuer_key_type × subject_key_type × format, parent_path = empty (depth 0)
 *   - ECA: issuer_key_type × subject_key_type, parent_path = depth 1
 *   - ECA_EE: eca_subject_key_type × ee_subject_key_type, parent_path = depth 1
 *   - Signature: ee_subject_key_type, parent_path = depth 1
 *
 * Compare all results to level1_artifacts. They must be identical.
 */
static void test_level2(void) {
    TEST_BEGIN("Level 2: after promote, compare with level 1 artifacts");

    n20_parent_path_t no_path = N20_MSG_PARENT_PATH_EMPTY;
    n20_slice_t path_elements[1] = {
        {.size = sizeof(compressed_input), .buffer = compressed_input},
    };
    n20_parent_path_t path_depth1 = {
        .length = 1, .is_encoded = false, .decoded = &path_elements[0]};

    /* CDI2: no parent path (we are now at CDI1 level) */
    for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            for (size_t fi = 0; fi < NUM_CDI_FORMATS; fi++) {
                cert_buffer_t cert;
                bool ok =
                    issue_cdi_cert(KEY_TYPES[ii], KEY_TYPES[si], CDI_FORMATS[fi], no_path, &cert);
                ASSERT(ok,
                       "Level 2 CDI2 (iss=%d, sub=%d, fmt=%d) failed",
                       KEY_TYPES[ii],
                       KEY_TYPES[si],
                       CDI_FORMATS[fi]);
                ASSERT(level1_artifacts.cdi2_valid[ii][si][fi],
                       "Level 1 CDI2 (iss=%d, sub=%d, fmt=%d) was not valid",
                       KEY_TYPES[ii],
                       KEY_TYPES[si],
                       CDI_FORMATS[fi]);
                ASSERT(
                    cert.size == level1_artifacts.cdi2[ii][si][fi].size &&
                        memcmp(cert.data, level1_artifacts.cdi2[ii][si][fi].data, cert.size) == 0,
                    "CDI2 mismatch (iss=%d, sub=%d, fmt=%d): level2 != level1",
                    KEY_TYPES[ii],
                    KEY_TYPES[si],
                    CDI_FORMATS[fi]);
            }
        }
    }

    /* ECA: parent_path depth 1 */
    for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            cert_buffer_t cert;
            bool ok = issue_eca_cert(
                KEY_TYPES[ii], KEY_TYPES[si], n20_certificate_format_x509_e, path_depth1, &cert);
            ASSERT(ok, "Level 2 ECA (iss=%d, sub=%d) failed", KEY_TYPES[ii], KEY_TYPES[si]);
            ASSERT(level1_artifacts.eca_valid[ii][si],
                   "Level 1 ECA (iss=%d, sub=%d) was not valid",
                   KEY_TYPES[ii],
                   KEY_TYPES[si]);
            ASSERT(cert.size == level1_artifacts.eca[ii][si].size &&
                       memcmp(cert.data, level1_artifacts.eca[ii][si].data, cert.size) == 0,
                   "ECA mismatch (iss=%d, sub=%d): level2 != level1",
                   KEY_TYPES[ii],
                   KEY_TYPES[si]);
        }
    }

    /* ECA_EE: parent_path depth 1 */
    for (size_t ei = 0; ei < NUM_KEY_TYPES; ei++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            cert_buffer_t cert;
            bool ok = issue_eca_ee_cert(
                KEY_TYPES[ei], KEY_TYPES[si], n20_certificate_format_x509_e, path_depth1, &cert);
            ASSERT(ok, "Level 2 ECA_EE (eca=%d, ee=%d) failed", KEY_TYPES[ei], KEY_TYPES[si]);
            ASSERT(level1_artifacts.eca_ee_valid[ei][si],
                   "Level 1 ECA_EE (eca=%d, ee=%d) was not valid",
                   KEY_TYPES[ei],
                   KEY_TYPES[si]);
            ASSERT(cert.size == level1_artifacts.eca_ee[ei][si].size &&
                       memcmp(cert.data, level1_artifacts.eca_ee[ei][si].data, cert.size) == 0,
                   "ECA_EE mismatch (eca=%d, ee=%d): level2 != level1",
                   KEY_TYPES[ei],
                   KEY_TYPES[si]);
        }
    }

    /* Signature: parent_path depth 1 */
    for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
        sig_buffer_t sig;
        bool ok =
            eca_ee_sign(KEY_TYPES[si], path_depth1, test_message, sizeof(test_message) - 1, &sig);
        ASSERT(ok, "Level 2 signature (ee=%d) failed", KEY_TYPES[si]);
        ASSERT(level1_artifacts.signature_valid[si],
               "Level 1 signature (ee=%d) was not valid",
               KEY_TYPES[si]);
        ASSERT(sig.size == level1_artifacts.signature[si].size &&
                   memcmp(sig.data, level1_artifacts.signature[si].data, sig.size) == 0,
               "Signature mismatch (ee=%d): level2 != level1",
               KEY_TYPES[si]);
    }

    TEST_PASS();
}

/*
 * This test is run after test_level2 and one promote step.
 * At this point we are at CDI2 level. Generate:
 *   - ECA: issuer_key_type × subject_key_type, parent_path = empty (depth 0)
 *   - ECA_EE: eca_subject_key_type × ee_subject_key_type, parent_path = empty
 *   - Signature: ee_subject_key_type, parent_path = empty
 *
 * Compare all results to level1_artifacts. They must be identical.
 */
static void test_level3(void) {
    TEST_BEGIN("Level 3: after second promote, compare with level 1 artifacts");

    n20_parent_path_t no_path = N20_MSG_PARENT_PATH_EMPTY;

    /* ECA: no parent path */
    for (size_t ii = 0; ii < NUM_KEY_TYPES; ii++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            cert_buffer_t cert;
            bool ok = issue_eca_cert(
                KEY_TYPES[ii], KEY_TYPES[si], n20_certificate_format_x509_e, no_path, &cert);
            ASSERT(ok, "Level 3 ECA (iss=%d, sub=%d) failed", KEY_TYPES[ii], KEY_TYPES[si]);
            ASSERT(level1_artifacts.eca_valid[ii][si],
                   "Level 1 ECA (iss=%d, sub=%d) was not valid",
                   KEY_TYPES[ii],
                   KEY_TYPES[si]);
            ASSERT(cert.size == level1_artifacts.eca[ii][si].size &&
                       memcmp(cert.data, level1_artifacts.eca[ii][si].data, cert.size) == 0,
                   "ECA mismatch (iss=%d, sub=%d): level3 != level1",
                   KEY_TYPES[ii],
                   KEY_TYPES[si]);
        }
    }

    /* ECA_EE: no parent path */
    for (size_t ei = 0; ei < NUM_KEY_TYPES; ei++) {
        for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
            cert_buffer_t cert;
            bool ok = issue_eca_ee_cert(
                KEY_TYPES[ei], KEY_TYPES[si], n20_certificate_format_x509_e, no_path, &cert);
            ASSERT(ok, "Level 3 ECA_EE (eca=%d, ee=%d) failed", KEY_TYPES[ei], KEY_TYPES[si]);
            ASSERT(level1_artifacts.eca_ee_valid[ei][si],
                   "Level 1 ECA_EE (eca=%d, ee=%d) was not valid",
                   KEY_TYPES[ei],
                   KEY_TYPES[si]);
            ASSERT(cert.size == level1_artifacts.eca_ee[ei][si].size &&
                       memcmp(cert.data, level1_artifacts.eca_ee[ei][si].data, cert.size) == 0,
                   "ECA_EE mismatch (eca=%d, ee=%d): level3 != level1",
                   KEY_TYPES[ei],
                   KEY_TYPES[si]);
        }
    }

    /* Signature: no parent path */
    for (size_t si = 0; si < NUM_KEY_TYPES; si++) {
        sig_buffer_t sig;
        bool ok = eca_ee_sign(KEY_TYPES[si], no_path, test_message, sizeof(test_message) - 1, &sig);
        ASSERT(ok, "Level 3 signature (ee=%d) failed", KEY_TYPES[si]);
        ASSERT(level1_artifacts.signature_valid[si],
               "Level 1 signature (ee=%d) was not valid",
               KEY_TYPES[si]);
        ASSERT(sig.size == level1_artifacts.signature[si].size &&
                   memcmp(sig.data, level1_artifacts.signature[si].data, sig.size) == 0,
               "Signature mismatch (ee=%d): level3 != level1",
               KEY_TYPES[si]);
    }

    TEST_PASS();
}

static void test_promote_1_to_2(void) {
    TEST_BEGIN("Promote from level 1 to level 2");
    ASSERT(do_promote(compressed_input, sizeof(compressed_input)), "Promote failed");
    TEST_PASS();
}

static void test_promote_2_to_3(void) {
    TEST_BEGIN("Promote from level 2 to level 3");
    ASSERT(do_promote(compressed_input, sizeof(compressed_input)), "Promote failed");
    TEST_PASS();
}

int main(void) {
    printf("nat20 integration test suite\n");
    printf("============================\n\n");

    test_dice_chain_readable();
    test_cdi_cert_x509_p256();
#if N20_WITH_COSE == 1
    test_cdi_cert_cose_p256();
#endif
    test_eca_cert_x509_p256();
    test_eca_ee_cert_x509_p256();
    test_eca_ee_sign_p256();

    /* Full parameterized chain test (promote is irreversible — runs once) */
    test_level1();
    test_promote_1_to_2();
    test_level2();
    test_promote_2_to_3();
    test_level3();

    printf("\n============================\n");
    printf("Results: %d passed, %d failed, %d total\n", tests_passed, tests_failed, tests_run);

    return tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
