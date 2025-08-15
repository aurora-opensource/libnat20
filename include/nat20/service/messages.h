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

#pragma once

#include <nat20/crypto.h>
#include <nat20/functionality.h>
#include <nat20/service/service.h>
#include <nat20/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum n20_msg_request_type_s {
    n20_msg_request_type_none_e = 0,
    /**
     * @brief Request to promote the caller's CDI to the next level.
     */
    n20_msg_request_type_promote_e = 1,

    /**
     * @brief Request to issue a CDI certificate.
     */
    n20_msg_request_type_issue_cdi_cert_e = 2,

    /**
     * @brief Request to issue an ECA certificate.
     */
    n20_msg_request_type_issue_eca_cert_e = 3,

    /**
     * @brief Request to sign with an ECA key.
     */
    n20_msg_request_type_eca_sign_e = 4,

    n20_msg_request_type_count_e = 5,
};

typedef enum n20_msg_request_type_s n20_msg_request_type_t;

struct n20_msg_promote_request_s {
    n20_slice_t compressed_context;
};

typedef struct n20_msg_promote_request_s n20_msg_promote_request_t;

struct n20_msg_issue_cdi_cert_request_s {
    /**
     * @brief The type of the parent key.
     *
     * This is used to determine how to derive the new CDI.
     */
    n20_crypto_key_type_t parent_key_type;

    /**
     * @brief The type of the new key to be issued.
     *
     * This is the type of the CDI that is being requested.
     */
    n20_crypto_key_type_t key_type;

    /**
     * @brief The length of the parent path.
     *
     * This is used to determine how many elements are in the parent path.
     */

    n20_open_dice_input_t next_context;

    /**
     * @brief The length of the parent path.
     *
     * This is used to determine how many elements are in the parent path.
     */
    size_t parent_path_length;
    /**
     * @brief The compressed path to the parent CDI.
     *
     * This is used to derive the new CDI from the parent CDI.
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];
    /**
     * @brief The format of the certificate to be issued.
     *
     * This is used to determine how the certificate should be formatted.
     */
    n20_certificate_format_t certificate_format;
};

typedef struct n20_msg_issue_cdi_cert_request_s n20_msg_issue_cdi_cert_request_t;

struct n20_msg_issue_eca_cert_request_s {
    /**
     * @brief The type of the parent key.
     *
     * This is used to sign the ECA certificate.
     */
    n20_crypto_key_type_t parent_key_type;

    /**
     * @brief The type of the ECA key to be issued.
     *
     * This is the type of the ECA key that is being requested.
     */
    n20_crypto_key_type_t key_type;

    /**
     * @brief The length of the parent path.
     *
     * This is used to determine how many elements are in the parent path.
     */
    size_t parent_path_length;

    /**
     * @brief The compressed path to the parent CDI.
     *
     * This is used to derive the parent secret for ECA key generation.
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];

    /**
     * @brief The format of the certificate to be issued.
     *
     * This is used to determine how the certificate should be formatted.
     */
    n20_certificate_format_t certificate_format;

    /**
     * @brief Context descriptor of the key identity and/or purpose.
     *
     * This is used in ECA_CTX derivation.
     */
    n20_string_slice_t context;

    /**
     * @brief Key usage as intended by the client.
     *
     * This is used in ECA_CTX derivation and certificate generation.
     */
    n20_slice_t key_usage;

    /**
     * @brief Challenge (nonce) - a high entropy value.
     *
     * This is used in ECA_CTX derivation and included in the certificate.
     */
    n20_slice_t challenge;
};

typedef struct n20_msg_issue_eca_cert_request_s n20_msg_issue_eca_cert_request_t;

struct n20_msg_eca_sign_request_s {
    /**
     * @brief The type of the parent key.
     *
     * This is used to sign the message.
     */
    n20_crypto_key_type_t parent_key_type;

    /**
     * @brief The type of the ECA key to derive.
     *
     * This is the type of the ECA key used for signing.
     */
    n20_crypto_key_type_t key_type;

    /**
     * @brief The length of the parent path.
     *
     * This is used to determine how many elements are in the parent path.
     */
    size_t parent_path_length;

    /**
     * @brief The compressed path to the parent CDI.
     *
     * This is used to derive the parent secret for ECA key generation.
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];

    /**
     * @brief Context descriptor of the key identity and/or purpose.
     *
     * This is used in ECA_CTX derivation.
     */
    n20_string_slice_t context;

    /**
     * @brief Key usage as intended by the client.
     *
     * This is used in ECA_CTX derivation.
     */
    n20_slice_t key_usage;

    /**
     * @brief Challenge (nonce) - a high entropy value.
     *
     * This is used in ECA_CTX derivation.
     */
    n20_slice_t challenge;

    /**
     * @brief The message to be signed.
     */
    n20_slice_t message;
};

typedef struct n20_msg_eca_sign_request_s n20_msg_eca_sign_request_t;

union n20_msg_request_payload_u {
    n20_msg_promote_request_t promote;
    n20_msg_issue_cdi_cert_request_t issue_cdi_cert;
    n20_msg_issue_eca_cert_request_t issue_eca_cert;
    n20_msg_eca_sign_request_t eca_sign;
};

typedef union n20_msg_request_payload_u n20_msg_request_payload_t;

struct n20_msg_request_s {
    /**
     * @brief The request type.
     *
     * This is a unique identifier for the request.
     */
    n20_msg_request_type_t request_type;

    /**
     * @brief The payload of the request.
     *
     * This is the data that is being sent with the request.
     */
    n20_msg_request_payload_t payload;
};

struct n20_msg_error_response_s {
    /**
     * @brief The error code of the response.
     *
     * This is used to indicate success or failure of the request.
     */
    n20_error_t error_code;
};

typedef struct n20_msg_error_response_s n20_msg_error_response_t;

typedef struct n20_msg_request_s n20_msg_request_t;

struct n20_msg_issue_cdi_cert_response_s {
    /**
     * @brief The error code of the response.
     *
     * This is used to indicate success or failure of the request.
     */
    n20_error_t error_code;
    /**
     * @brief The payload of the response.
     *
     * This is the data that is being sent with the response.
     */
    n20_slice_t certificate;
};

typedef struct n20_msg_issue_cdi_cert_response_s n20_msg_issue_cdi_cert_response_t;

/* ECA certificate response uses the same structure as CDI certificate response */
typedef n20_msg_issue_cdi_cert_response_t n20_msg_issue_eca_cert_response_t;

struct n20_msg_eca_sign_response_s {
    /**
     * @brief The error code of the response.
     *
     * This is used to indicate success or failure of the request.
     */
    n20_error_t error_code;
    /**
     * @brief The signature.
     */
    n20_slice_t signature;
};

typedef struct n20_msg_eca_sign_response_s n20_msg_eca_sign_response_t;

extern n20_error_t n20_msg_request_read(n20_msg_request_t *request, n20_slice_t msg_buffer);

extern n20_error_t n20_msg_request_write(n20_msg_request_t const *request,
                                         uint8_t *buffer,
                                         size_t *buffer_size);

extern n20_error_t n20_msg_issue_cdi_cert_response_read(n20_msg_issue_cdi_cert_response_t *response,
                                                        n20_slice_t buffer);

extern n20_error_t n20_msg_issue_cdi_cert_response_write(
    n20_msg_issue_cdi_cert_response_t const *response,
    uint8_t *buffer,
    size_t *const buffer_size_in_out);

/* ECA certificate response uses the same read/write functions as CDI certificate response */
#define n20_msg_issue_eca_cert_response_read n20_msg_issue_cdi_cert_response_read
#define n20_msg_issue_eca_cert_response_write n20_msg_issue_cdi_cert_response_write

extern n20_error_t n20_msg_error_response_read(n20_msg_error_response_t *response,
                                               n20_slice_t buffer);
extern n20_error_t n20_msg_error_response_write(n20_msg_error_response_t const *response,
                                                uint8_t *buffer,
                                                size_t *const buffer_size_in_out);

extern n20_error_t n20_msg_eca_sign_response_read(n20_msg_eca_sign_response_t *response,
                                                  n20_slice_t buffer);
extern n20_error_t n20_msg_eca_sign_response_write(n20_msg_eca_sign_response_t const *response,
                                                   uint8_t *buffer,
                                                   size_t *const buffer_size_in_out);

#ifdef __cplusplus
}
#endif
