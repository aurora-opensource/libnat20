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

#include <nat20/constants.h>
#include <nat20/crypto.h>
#include <nat20/open_dice.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file messages.h
 * @brief CBOR message definitions for NAT20 service communication.
 *
 * This header defines the message structures and functions for communication
 * between clients and the NAT20 service. All messages are encoded using CBOR
 * (Concise Binary Object Representation) for efficient serialization.
 *
 * The service supports DICE (Device Identifier Composition Engine) attestation
 * operations including CDI (Compound Device Identifier) management, ECA
 * (Embedded Certificate Authority) operations, and cryptographic signing.
 */

/**
 * @brief Maximum number of elements allowed in a parent path.
 *
 * This limit prevents unbounded memory allocation and ensures predictable
 * performance. Paths longer than this limit will be rejected.
 *
 * This value can be adjusted using -DNAT20_STATELESS_MAX_PATH_LENGTH=<value>
 * during cmake configuration. The default is 8.
 */
#ifndef N20_STATELESS_MAX_PATH_LENGTH
#define N20_STATELESS_MAX_PATH_LENGTH 8
#endif

/**
 * @brief Request type enumeration for NAT20 service operations.
 *
 * Each value corresponds to a specific operation that can be performed
 * by the NAT20 service. The request type determines how the payload
 * should be interpreted.
 */
enum n20_msg_request_type_s {
    /**
     * @brief No operation (invalid/uninitialized).
     */
    n20_msg_request_type_none_e = 0,

    /**
     * @brief Request to promote the caller's CDI to the next level.
     *
     * This operation derives a new CDI from the current one using
     * the provided context information.
     */
    n20_msg_request_type_promote_e = 1,

    /**
     * @brief Request to issue a CDI certificate.
     *
     * Creates a certificate that attests to the CDI and includes
     * DICE-specific extensions with the measurement context.
     */
    n20_msg_request_type_issue_cdi_cert_e = 2,

    /**
     * @brief Request to issue an ECA certificate.
     *
     * Issues an Endorsement Certificate Authority certificate
     * that can be used to sign other certificates.
     */
    n20_msg_request_type_issue_eca_cert_e = 3,

    /**
     * @brief Request to issue an ECA End-Entity certificate.
     *
     * Issues an end-entity certificate signed by an ECA key
     * for specific application purposes.
     */
    n20_msg_request_type_issue_eca_ee_cert_e = 4,

    /**
     * @brief Request to sign with an ECA End-Entity key.
     *
     * Performs a digital signature operation using a derived
     * ECA end-entity key.
     */
    n20_msg_request_type_eca_ee_sign_e = 5,

    /**
     * @brief Total number of request types.
     *
     * Used for bounds checking and iteration.
     */
    n20_msg_request_type_count_e = 6,
};

/**
 * @brief Alias for @ref n20_msg_request_type_s.
 */
typedef enum n20_msg_request_type_s n20_msg_request_type_t;

/**
 * @brief Promote request payload.
 *
 * Contains the compressed context needed to derive the next CDI level.
 * The compressed context is typically a hash of the code, configuration,
 * authority, mode, and hidden values.
 */
struct n20_msg_promote_request_s {
    /**
     * @brief Compressed context for CDI derivation.
     *
     * This is typically H(code_hash || conf_hash || auth_hash || mode || hidden)
     * where H is a cryptographic hash function.
     */
    n20_slice_t compressed_context;
};

/**
 * @brief Alias for @ref n20_msg_promote_request_s.
 */
typedef struct n20_msg_promote_request_s n20_msg_promote_request_t;

/**
 * @brief CDI certificate issuance request payload.
 *
 * Contains all information needed to issue a CDI certificate including
 * the parent key information, subject key type, DICE context, and
 * certificate format preferences.
 */
struct n20_msg_issue_cdi_cert_request_s {
    /**
     * @brief The type of the parent key.
     *
     * This determines the cryptographic algorithm of the issuer key
     * used to sign the new certificate.
     */
    n20_crypto_key_type_t issuer_key_type;

    /**
     * @brief The type of the new key to be issued.
     *
     * This determines the cryptographic algorithm of the subject key
     * that will be certified.
     */
    n20_crypto_key_type_t subject_key_type;

    /**
     * @brief DICE measurement context for the new CDI.
     *
     * Contains code hashes, configuration hashes, authority information,
     * mode, and other DICE-specific data that defines the CDI.
     */
    n20_open_dice_input_t next_context;

    /**
     * @brief The length of the parent path.
     *
     * Number of valid elements in the parent_path array.
     * Must be ≤ N20_STATELESS_MAX_PATH_LENGTH.
     */
    size_t parent_path_length;

    /**
     * @brief The compressed path to the parent CDI.
     *
     * Array of compressed contexts used to derive the parent CDI
     * from the root UDS (Unique Device Secret).
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];

    /**
     * @brief The format of the certificate to be issued.
     *
     * Determines whether to generate X.509 or COSE certificate format.
     */
    n20_certificate_format_t certificate_format;
};

/**
 * @brief Alias for @ref n20_msg_issue_cdi_cert_request_s.
 */
typedef struct n20_msg_issue_cdi_cert_request_s n20_msg_issue_cdi_cert_request_t;

/**
 * @brief ECA certificate issuance request payload.
 *
 * Contains information needed to issue an Endorsement Certificate Authority
 * certificate that can be used to sign other certificates.
 */
struct n20_msg_issue_eca_cert_request_s {
    /**
     * @brief The type of the parent key.
     *
     * This determines the cryptographic algorithm of the issuer key
     * used to sign the ECA certificate.
     */
    n20_crypto_key_type_t issuer_key_type;

    /**
     * @brief The type of the ECA key to be issued.
     *
     * This determines the cryptographic algorithm of the ECA key
     * that will be certified.
     */
    n20_crypto_key_type_t subject_key_type;

    /**
     * @brief The length of the parent path.
     *
     * Number of valid elements in the parent_path array.
     * Must be ≤ N20_STATELESS_MAX_PATH_LENGTH.
     */
    size_t parent_path_length;

    /**
     * @brief The compressed path to the parent CDI.
     *
     * Array of compressed contexts used to derive the parent secret
     * for ECA key generation.
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];

    /**
     * @brief The format of the certificate to be issued.
     *
     * Determines whether to generate X.509 or COSE certificate format.
     */
    n20_certificate_format_t certificate_format;

    /**
     * @brief Challenge (nonce) - a high entropy value.
     *
     * This value is used in ECA_CTX derivation to ensure uniqueness
     * and is included in the certificate for freshness verification.
     */
    n20_slice_t challenge;
};

/**
 * @brief Alias for @ref n20_msg_issue_eca_cert_request_s.
 */
typedef struct n20_msg_issue_eca_cert_request_s n20_msg_issue_eca_cert_request_t;

/**
 * @brief ECA End-Entity certificate issuance request payload.
 *
 * Contains information needed to issue an end-entity certificate
 * signed by an ECA key for specific application purposes.
 */
struct n20_msg_issue_eca_ee_cert_request_s {
    /**
     * @brief The type of the parent key.
     *
     * This determines the cryptographic algorithm of the ECA issuer key
     * used to sign the end-entity certificate.
     */
    n20_crypto_key_type_t issuer_key_type;

    /**
     * @brief The type of the end-entity key to be issued.
     *
     * This determines the cryptographic algorithm of the end-entity key
     * that will be certified.
     */
    n20_crypto_key_type_t subject_key_type;

    /**
     * @brief The length of the parent path.
     *
     * Number of valid elements in the parent_path array.
     * Must be ≤ N20_STATELESS_MAX_PATH_LENGTH.
     */
    size_t parent_path_length;

    /**
     * @brief The compressed path to the parent CDI.
     *
     * Array of compressed contexts used to derive the parent secret
     * for ECA key generation.
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];

    /**
     * @brief The format of the certificate to be issued.
     *
     * Determines whether to generate X.509 or COSE certificate format.
     */
    n20_certificate_format_t certificate_format;

    /**
     * @brief Context descriptor of the key identity and/or purpose.
     *
     * Application-specific identifier used in ECA_CTX derivation.
     * Keys with different names will never be identical.
     */
    n20_string_slice_t name;

    /**
     * @brief Key usage as intended by the client.
     *
     * Specifies the cryptographic operations the key is authorized
     * to perform. Used in both key derivation and certificate generation.
     */
    n20_slice_t key_usage;

    /**
     * @brief Challenge (nonce) - a high entropy value.
     *
     * This value is used in ECA_CTX derivation to ensure uniqueness
     * and is included in the certificate for freshness verification.
     */
    n20_slice_t challenge;
};

/**
 * @brief Alias for @ref n20_msg_issue_eca_ee_cert_request_s.
 */
typedef struct n20_msg_issue_eca_ee_cert_request_s n20_msg_issue_eca_ee_cert_request_t;

/**
 * @brief ECA End-Entity signing request payload.
 *
 * Contains information needed to perform a digital signature operation
 * using a derived ECA end-entity key.
 */
struct n20_msg_eca_ee_sign_request_s {
    /**
     * @brief The type of the ECA key to derive.
     *
     * This determines the cryptographic algorithm of the signing key.
     */
    n20_crypto_key_type_t subject_key_type;

    /**
     * @brief The length of the parent path.
     *
     * Number of valid elements in the parent_path array.
     * Must be ≤ N20_STATELESS_MAX_PATH_LENGTH.
     */
    size_t parent_path_length;

    /**
     * @brief The compressed path to the parent CDI.
     *
     * Array of compressed contexts used to derive the parent secret
     * for ECA key generation.
     */
    n20_slice_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];

    /**
     * @brief Context descriptor of the key identity and/or purpose.
     *
     * Application-specific identifier used in ECA_CTX derivation.
     * Must match the name used when the corresponding certificate was issued.
     */
    n20_string_slice_t name;

    /**
     * @brief Key usage as intended by the client.
     *
     * Specifies the cryptographic operations the key is authorized
     * to perform. Must match the key usage used during key derivation.
     */
    n20_slice_t key_usage;

    /**
     * @brief The message to be signed.
     *
     * The data that will be digitally signed using the derived key.
     */
    n20_slice_t message;
};

/**
 * @brief Alias for @ref n20_msg_eca_ee_sign_request_s.
 */
typedef struct n20_msg_eca_ee_sign_request_s n20_msg_eca_ee_sign_request_t;

/**
 * @brief Union of all possible request payloads.
 *
 * The interpretation of this union depends on the request_type field
 * in the containing n20_msg_request_s structure.
 */
union n20_msg_request_payload_u {
    n20_msg_promote_request_t promote;               /**< Promote request payload */
    n20_msg_issue_cdi_cert_request_t issue_cdi_cert; /**< CDI certificate request payload */
    n20_msg_issue_eca_cert_request_t issue_eca_cert; /**< ECA certificate request payload */
    n20_msg_issue_eca_ee_cert_request_t
        issue_eca_ee_cert;                     /**< ECA end-entity certificate request payload */
    n20_msg_eca_ee_sign_request_t eca_ee_sign; /**< ECA end-entity signing request payload */
};

/**
 * @brief Alias for @ref n20_msg_request_payload_u.
 *
 */
typedef union n20_msg_request_payload_u n20_msg_request_payload_t;

/**
 * @brief Complete request message structure.
 *
 * This structure represents a complete request sent to the NAT20 service.
 * The request_type field determines how to interpret the payload union.
 */
struct n20_msg_request_s {
    /**
     * @brief The request type.
     *
     * Unique identifier that determines which operation to perform
     * and how to interpret the payload field.
     */
    n20_msg_request_type_t request_type;

    /**
     * @brief The payload of the request.
     *
     * Contains the operation-specific data. The interpretation
     * depends on the request_type field.
     */
    n20_msg_request_payload_t payload;
};

/**
 * @brief Alias for @ref n20_msg_request_s.
 */
typedef struct n20_msg_request_s n20_msg_request_t;

/**
 * @brief Error response structure.
 *
 * Used to communicate operation failures back to the client.
 * Contains only an error code indicating the type of failure.
 */
struct n20_msg_error_response_s {
    /**
     * @brief The error code of the response.
     *
     * Indicates the specific error that occurred during request processing.
     * A value of n20_error_ok_e indicates success (though this structure
     * is typically used only for errors).
     */
    n20_error_t error_code;
};

/**
 * @brief Alias for @ref n20_msg_error_response_s.
 *
 */
typedef struct n20_msg_error_response_s n20_msg_error_response_t;

/**
 * @brief Certificate issuance response structure.
 *
 * Used to return newly issued certificates to clients.
 * Contains either an error code (on failure) or certificate data (on success).
 */
struct n20_msg_issue_cert_response_s {
    /**
     * @brief The error code of the response.
     *
     * Indicates success (n20_error_ok_e) or the specific error
     * that occurred during certificate issuance.
     */
    n20_error_t error_code;

    /**
     * @brief The issued certificate data.
     *
     * Contains the complete certificate in the requested format
     * (X.509 DER or COSE). Only valid when error_code is n20_error_ok_e.
     */
    n20_slice_t certificate;
};

/**
 * @brief Alias for @ref n20_msg_issue_cert_response_s.
 *
 */
typedef struct n20_msg_issue_cert_response_s n20_msg_issue_cert_response_t;

/**
 * @brief ECA End-Entity signing response structure.
 *
 * Used to return digital signatures to clients.
 * Contains either an error code (on failure) or signature data (on success).
 */
struct n20_msg_eca_ee_sign_response_s {
    /**
     * @brief The error code of the response.
     *
     * Indicates success (n20_error_ok_e) or the specific error
     * that occurred during signing operation.
     */
    n20_error_t error_code;

    /**
     * @brief The digital signature.
     *
     * Contains the signature bytes in the format appropriate for
     * the key algorithm used. Only valid when error_code is n20_error_ok_e.
     */
    n20_slice_t signature;
};

/**
 * @brief Alias for @ref n20_msg_eca_ee_sign_response_s.
 *
 */
typedef struct n20_msg_eca_ee_sign_response_s n20_msg_eca_ee_sign_response_t;

/**
 * @brief Read a request message from a CBOR-encoded buffer.
 *
 * Deserializes a CBOR-encoded request message into the provided structure.
 * The function validates the message format and populates all fields
 * according to the detected request type.
 *
 * @param request Pointer to the request structure to populate.
 * @param msg_buffer Buffer containing the CBOR-encoded message.
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_request_read(n20_msg_request_t *request, n20_slice_t msg_buffer);

/**
 * @brief Write a request message to a CBOR-encoded buffer.
 *
 * Serializes a request message structure into CBOR format.
 * The caller must provide a sufficiently large buffer.
 *
 * The serialized message is placed at the end of the buffer.
 * The beginning of the message is determined by adding the
 * difference between the buffer size before and after serialization.
 *
 * @code {.c}
 * uint8_t buffer[1024];
 * size_t buffer_size = sizeof(buffer);
 * n20_msg_request_write(&request, buffer, &buffer_size);
 * uint8_t *cbor_data = buffer + (sizeof(buffer) - buffer_size);
 * @endcode
 *
 * @param request Pointer to the request structure to serialize.
 * @param buffer Output buffer for the CBOR-encoded message.
 * @param buffer_size Pointer to buffer size (in: available space, out: bytes written).
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_request_write(n20_msg_request_t const *request,
                                         uint8_t *buffer,
                                         size_t *buffer_size);

/**
 * @brief Read a certificate issuance response from a CBOR-encoded buffer.
 *
 * Deserializes a CBOR-encoded certificate response message.
 * The response may contain either an error code or certificate data.
 *
 * @param response Pointer to the response structure to populate.
 * @param buffer Buffer containing the CBOR-encoded response.
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_issue_cert_response_read(n20_msg_issue_cert_response_t *response,
                                                    n20_slice_t buffer);

/**
 * @brief Write a certificate issuance response to a CBOR-encoded buffer.
 *
 * Serializes a certificate response structure into CBOR format.
 * The caller must provide a sufficiently large buffer.
 *
 * The serialized message is placed at the end of the buffer.
 * The beginning of the message is determined by adding the
 * difference between the buffer size before and after serialization.
 *
 * @code {.c}
 * uint8_t buffer[1024];
 * size_t buffer_size = sizeof(buffer);
 * n20_msg_issue_cert_response_write(&response, buffer, &buffer_size);
 * uint8_t *cbor_data = buffer + (sizeof(buffer) - buffer_size);
 * @endcode
 *
 * @param response Pointer to the response structure to serialize.
 * @param buffer Output buffer for the CBOR-encoded response.
 * @param buffer_size_in_out Pointer to buffer size (in: available space, out: bytes written).
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_issue_cert_response_write(n20_msg_issue_cert_response_t const *response,
                                                     uint8_t *buffer,
                                                     size_t *buffer_size_in_out);

/**
 * @brief Read an error response from a CBOR-encoded buffer.
 *
 * Deserializes a CBOR-encoded error response message.
 * Error responses contain only an error code.
 *
 * @param response Pointer to the error response structure to populate.
 * @param buffer Buffer containing the CBOR-encoded response.
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_error_response_read(n20_msg_error_response_t *response,
                                               n20_slice_t buffer);

/**
 * @brief Write an error response to a CBOR-encoded buffer.
 *
 * Serializes an error response structure into CBOR format.
 * The caller must provide a sufficiently large buffer.
 *
 * The serialized message is placed at the end of the buffer.
 * The beginning of the message is determined by adding the
 * difference between the buffer size before and after serialization.
 *
 * @code {.c}
 * uint8_t buffer[1024];
 * size_t buffer_size = sizeof(buffer);
 * n20_msg_error_response_write(&response, buffer, &buffer_size);
 * uint8_t *cbor_data = buffer + (sizeof(buffer) - buffer_size);
 * @endcode

 * @param response Pointer to the error response structure to serialize.
 * @param buffer Output buffer for the CBOR-encoded response.
 * @param buffer_size_in_out Pointer to buffer size (in: available space, out: bytes written).
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_error_response_write(n20_msg_error_response_t const *response,
                                                uint8_t *buffer,
                                                size_t *const buffer_size_in_out);

/**
 * @brief Read an ECA End-Entity signing response from a CBOR-encoded buffer.
 *
 * Deserializes a CBOR-encoded signing response message.
 * The response may contain either an error code or signature data.
 *
 * @param response Pointer to the signing response structure to populate.
 * @param buffer Buffer containing the CBOR-encoded response.
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_eca_ee_sign_response_read(n20_msg_eca_ee_sign_response_t *response,
                                                     n20_slice_t buffer);

/**
 * @brief Write an ECA End-Entity signing response to a CBOR-encoded buffer.
 *
 * Serializes a signing response structure into CBOR format.
 * The caller must provide a sufficiently large buffer.
 *
 * The serialized message is placed at the end of the buffer.
 * The beginning of the message is determined by adding the
 * difference between the buffer size before and after serialization.
 *
 * @code {.c}
 * uint8_t buffer[1024];
 * size_t buffer_size = sizeof(buffer);
 * n20_msg_eca_ee_sign_response_write(&response, buffer, &buffer_size);
 * uint8_t *cbor_data = buffer + (sizeof(buffer) - buffer_size);
 * @endcode
 *
 * @param response Pointer to the signing response structure to serialize.
 * @param buffer Output buffer for the CBOR-encoded response.
 * @param buffer_size_in_out Pointer to buffer size (in: available space, out: bytes written).
 * @return n20_error_ok_e on success, appropriate error code on failure.
 */
extern n20_error_t n20_msg_eca_ee_sign_response_write(
    n20_msg_eca_ee_sign_response_t const *response,
    uint8_t *buffer,
    size_t *const buffer_size_in_out);

#ifdef __cplusplus
}
#endif
