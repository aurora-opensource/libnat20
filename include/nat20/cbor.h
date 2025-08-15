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
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file */

/**
 * @brief Represents the CBOR data types.
 *
 * This enumeration defines the major types of CBOR (Concise Binary Object Representation)
 * data items as specified in RFC 8949. Each type corresponds to a specific kind of data
 * that can be encoded in CBOR.
 *
 * @sa https://tools.ietf.org/html/rfc8949
 */
typedef enum n20_cbor_type_s {
    /**
     * @brief No value type.
     *
     * This is not a valid CBOR type. It is used to indicate that
     * no value is present.
     */
    n20_cbor_type_none_e = 0xFF,
    /**
     * @brief Unsigned integer type.
     *
     * Represents non-negative integer values.
     */
    n20_cbor_type_uint_e = 0,
    /**
     * @brief Negative integer type.
     *
     * Represents negative integer values. The value is encoded as the
     * absolute value minus one. E.g. -1 is encoded as 0, -2 as 1, etc.
     */
    n20_cbor_type_nint_e = 1,
    /**
     * @brief Byte string type.
     *
     * Represents a sequence of raw binary data.
     */
    n20_cbor_type_bytes_e = 2,
    /**
     * @brief Text string type.
     *
     * Represents a sequence of UTF-8 encoded characters.
     */
    n20_cbor_type_string_e = 3,
    /**
     * @brief Array type.
     *
     * Represents an ordered collection of CBOR data items.
     */
    n20_cbor_type_array_e = 4,
    /**
     * @brief Map type.
     *
     * Represents a collection of key-value pairs, where keys are unique.
     */
    n20_cbor_type_map_e = 5,
    /**
     * @brief Tag type.
     *
     * Represents a tagged data item, used to indicate semantic meaning.
     */
    n20_cbor_type_tag_e = 6,
    /**
     * @brief Simple value or floating-point type.
     *
     * Represents simple values (e.g., true, false, null) or floating-point numbers.
     */
    n20_cbor_type_simple_float_e = 7,
} n20_cbor_type_t;

/**
 * @brief Write a CBOR header to the given stream.
 *
 * This function writes the CBOR header for a given type and value to the stream.
 *
 * @param s The stream to write to.
 * @param type The CBOR type (see @ref n20_cbor_type_t).
 * @param value The value associated with the CBOR type.
 */
extern void n20_cbor_write_header(n20_stream_t *s, n20_cbor_type_t type, uint64_t value);

/** @brief Write a NULL to the stream in CBOR format.
 *
 * This function encodes the NULL value using the CBOR encoding rules.
 */
extern void n20_cbor_write_null(n20_stream_t *const s);

/** @brief Write a boolean to the stream in CBOR format.
 *
 *
 * This function encodes the boolean value using the CBOR encoding rules.
 * The value `true` is encoded as 21 and `false` as 20 with a major type of 7.
 *
 * @param s The stream to write to.
 * @param b The boolean value to write.
 */
extern void n20_cbor_write_bool(n20_stream_t *const s, bool const b);

/** @brief Write a CBOR tag to the stream.
 *
 * This function encodes a CBOR tag using the CBOR encoding rules.
 *
 * @param s The stream to write to.
 * @param tag The tag to write.
 */
extern void n20_cbor_write_tag(n20_stream_t *const s, uint64_t const tag);

/**
 * @brief Write an unsigned integer to the stream in CBOR format.
 *
 * This function encodes the unsigned integer using the CBOR encoding rules.
 * The result is a CBOR header with major type 0 (unsigned integer) and the
 * value of the integer.
 *
 * @param s The stream to write to.
 * @param n The unsigned integer to write.
 */
extern void n20_cbor_write_uint(n20_stream_t *s, uint64_t value);

/**
 * @brief Writes a signed integer to the stream in CBOR format.
 *
 * This function uses both major types 0 (unsigned integer) and 1 (negative integer)
 * dpending on the sign of the integer. Positive integers are written using the
 * unsigned integer type, while negative integers are written using the negative
 * integer type.
 *
 * @param s The stream to write to.
 * @param n The signed integer to write.
 */
extern void n20_cbor_write_int(n20_stream_t *s, int64_t value);

/**
 * @brief Write a CBOR byte string to the given stream.
 *
 * This function encodes a byte string in CBOR format and writes it to the stream.
 * if @par data.size is not 0 but @par data.buffer is NULL, it writes a NULL value
 * instead.
 *
 * @param s The stream to write to.
 * @param data The byte string to encode.
 */
extern void n20_cbor_write_byte_string(n20_stream_t *s, n20_slice_t const data);

/**
 * @brief Write a CBOR text string to the given stream.
 *
 * This function encodes a text string in CBOR format and writes it to the stream.
 * if @par text.size is not 0 but @par text.buffer is NULL, it writes a NULL value
 * instead.
 *
 * @param s The stream to write to.
 * @param text The text string to encode.
 */
extern void n20_cbor_write_text_string(n20_stream_t *s, n20_string_slice_t const text);

extern bool n20_read_cbor_header(n20_istream_t *const s,
                                 n20_cbor_type_t *const type,
                                 uint64_t *const n);

extern bool n20_cbor_skip_item(n20_istream_t *const s);

/**
 * @brief Write a CBOR array header to the given stream.
 *
 * This function writes the CBOR header for an array to the stream.
 *
 * @param s The stream to write to.
 * @param size The number of elements in the array.
 */
extern void n20_cbor_write_array_header(n20_stream_t *s, size_t size);

/**
 * @brief Write a CBOR map header to the given stream.
 *
 * This function writes the CBOR header for a map to the stream.
 *
 * @param s The stream to write to.
 * @param size The number of key-value pairs in the map.
 */
extern void n20_cbor_write_map_header(n20_stream_t *s, size_t size);

/**
 * @brief Mode inputs to the DICE.
 */
enum n20_cwt_open_dice_modes_s {
    /**
     * @brief No security features (e.g. verified boot) have been configured on the device.
     */
    n20_cwt_open_dice_not_configured_e = 0,
    /**
     * @brief Device is operating normally with security features enabled.
     */
    n20_cwt_open_dice_normal_e = 1,
    /**
     * @brief Device is in debug mode, which is a non-secure state.
     */
    n20_cwt_open_dice_debug_e = 2,
    /**
     * @brief Device is in a debug or maintenance mode.
     */
    n20_cwt_open_dice_recovery_e = 3,
};

typedef enum n20_cwt_open_dice_modes_s n20_cwt_open_dice_modes_t;

struct n20_cwt_s {
    n20_string_slice_t issuer;
    n20_string_slice_t subject;
};

typedef struct n20_cwt_s n20_cwt_t;

enum n20_cose_key_ops_s {
    n20_cose_key_op_sign_e = 1,         // Key used for signing
    n20_cose_key_op_verify_e = 2,       // Key used for verifying signatures
    n20_cose_key_op_encrypt_e = 3,      // Key used for encryption
    n20_cose_key_op_decrypt_e = 4,      // Key used for decryption
    n20_cose_key_op_wrap_e = 5,         // Key used for wrapping keys
    n20_cose_key_op_unwrap_e = 6,       // Key used for unwrapping keys
    n20_cose_key_op_derive_key_e = 7,   // Key used for key derivation
    n20_cose_key_op_derive_bits_e = 8,  // Key used for deriving bits not a key
    n20_cose_key_op_mac_sign_e = 9,     // Key used message authentication code signing
    n20_cose_key_op_mac_verify_e = 10,  // Key used for message authentication code verification
};

typedef enum n20_cose_key_ops_s n20_cose_key_ops_t;
typedef uint16_t n20_cose_key_ops_map_t;

inline static void n20_set_cose_key_ops(n20_cose_key_ops_map_t *key_ops, n20_cose_key_ops_t op) {
    *key_ops |= 1 << (unsigned int)op;
}

inline static void n20_unset_cose_key_ops(n20_cose_key_ops_map_t *key_ops, n20_cose_key_ops_t op) {
    *key_ops &= ~(1 << (unsigned int)op);
}

inline static bool n20_is_cose_key_op_set(n20_cose_key_ops_map_t key_ops, n20_cose_key_ops_t op) {
    return (key_ops & (1 << (unsigned int)op)) != 0;
}

/**
 * @brief COSE Key structure.
 *
 * This structure represents a COSE key, which is used in the
 * CBOR Object Signing and Encryption (COSE) format.
 * It contains information about the key type, operations,
 * public and private keys, and the algorithm used.
 */
struct n20_cose_key_s {
    /**
     * @brief Compressed COSE Key Operations.
     *
     * This is a bitmask representing the operations that can be performed
     * with this key. Each bit corresponds to a specific operation, such as
     * signing, verifying, encrypting, decrypting, wrapping, unwrapping,
     * deriving keys, deriving bits, and message authentication code (MAC)
     * signing and verification.
     *
     * @see n20_cose_key_ops_s
     * @see n20_cose_key_ops_map_t
     */
    n20_cose_key_ops_map_t key_ops;
    /**
     * @brief Algorithm Identifier.
     *
     * This is an integer that identifies the algorithm used with this key.
     * It is used to specify the cryptographic algorithm that the key is
     * associated with, such as EdDSA, ECDSA, or AES.
     *
     * The values are defined in the COSE Algorithm Registry.
     * @see https://www.iana.org/assignments/cose/cose.xhtml#cose-algorithm
     *
     * Relevant values include:
     * - -9: ESP256 (ECDSA using P-256 and SHA-256)
     * - -51: ESP384 (ECDSA using P-384 and SHA-384)
     * - -19: Ed25519 (EdDSA using Ed25519)
     */
    int32_t algorithm_id;
    n20_slice_t x;  // X coordinate for EC keys
    n20_slice_t y;  // Y coordinate for EC keys
    n20_slice_t d;  // Private key for EC keys
};

typedef struct n20_cose_key_s n20_cose_key_t;

/**
 * @brief Render a COSE key structure as CBOR map.
 *
 * This function encodes a COSE key structure into a CBOR map format.
 * It writes the key type, operations, algorithm identifier, and
 * coordinates (X, Y) and private key (D) if available.
 * The function infers the key type (kty) and curve (crv) from the
 * given algorithm id. But it is the responsibility of the caller
 * to populate the x, y, and d fields of the key structure
 * with the appropriate values.
 * I.e., For an ED25519 key, the x field should contain the
 * public key, the y field should be empty, and the d field
 * may contain the private key. For an ECDSA key, the x and y fields
 * must contain the public key coordinates, and the d field
 * may contain the private key.
 *
 * If the key type is not supported, it writes a null value.
 *
 * @param s The stream to write the CBOR map to.
 * @param key The COSE key structure to encode.
 */
extern void n20_cose_write_key(n20_stream_t *const s, n20_cose_key_t const *const key);

struct n20_open_dice_cwt_s {
    n20_slice_t issuer;                    // Issuer of the CWT
    n20_slice_t subject;                   // Subject of the CWT
    n20_slice_t code_hash;                 // Hash of the code descriptor
    n20_slice_t code_descriptor;           // Code descriptor
    n20_slice_t configuration_hash;        // Hash of the configuration descriptor
    n20_slice_t configuration_descriptor;  // Configuration descriptor
    n20_slice_t authority_hash;            // Authority hash (optional)
    n20_slice_t authority_descriptor;      // Authority descriptor (optional)
    n20_cwt_open_dice_modes_t mode;        // DICE mode
    n20_cose_key_t subject_public_key;     // Public key of the subject
    uint8_t key_usage[2];                  // Key usage flags
};

typedef struct n20_open_dice_cwt_s n20_open_dice_cwt_t;

extern void n20_open_dice_cwt_write(n20_stream_t *const s, n20_open_dice_cwt_t const *const cwt);

extern n20_error_t n20_cose_sign1_payload(n20_crypto_context_t *crypto_ctx,
                                          n20_crypto_key_t const signing_key,
                                          int32_t signing_key_algorith_id,
                                          void (*payload_callback)(n20_stream_t *s, void *ctx),
                                          void *payload_ctx,
                                          uint8_t *cose_sign1,
                                          size_t *cose_sign1_size);

#ifdef __cplusplus
}
#endif
