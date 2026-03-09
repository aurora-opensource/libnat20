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

/** @file */

#pragma once

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/stream.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief COSE Key Operations.
 *
 * This enumeration defines the key operations that can be performed with a COSE key
 * as specified in RFC 8152 Section 7.1. These values are used to indicate what
 * cryptographic operations a key is authorized to perform.
 *
 * They correspond to the COSE key operation values defined in the COSE specification
 * and are used as such in the encoded CBOR structure.
 *
 * @see https://tools.ietf.org/html/rfc8152#section-7.1
 */
enum n20_cose_key_ops_s {
    /**
     * @brief Key used for signing operations.
     *
     * The key can be used to create digital signatures.
     */
    n20_cose_key_op_sign_e = 1,

    /**
     * @brief Key used for verifying signatures.
     *
     * The key can be used to verify digital signatures created by the corresponding
     * private key.
     */
    n20_cose_key_op_verify_e = 2,

    /**
     * @brief Key used for encryption operations.
     *
     * The key can be used to encrypt data for confidentiality.
     */
    n20_cose_key_op_encrypt_e = 3,

    /**
     * @brief Key used for decryption operations.
     *
     * The key can be used to decrypt data that was previously encrypted
     * with a matching public key.
     */
    n20_cose_key_op_decrypt_e = 4,

    /**
     * @brief Key used for wrapping other keys.
     *
     * The key can be used to encrypt other cryptographic keys for secure transport
     * or storage.
     */
    n20_cose_key_op_wrap_e = 5,

    /**
     * @brief Key used for unwrapping other keys.
     *
     * The key can be used to decrypt other cryptographic keys that were wrapped
     * for secure transport or storage.
     */
    n20_cose_key_op_unwrap_e = 6,

    /**
     * @brief Key used for key derivation.
     *
     * The key can be used as input material for deriving other cryptographic keys.
     */
    n20_cose_key_op_derive_key_e = 7,

    /**
     * @brief Key used for deriving bits (not keys).
     *
     * The key can be used as input material for deriving pseudorandom bits that
     * are not intended to be used as cryptographic keys.
     */
    n20_cose_key_op_derive_bits_e = 8,

    /**
     * @brief Key used for message authentication code signing.
     *
     * The key can be used to create message authentication codes (MACs) for
     * data integrity and authenticity.
     */
    n20_cose_key_op_mac_sign_e = 9,

    /**
     * @brief Key used for message authentication code verification.
     *
     * The key can be used to verify message authentication codes (MACs) for
     * data integrity and authenticity.
     */
    n20_cose_key_op_mac_verify_e = 10,
};

/**
 * @brief Alias for @ref n20_cose_key_ops_s.
 */
typedef enum n20_cose_key_ops_s n20_cose_key_ops_t;

/**
 * @brief Bitmask type for COSE key operations.
 *
 * This type represents a bitmask where each bit corresponds to a specific
 * COSE key operation. It allows multiple operations to be encoded in a
 * single value for efficient storage.
 *
 * Use the helper functions @ref n20_cose_key_ops_set, @ref n20_cose_key_ops_unset,
 * and @ref n20_cose_key_ops_is_set to manipulate and query this bitmask.
 */
typedef uint16_t n20_cose_key_ops_map_t;

/**
 * @brief Set a COSE key operation in the key operations bitmask.
 *
 * @param key_ops The bitmask to modify.
 * @param op The operation to set.
 */
inline void n20_cose_key_ops_set(n20_cose_key_ops_map_t *key_ops, n20_cose_key_ops_t op) {
    *key_ops |= 1 << (unsigned int)op;
}

/**
 * @brief Unset a COSE key operation in the key operations bitmask.
 *
 * @param key_ops The bitmask to modify.
 * @param op The operation to unset.
 */
inline void n20_cose_key_ops_unset(n20_cose_key_ops_map_t *key_ops, n20_cose_key_ops_t op) {
    *key_ops &= ~(1 << (unsigned int)op);
}

/**
 * @brief Test if a COSE key operation is set in the key operations bitmask.
 *
 * @param key_ops The bitmask to check.
 * @param op The operation to test for.
 */
inline bool n20_cose_key_ops_is_set(n20_cose_key_ops_map_t key_ops, n20_cose_key_ops_t op) {
    return (key_ops & (1 << (unsigned int)op)) != 0;
}

/**
 * @brief COSE Algorithm Identifiers.
 *
 * This enumeration defines the algorithm identifiers used in COSE
 * (CBOR Object Signing and Encryption) as specified in the IANA
 * COSE Algorithm Registry.
 *
 * @see https://www.iana.org/assignments/cose/cose.xhtml#cose-algorithm
 */
enum n20_cose_algorithm_id_s {
    /**
     * @brief EdDSA signature algorithms.
     *
     * This identifier is used for EdDSA signature algorithms, which
     * include Ed25519 and Ed448. However, specific identifiers for
     * Ed25519 and Ed448 are also defined separately.
     * This value has been deprecated according to [1] but is still in use
     * in the context of OpenDICE.
     *
     * [1] https://www.iana.org/assignments/cose/cose.xhtml
     */
    n20_cose_algorithm_id_eddsa_e = -8,
    /**
     * @brief ED25519 signature algorithms.
     *
     * This identifier is specifically for the Ed25519 signature algorithm.
     */
    n20_cose_algorithm_id_ed25519_e = -19,
    /**
     * @brief ECDSA signature algorithm with P-256 curve.
     *
     * This identifier is used for the ECDSA signature algorithm with P-256.
     * This value has been deprecated according to [1] but is still in use
     * in the context of OpenDICE.
     *
     * [1] https://www.iana.org/assignments/cose/cose.xhtml
     */
    n20_cose_algorithm_id_es256_e = -7,
    /**
     * @brief ECDSA signature algorithm with P-384 curve.
     *
     * This identifier is used for the ECDSA signature algorithm with P-384.
     * This value has been deprecated according to [1] but is still in use
     * in the context of OpenDICE.
     *
     * [1] https://www.iana.org/assignments/cose/cose.xhtml
     */
    n20_cose_algorithm_id_es384_e = -35,
    /**
     * @brief ECDSA signature algorithms with P-256 curve and SHA-256.
     *
     * This identifier is specifically for the ECDSA with P-256 and SHA-256.
     */
    n20_cose_algorithm_id_esp256_e = -9,
    /**
     * @brief ECDSA signature algorithms with P-384 curve and SHA-384.
     *
     * This identifier is specifically for the ECDSA with P-384 and SHA-384.
     */
    n20_cose_algorithm_id_esp384_e = -51,
};

/**
 * @brief Alias for @ref n20_cose_algorithm_id_s.
 */
typedef enum n20_cose_algorithm_id_s n20_cose_algorithm_id_t;

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
    n20_cose_algorithm_id_t algorithm_id;
    n20_slice_t x; /**< @brief X coordinate for EC keys */
    n20_slice_t y; /**< @brief Y coordinate for EC keys */
    n20_slice_t d; /**< @brief Private key for EC keys */
};

/**
 * @brief Alias for @ref n20_cose_key_s.
 */
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

/**
 * @brief Render a COSE Sign1 structure with a payload.
 *
 * This function encodes a COSE Sign1 structure into a CBOR format.
 * The payload is rendered recursively by calling the provided callback.
 * Following the libnat20 paradigm, must not fail, and must render
 * valid CBOR as long as all data is valid or NULL.
 *
 * Note that the function only renders the structure and the payload,
 * but not the signature. The caller is responsible for appending the
 * signature bytes after the structure is rendered.
 *
 * This function will prefix the payload with a byte string header
 * with a size inferred from the callback's effect on the stream. The callback
 * must advance the stream's write position even if a buffer overflow
 * occurs for the function to return the COSE Sign1 structure size correctly
 * even in the case that the stream buffer is too small or NULL.
 *
 * The @p signing_key_algorithm_id parameter informs the algorithm
 * in the protected attributes and the size of the signature. If the signing
 * key algorithm is not supported, the function will render the provided
 * algorithm ID to the protected attributes, but the signature size
 * will be zero, resulting in an empty signature even if a signature
 * is appended by the caller later.
 *
 * The resulting COSE Sign1 structure is a CBOR array with four elements:
 * 1. Protected attributes (as a byte string containing a CBOR map)
 * 2. Unprotected attributes (empty map)
 * 3. Payload (as a byte string)
 * 4. Signature byte string header. The actual signature bytes are not
 *    rendered by this function, but may be concatenated by the caller
 *    to complete the COSE Sign1 structure.
 *
 * The function populates the @p out_tbs_gather_list array with four slices
 * representing the four elements of the COSE Sig_structure. This array
 * can be used by the caller to sign the data in-place.
 * The caller must ensure that the @p out_tbs_gather_list array has
 * at least four elements. And all elements will be set by the function.
 * 1. Context and array header: "\x84\x6aSignature1", i.e., 0x84 for array
 *    of 4 elements and 0x6a for text string of length 10. It points to
 *    a static buffer.
 * 2. Protected attributes: Points to the rendered protected attributes in
 *    the stream.
 * 3. External additional authenticated data (EAAD): Points to a static
 *    empty byte string, but may be replaced by the caller to add EAAD
 *    not rendered by this function.
 * 4. Payload: Points to the rendered payload in the stream.
 *
 * The @p out_tbs_gather_list can be used to sign the data in-place IFF
 * the stream was not overflowed. The caller must check the stream
 * for buffer overflow using @ref n20_stream_has_buffer_overflow before
 * using the gather list for signing.
 *
 * The user should familiarize with @ref n20_stream_t to understand how
 * the stream's write position and buffer management works in the context
 * of this function, especially when rendering the payload through the callback.
 *
 * @param s The stream to write the COSE Sign1 structure to.
 * @param signing_key_algorithm_id The algorithm identifier for the signing key.
 * @param payload_callback Callback function to render the payload.
 * @param payload_ctx Callback context passed to the payload callback.
 * @param out_tbs_gather_list To-be-signed gather list populated by the function.
 */
extern void n20_cose_render_sign1_with_payload(n20_stream_t *s,
                                               n20_cose_algorithm_id_t signing_key_algorithm_id,
                                               void (*payload_callback)(n20_stream_t *s, void *ctx),
                                               void *payload_ctx,
                                               n20_slice_t out_tbs_gather_list[4]);

#ifdef __cplusplus
}
#endif
