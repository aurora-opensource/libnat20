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

#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>

void n20_cbor_write_header(n20_stream_t *const s, n20_cbor_type_t cbor_type, uint64_t n) {
    uint8_t header = (uint8_t)(cbor_type << 5);

    size_t value_size = 0;

    if (n < 24) {
        header |= (uint8_t)n;
        n20_stream_prepend(s, &header, /*src_len=*/1);
        return;
    } else if (n < 0x100) {
        header |= 24;
        value_size = 1;
    } else if (n < 0x10000) {
        header |= 25;
        value_size = 2;
    } else if (n < 0x100000000) {
        header |= 26;
        value_size = 4;
    } else {
        header |= 27;
        value_size = 8;
    }

    for (size_t i = 0; i < value_size; i++) {
        uint8_t byte = (uint8_t)(n >> (i * 8));
        n20_stream_prepend(s, &byte, /*src_len=*/1);
    }

    n20_stream_prepend(s, &header, /*src_len=*/1);
}

void n20_cbor_write_null(n20_stream_t *const s) {
    n20_cbor_write_header(s, n20_cbor_type_simple_float_e, 22);
}

void n20_cbor_write_bool(n20_stream_t *const s, bool const b) {
    n20_cbor_write_header(s, n20_cbor_type_simple_float_e, b ? 21 : 20);
}

void n20_cbor_write_tag(n20_stream_t *const s, uint64_t const tag) {
    n20_cbor_write_header(s, n20_cbor_type_tag_e, tag);
}

void n20_cbor_write_uint(n20_stream_t *const s, uint64_t const n) {
    n20_cbor_write_header(s, n20_cbor_type_uint_e, n);
}

void n20_cbor_write_int(n20_stream_t *const s, int64_t const n) {
    if (n >= 0) {
        n20_cbor_write_uint(s, (uint64_t)n);
    } else {
        n20_cbor_write_header(s, n20_cbor_type_nint_e, (uint64_t)(-n - 1));
    }
}

void n20_cbor_write_byte_string(n20_stream_t *const s, n20_slice_t const bytes) {
    if (bytes.size > 0 && bytes.buffer == NULL) {
        n20_cbor_write_null(s);
        return;
    }

    n20_stream_prepend(s, bytes.buffer, bytes.size);
    n20_cbor_write_header(s, n20_cbor_type_bytes_e, bytes.size);
}

void n20_cbor_write_text_string(n20_stream_t *const s, n20_string_slice_t const text) {
    if (text.size > 0 && text.buffer == NULL) {
        n20_cbor_write_null(s);
        return;
    }

    n20_stream_prepend(s, (uint8_t const *)text.buffer, text.size);
    n20_cbor_write_header(s, n20_cbor_type_string_e, text.size);
}

void n20_cbor_write_array_header(n20_stream_t *const s, size_t const len) {
    n20_cbor_write_header(s, n20_cbor_type_array_e, len);
}

void n20_cbor_write_map_header(n20_stream_t *const s, size_t const len) {
    n20_cbor_write_header(s, n20_cbor_type_map_e, len);
}

bool n20_read_cbor_header(n20_istream_t *const s, n20_cbor_type_t *const type, uint64_t *const n) {
    uint8_t header = 0;
    if (!n20_istream_get(s, &header)) {
        return false;
    }

    *type = (n20_cbor_type_t)(header >> 5);
    uint8_t additional_info = header & 0x1f;

    if (additional_info < 24 || additional_info > 27) {
        *n = additional_info;
        return true;
    }

    *n = 0;

    uint8_t additional_bytes = 1 << (additional_info - 24);
    for (int i = 0; i < additional_bytes; i++) {
        uint8_t byte = 0;
        if (!n20_istream_get(s, &byte)) {
            return false;
        }
        *n = (*n << 8) | byte;
    }

    return true;
}

bool n20_iterate_cbor_item(n20_istream_t *const s) {
    n20_cbor_type_t type = n20_cbor_type_none_e;
    uint64_t n = 0;
    if (!n20_read_cbor_header(s, &type, &n)) {
        return false;
    }

    switch (type) {
        case n20_cbor_type_array_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_iterate_cbor_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_map_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_iterate_cbor_item(s)) {
                    return false;
                }
                if (!n20_iterate_cbor_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_bytes_e:
        case n20_cbor_type_string_e: {
            uint8_t const *slice = n20_istream_get_slice(s, n);
            if (slice == NULL) {
                return false;
            }
            break;
        }
        default:
            break;
    }

    return true;
}

bool n20_cbor_skip_item(n20_istream_t *const s) {
    n20_cbor_type_t type = n20_cbor_type_none_e;
    uint64_t n = 0;
    if (!n20_read_cbor_header(s, &type, &n)) {
        return false;
    }

    switch (type) {
        case n20_cbor_type_array_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_cbor_skip_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_map_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_cbor_skip_item(s)) {
                    return false;
                }
                if (!n20_cbor_skip_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_bytes_e:
        case n20_cbor_type_string_e: {
            uint8_t const *slice = n20_istream_get_slice(s, n);
            if (slice == NULL) {
                return false;
            }
            break;
        }
        case n20_cbor_type_tag_e:
            return n20_cbor_skip_item(s);  // Skip the tag and the item it refers to.
        default:
            break;
    }

    return true;
}

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
void n20_cose_write_key(n20_stream_t *const s, n20_cose_key_t const *const key) {
    uint32_t pairs = 0;

    uint32_t crv = 0;       // Curve type
    uint32_t key_type = 0;  // Curve type
    switch (key->algorithm_id) {
        case -7:           // ES256
        case -9:           // ESP256
            crv = 1;       // P-256
            key_type = 2;  // EC2
            break;
        case -35:          // ES384
        case -51:          // ESP384
            crv = 2;       // P-384
            key_type = 2;  // EC2
            break;
        case -8:           // EdDSA
        case -19:          // Ed25519
            crv = 6;       // Ed25519
            key_type = 1;  // EC2
            break;
        default:
            n20_cbor_write_null(s);  // Unsupported key type
            return;
    }

    if (key->d.size > 0) {
        n20_cbor_write_byte_string(s, key->d);
        n20_cbor_write_int(s, -4);  // Private Key
        ++pairs;
    }

    if (key->y.size > 0) {
        n20_cbor_write_byte_string(s, key->y);
        n20_cbor_write_int(s, -3);  // Y coordinate
        ++pairs;
    }

    if (key->x.size > 0) {
        n20_cbor_write_byte_string(s, key->x);
        n20_cbor_write_int(s, -2);  // X coordinate
        ++pairs;
    }

    n20_cbor_write_int(s, crv);
    n20_cbor_write_int(s, -1);  // Curve type
    ++pairs;

    uint32_t ops = 0;
    for (int i = 11; i != 0; --i) {
        if (n20_is_cose_key_op_set(key->key_ops, (n20_cose_key_ops_t)i)) {
            n20_cbor_write_int(s, i);  // COSE Key Operation
            ++ops;
        }
    }

    n20_cbor_write_array_header(s, ops);
    n20_cbor_write_int(s, 4);  // COSE Key Ops
    ++pairs;

    n20_cbor_write_int(s, key->algorithm_id);  // Algorithm Identifier
    n20_cbor_write_int(s, 3);                  // Algorithm
    ++pairs;
    n20_cbor_write_int(s, key_type);  // Key Type
    n20_cbor_write_int(s, 1);         // Key Type
    ++pairs;
    n20_cbor_write_map_header(s, pairs);  // Map header with the number of pairs
}

static void n20_open_dice_write_name_as_hex(n20_stream_t *const s, n20_slice_t const name) {
    if (name.size != 0 && name.buffer == NULL) {
        n20_cbor_write_null(s);
        return;
    }

    for (size_t i = 0; i < name.size; ++i) {
        uint8_t byte = name.buffer[name.size - (i + 1)];
        uint8_t hex[2] = {(byte >> 4) + '0', (byte & 0x0f) + '0'};
        if (hex[0] > '9') {
            hex[0] += 39;  // Convert to 'a' - 'f'
        }
        if (hex[1] > '9') {
            hex[1] += 39;  // Convert to 'a' - 'f'
        }
        n20_stream_prepend(s, hex, sizeof(hex));
    }
    n20_cbor_write_header(s, n20_cbor_type_string_e, name.size * 2);
}

void n20_open_dice_cwt_write(n20_stream_t *const s, n20_open_dice_cwt_t const *const cwt) {

    uint32_t pairs = 0;
    // Write Key Usage
    n20_cbor_write_byte_string(s,
                               (n20_slice_t){.buffer = (uint8_t *)cwt->key_usage,
                                             .size = ((cwt->key_usage[0] | cwt->key_usage[1]) != 0)
                                                         ? 0
                                                         : (cwt->key_usage[1] != 0 ? 2 : 1)});
    n20_cbor_write_int(s, -4670553);
    ++pairs;  // Key Usage

    size_t mark = n20_stream_byte_count(s);

    n20_cose_write_key(s, &cwt->subject_public_key);  // Subject Public Key

    n20_cbor_write_header(s,
                          n20_cbor_type_bytes_e,
                          n20_stream_byte_count(s) - mark);  // Length of the subject public key
    n20_cbor_write_int(s, -4670552);                         // Subject Public Key
    ++pairs;                                                 // Subject Public Key

    uint8_t mode = (uint8_t)cwt->mode;  // Convert mode to uint8_t

    n20_cbor_write_byte_string(s, (n20_slice_t){.buffer = &mode, .size = 1});
    n20_cbor_write_int(s, -4670551);  // Mode
    ++pairs;

    if (cwt->authority_descriptor.size > 0) {
        n20_cbor_write_byte_string(s, cwt->authority_descriptor);
        n20_cbor_write_int(s, -4670550);  // Authority Descriptor
        ++pairs;
    }

    if (cwt->authority_hash.size > 0) {
        n20_cbor_write_byte_string(s, cwt->authority_hash);
        n20_cbor_write_int(s, -4670549);  // Authority Hash
        ++pairs;
    }

    if (cwt->configuration_descriptor.size > 0) {
        n20_cbor_write_byte_string(s, cwt->configuration_descriptor);
        n20_cbor_write_int(s, -4670548);  // Configuration Descriptor
        ++pairs;
    }

    if (cwt->configuration_hash.size > 0) {
        n20_cbor_write_byte_string(s, cwt->configuration_hash);
        n20_cbor_write_int(s, -4670547);  // Configuration Hash
        ++pairs;
    }
    if (cwt->code_descriptor.size > 0) {
        n20_cbor_write_byte_string(s, cwt->code_descriptor);
        n20_cbor_write_int(s, -4670546);  // Code Descriptor
        ++pairs;
    }
    if (cwt->code_hash.size > 0) {
        n20_cbor_write_byte_string(s, cwt->code_hash);
        n20_cbor_write_int(s, -4670545);  // Code Hash
        ++pairs;
    }

    if (cwt->subject.size > 0) {
        n20_open_dice_write_name_as_hex(s, cwt->subject);
        n20_cbor_write_int(s, 2);  // Subject
        ++pairs;
    }

    if (cwt->issuer.size > 0) {
        n20_open_dice_write_name_as_hex(s, cwt->issuer);
        n20_cbor_write_int(s, 1);  // Issuer
        ++pairs;
    }
    n20_cbor_write_map_header(s, pairs);  // Write the map header with the number of pairs
}

n20_slice_t const SIGN_1_CONTEXT_WITH_ARRAY4_HEADER = {
    .buffer = (uint8_t *)"\x84\x6aSignature1",
    .size = 12,
};

n20_slice_t const EMPTY_BYTES_STRING = {
    .buffer = (uint8_t *)"\x40",
    .size = 1,
};

n20_error_t n20_cose_sign1_payload(n20_crypto_context_t *crypto_ctx,
                                   n20_crypto_key_t const signing_key,
                                   int32_t signing_key_algorith_id,
                                   void (*payload_callback)(n20_stream_t *s, void *ctx),
                                   void *payload_ctx,
                                   uint8_t *cose_sign1,
                                   size_t *cose_sign1_size) {
    n20_stream_t s;
    size_t signature_size = 0;

    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;  // Null crypto context
    }
    if (payload_callback == NULL || payload_ctx == NULL) {
        /* Null payload callback or context. */
        return n20_error_missing_callback_function_or_context_e;
    }
    if (cose_sign1_size == NULL) {
        return n20_error_crypto_unexpected_null_size_e;  // Null size pointer
    }
    if (cose_sign1 == NULL && *cose_sign1_size != 0) {
        /* Buffer cannot be NULL if size is not zero. */
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    n20_slice_t sig_structure[4] = {
        SIGN_1_CONTEXT_WITH_ARRAY4_HEADER,
        N20_SLICE_NULL,      // Placeholder for the protected attributes
        EMPTY_BYTES_STRING,  // Empty bytestring for external eead
        N20_SLICE_NULL,      // Placeholder for the payload
    };

    switch (signing_key_algorith_id) {
        case -7:                  // ES256
        case -9:                  // ESP256
            signature_size = 64;  // ECDSA P-256 signature size
            break;
        case -8:                  // EdDSA
        case -19:                 // Ed25519
            signature_size = 64;  // Ed25519 signature size
            break;
        case -35:                 // ES384
        case -51:                 // ESP384
            signature_size = 96;  // ECDSA P-384 signature size
            break;
        default:
            return n20_error_crypto_unknown_algorithm_e;  // Unsupported algorithm
    }

    uint8_t *signature = cose_sign1 + *cose_sign1_size - signature_size;

    n20_stream_init(&s, cose_sign1, signature - cose_sign1);

    // The byte string header for the signature.
    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, signature_size);

    // Mark the end of the payload.
    size_t mark = n20_stream_byte_count(&s);

    payload_callback(&s, payload_ctx);

    n20_cbor_write_header(&s,
                          n20_cbor_type_bytes_e,
                          n20_stream_byte_count(&s) - mark);  // Length of the payload

    sig_structure[3] = (n20_slice_t){
        .buffer = n20_stream_data(&s),
        .size = n20_stream_byte_count(&s) - mark,
    };

    // Empty header for unprotected attributes
    n20_cbor_write_map_header(&s, 0);

    // Write protected attributes
    mark = n20_stream_byte_count(&s);
    n20_cbor_write_int(&s, signing_key_algorith_id);  // Algorithm identifier
    n20_cbor_write_int(&s, 1);                        // Algorithm identifier label
    n20_cbor_write_map_header(&s, 1);                 // Map header with one pair
    // The protected attributes are an encoded CBOR map, so
    // a byte string header needs to be added containing the
    // encoded map.
    n20_cbor_write_header(&s,
                          n20_cbor_type_bytes_e,
                          n20_stream_byte_count(&s) - mark);  // Length of the protected attributes

    sig_structure[1] = (n20_slice_t){
        .buffer = n20_stream_data(&s),
        .size = n20_stream_byte_count(&s) - mark,
    };

    n20_cbor_write_array_header(&s, 4);  // Array header with 4 elements

    n20_crypto_gather_list_t sig_structure_gather_list = {
        .count = 4,
        .list = sig_structure,
    };

    size_t sig_size_in_out = signature_size;
    n20_error_t err = crypto_ctx->sign(
        crypto_ctx, signing_key, &sig_structure_gather_list, signature, &sig_size_in_out);
    if (err != n20_error_ok_e) {
        return err;
    }
    if (sig_size_in_out != signature_size) {
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    *cose_sign1_size = n20_stream_byte_count(&s) + signature_size;

    return n20_error_ok_e;
}
