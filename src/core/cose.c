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

#include <nat20/cbor.h>
#include <nat20/cose.h>
#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/stream.h>
#include <nat20/types.h>

/*
 * This file contains functions for encoding COSE structures.
 * These constants are defined in RFC 8152 Section 13.
 */
#define N20_COSE_CURVE_P256 (1)
#define N20_COSE_CURVE_P384 (2)
#define N20_COSE_CURVE_ED25519 (6)

#define N20_COSE_KEY_TYPE_OKP (1)
#define N20_COSE_KEY_TYPE_EC2 (2)

#define N20_COSE_KEY_LABEL_PRIVATE_KEY (-4)
#define N20_COSE_KEY_LABEL_Y_COORDINATE (-3)
#define N20_COSE_KEY_LABEL_X_COORDINATE (-2)
#define N20_COSE_KEY_LABEL_CURVE (-1)
#define N20_COSE_KEY_LABEL_KEY_TYPE (1)
#define N20_COSE_KEY_LABEL_ALGORITHM_ID (3)
#define N20_COSE_KEY_LABEL_KEY_OPS (4)

/*
 * This constant is defined in RFC 8152 Section 3.1.
 */
#define N20_COSE_COMMON_HEADER_LABEL_ALGORITHM_ID (1)

void n20_cose_write_key(n20_stream_t *const s, n20_cose_key_t const *const key) {
    uint32_t pairs = 0;

    uint32_t crv = 0;
    uint32_t key_type = 0;
    switch (key->algorithm_id) {
        case n20_cose_algorithm_id_es256_e:
        case n20_cose_algorithm_id_esp256_e:
            crv = N20_COSE_CURVE_P256;
            key_type = N20_COSE_KEY_TYPE_EC2;
            break;
        case n20_cose_algorithm_id_es384_e:
        case n20_cose_algorithm_id_esp384_e:
            crv = N20_COSE_CURVE_P384;
            key_type = N20_COSE_KEY_TYPE_EC2;
            break;
        case n20_cose_algorithm_id_eddsa_e:
        case n20_cose_algorithm_id_ed25519_e:
            crv = N20_COSE_CURVE_ED25519;
            key_type = N20_COSE_KEY_TYPE_OKP;
            break;
        default:
            n20_cbor_write_null(s);  // Unsupported key type
            return;
    }

    if (key->d.size > 0) {
        n20_cbor_write_byte_string(s, key->d);
        n20_cbor_write_int(s, N20_COSE_KEY_LABEL_PRIVATE_KEY);
        ++pairs;
    }

    if (key->y.size > 0) {
        n20_cbor_write_byte_string(s, key->y);
        n20_cbor_write_int(s, N20_COSE_KEY_LABEL_Y_COORDINATE);
        ++pairs;
    }

    if (key->x.size > 0) {
        n20_cbor_write_byte_string(s, key->x);
        n20_cbor_write_int(s, N20_COSE_KEY_LABEL_X_COORDINATE);
        ++pairs;
    }

    n20_cbor_write_int(s, crv);
    n20_cbor_write_int(s, N20_COSE_KEY_LABEL_CURVE);
    ++pairs;

    uint32_t ops = 0;
    for (int i = n20_cose_key_op_mac_verify_e; i != 0; --i) {
        if (n20_cose_key_ops_is_set(key->key_ops, (n20_cose_key_ops_t)i)) {
            n20_cbor_write_int(s, i);
            ++ops;
        }
    }

    n20_cbor_write_array_header(s, ops);
    n20_cbor_write_int(s, N20_COSE_KEY_LABEL_KEY_OPS);
    ++pairs;

    n20_cbor_write_int(s, key->algorithm_id);
    n20_cbor_write_int(s, N20_COSE_KEY_LABEL_ALGORITHM_ID);
    ++pairs;
    n20_cbor_write_int(s, key_type);
    n20_cbor_write_int(s, N20_COSE_KEY_LABEL_KEY_TYPE);
    ++pairs;

    /* Map header with the number of pairs */
    n20_cbor_write_map_header(s, pairs);
}

static n20_slice_t const SIGN_1_CONTEXT_WITH_ARRAY4_HEADER = {
    .buffer = (uint8_t *)"\x84\x6aSignature1",
    .size = 12,
};

static n20_slice_t const EMPTY_BYTES_STRING = {
    .buffer = (uint8_t *)"\x40",
    .size = 1,
};

size_t n20_cose_get_signature_size(n20_cose_algorithm_id_t signing_key_algorithm_id) {
    switch (signing_key_algorithm_id) {
        case n20_cose_algorithm_id_es256_e:
        case n20_cose_algorithm_id_esp256_e:
        case n20_cose_algorithm_id_eddsa_e:
        case n20_cose_algorithm_id_ed25519_e:
            /* ECDSA P-256 or ED25519 signature size */
            return 64;
        case n20_cose_algorithm_id_es384_e:
        case n20_cose_algorithm_id_esp384_e:
            /* ECDSA P-384 signature size */
            return 96;
        default:
            return 0;
    }
}

void n20_cose_render_sign1_with_payload(n20_stream_t *s,
                                        n20_cose_algorithm_id_t signing_key_algorithm_id,
                                        void (*payload_callback)(n20_stream_t *s, void *ctx),
                                        void *payload_ctx,
                                        n20_slice_t tbs_gather_list[4]) {
    size_t signature_size = n20_cose_get_signature_size(signing_key_algorithm_id);

    tbs_gather_list[0] = SIGN_1_CONTEXT_WITH_ARRAY4_HEADER;
    /* Empty bytestring for external additional authenticated data EAAD */
    tbs_gather_list[2] = EMPTY_BYTES_STRING;

    /* The byte string header for the signature.
     * The actual signature bytes are expected to be added by the caller. */
    n20_cbor_write_header(s, n20_cbor_type_bytes_e, signature_size);

    /* Mark the end of the payload. */
    size_t mark = n20_stream_byte_count(s);

    /* If there is no callback, we can't render the payload.
     * This results in an empty payload. */
    if (payload_callback != NULL) {
        payload_callback(s, payload_ctx);
    }

    /* Write the byte string header with the payload size. */
    n20_cbor_write_header(s, n20_cbor_type_bytes_e, n20_stream_byte_count(s) - mark);

    /* Set the final region in the to-be-signed gather list
     * to the rendered payload. */
    tbs_gather_list[3] = (n20_slice_t){
        .buffer = n20_stream_data(s),
        .size = n20_stream_byte_count(s) - mark,
    };

    /* Empty header for unprotected attributes */
    n20_cbor_write_map_header(s, 0);

    /* Write protected attributes */
    mark = n20_stream_byte_count(s);
    n20_cbor_write_int(s, signing_key_algorithm_id);
    n20_cbor_write_int(s, N20_COSE_COMMON_HEADER_LABEL_ALGORITHM_ID);
    /* Map header with one pair */
    n20_cbor_write_map_header(s, 1);
    /* The protected attributes are an encoded CBOR map, so
     * a byte string header needs to be added containing the
     * encoded map. */
    n20_cbor_write_header(s, n20_cbor_type_bytes_e, n20_stream_byte_count(s) - mark);

    /* Set the second region in the to-be-signed gather list
     * to the rendered protected attributes. */
    tbs_gather_list[1] = (n20_slice_t){
        .buffer = n20_stream_data(s),
        .size = n20_stream_byte_count(s) - mark,
    };

    /* Array header with 4 elements */
    n20_cbor_write_array_header(s, 4);
}
