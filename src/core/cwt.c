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
#include <nat20/cwt.h>
#include <nat20/error.h>
#include <nat20/stream.h>
#include <nat20/types.h>

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

void n20_cwt_key_info_to_cose(n20_cose_key_t *const cose_key,
                              n20_open_dice_public_key_info_t const *const key_info) {
    if (key_info == NULL || cose_key == NULL) {
        return;
    }

    switch (key_info->algorithm) {
        case n20_crypto_key_type_ed25519_e:
            cose_key->algorithm_id = n20_cose_algorithm_id_eddsa_e;
            cose_key->x = key_info->key;
            cose_key->y = N20_SLICE_NULL;
            cose_key->d = N20_SLICE_NULL;
            return;
        case n20_crypto_key_type_secp256r1_e:
            cose_key->algorithm_id = n20_cose_algorithm_id_es256_e;
            break;
        case n20_crypto_key_type_secp384r1_e:
            cose_key->algorithm_id = n20_cose_algorithm_id_es384_e;
            break;
        default:
            /* Unsupported algorithm -> don't touch the COSE key structure. */
            return;
    }

    /* For NIST curves P-256 and P-384 the key is split into
     * X and Y coordinates. */
    size_t coordinate_size = key_info->key.size / 2;

    /* If the key size is odd skip the first byte to swallow
     * the format header. */
    cose_key->x.buffer = key_info->key.buffer + (key_info->key.size & 1);
    cose_key->x.size = coordinate_size;
    cose_key->y.buffer = cose_key->x.buffer + coordinate_size;
    cose_key->y.size = coordinate_size;
    cose_key->d = N20_SLICE_NULL;
}

void n20_open_dice_cwt_write(n20_stream_t *const s, n20_open_dice_cert_info_t const *const cwt) {
    uint32_t pairs = 0;

    // Write Profile Name
    if (cwt->open_dice_input.profile_name.size > 0) {
        n20_cbor_write_text_string(s, cwt->open_dice_input.profile_name);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_PROFILE);
        pairs++;
    }

    // Write Key Usage
    n20_cbor_write_byte_string(
        s,
        (n20_slice_t){.buffer = (uint8_t *)cwt->key_usage,
                      .size = (cwt->key_usage[1] != 0 ? 2 : (cwt->key_usage[0] != 0))});

    n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_KEY_USAGE);
    ++pairs;  // Key Usage

    size_t mark = n20_stream_byte_count(s);

    n20_cose_key_t subject_public_key = {0};
    n20_cose_key_ops_set(&subject_public_key.key_ops, n20_cose_key_op_verify_e);

    n20_cwt_key_info_to_cose(&subject_public_key, &cwt->subject_public_key);

    // Subject public key
    n20_cose_write_key(s, &subject_public_key);
    n20_cbor_write_header(s, n20_cbor_type_bytes_e, n20_stream_byte_count(s) - mark);
    n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_SUBJECT_PUBLIC_KEY);
    ++pairs;

    // Convert mode to uint8_t
    uint8_t mode = (uint8_t)cwt->open_dice_input.mode;

    n20_cbor_write_byte_string(s, (n20_slice_t){.buffer = &mode, .size = 1});
    n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_MODE);
    ++pairs;

    if (cwt->open_dice_input.authority_descriptor.size > 0) {
        n20_cbor_write_byte_string(s, cwt->open_dice_input.authority_descriptor);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_AUTHORITY_DESCRIPTOR);
        ++pairs;
    }

    if (cwt->open_dice_input.authority_hash.size > 0) {
        n20_cbor_write_byte_string(s, cwt->open_dice_input.authority_hash);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_AUTHORITY_HASH);
        ++pairs;
    }

    if (cwt->open_dice_input.configuration_descriptor.size > 0) {
        n20_cbor_write_byte_string(s, cwt->open_dice_input.configuration_descriptor);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_CONFIGURATION_DESCRIPTOR);
        ++pairs;
    }

    if (cwt->open_dice_input.configuration_hash.size > 0) {
        n20_cbor_write_byte_string(s, cwt->open_dice_input.configuration_hash);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_CONFIGURATION_HASH);
        ++pairs;
    }
    if (cwt->open_dice_input.code_descriptor.size > 0) {
        n20_cbor_write_byte_string(s, cwt->open_dice_input.code_descriptor);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_CODE_DESCRIPTOR);
        ++pairs;
    }
    if (cwt->open_dice_input.code_hash.size > 0) {
        n20_cbor_write_byte_string(s, cwt->open_dice_input.code_hash);
        n20_cbor_write_int(s, N20_OPEN_DICE_CWT_LABEL_CODE_HASH);
        ++pairs;
    }

    if (cwt->subject.size > 0) {
        n20_open_dice_write_name_as_hex(s, cwt->subject);
        n20_cbor_write_int(s, N20_CWT_LABEL_SUBJECT);
        ++pairs;
    }

    if (cwt->issuer.size > 0) {
        n20_open_dice_write_name_as_hex(s, cwt->issuer);
        n20_cbor_write_int(s, N20_CWT_LABEL_ISSUER);
        ++pairs;
    }

    // Write the map header with the number of pairs.
    n20_cbor_write_map_header(s, pairs);
}
