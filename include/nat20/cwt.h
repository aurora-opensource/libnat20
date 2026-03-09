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

#pragma once

#include <nat20/cose.h>
#include <nat20/crypto.h>
#include <nat20/open_dice.h>
#include <nat20/stream.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file */

/**
 * @defgroup open_dice_cwt_labels Open DICE CWT Label Constants
 *
 * These constants are defined in the OpenDice specification and represent
 * the labels used in the Open DICE CWT structure.
 *
 * [OpenDICE specification]
 * (https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md#cbor-cdi-certificates)
 *
 * @{
 */
/** Label for code hash. */
#define N20_OPEN_DICE_CWT_LABEL_CODE_HASH (-4670545)
/** Label for code descriptor. */
#define N20_OPEN_DICE_CWT_LABEL_CODE_DESCRIPTOR (-4670546)
/** Label for configuration hash. */
#define N20_OPEN_DICE_CWT_LABEL_CONFIGURATION_HASH (-4670547)
/** Label for configuration descriptor. */
#define N20_OPEN_DICE_CWT_LABEL_CONFIGURATION_DESCRIPTOR (-4670548)
/** Label for authority hash. */
#define N20_OPEN_DICE_CWT_LABEL_AUTHORITY_HASH (-4670549)
/** Label for authority descriptor. */
#define N20_OPEN_DICE_CWT_LABEL_AUTHORITY_DESCRIPTOR (-4670550)
/** Label for DICE mode. */
#define N20_OPEN_DICE_CWT_LABEL_MODE (-4670551)
/** Label for subject public key. */
#define N20_OPEN_DICE_CWT_LABEL_SUBJECT_PUBLIC_KEY (-4670552)
/** Label for key usage. */
#define N20_OPEN_DICE_CWT_LABEL_KEY_USAGE (-4670553)
/** Label for profile name. */
#define N20_OPEN_DICE_CWT_LABEL_PROFILE (-4670554)
/** @} */

/**
 * @defgroup cwt_labels CBOR Web Token (CWT) Label Constants
 *
 * These constants are defined in the CWT specification and represent
 * the labels used in the CWT structure.
 *
 * [CWT specification](https://tools.ietf.org/html/rfc8392)
 *
 * @{
 */
#define N20_CWT_LABEL_ISSUER (1)  /**< Label for issuer. */
#define N20_CWT_LABEL_SUBJECT (2) /**< Label for subject. */
/** @} */

/**
 * @brief Convert Open DICE public key information to COSE key format.
 *
 * If either argument is NULL this function is a no-op.
 *
 * If the @p key_info->algorithm is not supported, @p cose_key will be left unmodified.
 *
 * Supported algorithms are Ed25519, P-256, and P-384 which are expressed
 * by @ref n20_crypto_key_type_ed25519_e, @ref n20_crypto_key_type_secp256r1_e,
 * and @ref n20_crypto_key_type_secp384r1_e respectively.
 *
 * The function sets the algorithm ID to @ref n20_cose_algorithm_id_eddsa_e,
 * @ref n20_cose_algorithm_id_es256_e, or @ref n20_cose_algorithm_id_es384_e
 * respectively. Note that these values have been deprecated according to [1]
 * but are still in use.
 *
 * The function also populates the public key from the the supplied buffer
 * in @p key_info->key.
 *
 * In the case of P-256 and P-384, the function assumes that the key buffer
 * is formatted as an uncompressed EC point. If the buffer size is odd it
 * is assumed that the first byte is the format header `0x04` which gets ignored.
 * The point is then split into its X and Y coordinates and stored in
 * @p cose_key->x and @p cose_key->y respectively. @p cose_key->d is set to an
 * empty slice.
 *
 * In the case of ED25519, the function expects the key buffer to be in the
 * standard format for EdDSA keys and stores in @p cose_key->x.
 * @p cose_key->y and @p cose_key->d are set to empty slices.
 *
 * Buffers are not copied. Both @p key_info and @p cose_key point to the
 * same underlying buffers. No ownership transfer is implied. The buffers
 * must remain valid for the life time of both structures.
 *
 * [1] https://www.iana.org/assignments/cose/cose.xhtml
 *
 * @param cose_key Pointer to the COSE key structure to populate.
 * @param key_info Pointer to the Open DICE public key information.
 */
extern void n20_cwt_key_info_to_cose(n20_cose_key_t *const cose_key,
                                     n20_open_dice_public_key_info_t const *const key_info);

/**
 * @brief Render a CBOR web token (CWT) structure.
 *
 * This function encodes a CWT (RFC8392) structure into a CBOR representation
 * including the issuer and subject claims, the subject public key and the OpenDICE
 * claims as described in the OpenDICE specification [1].
 *
 * The function never fails, however, the stream needs to be checked
 * for buffer @ref n20_stream_has_buffer_overflow (or write position overflow
 * @ref n20_stream_has_write_position_overflow if the to-be-rendered size is measured)
 * after the call to ensure that it was rendered to the buffer successfully.
 *
 * The function is not responsible for managing the lifetime of the buffers
 * used by the input parameters. The caller must ensure that these buffers
 * remain valid for the duration of the function call.
 *
 * The function does not sanitize the input and may not produce a valid CWT.
 * E.g. if the key info is missing, or if the key algorithm is not supported.
 * the public key field will be rendered as a CBOR null value
 * @sa n20_cwt_key_info_to_cose.
 *
 * [1] https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md
 *
 * @param s The stream to write the CBOR representation to.
 * @param cert_info The CWT structure to render.
 */
extern void n20_open_dice_cwt_write(n20_stream_t *const s,
                                    n20_open_dice_cert_info_t const *const cert_info);

#ifdef __cplusplus
}
#endif
