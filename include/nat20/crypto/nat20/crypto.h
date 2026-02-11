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

/** @file */

#pragma once

#include <nat20/crypto.h>
#include <nat20/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open a new NAT20 cryptographic (digest) context.
 *
 * This is the factory function to create a crypto digest context
 * @ref n20_crypto_digest_context_t implementing SHA2
 * (SHA-224, SHA-256, SHA-384, SHA-512), HMAC, and HKDF without
 * external library dependencies.
 *
 * Each call to this function must be matched with a call to
 * @ref n20_crypto_nat20_close.
 *
 * In the current implementation the context returned is a singleton,
 * and @ref n20_crypto_nat20_close is a no-op. But this may change
 * in the future, and cannot be relied on.
 *
 * @param ctx_out Pointer to the context to be initialized.
 * @return n20_error_t Error code indicating success or failure.
 */
extern n20_error_t n20_crypto_nat20_open(n20_crypto_digest_context_t** ctx_out);

/**
 * @brief Close the NAT20 cryptographic context.
 *
 * This function closes and frees the resources associated with the
 * context @ref ctx_out.
 *
 * In the current implementation this is a no-op, as the context
 * is a singleton. But this may change in the future, and must
 * not be relied on.
 *
 * @param ctx_out Pointer to the context to be closed.
 * @return n20_error_t Error code indicating success or failure.
 */
extern n20_error_t n20_crypto_nat20_close(n20_crypto_digest_context_t* ctx_out);

/**
 * @brief Compute HMAC (Hash-based Message Authentication Code).
 *
 * This function computes the HMAC of the input message using the specified
 * digest algorithm and key.
 *
 * This function requires a valid crypto digest context that implements
 * at least the function @ref n20_crypto_digest_context_s.digest. The context
 * is not required to implement any other function. This function may be used
 * to implement @ref n20_crypto_digest_context_s.hmac.
 *
 * For errors and expected behavior see @ref n20_crypto_digest_context_s.hmac.
 *
 * @param ctx Pointer to the cryptographic context.
 * @param alg_in Digest algorithm to use.
 * @param key Secret key for HMAC.
 * @param msg_in Input message to authenticate.
 * @param mac_out Output buffer for the computed MAC.
 * @param mac_size_in_out Input: size of the output buffer. Output: size of the computed MAC.
 * @return n20_error_t Error code indicating success or failure.
 */
extern n20_error_t n20_hmac(n20_crypto_digest_context_t* ctx,
                            n20_crypto_digest_algorithm_t alg_in,
                            n20_slice_t const key,
                            n20_crypto_gather_list_t const* msg_in,
                            uint8_t* mac_out,
                            size_t* mac_size_in_out);

/**
 * @brief Compute HKDF (HMAC-based Key Derivation Function).
 *
 * This function derives a key of the specified length using the HKDF
 * algorithm with the given input keying material (IKM), salt, and info.
 *
 * This function requires a valid crypto digest context that implements
 * at least the functions @ref n20_crypto_digest_context_s.hkdf_extract
 * and @ref n20_crypto_digest_context_s.hkdf_expand.
 * This function may be used to implement @ref n20_crypto_digest_context_s.hkdf.
 *
 * For errors and expected behavior see @ref n20_crypto_digest_context_s.hkdf.
 *
 * @param ctx Pointer to the cryptographic context.
 * @param alg_in Digest algorithm to use.
 * @param ikm Input keying material.
 * @param salt Optional salt value (can be empty).
 * @param info Optional context and application specific information.
 * @param key_octets Length of the derived key in octets.
 * @param out Output buffer for the derived key.
 * @return n20_error_t Error code indicating success or failure.
 */
extern n20_error_t n20_hkdf(n20_crypto_digest_context_t* ctx,
                            n20_crypto_digest_algorithm_t alg_in,
                            n20_slice_t const ikm,
                            n20_slice_t const salt,
                            n20_slice_t const info,
                            size_t key_octets,
                            uint8_t* out);

/**
 * @brief Extract a pseudorandom key (PRK) from input keying material (IKM) and salt.
 *
 * This function performs the HKDF extract step, deriving a pseudorandom key (PRK)
 * from the input keying material (IKM) and an optional salt.
 *
 * This function requires a valid crypto digest context that implements
 * at least the function @ref n20_crypto_digest_context_s.hmac.
 * This function may be used to implement @ref n20_crypto_digest_context_s.hkdf_extract.
 *
 * For errors and expected behavior see @ref n20_crypto_digest_context_s.hkdf_extract.
 *
 * @param ctx Pointer to the cryptographic context.
 * @param alg_in Digest algorithm to use.
 * @param ikm Input keying material.
 * @param salt Optional salt value (can be empty).
 * @param prk Output buffer for the pseudorandom key.
 * @param prk_size_in_out Input: size of the output buffer. Output: size of the derived PRK.
 * @return n20_error_t Error code indicating success or failure.
 */
extern n20_error_t n20_hkdf_extract(n20_crypto_digest_context_t* ctx,
                                    n20_crypto_digest_algorithm_t alg_in,
                                    n20_slice_t ikm,
                                    n20_slice_t const salt,
                                    uint8_t* prk,
                                    size_t* prk_size_in_out);

/**
 * @brief Expand a pseudorandom key (PRK) into output keying material (OKM).
 *
 * This function performs the HKDF expand step, deriving output keying material (OKM)
 * from a pseudorandom key (PRK) and optional context information.
 *
 * This function requires a valid crypto digest context that implements
 * at least the function @ref n20_crypto_digest_context_s.hmac.
 * This function may be used to implement @ref n20_crypto_digest_context_s.hkdf_expand.
 *
 * For errors and expected behavior see @ref n20_crypto_digest_context_s.hkdf_expand.
 *
 * @param ctx Pointer to the cryptographic context.
 * @param alg_in Digest algorithm to use.
 * @param prk Pseudorandom key.
 * @param info Optional context and application specific information.
 * @param key_octets Length of the derived key in octets.
 * @param out Output buffer for the derived key.
 * @return n20_error_t Error code indicating success or failure.
 */
extern n20_error_t n20_hkdf_expand(n20_crypto_digest_context_t* ctx,
                                   n20_crypto_digest_algorithm_t alg_in,
                                   n20_slice_t const prk,
                                   n20_slice_t const info,
                                   size_t key_octets,
                                   uint8_t* out);
#ifdef __cplusplus
}
#endif
