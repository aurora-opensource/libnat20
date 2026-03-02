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

/**
 * @file rfc6979.h
 */

#include <nat20/crypto.h>
#include <nat20/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Big number represented in 32 bit machine words in little endian order.
 * I.e., each word is in machine byte order, but the word with the lowest
 * index always has the lowest significance.
 */
struct n20_bn_s {
    size_t word_count;
    uint32_t* words;
};

/** @brief Alias for @ref n20_bn_s. */
typedef struct n20_bn_s n20_bn_t;

/**
 * @brief Convert a big number to big endian octets.
 *
 * The octets are in big endian order, i.e., the most significant byte is at
 * the lowest index.
 *
 * If the big number is too large to fit into the output buffer, the function
 * will truncate the most significant bits. If the big number is smaller
 * than the output buffer, the function will pad the output with leading zeros.
 *
 * @param octets The output buffer for the octets. Must have a capacity of at
 * least @p octets_len bytes.
 * @param octets_len The capacity of the output buffer in bytes.
 * @param bn The big number to convert.
 */
extern void n20_bn_to_octets(uint8_t* octets, size_t octets_len, n20_bn_t const* bn);

/**
 * @brief Generate a deterministic nonce k according to RFC 6979.
 *
 * This function generates a deterministic nonce k for use in ECDSA
 * signatures, following the procedure described in RFC 6979.
 *
 * The @p m_octets parameter is optional and may be NULL. If it is not NULL, it should
 * point to the message to be signed in octet form. If it is NULL, the function will
 * generate k based only on the private key. This is useful for deterministic key
 * derivation, because k is uniformly distributed in the same way as the private key,
 * for the same elliptic curve parameters.
 *
 * Since no dynamic memory allocation is performed, the caller is responsible for providing
 * all necessary buffers and ensuring they have sufficient capacity.
 *
 * The @p skip_candidates parameter allows the caller to specify how many viable candidates for k
 * to skip before selecting the final nonce. This can be used to generate multiple nonces for
 * the same message and key by calling this function multiple times with the same arguments but
 * different values for @p skip_candidates. This addresses RFC 6979 3.4 Usage Notes which stipulates
 * that if the resulting r part of the signature is zero, the second phase of the nonce generation
 * should keep looping until a k is found that results in a non-zero r.
 * The overhead of this approach is high, but the probability of needing to skip even one candidate
 * is low to the point of implausibility.
 *
 * @param ctx The digest context to use for hashing.
 * @param digest_algorithm The digest algorithm to use.
 * @param key_type The type of the elliptic curve key.
 * @param x_octets The private key in octet form.
 * @param m_octets The message to be signed in octet form.
 * @param k The output big number for the generated nonce.
 * @param skip_candidates The number of viable candidates to skip before selecting the final nonce.
 * @return An error code indicating success or failure.
 */
extern n20_error_t n20_rfc6979_k_generation(n20_crypto_digest_context_t* ctx,
                                            n20_crypto_digest_algorithm_t digest_algorithm,
                                            n20_crypto_key_type_t key_type,
                                            n20_slice_t const* x_octets,
                                            n20_crypto_gather_list_t const* m_octets,
                                            n20_bn_t* k,
                                            size_t skip_candidates);

#ifdef __cplusplus
}
#endif
