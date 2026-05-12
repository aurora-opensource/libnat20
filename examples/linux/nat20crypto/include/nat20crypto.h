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

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/types.h>

/**
 * nat20crypto_open - Obtain a Linux kernel crypto context
 * @ctx: Output pointer to receive the crypto context
 *
 * Returns an n20_crypto_context_t that implements the libnat20 crypto
 * interface using Linux kernel crypto primitives. The context supports
 * ECDSA signing (P-256, P-384), SHA-2 hashing, HMAC, HKDF, and key
 * derivation via RFC 6979. Ed25519 is not currently supported.
 *
 * Each call to nat20crypto_open() must be paired with a corresponding
 * call to nat20crypto_close(). Key handles created through a context
 * instance must only be used with that same instance and must be freed
 * before closing it.
 *
 * The returned context is safe for concurrent use from multiple threads.
 *
 * Return: n20_error_ok_e on success, n20_error_crypto_unexpected_null_e
 *         if @ctx is NULL.
 */
n20_error_t nat20crypto_open(n20_crypto_context_t** ctx);

/**
 * nat20crypto_close - Release a Linux kernel crypto context
 * @ctx: The crypto context obtained from nat20crypto_open()
 *
 * Releases any resources associated with the context. All key handles
 * created through this context must be freed before calling this
 * function.
 *
 * Return: n20_error_ok_e on success, n20_error_crypto_unexpected_null_e
 *         if @ctx is NULL.
 */
n20_error_t nat20crypto_close(n20_crypto_context_t* ctx);

/**
 * nat20crypto_make_secret - Wrap raw key material as a CDI key handle
 * @ctx: The crypto context obtained from nat20crypto_open()
 * @secret_in: Slice containing the raw secret (up to 32 bytes are used)
 * @key_out: Output pointer to receive the new key handle
 *
 * Creates an opaque key handle of type n20_crypto_key_type_cdi_e from
 * the provided raw secret material. The key handle can be used with
 * the context's kdf function to derive signing keys.
 *
 * The caller is responsible for freeing the returned key handle via
 * ctx->key_free() when it is no longer needed.
 *
 * Return: n20_error_ok_e on success, or an appropriate error code if
 *         any argument is NULL or allocation fails.
 */
n20_error_t nat20crypto_make_secret(struct n20_crypto_context_s* ctx,
                                    n20_slice_t const* secret_in,
                                    n20_crypto_key_t* key_out);
