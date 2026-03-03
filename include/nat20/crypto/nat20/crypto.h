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
n20_error_t n20_crypto_nat20_open(n20_crypto_digest_context_t** ctx_out);

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
n20_error_t n20_crypto_nat20_close(n20_crypto_digest_context_t* ctx_out);

#ifdef __cplusplus
}
#endif
