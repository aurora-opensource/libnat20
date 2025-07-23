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
#include <nat20/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open a new BoringSSL cryptographic context.
 *
 * Instantiates a new cryptographic context using BoringSSL.
 *
 * Each call to this function must be paired with a call to
 * @ref n20_crypto_boringssl_close to release the resources.
 *
 * Note that in the current implementation, each call to this function
 * returns the same context and does not allocate new resources.
 * The `close` counterpart is a no-op.
 * However, because the implementation is entirely stateless,
 * and reentrant it is still possible to write code that
 * instantiates multiple contexts and closes them.
 *
 * This behavior is subject to change in the future and must
 * not be relied upon by the caller. For a single context instance,
 * no thread-safety guarantees may be assumed.
 *
 * @param ctx A pointer to the context to be opened.
 * @return n20_error_t The result of the operation.
 */
n20_error_t n20_crypto_boringssl_open(n20_crypto_context_t** ctx);

/**
 * @brief Close a BoringSSL cryptographic context.
 *
 * Releases the resources associated with the given context.
 *
 * This function must be called for each context opened with
 * @ref n20_crypto_boringssl_open.
 *
 * This is a no-op in the current implementation, however, this
 * behavior is subject to change in the future and must not
 * be relied upon by the caller.
 *
 * @param ctx The context to be closed.
 * @return n20_error_t The result of the operation.
 */
n20_error_t n20_crypto_boringssl_close(n20_crypto_context_t* ctx);

/**
 * @brief Create a new a key handle from a secret value.
 *
 * This function stores the given secret value in memory
 * and makes it available as a key handle of type
 * @ref n20_crypto_key_type_cdi_e.
 *
 * This key handle can then be used with the @ref n20_crypto_context_s.kdf
 * function of the same context as given by the @p ctx parameter. And
 * must eventually be freed with @ref n20_crypto_context_s.key_free.
 *
 * Note that this is a functional reference implementation that keeps
 * the secret in memory with no additional protection.
 * Integrators should provide their own cryptographic context and means
 * to create opaque key handles.
 *
 * @param ctx The cryptographic context.
 * @param secret_in The input secret value.
 * @param key_out The output key.
 * @return n20_error_t The result of the operation.
 */
n20_error_t n20_crypto_boringssl_make_secret(struct n20_crypto_context_s* ctx,
                                             n20_slice_t const* secret_in,
                                             n20_crypto_key_t* key_out);

#ifdef __cplusplus
}
#endif
