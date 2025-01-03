/*
 * Copyright 2024 Aurora Operations, Inc.
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

/** @file */

#pragma once

#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum n20_crypto_error_s {
    n20_crypto_error_ok_e,
    n20_crypto_error_invalid_context_e,
    n20_crypto_error_unexpected_null_e,
    n20_crypto_error_not_implemented_e,
    n20_crypto_error_incompatible_algorithm_e,
    n20_crypto_error_unkown_algorithm_e,
    n20_crypto_error_invalid_key_e,
    n20_crypto_error_no_memory_e,
    n20_crypto_error_insufficient_buffer_size_e,
    n20_crypto_error_implementation_specific_e,
} n20_crypto_error_t;

typedef enum n20_crypto_digest_algorithm_s {
    n20_crypto_digest_algorithm_sha2_224_e,
    n20_crypto_digest_algorithm_sha2_256_e,
    n20_crypto_digest_algorithm_sha2_384_e,
    n20_crypto_digest_algorithm_sha2_512_e,
} n20_crypto_digest_algorithm_t;

typedef enum n20_crypto_key_type_s {
    n20_crypto_key_type_secp256r1_e,
    n20_crypto_key_type_secp384r1_e,
    n20_crypto_key_type_ed25519_e,
    n20_crypto_key_type_cdi_e,
} n20_crypto_key_type_t;

// Opaque key handle.
typedef void* n20_crypto_key_t;

/**
 * @brief
 *
 */
typedef struct n20_crypto_buffer_s {
    /**
     * @brief
     *
     */
    size_t size;
    /**
     * @brief
     *
     */
    uint8_t* buffer;
} n20_crypto_buffer_t;

typedef struct n20_crypto_gather_list_s {
    size_t count;
    n20_crypto_buffer_t* list;
} n20_crypto_gather_list_t;

typedef struct n20_crypto_context_s {
    /**
     * @brief Digest a message in a one shot operation.
     *
     * This function digests the message given by the gather list @ref msg_in.
     *
     * Each buffer in the gather list is concatenated in the order they
     * appear in the list.
     *
     * Buffers of zero @ref n20_crypto_buffer_s.size are allowed and treated
     * as empty. In this case the @ref n20_crypto_buffer_s.buffer is ignored.
     *
     *
     * Implementations must implement the following digests.
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     *
     * # Errors
     *
     * - @ref n20_crypto_error_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_crypto_error_unexpected_null_e must be returned
     *   if @ref digest_size_in_out is NULL.
     * - @ref n20_crypto_error_unkown_algorithm_e must be returned if
     *   @ref alg_in is out of range.
     * - @ref n20_crypto_error_insufficient_buffer_size_e must be returned
     *   if @ref digest_out is NULL or if @ref digest_size_in_out indicates
     *   that the given buffer has insufficient capacity for the resulting
     *   digest. In this case the implementation MUST set
     *   @ref digest_size_in_out to the size required by the algorithm
     *   selected in @ref alg_in.
     * - @ref n20_crypto_error_unexpected_null_e must be returned
     *   if non of the above conditions were met AND @ref msg_in is NULL.
     *   This means that `msg_in == NULL` MUST be tolerated when
     *   querying the output buffer size.
     * - @ref n20_crypto_error_unexpected_null_e must be returned if
     *   the @ref msg_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     *
     * Implementations may return @ref n20_crypto_error_no_memory_e if
     * any kind of internal resource allocation failed.
     *
     * Implementations may return @ref n20_crypto_error_implementation_specific_e.
     * However, it is impossible to meaningfully recover from this error, therefore,
     * it is strongly discouraged for implementations to return this error,
     * and given the nature of the algorithms, it should never be necessary to do so.
     *
     * @param ctx The crypto context.
     * @param alg_in Designates the desired digest algorithm.
     * @param msg_in The message that is to be digested.
     * @param digest_out A buffer with sufficient capacity to hold
     *        @ref digest_size_in_out (on input) bytes or NULL.
     * @param digest_size_in_out On input the capacity of the given buffer.
     *        On output the size of the digest.
     */
    n20_crypto_error_t (*digest)(struct n20_crypto_context_s* ctx,
                                 n20_crypto_digest_algorithm_t alg_in,
                                 n20_crypto_gather_list_t const* msg_in,
                                 uint8_t* digest_out,
                                 size_t* digest_size_in_out);
    n20_crypto_error_t (*kdf)(struct n20_crypto_context_s* ctx,
                              n20_crypto_key_t key_in,
                              n20_crypto_key_type_t key_type_in,
                              n20_crypto_gather_list_t const* context_in,
                              n20_crypto_key_t* key_out);
    n20_crypto_error_t (*sign)(struct n20_crypto_context_s* ctx,
                               n20_crypto_key_t key_in,
                               n20_crypto_gather_list_t const* msg,
                               uint8_t* signature_out,
                               size_t* signature_size_in_out);
    n20_crypto_error_t (*get_cdi)(struct n20_crypto_context_s* ctx, n20_crypto_key_t* key_out);
    n20_crypto_error_t (*key_get_public_key)(struct n20_crypto_context_s* ctx,
                                             n20_crypto_key_t key_in,
                                             uint8_t* public_key_out,
                                             size_t* public_key_size_out);
    n20_crypto_error_t (*key_free)(struct n20_crypto_context_s* ctx, n20_crypto_key_t key_in);
} n20_crypto_context_t;

#ifdef __cplusplus
}
#endif
