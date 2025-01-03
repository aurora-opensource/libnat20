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

/**
 * @brief Error codes that may be returned by a crypto interface implementation.
 */
typedef enum n20_crypto_error_s {
    /**
     * @brief No error occurred.
     */
    n20_crypto_error_ok_e = 0,
    /**
     * @brief The crypto context given to an interface function was NULL.
     *
     * Implementation may deploy additional techniques to determine
     * if the context was valid.
     */
    n20_crypto_error_invalid_context_e = 1,
    /**
     * @brief
     *
     */
    n20_crypto_error_unexpected_null_e = 2,
    n20_crypto_error_unexpected_null_key_in_e = 3,
    n20_crypto_error_unexpected_null_key_out_e = 4,
    n20_crypto_error_unexpected_null_size_e = 5,
    n20_crypto_error_unexpected_null_data_e = 6,
    n20_crypto_error_unexpected_null_list_e = 7,
    n20_crypto_error_unexpected_null_slice_e = 8,
    n20_crypto_error_not_implemented_e = 9,
    n20_crypto_error_incompatible_algorithm_e = 10,
    n20_crypto_error_unkown_algorithm_e = 11,
    n20_crypto_error_invalid_key_e = 12,
    n20_crypto_error_invalid_key_type_e = 13,
    n20_crypto_error_no_memory_e = 14,
    n20_crypto_error_insufficient_buffer_size_e = 15,
    n20_crypto_error_implementation_specific_e = 16,
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
 * @brief A single consecutive non mutable buffer slice.
 *
 * A slice refers to a non mutable (const) buffer.
 *
 * A slice never owns this buffer, i.e., the user must
 * assure that the buffer outlives this structure as
 * long as this structure references the buffer.
 */
typedef struct n20_crypto_slice_s {
    /**
     * @brief The size of the slice.
     */
    size_t size;
    /**
     * @brief The buffer.
     *
     * This pointer must reference a buffer of sufficient
     * capacity to accommodate @ref size bytes of data.
     *
     * Implementation must ignore this value if @ref size is `0`.
     *
     * This field may be NULL only if @ref size is `0`.
     */
    uint8_t const* buffer;
} n20_crypto_slice_t;

/**
 * @brief A list of non mutable buffer slices.
 *
 * This structure must be initialized such that @ref list points
 * to a buffer of sizeof( @ref n20_crypto_slice_t ) * @ref count,
 * where @ref count refers to the number of slices in the gather
 * list.
 *
 * Implementations must process the slices in the order in which
 * they appear in the list.
 *
 * The gather list never takes ownership of any buffers.
 */
typedef struct n20_crypto_gather_list_s {
    /**
     * @brief Number of slices in the buffer
     *
     */
    size_t count;
    n20_crypto_slice_t* list;
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
     * Buffers of zero @ref n20_crypto_slice_s.size are allowed and treated
     * as empty. In this case the @ref n20_crypto_slice_s.buffer is ignored.
     *
     *
     * Implementations must implement the following digests.
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     * ## Errors
     *
     * - @ref n20_crypto_error_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_crypto_error_unexpected_null_size_e must be returned
     *   if @p digest_size_in_out is NULL.
     * - @ref n20_crypto_error_unkown_algorithm_e must be returned if
     *   @p alg_in is out of range.
     * - @ref n20_crypto_error_insufficient_buffer_size_e must be returned
     *   if @p digest_out is NULL or if @p digest_size_in_out indicates
     *   that the given buffer has insufficient capacity for the resulting
     *   digest. In this case the implementation MUST set
     *   @p digest_size_in_out to the size required by the algorithm
     *   selected in @p alg_in.
     * - @ref n20_crypto_error_unexpected_null_data_e must be returned
     *   if non of the above conditions were met AND @p msg_in is NULL.
     *   This means that `msg_in == NULL` MUST be tolerated when
     *   querying the output buffer size.
     * - @ref n20_crypto_error_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p msg_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p msg_in is NULL.
     * - @ref n20_crypto_error_unexpected_null_slice_e must be returned if
     *   the @p msg_in gather list contains a buffer that has non zero
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
     *        @p digest_size_in_out (on input) bytes or NULL.
     * @param digest_size_in_out On input the capacity of the given buffer.
     *        On output the size of the digest.
     */
    n20_crypto_error_t (*digest)(struct n20_crypto_context_s* ctx,
                                 n20_crypto_digest_algorithm_t alg_in,
                                 n20_crypto_gather_list_t const* msg_in,
                                 uint8_t* digest_out,
                                 size_t* digest_size_in_out);

    /**
     * @brief Derive a key from an opaque secret and context.
     *
     * Deterministically, derive a key from @p key_in - an opaque key
     * handle referencing a secret pseudo random key - and
     * @p context_in - a caller supplied context.
     *
     * No specific implementation is required by this specification.
     * However, the implementation must be sufficiently robust in
     * that it must not leak information about the underlying secret
     * and the derived key or allow inferences about either key bits.
     *
     * Implementations need not guarantee that the underlying key
     * material is hidden from the caller through system architectural
     * measures.
     * However, this crypto API never requires exposure of the underlying
     * key material, so that implementations that delegate cryptographic
     * operations to an isolated service or secure element are feasible
     * and encouraged.
     *
     * Implementations must support the derivation of CDIs as well
     * as key pairs for ed25519, SECP-256R1, and SECP-384R1.
     *
     * The key handle returned in @p key_out must be destroyed
     * with @ref key_free.
     *
     * ## Example
     * @code{.c}
     * n20_crypto_error_t rc;
     *
     * n20_crypto_context_s *ctx = open_my_crypto_implementation();
     *
     * // Get local cdi.
     * n20_crypto_key_t cdi = NULL;
     * rc = ctx->get_cdi(ctx, &cdi);
     * if (rc != n20_crypto_error_ok_e) {
     *     // error handling
     * }
     *
     * // Assemble the derivation context.
     * char const context_str[] = "kdf context";
     * n20_crypto_slice_t context_buffer = {
     *     .size = sizeof(context_str) -1,
     *     .buffer = (uint8_t const*)context_str,
     * };
     * n20_crypto_gather_list_t context = {
     *     .count = 1,
     *     .list = context_buffer,
     * };
     *
     * // Perform key derivation.
     * n20_crypto_key_t derived_key = nullptr;
     * rc = ctx->kdf(ctx, cdi, n20_crypto_key_type_ed25519_e, &context, &derived_key);
     * if (rc != n20_crypto_error_ok_e) {
     *     // error handling
     * }
     *
     * // Perform key operation.
     *
     * // Clean up.
     * rc = ctx->key_free(ctx, derived_key);
     * if (rc != n20_crypto_error_ok_e) {
     *     // error handling
     * }
     *
     * rc = ctx->key_free(ctx, cdi);
     * if (rc != n20_crypto_error_ok_e) {
     *     // error handling
     * }
     *
     * @endcode
     *
     * ## Errors
     * - @ref n20_crypto_error_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_crypto_error_unexpected_null_key_in_e must be returned
     *   if the @p key_in is NULL.
     * - @ref n20_crypto_error_invalid_key_e must be returned if
     *   @p key_in is not of the type @ref n20_crypto_key_type_cdi_e.
     * - @ref n20_crypto_error_unexpected_null_key_out_e must be returned
     *   if @p key_out is NULL.
     * - @ref n20_crypto_error_unexpected_null_data_e must be returned
     *   if @p context_in is NULL.
     * - @ref n20_crypto_error_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p context_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p context_in is NULL.
     * - @ref n20_crypto_error_unexpected_null_slice_e must be returned if
     *   the @p context_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     * - @ref n20_crypto_error_invalid_key_type_e must be returned
     *   if @p key_type_in is not in the range given by @ref n20_crypto_key_type_t.
     *
     * @param ctx The crypto context.
     * @param key_in The opaque key handle denoting the secret key input.
     * @param key_type_in The type of the to-be-derived key.
     * @param context_in A gatherlist describing the context of the to-be-derived key.
     * @param key_out Output buffer for the derived key handle.
     */
    n20_crypto_error_t (*kdf)(struct n20_crypto_context_s* ctx,
                              n20_crypto_key_t key_in,
                              n20_crypto_key_type_t key_type_in,
                              n20_crypto_gather_list_t const* context_in,
                              n20_crypto_key_t* key_out);
    /**
     * @brief Sign a message using an opaque key handle.
     *
     * Sign a message using an @p key_in - an opaque key handle
     * created using @ref kdf.
     *
     * (TODO describe the signature format for the different algorithms)
     *
     * ## Errors
     * - @ref n20_crypto_error_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_crypto_error_unexpected_null_key_in_e must be returned
     *   if the @p key_in is NULL.
     * - @ref n20_crypto_error_unexpected_null_size_e must be returned if
     *   @p signature_size_in_out is NULL.
     * - @ref n20_crypto_error_invalid_key_e must be returned
     *   if @p key_in is not of the types @ref n20_crypto_key_type_ed25519,
     *   @ref n20_crypto_key_type_secp256r1_e, or
     *   @ref n20_crypto_key_type_secp384r1_e.
     * - @ref n20_crypto_error_unexpected_null_data_e must be returned
     *   if @p context_in is NULL.
     * - @ref n20_crypto_error_insufficient_buffer_size_e if
     *   @p signature_out is NULL or if @p *signature_size_in_out indicates
     *   that the given buffer is too small.
     *   If @ref n20_crypto_error_insufficient_buffer_size_e is returned
     *   the implementation must set @p *signature_size_in_out to the maximum
     *   required buffer size for the signature algorithm requested.
     * - @ref n20_crypto_error_unexpected_null_data_e must be returned
     *   if @p msg_in is NULL.
     * - @ref n20_crypto_error_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p msg_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p msg_in is NULL.
     * - @ref n20_crypto_error_unexpected_null_slice_e must be returned if
     *   the @p msg_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     * - @ref n20_crypto_error_invalid_key_type_e must be returned
     *   if @p key_type_in is not in the range given by @ref n20_crypto_key_type_t.
     *
     * @param ctx The crypto context.
     * @param key_in The opaque key handle denoting the private signing key.
     * @param msg_in The message that is to be signed.
     * @param signature_out A buffer that is to hold the signature.
     * @param signature_size_in_out A size buffer that holds the size of the
     *        given buffer (in) and the size of the required/used signature
     *        buffer (out).
     */
    n20_crypto_error_t (*sign)(struct n20_crypto_context_s* ctx,
                               n20_crypto_key_t key_in,
                               n20_crypto_gather_list_t const* msg_in,
                               uint8_t* signature_out,
                               size_t* signature_size_in_out);
    /**
     * @brief Return the local cdi handle.
     *
     * This function is used to bootstrap all key derivation for the
     * current DICE service level.
     *
     * The function places the handle to the CDI into @key_out.
     *
     * The CDI key handle must be destroyed with @ref key_free.
     *
     * ## Errors
     * - @ref n20_crypto_error_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_crypto_error_unexpected_null_key_out_e must be returned
     *   if @p key_out is NULL.
     *
     * @param ctx The crypto context.
     * @param key_out A buffer to take the opaque key handle of the root
     *        secret that is the local CDI.
     */
    n20_crypto_error_t (*get_cdi)(struct n20_crypto_context_s* ctx, n20_crypto_key_t* key_out);
    /**
     * @brief Export the public key.
     *
     * (TODO) Describe the public key format.
     *
     * @param ctx The crypto context.
     * @param key_in The opaque key handle denoting the key pair of which the public key
     *        shall be extracted.
     * @param public_key_out A buffer to accommodate the encoded public key.
     * @param public_key_size_in_out A size buffer that holds the size of the
     *        given buffer (in) and the size of the required/used public key
     *        buffer (out).
     */
    n20_crypto_error_t (*key_get_public_key)(struct n20_crypto_context_s* ctx,
                                             n20_crypto_key_t key_in,
                                             uint8_t* public_key_out,
                                             size_t* public_key_size_in_out);
    /**
     * @brief Destroy a key handle.
     *
     * Destroys a key handle obtained by calling @ref get_cdi or @ref kdf.
     *
     * Unless an invalid context is given, this function shall not fail.
     *
     * Passing NULL as @p key_in is explicitly allowed and yield
     * @ref n20_crypto_error_ok_e.
     *
     * ## Errors
     * - @ref n20_crypto_error_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     *
     * @param ctx The crypto context.
     * @param key_in The key handle to be freed.
     */
    n20_crypto_error_t (*key_free)(struct n20_crypto_context_s* ctx, n20_crypto_key_t key_in);
} n20_crypto_context_t;

#ifdef __cplusplus
}
#endif
