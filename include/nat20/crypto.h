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

/** @file */

#pragma once

#include <nat20/error.h>
#include <nat20/types.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumeration of supported digest algorithms.
 *
 * Implementations of this interface must provide
 * all of these algorithms.
 */
enum n20_crypto_digest_algorithm_s {
    /**
     * @brief SHA 2 224.
     */
    n20_crypto_digest_algorithm_sha2_224_e,
    /**
     * @brief SHA 2 256.
     */
    n20_crypto_digest_algorithm_sha2_256_e,
    /**
     * @brief SHA 2 384.
     */
    n20_crypto_digest_algorithm_sha2_384_e,
    /**
     * @brief SHA 2 512.
     */
    n20_crypto_digest_algorithm_sha2_512_e,
};

/**
 * @brief Alias for @ref n20_crypto_digest_algorithm_s
 */
typedef enum n20_crypto_digest_algorithm_s n20_crypto_digest_algorithm_t;

/**
 * @brief Enumerations of supported key types.
 *
 * Implementations of this interface must provide
 * the following cryptographic key types.
 */
enum n20_crypto_key_type_s {
    /**
     * @brief No key type.
     *
     * This value is used as default initialization value
     * for key types. It indicates that no key type is selected.
     */
    n20_crypto_key_type_none_e = 0,
    /**
     * @brief Secp256r1.
     *
     * Select the NIST curve P-256 also known as Secp256r1 or prime256v1.
     */
    n20_crypto_key_type_secp256r1_e,
    /**
     * @brief Secp384r1.
     *
     * Select the NIST curve P-384.
     */
    n20_crypto_key_type_secp384r1_e,
    /**
     * @brief Select ed25519.
     *
     * Select the ED25519 curve with EDDSA signing scheme.
     */
    n20_crypto_key_type_ed25519_e,
    /**
     * @brief Select CDI.
     *
     * This key type refers to a compound device identifier. A derived
     * secret that can be used to derive other secrets and key pairs.
     */
    n20_crypto_key_type_cdi_e,
};

/**
 * @brief Alias for @ref n20_crypto_key_type_s
 */
typedef enum n20_crypto_key_type_s n20_crypto_key_type_t;

/**
 * @brief Opaque key handle.
 *
 * This handle is used to refer to a key that can be used by the
 * crypto implementation. The nature of the key is completely
 * opaque to the caller.
 *
 * The lifecycle begins with a call to @ref n20_crypto_context_t.kdf
 * or an implementation specific factory function that
 * returns a key of the type @ref n20_crypto_key_type_t
 * and ends with a call to @ref n20_crypto_context_t.key_free.
 */
typedef void* n20_crypto_key_t;

/**
 * @brief A list of immutable buffer slices.
 *
 * This structure must be initialized such that @ref list points
 * to a buffer of sizeof( @ref n20_slice_t ) * @ref count,
 * where @ref count refers to the number of slices in the gather
 * list.
 *
 * Implementations must process the slices in the order in which
 * they appear in the list.
 *
 * The gather list never takes ownership of any buffers.
 */
struct n20_crypto_gather_list_s {
    /**
     * @brief Number of slices in the gather list.
     */
    size_t count;
    /**
     * @brief Points to an array of @ref n20_slice_t.
     *
     * The array pointed to must accommodate at least @ref count
     * elements of @ref n20_slice_t.
     *
     * This structure does not take ownership of the array.
     *
     */
    n20_slice_t const* list;
};

/**
 * @brief Alias for @ref n20_crypto_gather_list_s
 */
typedef struct n20_crypto_gather_list_s n20_crypto_gather_list_t;

/**
 * @brief Context for a digest operation.
 *
 * This is a subset of the @ref n20_crypto_context_t
 * that is used to perform digest operations and
 * algorithms that are based on digest algorithms
 * like HMAC and HKDF.
 */
struct n20_crypto_digest_context_s {
    /**
     * @brief Digest a message in a one shot operation.
     *
     * This function digests the message given by the gather list @p msg_in.
     * @p msg_in may point to an array of gather lists. @p msg_count gives
     * the number of gather lists in the array.
     *
     * Each buffer in the gather list is concatenated in the order they
     * appear in the list.
     *
     * Buffers with zero @ref n20_slice_s.size are allowed and treated
     * as empty. In this case the @ref n20_slice_s.buffer is ignored.
     *
     * Implementations must implement the following digests.
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     * ## Errors
     *
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unexpected_null_size_e must be returned
     *   if @p digest_size_in_out is NULL.
     * - @ref n20_error_crypto_unknown_algorithm_e must be returned if
     *   @p alg_in is out of range.
     * - @ref n20_error_crypto_insufficient_buffer_size_e must be returned
     *   if @p digest_out is NULL or if @p digest_size_in_out indicates
     *   that the given buffer has insufficient capacity for the resulting
     *   digest. In this case the implementation MUST set
     *   @p digest_size_in_out to the size required by the algorithm
     *   selected in @p alg_in.
     * - @ref n20_error_crypto_unexpected_null_data_e must be returned
     *   if none of the above conditions were met AND @p msg_in is NULL.
     *   This means that `msg_in == NULL` MUST be tolerated when
     *   querying the output buffer size.
     * - @ref n20_error_crypto_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p msg_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p msg_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_slice_e must be returned if
     *   the @p msg_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     *
     * Implementations may return @ref n20_error_crypto_no_resources_e if
     * any kind of internal resource allocation failed.
     *
     * Implementations may return @ref n20_error_crypto_implementation_specific_e.
     * However, it is impossible to meaningfully recover from this error, therefore,
     * it is strongly discouraged for implementations to return this error,
     * and given the nature of the algorithms, it should never be necessary to do so.
     *
     * ## Design rationale
     *
     * The API uses a one shot paradigm to allow implementations to hide resource
     * and state management from the caller, i.e., the libnat20 DICE service functionality.
     * The latter is expected to operate in a context where dynamic memory allocation
     * might not be available or desirable, and allocating memory for a digest context
     * would be a burden for the implementation, especially if the context size
     * depends on the implementation of this interface.
     *
     * This requires the entire message to be in memory at the time of the call.
     * The gather list is a trade off that allows the caller to composite a message without
     * needing to allocate a contiguous buffer for the entire message.
     *
     * This falls short when part of the message is already supplied as a gather list
     * as is the case if HMAC is implemented in terms of this digest function.
     * Allocating a new gather list is not feasible if no dynamic memory allocation
     * is possible. Also, the length of the new gather list cannot be anticipated.
     * Nesting of gather lists could have been chosen as a solution, but it would
     * introduce potentially unbounded stack growth.
     *
     * The choice to support an array of gather lists is a compromise that allows
     * HMAC implementation to compose a message provided as a gather list with the
     * key as a fixed size array of two gather lists that can be placed on the stack.
     * While not completely generic, it allows for all anticipated use cases required by
     * the libnat20 DICE service functionality.
     *
     * @param ctx The crypto context.
     * @param alg_in Designates the desired digest algorithm.
     * @param msg_in The message that is to be digested.
     * @param msg_count The number of gather lists in the @p msg_in array.
     * @param digest_out A buffer with sufficient capacity to hold
     *        @p digest_size_in_out (on input) bytes or NULL.
     * @param digest_size_in_out On input the capacity of the given buffer.
     *        On output the size of the digest.
     */
    n20_error_t (*digest)(struct n20_crypto_digest_context_s* ctx,
                          n20_crypto_digest_algorithm_t alg_in,
                          n20_crypto_gather_list_t const* msg_in,
                          size_t msg_count,
                          uint8_t* digest_out,
                          size_t* digest_size_in_out);

    /**
     * @brief Compute a HMAC of a message.
     *
     * This function computes an HMAC of the message given by the gather list
     * @p msg_in using the key given by @p key.
     *
     * Each buffer in the gather list is concatenated in the order they
     * appear in the list.
     *
     * Buffers with zero @ref n20_slice_s.size are allowed and treated
     * as empty. In this case the @ref n20_slice_s.buffer is ignored.
     *
     * Implementations must support the following algorithms:
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unexpected_null_size_e must be returned
     *   if @p mac_size_in_out is NULL.
     * - @ref n20_error_crypto_unknown_algorithm_e must be returned if
     *   @p alg_in is out of range.
     * - @ref n20_error_crypto_unexpected_null_slice_key_e must be returned
     *   if @p key.buffer is NULL and @p key.size is not `0`.
     * - @ref n20_error_crypto_insufficient_buffer_size_e must be returned
     *   if @p mac_out is NULL or if @p mac_size_in_out indicates
     *   that the given buffer has insufficient capacity for the resulting
     *   MAC. In this case the implementation MUST set
     *   @p mac_size_in_out to the size required by the algorithm
     *   selected in @p alg_in.
     * - @ref n20_error_crypto_unexpected_null_data_e must be returned
     *   if none of the above conditions were met AND @p msg_in is NULL.
     *   This means that `msg_in == NULL` MUST be tolerated when
     *   querying the output buffer size.
     * - @ref n20_error_crypto_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p msg_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p msg_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_slice_e must be returned if
     *   the @p msg_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     *
     * Implementations may return @ref n20_error_crypto_no_resources_e if
     * any kind of internal resource allocation failed.
     *
     * Implementations may return @ref n20_error_crypto_implementation_specific_e.
     * However, it is impossible to meaningfully recover from this error, therefore,
     * it is strongly discouraged for implementations to return this error,
     * and given the nature of the algorithms, it should never be necessary to do so.
     */
    n20_error_t (*hmac)(struct n20_crypto_digest_context_s* ctx,
                        n20_crypto_digest_algorithm_t alg_in,
                        n20_slice_t const key,
                        n20_crypto_gather_list_t const* msg_in,
                        uint8_t* mac_out,
                        size_t* mac_size_in_out);

    /**
     * @brief Perform a HKDF operation.
     *
     * This function performs a HKDF operation using the
     * input key material @p ikm_in, the salt @p salt_in,
     * and the info @p info_in.
     * The output key is written to @p key_out. Callers must provide
     * a buffer with sufficient capacity to hold the output key.
     * The size of the output key is given by @p key_octets_in.
     *
     * Implementations must support the following algorithms:
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unknown_algorithm_e must be returned if
     *   @p alg_in is out of range.
     * - @ref n20_error_crypto_unexpected_null_slice_ikm_e must be returned
     *   if @p ikm_in.buffer is NULL and @p ikm_in.size is not `0`.
     * - @ref n20_error_crypto_unexpected_null_slice_salt_e must be returned
     *   if @p salt_in.buffer is NULL and @p salt_in.size is not `0`.
     * - @ref n20_error_crypto_unexpected_null_slice_info_e must be returned
     *   if @p info_in.buffer is NULL and @p info_in.size is not `0`.
     * - @ref n20_error_crypto_insufficient_buffer_size_e must be returned
     *   if @p key_out is NULL and @p key_octets_in is not `0`.
     *
     * Implementations may return @ref n20_error_crypto_no_resources_e if
     * any kind of internal resource allocation failed.
     *
     * Implementations may return @ref n20_error_crypto_implementation_specific_e.
     * However, it is impossible to meaningfully recover from this error, therefore,
     * it is strongly discouraged for implementations to return this error,
     * and given the nature of the algorithms, it should never be necessary to do so.
     */
    n20_error_t (*hkdf)(struct n20_crypto_digest_context_s* ctx,
                        n20_crypto_digest_algorithm_t alg_in,
                        n20_slice_t ikm_in,
                        n20_slice_t salt_in,
                        n20_slice_t info_in,
                        size_t key_octets_in,
                        uint8_t* key_out);

    /**
     * @brief Perform a HKDF_EXTRACT operation.
     *
     * This function performs a HKDF_EXTRACT operation using the
     * input key material @p ikm_in and the salt @p salt_in.
     *
     * The output pseudorandom key is written to @p prk_out.
     * The size of the output buffer must be provided in @p prk_size_in_out.
     * If the output buffer is NULL, or the size is not sufficient
     * to hold the output pseudorandom key, the implementation must
     * set @p prk_size_in_out to the size required by the algorithm
     * and return @ref n20_error_crypto_insufficient_buffer_size_e.
     *
     * Implementations must support the following algorithms:
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unknown_algorithm_e must be returned if
     *   @p alg_in is out of range.
     * - @ref n20_error_crypto_unexpected_null_slice_ikm_e must be returned
     *   if @p ikm.buffer is NULL and @p ikm.size is not `0`.
     * - @ref n20_error_crypto_unexpected_null_slice_salt_e must be returned
     *   if @p salt.buffer is NULL and @p salt.size is not `0`.
     * - @ref n20_error_crypto_insufficient_buffer_size_e must be returned
     *   if @p prk_out is NULL or if @p prk_size_in_out is not sufficient.
     *   In this case the implementation MUST set @p prk_size_in_out to the size
     *   required by the algorithm selected in @p alg_in.
     *
     * Implementations may return @ref n20_error_crypto_no_resources_e if
     * any kind of internal resource allocation failed.
     *
     * Implementations may return @ref n20_error_crypto_implementation_specific_e.
     * However, it is impossible to meaningfully recover from this error, therefore,
     * it is strongly discouraged for implementations to return this error,
     * and given the nature of the algorithms, it should never be necessary to do so.
     */
    n20_error_t (*hkdf_extract)(struct n20_crypto_digest_context_s* ctx,
                                n20_crypto_digest_algorithm_t alg_in,
                                n20_slice_t ikm_in,
                                n20_slice_t salt_in,
                                uint8_t* prk_out,
                                size_t* prk_size_in_out);

    /**
     * @brief Perform a HKDF_EXPAND operation.
     *
     * This function performs a HKDF_EXPAND operation using the
     * pseudo random key material @p prk_in and the info @p info_in.
     * The output key is written to @p key_out. Callers must provide
     * a buffer with sufficient capacity to hold the output key.
     * The size of the output key is given by @p key_octets.
     *
     * Implementations must support the following algorithms:
     * - SHA2 224
     * - SHA2 256
     * - SHA2 384
     * - SHA2 512
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unknown_algorithm_e must be returned if
     *   @p alg_in is out of range.
     * - @ref n20_error_crypto_unexpected_null_slice_prk_e must be returned
     *   if @p prk_in.buffer is NULL and @p prk_in.size is not `0`.
     * - @ref n20_error_crypto_unexpected_null_slice_info_e must be returned
     *   if @p info_in.buffer is NULL and @p info_in.size is not `0`.
     * - @ref n20_error_crypto_insufficient_buffer_size_e must be returned
     *   if @p key_out is NULL and @p key_octets_in is not `0`.
     *
     * Implementations may return @ref n20_error_crypto_no_resources_e if
     * any kind of internal resource allocation failed.
     *
     * Implementations may return @ref n20_error_crypto_implementation_specific_e.
     * However, it is impossible to meaningfully recover from this error, therefore,
     * it is strongly discouraged for implementations to return this error,
     * and given the nature of the algorithms, it should never be necessary to do so.
     */
    n20_error_t (*hkdf_expand)(struct n20_crypto_digest_context_s* ctx,
                               n20_crypto_digest_algorithm_t alg_in,
                               n20_slice_t prk_in,
                               n20_slice_t info_in,
                               size_t key_octets_in,
                               uint8_t* key_out);
};

/**
 * @brief Alias for @ref n20_crypto_digest_context_s
 */
typedef struct n20_crypto_digest_context_s n20_crypto_digest_context_t;

/**
 * @brief The crypto context.
 *
 * The crypto context is the main interface to the crypto API.
 * It provides cryptographic operations to the higher layers of
 * the DICE service functionality.
 * Integrators must provide an implementation of this interface
 * that is suitable for the target platform and runtime environment.
 */
struct n20_crypto_context_s {
    /**
     * @brief The digest context.
     *
     * This context is used for performing cryptographic digest operations.
     * It is initialized by the implementation and must have all
     * functions implemented as described in the @ref n20_crypto_digest_context_s.
     */
    n20_crypto_digest_context_t digest_ctx;
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
     * n20_error_t rc;
     *
     * n20_crypto_context_s *ctx = open_my_crypto_implementation();
     *
     * // Get local cdi or uds by means of an implementation specific
     * // mechanism.
     * n20_crypto_key_t cdi = my_crypto_implementation_get_secret_handle();
     *
     * // Assemble the derivation context.
     * char const context_str[] = "kdf context";
     * n20_slice_t context_buffer = {
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
     * if (rc != n20_error_ok_e) {
     *     // error handling
     * }
     *
     * // Perform key operation.
     *
     * // Clean up.
     * rc = ctx->key_free(ctx, derived_key);
     * if (rc != n20_error_ok_e) {
     *     // error handling
     * }
     *
     * rc = ctx->key_free(ctx, cdi);
     * if (rc != n20_error_ok_e) {
     *     // error handling
     * }
     *
     * @endcode
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unexpected_null_key_in_e must be returned
     *   if the @p key_in is NULL.
     * - @ref n20_error_crypto_invalid_key_e must be returned if
     *   @p key_in is not of the type @ref n20_crypto_key_type_cdi_e.
     * - @ref n20_error_crypto_unexpected_null_key_out_e must be returned
     *   if @p key_out is NULL.
     * - @ref n20_error_crypto_unexpected_null_data_e must be returned
     *   if @p context_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p context_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p context_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_slice_e must be returned if
     *   the @p context_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     * - @ref n20_error_crypto_invalid_key_type_e must be returned
     *   if @p key_type_in is not in the range given by @ref n20_crypto_key_type_t.
     *
     * @param ctx The crypto context.
     * @param key_in The opaque key handle denoting the secret key input.
     * @param key_type_in The type of the to-be-derived key.
     * @param context_in A gatherlist describing the context of the to-be-derived key.
     * @param key_out Output buffer for the derived key handle.
     */
    n20_error_t (*kdf)(struct n20_crypto_context_s* ctx,
                       n20_crypto_key_t key_in,
                       n20_crypto_key_type_t key_type_in,
                       n20_crypto_gather_list_t const* context_in,
                       n20_crypto_key_t* key_out);
    /**
     * @brief Sign a message using an opaque key handle.
     *
     * Sign a message using @p key_in - an opaque key handle
     * created using @ref kdf.
     *
     * The signature format depends on the signature algorithm used.
     * - ed25519: The signature is a 64 octet string that is the
     *   concatenation of R and S as described in RFC8032 5.1.6.
     * - ECDSA: The signature is the concatenation of the big-endian
     *   encoded unsigned integers R and S. Both integers always
     *   have the same size as the signing key in octets, i.e.,
     *   32 for P-256 and 48 for P-384, and they are padded with
     *   leading zeroes if necessary.
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unexpected_null_key_in_e must be returned
     *   if the @p key_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_size_e must be returned if
     *   @p signature_size_in_out is NULL.
     * - @ref n20_error_crypto_invalid_key_e must be returned
     *   if @p key_in is not of the types @ref n20_crypto_key_type_ed25519_e,
     *   @ref n20_crypto_key_type_secp256r1_e, or
     *   @ref n20_crypto_key_type_secp384r1_e.
     * - @ref n20_error_crypto_unexpected_null_data_e must be returned
     *   if @p context_in is NULL.
     * - @ref n20_error_crypto_insufficient_buffer_size_e if
     *   @p signature_out is NULL or if @p *signature_size_in_out indicates
     *   that the given buffer is too small.
     *   If @ref n20_error_crypto_insufficient_buffer_size_e is returned
     *   the implementation must set @p *signature_size_in_out to the maximum
     *   required buffer size for the signature algorithm requested.
     * - @ref n20_error_crypto_unexpected_null_data_e must be returned
     *   if @p msg_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_list_e must be returned
     *   if @ref n20_crypto_gather_list_t.count in @p msg_in is not `0`
     *   and @ref n20_crypto_gather_list_t.list in @p msg_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_slice_e must be returned if
     *   the @p msg_in gather list contains a buffer that has non zero
     *   size but a buffer that is NULL.
     *
     * @param ctx The crypto context.
     * @param key_in The opaque key handle denoting the private signing key.
     * @param msg_in The message that is to be signed.
     * @param signature_out A buffer that is to hold the signature.
     * @param signature_size_in_out A size buffer that holds the size of the
     *        given buffer (in) and the size of the required/used signature
     *        buffer (out).
     */
    n20_error_t (*sign)(struct n20_crypto_context_s* ctx,
                        n20_crypto_key_t key_in,
                        n20_crypto_gather_list_t const* msg_in,
                        uint8_t* signature_out,
                        size_t* signature_size_in_out);

    /**
     * @brief Export the public key of an asymmetric key.
     *
     * The public key format depends on the signature key algorithm used.
     * - ED25519: The 32 byte compressed point format as described in
     *   RFC8032 Section 5.1.5.
     * - ECDSA: The public key is the concatenation of the big-endian
     *   representation of the x and y coordinates. Both integers always
     *   have the same size as the signing key in octets, i.e.,
     *   32 for P-256 and 48 for P-384, and they are padded with
     *   leading zeroes if necessary. This corresponds to the uncompressed
     *   point encoding as specified in X9.62 without the leading 0x04
     *   header.
     *
     * The caller must provide a sufficiently sized buffer as @p public_key_out
     * setting @p *public_key_size_in_out to the correct buffer size.
     * The required buffer size can be queried by setting @p public_key_out
     * to NULL. In that case @ref n20_error_crypto_insufficient_buffer_size_e
     * is returned and @p *public_key_size_in_out is set to the required buffer
     * size.
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     * - @ref n20_error_crypto_unexpected_null_key_in_e must be returned
     *   if the @p key_in is NULL.
     * - @ref n20_error_crypto_unexpected_null_size_e must be returned if
     *   @p public_key_size_in_out is NULL.
     * - @ref n20_error_crypto_invalid_key_e must be returned
     *   if @p key_in is not of the types @ref n20_crypto_key_type_ed25519_e,
     *   @ref n20_crypto_key_type_secp256r1_e, or
     *   @ref n20_crypto_key_type_secp384r1_e.
     * - @ref n20_error_crypto_insufficient_buffer_size_e if
     *   @p public_key_out is NULL or if @p *public_key_size_in_out indicates
     *   that the given buffer is too small.
     *   If @ref n20_error_crypto_insufficient_buffer_size_e is returned
     *   the implementation must set @p *public_key_size_in_out to the maximum
     *   required buffer size for the signature algorithm requested.
     *
     * @param ctx The crypto context.
     * @param key_in The opaque key handle denoting the key pair of which the public key
     *        shall be extracted.
     * @param public_key_out A buffer to accommodate the encoded public key.
     * @param public_key_size_in_out A size buffer that holds the size of the
     *        given buffer (in) and the size of the required/used public key
     *        buffer (out).
     */
    n20_error_t (*key_get_public_key)(struct n20_crypto_context_s* ctx,
                                      n20_crypto_key_t key_in,
                                      uint8_t* public_key_out,
                                      size_t* public_key_size_in_out);
    /**
     * @brief Destroy a key handle.
     *
     * Destroys a key handle obtained by calling @ref kdf or an implementation
     * specific method to create a key handle.
     *
     * Unless an invalid context is given, this function shall not fail.
     *
     * Passing NULL as @p key_in is explicitly allowed and yield
     * @ref n20_error_ok_e.
     *
     * ## Errors
     * - @ref n20_error_crypto_invalid_context_e must be returned
     *   if ctx is NULL.
     *   Additional mechanisms may be implemented to determine
     *   if the context is valid, but an implementation must
     *   accept an instance if it was created with the implementation
     *   specific factory and not freed.
     *
     * @param ctx The crypto context.
     * @param key_in The key handle to be freed.
     */
    n20_error_t (*key_free)(struct n20_crypto_context_s* ctx, n20_crypto_key_t key_in);
};

/**
 * @brief Alias for @ref n20_crypto_context_s.
 */
typedef struct n20_crypto_context_s n20_crypto_context_t;

#ifdef __cplusplus
}
#endif
