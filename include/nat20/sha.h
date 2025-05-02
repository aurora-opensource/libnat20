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

/**
 * @file sha.h
 * @brief Implementation of the SHA-2 family of cryptographic hash functions.
 *
 * This file provides functions for computing SHA-224, SHA-256, SHA-384, and SHA-512 hashes.
 * These implementations are based on the NIST FIPS 180-4 specification.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#pragma once

#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup SHA SHA-2 Hash Functions
 * @brief Functions for computing SHA-224, SHA-256, SHA-384, and SHA-512 hashes.
 *
 * These functions implement the SHA-2 family of cryptographic hash functions as defined in
 * the NIST FIPS 180-4 specification. The implementation deviates from the specification
 * for SHA-384 and SHA-512 in that the maximum supported message size is limited to 2^64 bits.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 *
 * # Usage Example
 * The following example demonstrates how to compute a SHA-256 hash using the provided functions.
 * @code{.c}
 *   n20_sha224_sha256_state_t state = n20_sha256_init();
 *   uint8_t data[] = "Hello, World!";
 *   n20_sha256_update(&state, data, sizeof(data) - 1);
 *   uint8_t digest[32];
 *   n20_sha256_finalize(&state, digest);
 *   // The digest now contains the SHA-256 hash of the input data.
 * @endcode
 *
 * @{
 */

/**
 * @brief State structure for SHA-224 and SHA-256 computations.
 */
typedef struct n20_sha224_sha256_state_s {
    uint32_t W[16]; /**< Working buffer. */
    uint32_t H[8];  /**< Hash state. */
    uint32_t fill;  /**< Current fill level of the working buffer. */
    uint64_t total; /**< Total number of processed bytes. */
} n20_sha224_sha256_state_t;

/**
 * @brief Initializes the state for SHA-224 computation.
 *
 * Initializes the SHA-224 state with the appropriate initial hash values.
 * (See NIST FIPS 180-4, Section 5.3.2)
 *
 * The state is fully self contained and, if placed on the stack, does not
 * need to be freed.
 *
 * The state is ready to accept input data for hashing.
 *
 * @return The initialized state.
 */
extern n20_sha224_sha256_state_t n20_sha224_init(void);

/**
 * @brief Updates the SHA-224 state with new data.
 *
 * This function processes the input data and updates the internal state.
 * It can be called multiple times with different data chunks of varying sizes.
 *
 * To produce correct results, the @p state must be initialized with
 * @ref n20_sha224_init before the first call to this function.
 * To compute the final digest, the state must be finalized with
 * @ref n20_sha224_finalize after all data has been processed.
 *
 * The total size of the input data must not exceed 2^64 bits (2^61 bytes).
 *
 * If @p state or @p data is NULL, the function does nothing.
 *
 * @param state The SHA-224 state.
 * @param data The input data.
 * @param data_size The size of the input data in bytes.
 */
extern void n20_sha224_update(n20_sha224_sha256_state_t *state, n20_slice_t const data);

/**
 * @brief Finalizes the SHA-224 computation and produces the hash digest.
 *
 * This function processes any remaining data in the internal state, applies
 * appropriate padding and produces the final hash digest.
 *
 * The output digest is written to the provided buffer. The pointer @p digest
 * must be dereferenceable and the size of the buffer must be at least
 * 28 bytes (SHA-224 digest size).
 *
 * If @p state is NULL, the function does nothing.
 *
 * @param state The SHA-224 state.
 * @param digest The output buffer for the hash digest (28 bytes).
 */
extern void n20_sha224_finalize(n20_sha224_sha256_state_t *state, uint8_t digest[28]);

/**
 * @brief Initializes the state for SHA-256 computation.
 *
 * Initializes the SHA-256 state with the appropriate initial hash values.
 * (See NIST FIPS 180-4, Section 5.3.3)
 *
 * The state is fully self contained and, if placed on the stack, does not
 * need to be freed.
 *
 * The state is ready to accept input data for hashing.
 *
 * @return The initialized state.
 */
extern n20_sha224_sha256_state_t n20_sha256_init(void);

/**
 * @brief Updates the SHA-256 state with new data.
 *
 * This function processes the input data and updates the internal state.
 * It can be called multiple times with different data chunks of varying sizes.
 *
 * To produce correct results, the @p state must be initialized with
 * @ref n20_sha256_init before the first call to this function.
 * To compute the final digest, the state must be finalized with
 * @ref n20_sha256_finalize after all data has been processed.
 *
 * The total size of the input data must not exceed 2^64 bits (2^61 bytes).
 *
 * If @p state or @p data is NULL, the function does nothing.
 *
 * @param state The SHA-256 state.
 * @param data The input data.
 * @param data_size The size of the input data in bytes.
 */
extern void n20_sha256_update(n20_sha224_sha256_state_t *state, n20_slice_t const data);

/**
 * @brief Finalizes the SHA-256 computation and produces the hash digest.
 *
 * This function processes any remaining data in the internal state, applies
 * appropriate padding and produces the final hash digest.
 *
 * The output digest is written to the provided buffer. The pointer @p digest
 * must be dereferenceable and the size of the buffer must be at least
 * 32 bytes (SHA-256 digest size).
 *
 * If @p state is NULL, the function does nothing.
 *
 * @param state The SHA-256 state.
 * @param digest The output buffer for the hash digest (32 bytes).
 */
extern void n20_sha256_finalize(n20_sha224_sha256_state_t *state, uint8_t digest[32]);

/**
 * @brief State structure for SHA-384 and SHA-512 computations.
 */
typedef struct n20_sha384_sha512_state_s {
    uint64_t W[16]; /**< Working buffer. */
    uint64_t H[8];  /**< Hash state. */
    uint32_t fill;  /**< Current fill level of the buffer. */
    uint64_t total; /**< Total number of processed bytes. */
} n20_sha384_sha512_state_t;

/**
 * @brief Initializes the state for SHA-384 computation.
 *
 * Initializes the SHA-384 state with the appropriate initial hash values.
 * (See NIST FIPS 180-4, Section 5.3.4)
 *
 * The state is fully self contained and, if placed on the stack, does not
 * need to be freed.
 *
 * The state is ready to accept input data for hashing.
 *
 * @return The initialized state.
 * @note The implementation deviates from the NIST FIPS 180-4 specification in that the
 *       maximum supported message size is limited to 2^64 bits.
 */
extern n20_sha384_sha512_state_t n20_sha384_init(void);

/**
 * @brief Updates the SHA-384 state with new data.
 *
 * This function processes the input data and updates the internal state.
 * It can be called multiple times with different data chunks of varying sizes.
 *
 * To produce correct results, the @p state must be initialized with
 * @ref n20_sha384_init before the first call to this function.
 * To compute the final digest, the state must be finalized with
 * @ref n20_sha384_finalize after all data has been processed.
 *
 * If @p state or @p data is NULL, the function does nothing.
 *
 * The total size of the input data must not exceed 2^64 bits (2^61 bytes).
 * @note The implementation deviates from the NIST FIPS 180-4 specification in that the
 *       maximum supported message size is limited to 2^64 bits.
 *
 * @param state The SHA-384 state.
 * @param data The input data.
 * @param data_size The size of the input data in bytes.
 */
extern void n20_sha384_update(n20_sha384_sha512_state_t *state, n20_slice_t const data);

/**
 * @brief Finalizes the SHA-384 computation and produces the hash digest.
 *
 * This function processes any remaining data in the internal state, applies
 * appropriate padding and produces the final hash digest.
 *
 * The output digest is written to the provided buffer. The pointer @p digest
 * must be dereferenceable and the size of the buffer must be at least
 * 48 bytes (SHA-384 digest size).
 *
 * If @p state is NULL, the function does nothing.
 *
 * @param state The SHA-384 state.
 * @param digest The output buffer for the hash digest (48 bytes).
 */
extern void n20_sha384_finalize(n20_sha384_sha512_state_t *state, uint8_t digest[48]);

/**
 * @brief Initializes the state for SHA-512 computation.
 *
 * Initializes the SHA-512 state with the appropriate initial hash values.
 * (See NIST FIPS 180-4, Section 5.3.5)
 *
 * The state is fully self contained and, if placed on the stack, does not
 * need to be freed.
 *
 * The state is ready to accept input data for hashing.
 *
 * @return The initialized state.
 * @note The implementation deviates from the NIST FIPS 180-4 specification in that the
 *       maximum supported message size is limited to 2^64 bits.
 */
extern n20_sha384_sha512_state_t n20_sha512_init(void);

/**
 * @brief Updates the SHA-512 state with new data.
 *
 * This function processes the input data and updates the internal state.
 * It can be called multiple times with different data chunks of varying sizes.
 *
 * To produce correct results, the @p state must be initialized with
 * @ref n20_sha512_init before the first call to this function.
 * To compute the final digest, the state must be finalized with
 * @ref n20_sha512_finalize after all data has been processed.
 *
 * If @p state or @p data is NULL, the function does nothing.
 *
 * The total size of the input data must not exceed 2^64 bits (2^61 bytes).
 * @note The implementation deviates from the NIST FIPS 180-4 specification in that the
 *       maximum supported message size is limited to 2^64 bits.
 *
 * @param state The SHA-512 state.
 * @param data The input data.
 * @param data_size The size of the input data in bytes.
 */
extern void n20_sha512_update(n20_sha384_sha512_state_t *state, n20_slice_t const data);

/**
 * @brief Finalizes the SHA-512 computation and produces the hash digest.
 *
 * This function processes any remaining data in the internal state, applies
 * appropriate padding and produces the final hash digest.
 *
 * The output digest is written to the provided buffer. The pointer @p digest
 * must be dereferenceable and the size of the buffer must be at least
 * 64 bytes (SHA-512 digest size).
 *
 * If @p state is NULL, the function does nothing.
 *
 * @param state The SHA-512 state.
 * @param digest The output buffer for the hash digest (64 bytes).
 */
extern void n20_sha512_finalize(n20_sha384_sha512_state_t *state, uint8_t digest[64]);

/** @} */ /* End of SHA group */

#ifdef __cplusplus
}
#endif
