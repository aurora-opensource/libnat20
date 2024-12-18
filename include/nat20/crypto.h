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
#pragma once

#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum n20_crypto_error_s {
    n20_crypto_error_ok_e,
    n20_crypto_error_unexpected_null_e,
    n20_crypto_error_not_implemented_e,
    n20_crypto_error_incompatible_algorithm_e,
    n20_crypto_error_unkown_algorithm_e,
    n20_crypto_error_missing_context_e,
    n20_crypto_error_invalid_key_e,
    n20_crypto_error_no_memory_e,
    n20_crypto_error_insufficient_buffer_size_e,
    n20_crypto_error_implementation_specific_e,
    n20_crypto_error_invalid_context_e,
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

typedef struct n20_crypto_buffer_s {
    size_t size;
    uint8_t* buffer;
} n20_crypto_buffer_t;

typedef struct n20_crypto_gather_list_s {
    size_t count;
    n20_crypto_buffer_t* list;
} n20_crypto_gather_list_t;

typedef struct n20_crypto_context_s {
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
    n20_crypto_error_t (*key_get_public_key)(struct n20_crypto_context_s* ctx,
                                             n20_crypto_key_t key_in,
                                             uint8_t* public_key_out,
                                             size_t* public_key_size_out);
    n20_crypto_error_t (*key_free)(struct n20_crypto_context_s* ctx, n20_crypto_key_t key_in);
} n20_crypto_context_t;

#ifdef __cplusplus
}
#endif
