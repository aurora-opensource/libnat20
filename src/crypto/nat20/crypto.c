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

#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/crypto/nat20/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "nat20/error.h"
#include "nat20/types.h"

union n20_digest_state_u {
    n20_sha384_sha512_state_t sha_512;
    n20_sha224_sha256_state_t sha_256;
};

typedef union n20_digest_state_u n20_digest_state_t;

#define N20_SHA2_224_OCTETS 28
#define N20_SHA2_256_OCTETS 32
#define N20_SHA2_384_OCTETS 48
#define N20_SHA2_512_OCTETS 64

static size_t digest_enum_to_size(n20_crypto_digest_algorithm_t alg_in) {
    switch (alg_in) {
        case n20_crypto_digest_algorithm_sha2_224_e:
            return N20_SHA2_224_OCTETS;
        case n20_crypto_digest_algorithm_sha2_256_e:
            return N20_SHA2_256_OCTETS;
        case n20_crypto_digest_algorithm_sha2_384_e:
            return N20_SHA2_384_OCTETS;
        case n20_crypto_digest_algorithm_sha2_512_e:
            return N20_SHA2_512_OCTETS;
        default:
            return 0;
    }
}

static void* (*volatile volatile_memset)(void*, int, size_t) = memset;

static void n20_memzero(void* dst, size_t n) { volatile_memset(dst, 0, n); }

static inline n20_error_t n20_digest_internal(n20_digest_state_t* state,
                                              n20_crypto_digest_algorithm_t alg_in,
                                              n20_crypto_gather_list_t const* msg_in,
                                              size_t msg_count,
                                              uint8_t* digest_out,
                                              size_t* digest_size_in_out) {
    switch (alg_in) {
        case n20_crypto_digest_algorithm_sha2_224_e:
            state->sha_256 = n20_sha224_init();
            break;
        case n20_crypto_digest_algorithm_sha2_256_e:
            state->sha_256 = n20_sha256_init();
            break;
        case n20_crypto_digest_algorithm_sha2_384_e:
            state->sha_512 = n20_sha384_init();
            break;
        case n20_crypto_digest_algorithm_sha2_512_e:
            state->sha_512 = n20_sha512_init();
            break;
        default:
            return n20_error_crypto_unknown_algorithm_e;
    }

    if (digest_size_in_out == NULL) {
        return n20_error_crypto_unexpected_null_size_e;
    }

    size_t digest_size = digest_enum_to_size(alg_in);

    // If the provided buffer size is too small or no buffer was provided
    // set the required buffer size and return
    // n20_error_crypto_insufficient_buffer_size_e.
    if (digest_size > *digest_size_in_out || digest_out == NULL) {
        *digest_size_in_out = digest_size;
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    // It can be tolerated above if no message was given.
    // The caller might just query the required buffer size.
    // But from here a message must be provided.
    if (msg_in == NULL) {
        return n20_error_crypto_unexpected_null_data_e;
    }

    if (msg_in->count != 0 && msg_in->list == NULL) {
        return n20_error_crypto_unexpected_null_list_e;
    }

    for (size_t j = 0; j < msg_count; ++j) {
        for (size_t i = 0; i < msg_in[j].count; ++i) {
            if (msg_in[j].list[i].size == 0) continue;
            if (msg_in[j].list[i].buffer == NULL) {
                return n20_error_crypto_unexpected_null_slice_e;
            }

            if (alg_in == n20_crypto_digest_algorithm_sha2_224_e ||
                alg_in == n20_crypto_digest_algorithm_sha2_256_e) {
                // n20_sha224_update is an alias for n20_sha256_update.
                // The algorithms only differ during initialization and finalization.
                n20_sha256_update(&state->sha_256, msg_in[j].list[i]);
            } else {
                // n20_sha384_update is an alias for n20_sha512_update.
                // The algorithms only differ during initialization and finalization.
                n20_sha512_update(&state->sha_512, msg_in[j].list[i]);
            }
        }
    }

    switch (alg_in) {
        case n20_crypto_digest_algorithm_sha2_224_e:
            n20_sha224_finalize(&state->sha_256, digest_out);
            break;
        case n20_crypto_digest_algorithm_sha2_256_e:
            n20_sha256_finalize(&state->sha_256, digest_out);
            break;
        case n20_crypto_digest_algorithm_sha2_384_e:
            n20_sha384_finalize(&state->sha_512, digest_out);
            break;
        case n20_crypto_digest_algorithm_sha2_512_e:
            n20_sha512_finalize(&state->sha_512, digest_out);
            break;
        default:
            return n20_error_crypto_unknown_algorithm_e;
    }

    *digest_size_in_out = digest_size;

    return n20_error_ok_e;
}

n20_error_t n20_digest(n20_crypto_digest_context_t* ctx,
                       n20_crypto_digest_algorithm_t alg_in,
                       n20_crypto_gather_list_t const* msg_in,
                       size_t msg_count,
                       uint8_t* digest_out,
                       size_t* digest_size_in_out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    n20_digest_state_t state = {0};

    n20_error_t err =
        n20_digest_internal(&state, alg_in, msg_in, msg_count, digest_out, digest_size_in_out);
    n20_memzero(&state, sizeof(state));

    return err;
}

#define MAX_BLOCK_SIZE 128  // Maximum block size for HMAC

static inline n20_error_t n20_hmac_internal(n20_crypto_digest_context_t* ctx,
                                            uint8_t* K,
                                            uint8_t* inner_digest,
                                            n20_crypto_digest_algorithm_t alg_in,
                                            n20_slice_t const key,
                                            n20_crypto_gather_list_t const* msg_in,
                                            uint8_t* mac_out,
                                            size_t* mac_size_in_out) {
    size_t block_size = MAX_BLOCK_SIZE;
    size_t digest_size = digest_enum_to_size(alg_in);
    if (digest_size == 0) {
        return n20_error_crypto_unknown_algorithm_e;
    }
    switch (alg_in) {
        case n20_crypto_digest_algorithm_sha2_224_e:
        case n20_crypto_digest_algorithm_sha2_256_e:
            block_size = N20_SHA2_256_OCTETS * 2;
            break;
        case n20_crypto_digest_algorithm_sha2_384_e:
        case n20_crypto_digest_algorithm_sha2_512_e:
            block_size = N20_SHA2_512_OCTETS * 2;
            break;
        default:
            return n20_error_crypto_unknown_algorithm_e;
    }

    if (mac_size_in_out == NULL) {
        return n20_error_crypto_unexpected_null_size_e;
    }

    if (key.buffer == NULL && key.size != 0) {
        return n20_error_crypto_unexpected_null_slice_key_e;
    }

    if (mac_out == NULL || *mac_size_in_out < digest_size) {
        *mac_size_in_out = digest_size;
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    n20_error_t rc;

    if (key.size > block_size) {
        n20_crypto_gather_list_t key_list = {
            1,
            &key,
        };
        // If the key is longer than the block size, hash it first.
        rc = ctx->digest(ctx, alg_in, &key_list, 1, K, &digest_size);
        if (rc != n20_error_ok_e) {
            return rc;  // Return error if digest computation fails
        }
    } else {
        // If the key is shorter than the block size, pad it with zeros
        memcpy(K, key.buffer, key.size);
    }

    for (size_t i = 0; i < block_size; ++i) {
        K[i] ^= 0x36;  // Inner padding
    }

    n20_slice_t pad = {
        block_size,
        K,
    };

    if (msg_in == NULL) {
        return n20_error_crypto_unexpected_null_data_e;
    }

    if (msg_in->count != 0 && msg_in->list == NULL) {
        return n20_error_crypto_unexpected_null_list_e;
    }

    n20_crypto_gather_list_t msg[2] = {
        {
            1,
            &pad,
        },
        *msg_in,
    };

    rc = ctx->digest(ctx, alg_in, msg, 2, inner_digest,
                     &digest_size);  // Compute the inner digest
    if (rc != n20_error_ok_e) {
        return rc;  // Return error if digest computation fails
    }

    for (size_t i = 0; i < block_size; ++i) {
        // Undo inner padding (0x36) and apply outer padding (0x5c).
        // 0x36 XOR 0x5c = 0x6a.
        K[i] ^= 0x6a;
    }

    n20_slice_t inner_digest_slice = {
        digest_size,
        inner_digest,
    };

    msg[1].count = 1;
    msg[1].list = &inner_digest_slice;  // Set the inner digest as the second message

    return ctx->digest(ctx, alg_in, msg, 2, mac_out,
                       mac_size_in_out);  // Compute the final HMAC
}

n20_error_t n20_hmac(n20_crypto_digest_context_t* ctx,
                     n20_crypto_digest_algorithm_t alg_in,
                     n20_slice_t const key,
                     n20_crypto_gather_list_t const* msg_in,
                     uint8_t* mac_out,
                     size_t* mac_size_in_out) {

    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    uint8_t K[MAX_BLOCK_SIZE] = {0};
    uint8_t inner_digest[N20_SHA2_512_OCTETS] = {0};  // Buffer for inner digest

    n20_error_t rc =
        n20_hmac_internal(ctx, K, inner_digest, alg_in, key, msg_in, mac_out, mac_size_in_out);

    n20_memzero(K, sizeof(K));                        // Clear the key buffer
    n20_memzero(inner_digest, sizeof(inner_digest));  // Clear the inner digest buffer

    return rc;
}

n20_error_t n20_hkdf(n20_crypto_digest_context_t* ctx,
                     n20_crypto_digest_algorithm_t alg_in,
                     n20_slice_t const ikm,
                     n20_slice_t const salt,
                     n20_slice_t const info,
                     size_t key_octets,
                     uint8_t* out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    size_t prk_size = digest_enum_to_size(alg_in);
    if (prk_size == 0) {
        return n20_error_crypto_unknown_algorithm_e;  // Unknown algorithm
    }

    if (ikm.buffer == NULL && ikm.size != 0) {
        return n20_error_crypto_unexpected_null_slice_ikm_e;
    }

    if (salt.buffer == NULL && salt.size != 0) {
        return n20_error_crypto_unexpected_null_slice_salt_e;
    }

    if (info.buffer == NULL && info.size != 0) {
        return n20_error_crypto_unexpected_null_slice_info_e;
    }

    uint8_t prk[N20_SHA2_512_OCTETS] = {0};  // Buffer for the pseudorandom key

    n20_error_t rc = ctx->hkdf_extract(ctx, alg_in, ikm, salt, prk, &prk_size);
    if (rc != n20_error_ok_e) {
        n20_memzero(prk, sizeof(prk));  // Clear the pseudorandom key buffer
        return rc;
    }

    rc = ctx->hkdf_expand(ctx, alg_in, (n20_slice_t){prk_size, prk}, info, key_octets, out);
    n20_memzero(prk, sizeof(prk));  // Clear the pseudorandom key buffer
    return rc;
}

n20_error_t n20_hkdf_extract(n20_crypto_digest_context_t* ctx,
                             n20_crypto_digest_algorithm_t alg_in,
                             n20_slice_t ikm,
                             n20_slice_t const salt,
                             uint8_t* prk,
                             size_t* prk_size_in_out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }
    size_t digest_size = digest_enum_to_size(alg_in);
    if (digest_size == 0) {
        return n20_error_crypto_unknown_algorithm_e;  // Unknown algorithm
    }

    if (ikm.buffer == NULL && ikm.size != 0) {
        return n20_error_crypto_unexpected_null_slice_ikm_e;
    }

    if (salt.buffer == NULL && salt.size != 0) {
        return n20_error_crypto_unexpected_null_slice_salt_e;
    }

    if (prk_size_in_out == NULL) {
        return n20_error_crypto_unexpected_null_size_e;
    }

    if (*prk_size_in_out < digest_size || prk == NULL) {
        *prk_size_in_out = digest_size;
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    n20_crypto_gather_list_t ikm_list = {
        1,
        &ikm,
    };

    return ctx->hmac(ctx, alg_in, salt, &ikm_list, prk, prk_size_in_out);
}

n20_error_t n20_hkdf_expand(n20_crypto_digest_context_t* ctx,
                            n20_crypto_digest_algorithm_t alg_in,
                            n20_slice_t const prk,
                            n20_slice_t const info,
                            size_t key_octets,
                            uint8_t* out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    size_t digest_size = digest_enum_to_size(alg_in);
    if (digest_size == 0) {
        return n20_error_crypto_unknown_algorithm_e;  // Unknown algorithm
    }

    if (prk.buffer == NULL && prk.size != 0) {
        return n20_error_crypto_unexpected_null_slice_prk_e;
    }

    if (info.buffer == NULL && info.size != 0) {
        return n20_error_crypto_unexpected_null_slice_info_e;
    }

    if (key_octets == 0) {
        return n20_error_ok_e;  // No key to expand, return success
    }

    if (out == NULL) {
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    uint8_t i = 1;

    n20_slice_t hmac_inputs[3] = {{
                                      0,
                                      NULL,
                                  },
                                  {
                                      info.size,
                                      info.buffer,
                                  },
                                  {1, &i}};

    n20_crypto_gather_list_t hmac_input = {3, &hmac_inputs[0]};

    // As long as the output buffer has enough space,
    // write the key bits directly to the output buffer.
    while (key_octets >= digest_size) {
        ctx->hmac(ctx, alg_in, prk, &hmac_input, out, &digest_size);
        // The output written becomes part of the next round input.
        // So store its pointer in the gather list
        // before moving the write position forward.
        hmac_inputs[0].size = digest_size;
        hmac_inputs[0].buffer = out;
        key_octets -= digest_size;
        out += digest_size;
        ++i;
    }

    // If the remaining key octets are less than the digest size,
    // the HMAC output has to be written into a large enough buffer
    // before copying the remaining bytes to the output buffer.
    // The post condition of the loop above is that key_octets is less than digest_size.
    // So the next block only needs to run if key_octets > 0.
    if (key_octets > 0) {
        uint8_t T[N20_SHA2_512_OCTETS] = {0};  // Buffer for the output
        n20_error_t rc = ctx->hmac(ctx, alg_in, prk, &hmac_input, T, &digest_size);
        if (rc != n20_error_ok_e) {
            n20_memzero(T, sizeof(T));
            return rc;  // Return error if HMAC computation fails
        }
        // Copy the remaining bytes to the output buffer
        memcpy(out, T, key_octets);
        n20_memzero(T, sizeof(T));
    }

    return n20_error_ok_e;
}

static n20_crypto_digest_context_t n20_crypto_digest_context = {
    .digest = n20_digest,
    .hmac = n20_hmac,
    .hkdf = n20_hkdf,
    .hkdf_extract = n20_hkdf_extract,
    .hkdf_expand = n20_hkdf_expand,
};

n20_error_t n20_crypto_nat20_open(n20_crypto_digest_context_t** ctx_out) {
    if (ctx_out == NULL) {
        return n20_error_crypto_unexpected_null_e;
    }

    *ctx_out = &n20_crypto_digest_context;
    return n20_error_ok_e;
}

n20_error_t n20_crypto_nat20_close(n20_crypto_digest_context_t* ctx_out) {
    if (ctx_out == NULL) {
        return n20_error_crypto_unexpected_null_e;
    }

    return n20_error_ok_e;
}
