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

#include <nat20/crypto.h>
#include <nat20/crypto/nat20/rfc6979.h>
#include <nat20/error.h>
#include <nat20/types.h>

/**
 * Subtract one big num @p b from another @p a, and stores the result
 * in @p res.
 *
 * It is safe to pass @p res as either or both of the other operands.
 *
 * The function returns true if the result of the operation does not
 * fit into the output or if the second operand is larger than the first.
 * This means that if all operands and the result have the same width,
 * the return value is equivalent to carry. However, if @p a and/or @p b
 * are wider than @p res, a return value of true may also indicate
 * data loss.
 */
static bool n20_bn_sub_overflow(n20_bn_t const* a, n20_bn_t const* b, n20_bn_t* res) {
    uint32_t carry = 0;
    size_t i = 0;
    size_t max_words = a->word_count > b->word_count ? a->word_count : b->word_count;
    max_words = max_words > res->word_count ? max_words : res->word_count;

    for (; i < max_words; ++i) {
        uint32_t res_ = 0;
        if (i < a->word_count) {
            res_ = a->words[i];
        }
        carry = __builtin_sub_overflow(res_, carry, &res_) ? 1 : 0;
        if (i < b->word_count) {
            carry |= __builtin_sub_overflow(res_, b->words[i], &res_) ? 1 : 0;
        }

        if (i < res->word_count) {
            res->words[i] = res_;
        } else if (res_ != 0) {
            /* Result does not fit into output bn. */
            return true;
        }
    }

    return carry;
}

static void n20_slice_to_bn(n20_bn_t* bn, n20_slice_t const* slice) {
    uint32_t octet = slice->size;
    for (size_t i = 0; i < bn->word_count; ++i) {
        bn->words[i] = 0;
        for (int j = 0; j < 4; ++j) {
            bn->words[i] >>= 8;
            if (octet) {
                octet -= 1;
                bn->words[i] |= ((uint32_t)slice->buffer[octet]) << 24;
            }
        }
    }
}

void n20_bn_to_octets(uint8_t* octets, size_t octets_len, n20_bn_t const* bn) {
    for (size_t i = 0; i < octets_len; ++i) {
        size_t word_index = i >> 2;
        size_t byte_index = i & 0x3;
        if (word_index < bn->word_count) {
            octets[octets_len - i - 1] =
                (uint8_t)((bn->words[word_index] >> (8 * byte_index)) & 0xff);
        } else {
            octets[octets_len - i - 1] = 0;
        }
    }
}

static bool n20_bn_is_zero(n20_bn_t* bn) {
    for (size_t i = 0; i < bn->word_count; ++i) {
        if (bn->words[i] != 0) return false;
    }
    return true;
}

static int n20_bn_cmp(n20_bn_t* a, n20_bn_t* b) {
    size_t max_words = a->word_count > b->word_count ? a->word_count : b->word_count;
    int result = 0;
    for (size_t i_ = max_words; i_ > 0; --i_) {
        size_t i = i_ - 1;
        uint32_t aw = i < a->word_count ? a->words[i] : 0;
        uint32_t bw = i < b->word_count ? b->words[i] : 0;
        result += (!result) * ((aw > bw) - (aw < bw));
    }
    return result;
}

uint32_t n20_p256_n_bits[] = {
    0xfc632551,
    0xf3b9cac2,
    0xa7179e84,
    0xbce6faad,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x00000000,
    0xFFFFFFFF,
};

#define N20_P256_N_OCTETS (sizeof(n20_p256_n_bits))
#define N20_P256_N_WORDS (N20_P256_N_OCTETS / sizeof(n20_p256_n_bits[0]))

n20_bn_t n20_p256_n = {
    /* .word_count = */ N20_P256_N_WORDS,
    /* .words = */ n20_p256_n_bits,
};

uint32_t n20_p384_n_bits[] = {
    0xccc52973,
    0xecec196a,
    0x48b0a77a,
    0x581a0db2,
    0xf4372ddf,
    0xc7634d81,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
};

#define N20_P384_N_OCTETS (sizeof(n20_p384_n_bits))
#define N20_P384_N_WORDS (N20_P384_N_OCTETS / sizeof(n20_p384_n_bits[0]))

n20_bn_t n20_p384_n = {
    /* .word_count = */ N20_P384_N_WORDS,
    /* .words = */ n20_p384_n_bits,
};

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

n20_error_t n20_rfc6979_k_generation(n20_crypto_digest_context_t* ctx,
                                     n20_crypto_digest_algorithm_t digest_algorithm,
                                     n20_crypto_key_type_t key_type,
                                     n20_slice_t const* x_octets,
                                     n20_crypto_gather_list_t const* m_octets,
                                     n20_bn_t* k,
                                     size_t skip_candidates) {
    n20_bn_t* q = NULL;
    size_t qlen_octets = 0;
    if (key_type == n20_crypto_key_type_secp256r1_e) {
        q = &n20_p256_n;
        qlen_octets = N20_P256_N_OCTETS;
    } else if (key_type == n20_crypto_key_type_secp384r1_e) {
        q = &n20_p384_n;
        qlen_octets = N20_P384_N_OCTETS;
    } else {
        return n20_error_crypto_invalid_key_type_e;
    }

    n20_error_t err;
    uint8_t h1_bytes[64] = {0};
    size_t h1_size = sizeof(h1_bytes);
    n20_slice_t h1_slice = {
        /* .size = */ 0,
        /* .buffer = */ h1_bytes,
    };

    if (m_octets != NULL) {
        err = ctx->digest(ctx, digest_algorithm, m_octets, 1, h1_bytes, &h1_size);
        if (err != n20_error_ok_e) {
            return err;
        }

        /*
         * The message digest needs to be converted to an octet sequence using
         * bits2octets as specified by RFC 6979. This means that the first qlen
         * bits of the digest are interpreted as a big-endian integer (bits2int)
         * and then modulo reduced by q to get the final value for h1.
         * Finally the result is converted back to an octet sequence.
         *
         * First truncate the digest to qlen bits by taking the first qlen octets.
         */
        h1_slice.size = h1_size < qlen_octets ? h1_size : qlen_octets;
        n20_slice_to_bn(k, &h1_slice);

        /*
         * If the resulting integer is greater than or equal to q, reduce it modulo q.
         */
        if (n20_bn_cmp(k, q) >= 0) {
            if (n20_bn_sub_overflow(k, q, k)) {
                return n20_error_crypto_implementation_specific_e;
            }
        }

        /*
         * Convert the integer back to an octet sequence.
         */
        h1_size = qlen_octets;
        n20_bn_to_octets(h1_bytes, h1_size, k);
        h1_slice.size = h1_size;
    }

    uint8_t V[64];
    uint8_t K[64];
    size_t digest_size = digest_enum_to_size(digest_algorithm);
    if (digest_size == 0 || digest_size > sizeof(V) || digest_size > sizeof(K)) {
        return n20_error_crypto_unknown_algorithm_e;
    }

    /* Initialize V with digest_size octets of value 0x01. */
    memset(V, 0x01, digest_size);
    /* Initialize K with digest_size octets of value 0x00. */
    memset(K, 0x00, digest_size);

    uint8_t internal_octet = 0x00;
    size_t out_size = 64;

    n20_crypto_gather_list_t hmac_msg;
    n20_slice_t hmac_slices[4] = {
        {.size = digest_size, .buffer = V},
        {.size = 1, .buffer = &internal_octet},
        *x_octets,
        h1_slice,
    };
    hmac_msg.list = hmac_slices;

    /*
     * Run two rounds of the pseudorandom number generator to warm up K and V
     * with the key/seed (x_octets) and the optional message (m_octets).
     */
    do {
        /* Update K. */
        hmac_msg.count = 4;

        err = ctx->hmac(ctx,
                        digest_algorithm,
                        (n20_slice_t){.size = digest_size, .buffer = K},
                        &hmac_msg,
                        K,
                        &out_size);
        if (err != n20_error_ok_e) {
            return err;
        }

        /* Update V. */
        hmac_msg.count = 1;

        err = ctx->hmac(ctx,
                        digest_algorithm,
                        (n20_slice_t){.size = digest_size, .buffer = K},
                        &hmac_msg,
                        V,
                        &out_size);
        if (err != n20_error_ok_e) {
            return err;
        }

        internal_octet += 1;
    } while (internal_octet < 2);

    /* Internal octet is reused for updating K below.
     * It remains 0 though and is never incremented again. */
    internal_octet = 0;

    uint8_t T[48];

    /*
     * Loop until k is valid.
     * k is valid if it is not zero and less than the group order.
     */
    while (true) {
        /* Generate T. */
        size_t T_size = 0;
        while (T_size < qlen_octets) {

            /* Update V */
            hmac_msg.count = 1;
            err = ctx->hmac(ctx,
                            digest_algorithm,
                            (n20_slice_t){.size = digest_size, .buffer = K},
                            &hmac_msg,
                            V,
                            &out_size);
            if (err != n20_error_ok_e) {
                return err;
            }

            /* Copy the generated bytes to T. */
            size_t to_copy =
                (T_size + digest_size > qlen_octets) ? (qlen_octets - T_size) : digest_size;
            memcpy(T + T_size, V, to_copy);
            T_size += to_copy;
        }

        n20_slice_t T_slice = {
            .size = qlen_octets,
            .buffer = T,
        };
        n20_slice_to_bn(k, &T_slice);

        if (!n20_bn_is_zero(k) && n20_bn_cmp(k, q) < 0) {
            if (skip_candidates == 0) {
                /* Success! */
                return n20_error_ok_e;
            }
            skip_candidates -= 1;
        }

        /* Update K. */
        hmac_msg.count = 2;
        err = ctx->hmac(ctx,
                        digest_algorithm,
                        (n20_slice_t){.size = digest_size, .buffer = K},
                        &hmac_msg,
                        K,
                        &out_size);
        if (err != n20_error_ok_e) {
            return err;
        }

        /* Update V */
        hmac_msg.count = 1;
        err = ctx->hmac(ctx,
                        digest_algorithm,
                        (n20_slice_t){.size = digest_size, .buffer = K},
                        &hmac_msg,
                        V,
                        &out_size);
        if (err != n20_error_ok_e) {
            return err;
        }
    }
    // Unreachable.
}
