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

#include <asm/byteorder.h>
#include <crypto/akcipher.h>
#include <crypto/ecdh.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/crypto/nat20/rfc6979.h>
#include <nat20/error.h>
#include <nat20crypto.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#include <crypto/ecc.h>
#else
#include <crypto/internal/ecc.h>
#endif

static n20_error_t nat20crypto_digest(n20_crypto_digest_context_t* ctx,
                                      n20_crypto_digest_algorithm_t alg_in,
                                      n20_crypto_gather_list_t const* msg_in,
                                      size_t msg_count,
                                      uint8_t* digest_out,
                                      size_t* digest_size_in_out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    if (digest_size_in_out == NULL) {
        return n20_error_crypto_unexpected_null_size_e;
    }

    char const* digest_name = NULL;

    switch (alg_in) {
        case n20_crypto_digest_algorithm_sha2_224_e:
            digest_name = "sha224";
            break;
        case n20_crypto_digest_algorithm_sha2_256_e:
            digest_name = "sha256";
            break;
        case n20_crypto_digest_algorithm_sha2_384_e:
            digest_name = "sha384";
            break;
        case n20_crypto_digest_algorithm_sha2_512_e:
            digest_name = "sha512";
            break;
        default:
            return n20_error_crypto_unknown_algorithm_e;
    }

    struct crypto_shash* md_tfm = crypto_alloc_shash(digest_name, 0, 0);
    if (IS_ERR(md_tfm)) {
        printk(KERN_ERR "Failed to allocate hash context: %ld\n", PTR_ERR(md_tfm));
        return n20_error_crypto_no_resources_e;
    }

    size_t digest_size = crypto_shash_digestsize(md_tfm);

    if (*digest_size_in_out < digest_size || digest_out == NULL) {
        *digest_size_in_out = digest_size;
        crypto_free_shash(md_tfm);
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    if (msg_in == NULL) {
        crypto_free_shash(md_tfm);
        return n20_error_crypto_unexpected_null_data_e;
    }

    struct shash_desc* md_ctx =
        kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(md_tfm), GFP_KERNEL);
    if (md_ctx == NULL) {
        crypto_free_shash(md_tfm);
        printk(KERN_ERR "Failed to allocate hash descriptor.\n");
        return n20_error_crypto_no_resources_e;
    }
    md_ctx->tfm = md_tfm;

    if (0 > crypto_shash_init(md_ctx)) {
        kfree(md_ctx);
        crypto_free_shash(md_tfm);
        return n20_error_crypto_implementation_specific_e;
    }

    for (size_t list_index = 0; list_index < msg_count; ++list_index) {
        if (msg_in[list_index].count == 0) continue;
        if (msg_in[list_index].list == NULL) {
            kfree(md_ctx);
            crypto_free_shash(md_tfm);
            return n20_error_crypto_unexpected_null_list_e;
        }
        for (size_t slice_index = 0; slice_index < msg_in[list_index].count; ++slice_index) {
            if (msg_in[list_index].list[slice_index].size == 0) continue;
            if (msg_in[list_index].list[slice_index].buffer == NULL) {
                kfree(md_ctx);
                crypto_free_shash(md_tfm);
                return n20_error_crypto_unexpected_null_slice_e;
            }
            if (0 > crypto_shash_update(md_ctx,
                                        msg_in[list_index].list[slice_index].buffer,
                                        msg_in[list_index].list[slice_index].size)) {
                kfree(md_ctx);
                crypto_free_shash(md_tfm);
                return n20_error_crypto_implementation_specific_e;
            }
        }
    }

    if (0 > crypto_shash_final(md_ctx, digest_out)) {
        kfree(md_ctx);
        crypto_free_shash(md_tfm);
        return n20_error_crypto_implementation_specific_e;
    }

    *digest_size_in_out = digest_size;
    kfree(md_ctx);
    crypto_free_shash(md_tfm);
    return n20_error_ok_e;
}

struct nat20crypto_key {
    n20_crypto_key_type_t type;
    union {
        /* This variant is used for ECC keys. */
        struct {
            size_t ndigits;
            uint64_t digits[6];
        };
        /* This variant is used for CDIs. */
        struct {
            uint8_t bits[32];
        };
    };
};

typedef struct nat20crypto_key nat20crypto_key_t;

static nat20crypto_key_t* nat20crypto_key_alloc(n20_crypto_key_type_t type) {
    nat20crypto_key_t* key = (nat20crypto_key_t*)kmalloc(sizeof(nat20crypto_key_t), GFP_KERNEL);
    if (key == NULL) {
        return NULL;
    }
    key->type = type;
    return key;
}

static void nat20crypto_key_destroy(nat20crypto_key_t* key) {
    if (key != NULL) {
        memzero_explicit(key, sizeof(nat20crypto_key_t));
        kfree(key);
    }
}

static n20_error_t nat20crypto_kdf(struct n20_crypto_context_s* ctx,
                                   n20_crypto_key_t key_in,
                                   n20_crypto_key_type_t key_type_in,
                                   n20_crypto_gather_list_t const* context_in,
                                   n20_crypto_key_t* key_out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    if (key_in == NULL) {
        return n20_error_crypto_unexpected_null_key_in_e;
    }

    nat20crypto_key_t* cdi_key = (nat20crypto_key_t*)key_in;
    if (cdi_key->type != n20_crypto_key_type_cdi_e) {
        return n20_error_crypto_invalid_key_e;
    }

    if (key_out == NULL) {
        return n20_error_crypto_unexpected_null_key_out_e;
    }

    if (context_in == NULL) {
        return n20_error_crypto_unexpected_null_data_e;
    }

    if (context_in->count != 0 && context_in->list == NULL) {
        return n20_error_crypto_unexpected_null_list_e;
    }

    /* Compute the total length of the context and copy it
     * into a consecutive buffer. */
    size_t context_size = 0;
    for (size_t i = 0; i < context_in->count; ++i) {
        if (context_in->list[i].size != 0 && context_in->list[i].buffer == NULL) {
            return n20_error_crypto_unexpected_null_slice_e;
        }
        context_size += context_in->list[i].size;
    }
    uint8_t* context_buffer = (uint8_t*)kmalloc(context_size, GFP_KERNEL);
    if (context_buffer == NULL) {
        return n20_error_crypto_no_resources_e;
    }
    size_t copied = 0;
    for (size_t i = 0; i < context_in->count; ++i) {
        memcpy(context_buffer + copied, context_in->list[i].buffer, context_in->list[i].size);
        copied += context_in->list[i].size;
    }

    uint8_t derived[32];

    n20_error_t rc;
    rc = ctx->digest_ctx.hkdf_expand(&ctx->digest_ctx,
                                     n20_crypto_digest_algorithm_sha2_512_e,
                                     (n20_slice_t){
                                         .size = sizeof(cdi_key->bits),
                                         .buffer = cdi_key->bits,
                                     },
                                     (n20_slice_t){
                                         .size = context_size,
                                         .buffer = context_buffer,
                                     },
                                     32,
                                     derived);
    kfree(context_buffer);

    if (rc != n20_error_ok_e) {
        goto out;
    }

    switch (key_type_in) {
        case n20_crypto_key_type_cdi_e: {
            nat20crypto_key_t* new_cdi_key = nat20crypto_key_alloc(n20_crypto_key_type_cdi_e);
            if (new_cdi_key == NULL) {
                rc = n20_error_crypto_no_resources_e;
                goto out;
            }
            memcpy(new_cdi_key->bits, derived, 32);
            *key_out = new_cdi_key;
            rc = n20_error_ok_e;
            goto out;
        }
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            n20_slice_t x_octets = {
                .size = 32,
                .buffer = derived,
            };
            nat20crypto_key_t* new_ecc_key = nat20crypto_key_alloc(key_type_in);
            if (new_ecc_key == NULL) {
                rc = n20_error_crypto_no_resources_e;
                goto out;
            }

            n20_bn_t k_bn;
            k_bn.word_count = key_type_in == n20_crypto_key_type_secp256r1_e ? 8 : 12;
            k_bn.words = (uint32_t*)new_ecc_key->digits;
            new_ecc_key->ndigits = k_bn.word_count / 2;
            rc = n20_rfc6979_k_generation(&ctx->digest_ctx,
                                          n20_crypto_digest_algorithm_sha2_512_e,
                                          key_type_in,
                                          &x_octets,
                                          NULL,
                                          &k_bn,
                                          0);
            if (rc != n20_error_ok_e) {
                nat20crypto_key_destroy(new_ecc_key);
                goto out;
            }
            *key_out = new_ecc_key;
            rc = n20_error_ok_e;
            goto out;
        }

        case n20_crypto_key_type_ed25519_e:
        /* fallthrough */
        default:
            /* Unsupported key type for KDF. */
            break;
    }

    rc = n20_error_crypto_invalid_key_type_e;
out:
    memzero_explicit(derived, sizeof(derived));
    return rc;
}

/* The kernel's ECC library does not export a general scalar-point
 * multiplication function. However, ecc_make_pub_key computes
 * k * G (the generator point multiplication) which is exactly
 * what ECDSA signing needs for computing the nonce point. The
 * output is byte-swapped relative to the internal VLI representation,
 * so callers must ecc_swap_digits the x-coordinate back. */
static int nat20crypto_mult_g(unsigned int curve_id,
                              size_t ndigits,
                              uint64_t* k,
                              uint64_t* pubkey_xy) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
    int ret = 0;
    /* Before version 6.10.0 ecc_make_pub_key swapped the bytes
     * of the key, so we have to swap them back before calling
     * ecc_make_pub_key. */
    uint64_t privkey[6] = {0};
    ecc_swap_digits(k, privkey, ndigits);
    ret = ecc_make_pub_key(curve_id, ndigits, privkey, pubkey_xy);
    memzero_explicit(privkey, sizeof(privkey));
    return ret;
#else
    return ecc_make_pub_key(curve_id, ndigits, k, pubkey_xy);
#endif
}

static n20_error_t nat20crypto_sign(struct n20_crypto_context_s* ctx,
                                    n20_crypto_key_t key_in,
                                    n20_crypto_gather_list_t const* msg_in,
                                    uint8_t* signature_out,
                                    size_t* signature_size_in_out) {

    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    if (key_in == NULL) {
        return n20_error_crypto_unexpected_null_key_in_e;
    }

    if (signature_size_in_out == NULL) {
        return n20_error_crypto_unexpected_null_size_e;
    }

    nat20crypto_key_t* priv_key = (nat20crypto_key_t*)key_in;
    int err;

    size_t ndigits = 0;
    struct ecc_curve const* curve = NULL;
    n20_crypto_digest_algorithm_t digest_algorithm;
    unsigned int curve_id = 0;
    switch (priv_key->type) {
        case n20_crypto_key_type_secp256r1_e:
            ndigits = 4;
            curve = ecc_get_curve(ECC_CURVE_NIST_P256);
            curve_id = ECC_CURVE_NIST_P256;
            digest_algorithm = n20_crypto_digest_algorithm_sha2_256_e;
            break;
        case n20_crypto_key_type_secp384r1_e:
            ndigits = 6;
            curve = ecc_get_curve(ECC_CURVE_NIST_P384);
            curve_id = ECC_CURVE_NIST_P384;
            digest_algorithm = n20_crypto_digest_algorithm_sha2_384_e;
            break;
        default:
            return n20_error_crypto_invalid_key_e;
    }
    size_t expected_signature_size = ndigits * 16;

    if (*signature_size_in_out < expected_signature_size || signature_out == NULL) {
        *signature_size_in_out = expected_signature_size;
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    if (curve == NULL) {
        return n20_error_crypto_invalid_key_e;
    }

    if (msg_in == NULL) {
        return n20_error_crypto_unexpected_null_data_e;
    }

    if (msg_in->count != 0 && msg_in->list == NULL) {
        return n20_error_crypto_unexpected_null_list_e;
    }

    n20_error_t result = n20_error_crypto_implementation_specific_e;
    uint64_t z[6] = {0};
    uint64_t k[6] = {0};
    uint64_t k_inv[6] = {0};
    uint64_t rs[12] = {0};
    uint64_t* r = &rs[0];
    uint64_t* s = &rs[ndigits];
    uint64_t* xy = rs;            // Reuse rs buffer for point multiplication
    uint64_t* key_bytes = k_inv;  // Reuse k_inv buffer for key bytes

    size_t digest_size = 6 * 8;

    /* Digest the message into s (temporary). */
    n20_error_t n20_err = ctx->digest_ctx.digest(
        &ctx->digest_ctx, digest_algorithm, msg_in, 1, (uint8_t*)s, &digest_size);
    if (n20_err != n20_error_ok_e) {
        printk(KERN_ERR "Failed to digest message: %d\n", n20_err);
        result = n20_err;
        goto cleanup;
    }

    n20_slice_t z_slice = {
        .size = digest_size,
        .buffer = (uint8_t*)s,
    };

    n20_crypto_gather_list_t gather_list = {
        .count = 1,
        .list = &z_slice,
    };

    /* Convert digest to little-endian big number for modular arithmetic.
     * z is stable across loop iterations. */
    ecc_swap_digits(s, z, ndigits);

    /* k_bn uses 32bit words instead of 64bit words.
     * But the in memory representation is compatible
     * on little-endian systems. */
#ifndef __LITTLE_ENDIAN
#error "Big-endian systems are not supported"
#endif
    n20_bn_t k_bn = {
        .word_count = ndigits * 2,
        .words = (uint32_t*)k,
    };

    /* On the first iteration, s still holds the big-endian digest as needed by gather_list.
     * It is clobbered during the loop body and must be restored between iterations.
     * Since z is stable, s can be restored by swapping digits back from z. */
    for (unsigned int skip = 0; skip < 8; ++skip, ecc_swap_digits(z, s, ndigits)) {
        /* key_bytes aliases k_inv which is clobbered below.
         * Recompute on each iteration. */
        ecc_swap_digits(priv_key->digits, key_bytes, ndigits);

        n20_slice_t key_slice = {
            .size = ndigits * 8,
            .buffer = (uint8_t*)key_bytes,
        };

        /* Generate k (deterministic per RFC 6979; skip selects the candidate). */
        n20_err = n20_rfc6979_k_generation(&ctx->digest_ctx,
                                           digest_algorithm,
                                           priv_key->type,
                                           &key_slice,
                                           &gather_list,
                                           &k_bn,
                                           skip);
        if (n20_err != n20_error_ok_e) {
            result = n20_err;
            goto cleanup;
        }

        /* Mod Invert k */
        vli_mod_inv(k_inv, k, curve->n, ndigits);

        /* Compute x1 = (k * G).x */
        err = nat20crypto_mult_g(curve_id, ndigits, k, xy);
        if (err) {
            printk(KERN_ERR "Failed to compute nonce point: %d\n", err);
            result = n20_error_crypto_implementation_specific_e;
            goto cleanup;
        }
        ecc_swap_digits(xy, s, ndigits);
        for (size_t i = 0; i < ndigits; i++) {
            r[i] = s[i];
        }

        /* r = x1 mod n */
        if (vli_cmp(r, curve->n, ndigits) >= 0) {
            vli_sub(r, r, curve->n, ndigits);
        }

        if (vli_is_zero(r, ndigits)) continue;

        /* s = k^-1 (H(m) + d_A * r) mod n */

        /* s = d_A * r mod n */
        vli_mod_mult_slow(s, priv_key->digits, r, curve->n, ndigits);

        /* Modular add z (H(m)) and s: s = (s + z) mod n.
         * Compute n - z into k (scratch). */
        if (vli_cmp(z, curve->n, ndigits) >= 0) {
            /* If z >= n we need to modular reduce z before negating,
             * otherwise the subtraction below will underflow. */
            vli_sub(k, z, curve->n, ndigits);
            vli_sub(k, curve->n, k, ndigits);
        } else {
            vli_sub(k, curve->n, z, ndigits);
        };

        if (vli_cmp(k, s, ndigits) <= 0) {
            /* If s >= n - z, we can compute s + z mod n as s - (n - z) <=> s - k. */
            vli_sub(s, s, k, ndigits);
        } else {
            /* If s fits into k (i.e. n - z), we can just add s and z. */
            uint64_t carry = 0;
            for (size_t i = 0; i < ndigits; i++) {
                carry = __builtin_add_overflow(s[i], carry, &s[i]);
                carry |= __builtin_add_overflow(s[i], z[i], &s[i]);
            }
        }

        vli_mod_mult_slow(s, k_inv, s, curve->n, ndigits);

        if (vli_is_zero(s, ndigits)) continue;

        ecc_swap_digits(r, (uint64_t*)signature_out, ndigits);
        ecc_swap_digits(s, ((uint64_t*)signature_out) + ndigits, ndigits);

        *signature_size_in_out = expected_signature_size;
        result = n20_error_ok_e;
        goto cleanup;
    }

cleanup:
    memzero_explicit(z, sizeof(z));
    memzero_explicit(k, sizeof(k));
    memzero_explicit(k_inv, sizeof(k_inv));
    memzero_explicit(rs, sizeof(rs));
    return result;
}

static n20_error_t nat20crypto_key_get_public_key(struct n20_crypto_context_s* ctx,
                                                  n20_crypto_key_t key_in,
                                                  uint8_t* public_key_out,
                                                  size_t* public_key_size_in_out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    if (key_in == NULL) {
        return n20_error_crypto_unexpected_null_key_in_e;
    }

    if (public_key_size_in_out == NULL) {
        return n20_error_crypto_unexpected_null_size_e;
    }

    nat20crypto_key_t* priv_key = (nat20crypto_key_t*)key_in;

    /* Determine public key size based on curve type */
    size_t public_key_size = 0;
    unsigned int curve_id = 0;

    switch (priv_key->type) {
        case n20_crypto_key_type_secp256r1_e:
            public_key_size = 64; /* 32 bytes x + 32 bytes y */
            curve_id = ECC_CURVE_NIST_P256;
            break;
        case n20_crypto_key_type_secp384r1_e:
            public_key_size = 96; /* 48 bytes x + 48 bytes y */
            curve_id = ECC_CURVE_NIST_P384;
            break;
        case n20_crypto_key_type_ed25519_e:
        case n20_crypto_key_type_cdi_e:
        default:
            return n20_error_crypto_invalid_key_e;
    }

    if (*public_key_size_in_out < public_key_size || public_key_out == NULL) {
        *public_key_size_in_out = public_key_size;
        return n20_error_crypto_insufficient_buffer_size_e;
    }

    *public_key_size_in_out = public_key_size;

    int err = nat20crypto_mult_g(
        curve_id, priv_key->ndigits, priv_key->digits, (uint64_t*)public_key_out);

    if (err) {
        printk(KERN_ERR "Failed to generate public key: %d\n", err);
        return n20_error_crypto_implementation_specific_e;
    }

    return n20_error_ok_e;
}

static n20_error_t nat20crypto_key_free(struct n20_crypto_context_s* ctx, n20_crypto_key_t key_in) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    if (key_in == NULL) {
        return n20_error_ok_e;
    }

    nat20crypto_key_t* priv_key = (nat20crypto_key_t*)key_in;
    nat20crypto_key_destroy(priv_key);

    return n20_error_ok_e;
}

static n20_crypto_context_t linux_crypto_ctx = {
    {nat20crypto_digest, n20_hmac, n20_hkdf, n20_hkdf_extract, n20_hkdf_expand},
    nat20crypto_kdf,
    nat20crypto_sign,
    nat20crypto_key_get_public_key,
    nat20crypto_key_free};

n20_error_t nat20crypto_open(n20_crypto_context_t** ctx) {
    if (ctx == NULL) {
        return n20_error_crypto_unexpected_null_e;
    }

    *ctx = &linux_crypto_ctx;

    return n20_error_ok_e;
}
EXPORT_SYMBOL(nat20crypto_open);

n20_error_t nat20crypto_close(n20_crypto_context_t* ctx) {
    if (ctx == NULL) {
        return n20_error_crypto_unexpected_null_e;
    }

    return n20_error_ok_e;
}
EXPORT_SYMBOL(nat20crypto_close);

n20_error_t nat20crypto_make_secret(struct n20_crypto_context_s* ctx,
                                    n20_slice_t const* secret_in,
                                    n20_crypto_key_t* key_out) {
    if (ctx == NULL) {
        return n20_error_crypto_invalid_context_e;
    }

    if (secret_in == NULL || secret_in->buffer == NULL || secret_in->size == 0) {
        return n20_error_crypto_unexpected_null_data_e;
    }

    if (key_out == NULL) {
        return n20_error_crypto_unexpected_null_key_out_e;
    }

    nat20crypto_key_t* new_key = nat20crypto_key_alloc(n20_crypto_key_type_cdi_e);
    if (!new_key) {
        return n20_error_crypto_no_resources_e;
    }
    memzero_explicit(new_key->bits, sizeof(new_key->bits));

    memcpy(new_key->bits,
           secret_in->buffer,
           sizeof(new_key->bits) < secret_in->size ? sizeof(new_key->bits) : secret_in->size);

    *key_out = new_key;
    return n20_error_ok_e;
}
EXPORT_SYMBOL(nat20crypto_make_secret);

static int __init nat20crypto_init(void) {
    printk(KERN_INFO "nat20crypto - init\n");
    // Currently, there is nothing to initialize in this module.
    return 0;
}

static void __exit nat20crypto_exit(void) {
    printk(KERN_INFO "nat20crypto - cleanup\n");
    // Currently, there is nothing to clean up in this module.
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Aurora Operations, Inc.");
MODULE_DESCRIPTION("NAT20 Crypto Module using Linux Kernel Crypto API");

module_init(nat20crypto_init);
module_exit(nat20crypto_exit);
