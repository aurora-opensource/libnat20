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

#include "n20r_monocypher.h"

#include <monocypher-ed25519.h>
#include <monocypher.h>

/* Bytes of stack zeroed below an operation's frame: more than the deepest
 * operation reaches (signing with verification, about 2 KiB on armv7
 * Thumb-2; measure on your target). */
#ifndef N20R_MONOCYPHER_STACK_WIPE
#define N20R_MONOCYPHER_STACK_WIPE 3072
#endif

#define NOINLINE __attribute__((noinline))

/* Zeroes N20R_MONOCYPHER_STACK_WIPE bytes of stack below the caller's frame,
 * where the operation that just returned ran. The writes are volatile, so
 * the compiler cannot drop them as dead stores. */
static NOINLINE void wipe_stack(void) {
    volatile uint8_t area[N20R_MONOCYPHER_STACK_WIPE];
    for (size_t i = 0; i < sizeof(area); i++) area[i] = 0;
}

/* Zeroes the registers a callee may clobber, which can still hold bytes of
 * a secret. On 32-bit Arm (AAPCS) those are r0-r3 and r12; elsewhere this
 * example clears nothing. */
static inline void wipe_registers(void) {
#if defined(__arm__)
    __asm__ volatile("mov r0, #0\n\tmov r1, #0\n\tmov r2, #0\n\tmov r3, #0\n\tmov r12, #0" ::
                         : "r0", "r1", "r2", "r3", "r12");
#endif
}

/* Runs one operation body, then wipes what it left behind. */
#define WIPED(call)       \
    do {                  \
        int rc_ = (call); \
        wipe_stack();     \
        wipe_registers(); \
        return rc_;       \
    } while (0)

static n20r_monocypher_slot_t *slot(n20r_monocypher_t *state, n20r_key_t key, uint32_t kind) {
    uintptr_t index = (uintptr_t)key - 1;
    if (state == NULL || index >= N20R_MONOCYPHER_KEY_SLOTS) return NULL;
    n20r_monocypher_slot_t *s = &state->slots[index];
    return s->kind == kind + 1 ? s : NULL;
}

static n20r_monocypher_slot_t *free_slot(n20r_monocypher_t *state, n20r_key_t *key) {
    for (uintptr_t i = 0; i < N20R_MONOCYPHER_KEY_SLOTS; i++) {
        if (state->slots[i].kind == 0) {
            *key = (n20r_key_t)(i + 1);
            return &state->slots[i];
        }
    }
    return NULL;
}

static NOINLINE int sha512_body(n20r_slice_t const *parts, size_t count, uint8_t digest[64]) {
    crypto_sha512_ctx ctx;
    crypto_sha512_init(&ctx);
    for (size_t i = 0; i < count; i++) crypto_sha512_update(&ctx, parts[i].data, parts[i].size);
    crypto_sha512_final(&ctx, digest);
    return 0;
}

static int op_sha512(void *ctx, n20r_slice_t const *parts, size_t count, uint8_t digest[64]) {
    (void)ctx;
    if ((parts == NULL && count != 0) || digest == NULL) return 1;
    WIPED(sha512_body(parts, count, digest));
}

/* HKDF-Expand-SHA512 with 32 bytes of output: the first half of
 * T(1) = HMAC-SHA512(prk, info || 0x01). */
static NOINLINE int kdf_body(uint8_t const prk[32],
                             n20r_slice_t const *context,
                             size_t count,
                             uint8_t out[32]) {
    crypto_sha512_hmac_ctx ctx;
    uint8_t block[64];
    uint8_t const counter = 1;
    crypto_sha512_hmac_init(&ctx, prk, 32);
    for (size_t i = 0; i < count; i++)
        crypto_sha512_hmac_update(&ctx, context[i].data, context[i].size);
    crypto_sha512_hmac_update(&ctx, &counter, 1);
    crypto_sha512_hmac_final(&ctx, block); /* also wipes ctx */
    for (size_t i = 0; i < 32; i++) out[i] = block[i];
    crypto_wipe(block, sizeof(block));
    return 0;
}

static int op_kdf(void *ctx,
                  n20r_key_t cdi,
                  uint32_t kind,
                  n20r_slice_t const *context,
                  size_t count,
                  n20r_key_t *key_out) {
    n20r_monocypher_t *state = ctx;
    n20r_monocypher_slot_t const *in = slot(state, cdi, N20R_KEY_CDI);
    n20r_monocypher_slot_t *out;
    n20r_key_t key;
    if (in == NULL || (kind != N20R_KEY_CDI && kind != N20R_KEY_ED25519) || key_out == NULL ||
        (context == NULL && count != 0))
        return 1;
    out = free_slot(state, &key);
    if (out == NULL) return 2;
    out->kind = kind + 1;
    *key_out = key;
    WIPED(kdf_body(in->bytes, context, count, out->bytes));
}

static NOINLINE int public_key_body(uint8_t const seed[32], uint8_t public_key[32]) {
    uint8_t seed_copy[32], secret_key[64];
    for (size_t i = 0; i < 32; i++) seed_copy[i] = seed[i];
    crypto_ed25519_key_pair(secret_key, public_key, seed_copy); /* wipes seed_copy */
    crypto_wipe(secret_key, sizeof(secret_key));
    return 0;
}

static int op_public_key(void *ctx, n20r_key_t key, uint8_t public_key[32]) {
    n20r_monocypher_slot_t const *s = slot(ctx, key, N20R_KEY_ED25519);
    if (s == NULL || public_key == NULL) return 1;
    WIPED(public_key_body(s->bytes, public_key));
}

static NOINLINE int sign_body(uint8_t const seed[32],
                              uint8_t const *message,
                              size_t message_size,
                              uint8_t signature[64]) {
    uint8_t seed_copy[32], secret_key[64], public_key[32], sig[64];
    int rc;
    for (size_t i = 0; i < 32; i++) seed_copy[i] = seed[i];
    crypto_ed25519_key_pair(secret_key, public_key, seed_copy);
    crypto_ed25519_sign(sig, secret_key, message, message_size);
    crypto_wipe(secret_key, sizeof(secret_key));
    /* Released only once it verified: a faulty signature next to a correct
     * one over the same message can give the key away. */
    rc = crypto_ed25519_check(sig, public_key, message, message_size) == 0 ? 0 : 4;
    for (size_t i = 0; i < 64; i++) signature[i] = rc == 0 ? sig[i] : 0;
    crypto_wipe(sig, sizeof(sig));
    return rc;
}

static int op_sign(
    void *ctx, n20r_key_t key, uint8_t const *message, size_t message_size, uint8_t signature[64]) {
    n20r_monocypher_slot_t const *s = slot(ctx, key, N20R_KEY_ED25519);
    if (s == NULL || signature == NULL || (message == NULL && message_size != 0)) return 1;
    WIPED(sign_body(s->bytes, message, message_size, signature));
}

static void op_key_free(void *ctx, n20r_key_t key) {
    n20r_monocypher_t *state = ctx;
    uintptr_t index = (uintptr_t)key - 1;
    if (state == NULL || index >= N20R_MONOCYPHER_KEY_SLOTS) return;
    crypto_wipe(state->slots[index].bytes, 32);
    state->slots[index].kind = 0;
}

void n20r_monocypher_init(n20r_monocypher_t *state, n20r_crypto_t *crypto) {
    crypto_wipe((uint8_t *)state, sizeof(*state));
    crypto->ctx = state;
    crypto->sha512 = op_sha512;
    crypto->kdf = op_kdf;
    crypto->public_key = op_public_key;
    crypto->sign = op_sign;
    crypto->key_free = op_key_free;
}

int n20r_monocypher_import_cdi(n20r_monocypher_t *state, uint8_t const cdi[32], n20r_key_t *key) {
    n20r_monocypher_slot_t *s;
    if (state == NULL || cdi == NULL || key == NULL) return 1;
    s = free_slot(state, key);
    if (s == NULL) return 2;
    for (size_t i = 0; i < 32; i++) s->bytes[i] = cdi[i];
    s->kind = N20R_KEY_CDI + 1;
    return 0;
}

int n20r_monocypher_export_cdi(n20r_monocypher_t *state, n20r_key_t key, uint8_t cdi_out[32]) {
    n20r_monocypher_slot_t const *s = slot(state, key, N20R_KEY_CDI);
    if (s == NULL || cdi_out == NULL) return 1;
    for (size_t i = 0; i < 32; i++) cdi_out[i] = s->bytes[i];
    return 0;
}

int n20r_monocypher_keys_in_use(n20r_monocypher_t const *state) {
    int n = 0;
    for (size_t i = 0; i < N20R_MONOCYPHER_KEY_SLOTS; i++) n += state->slots[i].kind != 0;
    return n;
}

void n20r_monocypher_cleanup(n20r_monocypher_t *state) {
    crypto_wipe((uint8_t *)state, sizeof(*state));
}
