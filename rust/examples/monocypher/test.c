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

/*
 * Host test of the example backend: issues the device-identity and
 * next-stage certificates through libnat20_rust.a with it, and checks
 *  - the next-stage certificate against the one C libnat20 issues for the
 *    same inputs (rust/nat20/tests/differential.rs),
 *  - the whole handover against the library's built-in backend, byte for
 *    byte, when the library was built with soft-crypto,
 *  - that 3 key slots are enough and the library frees every key it
 *    derives, on success and on error.
 *
 * Build and run with `make test` in this directory.
 */

#include <stdio.h>
#include <string.h>

#include "n20r_monocypher.h"

/* rustup's prebuilt host core refers to the unwinder's personality
 * routine; the library is built with panic=abort and never unwinds, so a
 * stand-in that is never called satisfies the reference. Bare-metal
 * builds rebuild core and need no such thing. */
void rust_eh_personality(void);
void rust_eh_personality(void) {}

static char const golden_hex[] =
    "8443a10127a05901aeab01782830353665343332656539336139333937333734366363613431353538643234393830"
    "3932613530660278283764343837653863303333353436653331376666343131613164633830306666326430653566"
    "31633a0047445058401111111111111111111111111111111111111111111111111111111111111111111111111111"
    "11111111111111111111111111111111111111111111111111113a004744514f6e6578742073746167652076312e30"
    "3a00474452584022222222222222222222222222222222222222222222222222222222222222222222222222222222"
    "2222222222222222222222222222222222222222222222223a004744534b626f6f7420636f6e6669673a0047445458"
    "4033333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
    "3333333333333333333333333333333333333a0047445641013a00474457582da50101032704810220062158206f1b"
    "6c111449b06e7a92f410ab4d2112a6cdbe8f86d54c0157ec57fdb224aae53a0047445841203a00474459746578616d"
    "706c652e646963652e70726f66696c6558406995c4b1aa69bbb804d71005106858b326586dc080d68efe247406b3b8"
    "688144a79bffcb662064f1a1a3b663d83f457def52f3d37e746396666441fc8958420f";

static uint8_t const cdi[32] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
};

static int failures;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                              \
        }                                                                            \
    } while (0)

/* Issues both certificates into handover with crypto/root, returning the
 * next CDI handle, or NULL on failure. */
static n20r_key_t issue(n20r_crypto_t const *crypto,
                        n20r_key_t root,
                        uint8_t *handover,
                        size_t size) {
    static uint8_t code_hash[64], config_hash[64], authority_hash[64], hidden[32];
    static uint8_t ctx[N20R_DICE_CTX_SIZE] __attribute__((aligned(8)));
    static char const code_descriptor[] = "next stage v1.0";
    static char const config_descriptor[] = "boot config";
    static char const profile[] = "example.dice.profile";
    n20r_key_t next = NULL;

    memset(code_hash, 0x11, sizeof(code_hash));
    memset(config_hash, 0x22, sizeof(config_hash));
    memset(authority_hash, 0x33, sizeof(authority_hash));
    memset(hidden, 0x44, sizeof(hidden));
    if (n20r_issue_device_id_key(crypto, root, handover, size) != N20R_OK) return NULL;
    if (n20r_ctx_init(ctx, sizeof(ctx)) ||
        n20r_set_code_hash(ctx, code_hash, sizeof(code_hash), NULL) ||
        n20r_set_code_descriptor(
            ctx, (uint8_t const *)code_descriptor, sizeof(code_descriptor) - 1, NULL) ||
        n20r_set_configuration_hash(ctx, config_hash, sizeof(config_hash), NULL) ||
        n20r_set_configuration_descriptor(
            ctx, (uint8_t const *)config_descriptor, sizeof(config_descriptor) - 1, NULL) ||
        n20r_set_authority_hash(ctx, authority_hash, sizeof(authority_hash), NULL) ||
        n20r_set_profile_name(ctx, (uint8_t const *)profile, sizeof(profile) - 1, NULL) ||
        n20r_set_hidden(ctx, hidden, sizeof(hidden), NULL) || n20r_set_mode(ctx, 1))
        return NULL;
    if (n20r_issue_next_stage_cwt(crypto, ctx, root, &next, handover, size) != N20R_OK) next = NULL;
    n20r_ctx_cleanup(ctx);
    return next;
}

/* The last len bytes of the handover's entries, if they are a COSE_Sign1
 * entry of that length (tag 0xd2 in front): where the next-stage
 * certificate must be. */
static uint8_t const *last_entry(uint8_t const *handover, size_t len) {
    uint32_t terminator;
    memcpy(&terminator, handover + 12, 4);
    if (terminator < 17 + len || handover[terminator - len - 1] != 0xd2) return NULL;
    return handover + terminator - len;
}

int main(void) {
    static n20r_monocypher_t state;
    static uint8_t handover[2048] __attribute__((aligned(8)));
    static uint8_t small[64] __attribute__((aligned(8)));
    uint8_t golden[sizeof(golden_hex) / 2];
    n20r_crypto_t crypto;
    n20r_key_t root, next, unchanged = (n20r_key_t)0x5a5a;
    uint8_t const *cert;

    for (size_t i = 0; i < sizeof(golden); i++) sscanf(golden_hex + 2 * i, "%2hhx", &golden[i]);

    n20r_monocypher_init(&state, &crypto);
    CHECK(n20r_monocypher_import_cdi(&state, cdi, &root) == 0);
    next = issue(&crypto, root, handover, sizeof(handover));
    CHECK(next != NULL);
    CHECK(n20r_monocypher_keys_in_use(&state) == 2);
    cert = last_entry(handover, sizeof(golden));
    CHECK(cert != NULL && memcmp(cert, golden, sizeof(golden)) == 0);
    crypto.key_free(crypto.ctx, next);
    CHECK(n20r_monocypher_keys_in_use(&state) == 1);

    /* Fails after the next CDI is derived: nothing handed out, nothing kept. */
    next = unchanged;
    CHECK(n20r_issue_next_stage_cwt(&crypto, NULL, root, &next, small, sizeof(small)) != N20R_OK);
    CHECK(next == unchanged);
    CHECK(n20r_monocypher_keys_in_use(&state) == 1);

#ifdef WITH_SOFT_CRYPTO
    {
        static uint8_t soft[N20R_SOFT_CRYPTO_SIZE] __attribute__((aligned(8)));
        static uint8_t reference[2048] __attribute__((aligned(8)));
        n20r_crypto_t soft_crypto;
        n20r_key_t soft_root, soft_next;
        uint8_t a[32], b[32];
        CHECK(n20r_soft_crypto_init(soft, sizeof(soft), &soft_crypto) == N20R_OK);
        CHECK(n20r_soft_crypto_import_cdi(soft, cdi, &soft_root) == N20R_OK);
        next = issue(&crypto, root, handover, sizeof(handover));
        soft_next = issue(&soft_crypto, soft_root, reference, sizeof(reference));
        CHECK(next != NULL && soft_next != NULL);
        CHECK(memcmp(handover, reference, sizeof(handover)) == 0);
        CHECK(n20r_monocypher_export_cdi(&state, next, a) == 0);
        CHECK(n20r_soft_crypto_export_cdi(soft, soft_next, b) == N20R_OK);
        CHECK(memcmp(a, b, 32) == 0);
        n20r_soft_crypto_cleanup(soft);
        crypto.key_free(crypto.ctx, next);
    }
#endif

    n20r_monocypher_cleanup(&state);
    puts(failures ? "FAIL" : "PASS");
    return failures != 0;
}
