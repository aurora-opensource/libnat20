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
 * Stack probe: runs each secret-handling entry point of nat20_rust.h on a
 * stack of its own, painted beforehand, and reports for each
 *
 *   depth    bytes of stack the call touched (deepest byte not paint),
 *   residue  depth of the deepest byte left neither paint nor zero, and
 *   leaks    derived secrets (probe_secrets.h) still on the stack, as any
 *            8 contiguous bytes of one.
 *
 * Residue is the real check: it also catches what no list of secrets can,
 * such as SHA-512 compression state left from an HMAC keyed with a CDI.
 * Only the frames of the probe and of the entry point itself, above the
 * scrubbed region, may hold anything (RESIDUE_LIMIT). Exits 0 if every call
 * stays within it and leaks nothing.
 */

#include <stddef.h>
#include <stdint.h>

#include "nat20_rust.h"
#include "probe_secrets.h"

#define PAINT 0xa5
/* Leak search granularity: shorter windows would hit by chance. */
#define WINDOW 8
/* The thunk's and the entry point's own frames: arguments, saved registers. */
#define RESIDUE_LIMIT 256

void probe_puts(char const *s);
void probe_exit(int status) __attribute__((noreturn));
int probe_call_on_stack(int (*fn)(void), void *stack_top);
extern uint8_t __probe_stack_bottom[], __probe_stack_top[];

/* Freestanding: the library expects these from its environment. */
void *memcpy(void *dest, void const *src, size_t n) {
    uint8_t *d = dest;
    uint8_t const *s = src;

    while (n--) *d++ = *s++;
    return dest;
}

void *memmove(void *dest, void const *src, size_t n) {
    uint8_t *d = dest;
    uint8_t const *s = src;

    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        while (n--) d[n] = s[n];
    }
    return dest;
}

void *memset(void *dest, int c, size_t n) {
    uint8_t *d = dest;

    while (n--) *d++ = (uint8_t)c;
    return dest;
}

int memcmp(void const *a, void const *b, size_t n) {
    uint8_t const *x = a, *y = b;

    for (; n; n--, x++, y++)
        if (*x != *y) return *x - *y;
    return 0;
}

int bcmp(void const *a, void const *b, size_t n) { return memcmp(a, b, n); }

void __aeabi_memcpy(void *dest, void const *src, size_t n) { memcpy(dest, src, n); }

void __aeabi_memset(void *dest, size_t n, int c) { memset(dest, c, n); }

static void put_dec(unsigned long v) {
    char buf[12];
    char *p = buf + sizeof(buf) - 1;

    *p = '\0';
    do {
        *--p = '0' + v % 10;
        v /= 10;
    } while (v);
    probe_puts(p);
}

/* The inputs of tools/gen_vectors.py, which gen_secrets.py derives from. */
static uint8_t const cdi[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static uint8_t code_hash[64], config_descriptor[64], authority_hash[64];
static uint8_t hidden[32];

static uint8_t ctx[N20R_DICE_CTX_SIZE] __attribute__((aligned(8)));
static uint8_t handover[2048] __attribute__((aligned(8)));
static uint8_t next_cdi[32];
static uint8_t public_key[32];

static int call_public_key(void) { return n20r_device_id_public_key(cdi, public_key); }

static int call_device_id(void) {
    return n20r_issue_device_id_cwt(cdi, NULL, 0, handover, sizeof(handover));
}

static int call_next_stage(void) {
    return n20r_issue_next_stage_cwt(ctx, cdi, next_cdi, handover, sizeof(handover));
}

static int leaks(void) {
    size_t span = __probe_stack_top - __probe_stack_bottom;
    int found = 0;

    for (size_t s = 0; s < sizeof(secrets) / sizeof(secrets[0]); s++) {
        for (size_t w = 0; w + WINDOW <= 32; w += WINDOW / 2) {
            uint8_t const *needle = secrets[s].bytes + w;
            size_t i;

            for (i = 0; i + WINDOW <= span; i++)
                if (!memcmp(__probe_stack_bottom + i, needle, WINDOW)) break;
            if (i + WINDOW <= span) {
                probe_puts("    leak: ");
                probe_puts(secrets[s].name);
                probe_puts(" at depth ");
                put_dec(span - i);
                probe_puts("\n");
                found = 1;
                break;
            }
        }
    }
    return found;
}

static int run(char const *name, int (*fn)(void)) {
    uint8_t *bottom = __probe_stack_bottom;
    size_t span = __probe_stack_top - bottom;
    size_t depth = 0, residue = 0;
    int rc;

    memset(bottom, PAINT, span);
    rc = probe_call_on_stack(fn, __probe_stack_top);

    for (size_t i = 0; i < span; i++) {
        if (bottom[i] != PAINT && !depth) depth = span - i;
        if (bottom[i] != PAINT && bottom[i] != 0) {
            residue = span - i;
            break;
        }
    }
    probe_puts(name);
    probe_puts(": rc ");
    put_dec(rc);
    probe_puts(", depth ");
    put_dec(depth);
    probe_puts(", residue ");
    put_dec(residue);
    probe_puts("\n");
    if (residue > RESIDUE_LIMIT) probe_puts("    residue beyond the entry point's own frame\n");
    return leaks() || rc != N20R_OK || residue > RESIDUE_LIMIT;
}

int main(void) {
    int failed = 0;

    memset(code_hash, 0xc0, sizeof(code_hash));
    memset(config_descriptor, 0xc1, sizeof(config_descriptor));
    memset(authority_hash, 0xc2, sizeof(authority_hash));
    memset(hidden, 0xc3, sizeof(hidden));
    if (n20r_ctx_init(ctx, sizeof(ctx)) ||
        n20r_set_code_hash(ctx, code_hash, sizeof(code_hash), NULL) ||
        n20r_set_configuration_descriptor(
            ctx, config_descriptor, sizeof(config_descriptor), NULL) ||
        n20r_set_authority_hash(ctx, authority_hash, sizeof(authority_hash), NULL) ||
        n20r_set_hidden(ctx, hidden, sizeof(hidden), NULL) || n20r_set_mode(ctx, 1)) {
        probe_puts("stack-probe: context setup failed\n");
        probe_exit(1);
    }

    failed |= run("n20r_device_id_public_key", call_public_key);
    failed |= run("n20r_issue_device_id_cwt", call_device_id);
    failed |= run("n20r_issue_next_stage_cwt", call_next_stage);
    /* Searching for the wrong secrets would find nothing, and pass. */
    if (memcmp(next_cdi, secrets[1].bytes, sizeof(next_cdi))) {
        probe_puts("stack-probe: next CDI differs from probe_secrets.h\n");
        failed = 1;
    }
    probe_puts(failed ? "stack-probe: FAIL\n" : "stack-probe: PASS\n");
    return failed;
}
