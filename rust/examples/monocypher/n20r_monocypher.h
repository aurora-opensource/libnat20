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
 * An example crypto backend for libnat20_rust.a: n20r_crypto_t over
 * Monocypher (third_party/monocypher), in C, without dynamic allocation.
 *
 * It holds N20R_MONOCYPHER_KEY_SLOTS keys, the 3 the library needs at most
 * (nat20_rust.h, "Key slots"), and keeps the secrets contract: each
 * operation runs in a function of its own, after which the stack it reached
 * and the scratch registers are zeroed, and a freed key is wiped. Signatures
 * are verified before they are released.
 *
 * Nothing in libnat20 depends on this file; it shows what an integrator's
 * backend looks like.
 */

#ifndef N20R_MONOCYPHER_H
#define N20R_MONOCYPHER_H

#include "nat20_rust.h"

#ifdef __cplusplus
extern "C" {
#endif

#define N20R_MONOCYPHER_KEY_SLOTS 3

/** A key slot: a CDI or an Ed25519 seed. */
typedef struct n20r_monocypher_slot {
    uint32_t kind; /* N20R_KEY_* + 1, or 0 when free */
    uint8_t bytes[32];
} n20r_monocypher_slot_t;

/** The backend's state; the caller provides the storage. */
typedef struct n20r_monocypher {
    n20r_monocypher_slot_t slots[N20R_MONOCYPHER_KEY_SLOTS];
} n20r_monocypher_t;

/** Initialises state and fills *crypto with the backend's table. */
void n20r_monocypher_init(n20r_monocypher_t *state, n20r_crypto_t *crypto);

/** Copies a 32-byte CDI into a free slot and writes its handle to *key.
 *  Returns 0 on success. */
int n20r_monocypher_import_cdi(n20r_monocypher_t *state, uint8_t const cdi[32], n20r_key_t *key);

/** Writes the CDI key holds to cdi_out, which is the caller's to wipe.
 *  Returns 0 on success. */
int n20r_monocypher_export_cdi(n20r_monocypher_t *state, n20r_key_t key, uint8_t cdi_out[32]);

/** The number of slots that hold a key. */
int n20r_monocypher_keys_in_use(n20r_monocypher_t const *state);

/** Wipes every key. */
void n20r_monocypher_cleanup(n20r_monocypher_t *state);

#ifdef __cplusplus
}
#endif

#endif /* N20R_MONOCYPHER_H */
