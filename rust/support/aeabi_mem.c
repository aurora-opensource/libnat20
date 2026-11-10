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
 * ARM RTABI memory helpers for direct-rustc builds.
 *
 * LLVM lowers memory intrinsics to the __aeabi_mem* family on ARM EABI
 * targets ("Run-time ABI for the ARM Architecture", section 4.3). In
 * cargo builds the compiler_builtins crate provides them; direct-rustc
 * builds use an empty compiler_builtins stub (the intrinsics are expected
 * from the environment), and libgcc does not define this family. These
 * are thin wrappers over the platform's mem functions; unused ones are
 * dropped by --gc-sections.
 *
 * Note the RTABI argument order for memset: (dest, size, value) — unlike
 * ISO memset(dest, value, size). The 4/8 variants only add alignment
 * guarantees; delegating to the unaligned-safe platform functions is
 * always correct.
 */

#include <stddef.h>

void *memcpy(void *dest, void const *src, size_t n);
void *memmove(void *dest, void const *src, size_t n);
void *memset(void *dest, int c, size_t n);

/* __aeabi_memcpy and __aeabi_memset are NOT defined here: firmware that
 * builds C for ARM EABI typically provides those two already (as an EABI
 * compatibility shim). Only the variants such environments lack follow. */
void __aeabi_memcpy4(void *dest, void const *src, size_t n) { memcpy(dest, src, n); }
void __aeabi_memcpy8(void *dest, void const *src, size_t n) { memcpy(dest, src, n); }

void __aeabi_memmove(void *dest, void const *src, size_t n) { memmove(dest, src, n); }
void __aeabi_memmove4(void *dest, void const *src, size_t n) { memmove(dest, src, n); }
void __aeabi_memmove8(void *dest, void const *src, size_t n) { memmove(dest, src, n); }

void __aeabi_memset4(void *dest, size_t n, int c) { memset(dest, c, n); }
void __aeabi_memset8(void *dest, size_t n, int c) { memset(dest, c, n); }

void __aeabi_memclr(void *dest, size_t n) { memset(dest, 0, n); }
void __aeabi_memclr4(void *dest, size_t n) { memset(dest, 0, n); }
void __aeabi_memclr8(void *dest, size_t n) { memset(dest, 0, n); }
