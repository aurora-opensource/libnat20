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

//! Compiles the vendored Monocypher C sources when the `mono-crypto`
//! feature is enabled. The sources live in `third_party/monocypher` next to
//! the crates.

fn main() {
    #[cfg(feature = "mono-crypto")]
    {
        let mono =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../third_party/monocypher");
        let glue = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/crypto/mono_glue.c");

        let mut build = cc::Build::new();
        build
            .file(mono.join("monocypher.c"))
            .file(mono.join("monocypher-ed25519.c"))
            .file(&glue)
            .include(&mono)
            .opt_level_str("s")
            .flag_if_supported("-ffunction-sections")
            .flag_if_supported("-fdata-sections")
            .flag_if_supported("-fno-unwind-tables")
            .flag_if_supported("-fno-asynchronous-unwind-tables");

        let target = std::env::var("TARGET").unwrap_or_default();
        if target.starts_with("armv7a-none-eabi") {
            // Match the Rust code: Thumb-2, soft float, no NEON/VFP.
            // -mno-unaligned-access is load-bearing: firmware may run with
            // SCTLR.A (strict alignment checking) set, and GCC otherwise
            // compiles Monocypher's byte-wise loads into word-sized ldr,
            // which data-aborts on unaligned hash inputs. (The Rust side is
            // unaffected: armv7a-none-eabi is a strict-align target.)
            // What a firmware environment adds, such as a reserved
            // register, comes from CFLAGS_<target> (see firmware/).
            build
                .compiler("arm-none-eabi-gcc")
                .flag("-march=armv7-a")
                .flag("-mthumb")
                .flag("-mfloat-abi=soft")
                .flag("-mno-unaligned-access");
        }
        build.compile("nat20_monocypher");

        println!("cargo:rerun-if-changed={}", mono.display());
        println!("cargo:rerun-if-changed={}", glue.display());
    }
}
