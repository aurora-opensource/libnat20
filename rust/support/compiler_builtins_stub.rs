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

//! Empty `compiler_builtins` stand-in for direct-rustc builds (no cargo).
//!
//! rustc injects `compiler_builtins` as an implicit dependency of every
//! crate. Cargo builds provide the real crate; a firmware build that invokes
//! rustc directly compiles this stub instead (the same technique the Linux
//! kernel uses) because the environment already provides the intrinsics:
//! `__aeabi_*` from libgcc or its own runtime, and mem* from the platform.
//!
//! `#![no_builtins]` keeps the compiler from turning any code here back
//! into intrinsic calls. Compiling this file requires RUSTC_BOOTSTRAP=1
//! (the `compiler_builtins` attribute is perma-unstable).

#![feature(compiler_builtins)]
#![compiler_builtins]
#![no_builtins]
#![no_std]
