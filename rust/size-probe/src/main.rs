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

//! Bare-metal size probe: links the full nat20 FFI surface so that
//! `cargo size`/`llvm-size` reports the real .text cost of the library.
//! This binary is never executed.
//!
//! Without features it hands the library a crypto table of functions that
//! do nothing, so the size is the library's own and the panic-never check
//! covers exactly the library; with `soft-crypto` it uses the built-in
//! software backend.

#![no_std]
#![no_main]

use core::ffi::c_void;

use nat20_rust::{
    n20r_ctx_cleanup, n20r_ctx_init, n20r_device_id_public_key, n20r_encode_cbor_map,
    n20r_handover_validate, n20r_issue_device_id_key, n20r_issue_next_stage_cwt,
    n20r_set_authority_hash, n20r_set_code_descriptor, n20r_set_code_hash,
    n20r_set_configuration_hash, n20r_set_mode, N20rCborMapEntry, N20rCrypto, N20rKey, N20rSlice,
    N20R_CBOR_BYTES, N20R_DICE_CTX_SIZE,
};

/// Storage for the DICE context, aligned as `n20r_ctx_init` requires.
#[repr(C, align(8))]
struct CtxStorage([u8; N20R_DICE_CTX_SIZE]);

/// The handover region, aligned as the handover header requires.
#[repr(C, align(4))]
struct HandoverStorage([u8; 1024]);

static mut HANDOVER: HandoverStorage = HandoverStorage([0; 1024]);
static mut MEASUREMENT: [u8; 64] = [0; 64];
static mut CTX: CtxStorage = CtxStorage([0; N20R_DICE_CTX_SIZE]);

#[cfg(not(feature = "soft-crypto"))]
mod backend {
    use super::*;

    // A backend that computes nothing, through volatile accesses so that
    // the library's calls are not optimized away.
    unsafe extern "C" fn sha512(_: *mut c_void, p: *const N20rSlice, n: usize, d: *mut u8) -> i32 {
        core::ptr::write_volatile(d, n as u8);
        core::ptr::read_volatile(p.cast::<u8>()) as i32
    }
    unsafe extern "C" fn kdf(
        _: *mut c_void,
        k: N20rKey,
        _: u32,
        _: *const N20rSlice,
        _: usize,
        o: *mut N20rKey,
    ) -> i32 {
        core::ptr::write_volatile(o, k);
        0
    }
    unsafe extern "C" fn public_key(_: *mut c_void, _: N20rKey, o: *mut u8) -> i32 {
        core::ptr::write_volatile(o, 0);
        0
    }
    unsafe extern "C" fn sign(
        _: *mut c_void,
        _: N20rKey,
        m: *const u8,
        _: usize,
        o: *mut u8,
    ) -> i32 {
        core::ptr::write_volatile(o, core::ptr::read_volatile(m));
        0
    }
    unsafe extern "C" fn key_free(_: *mut c_void, k: N20rKey) {
        core::ptr::read_volatile(&k);
    }

    /// The table and the root CDI handle.
    pub fn crypto() -> (N20rCrypto, N20rKey) {
        (
            N20rCrypto {
                ctx: core::ptr::null_mut(),
                sha512: Some(sha512),
                kdf: Some(kdf),
                public_key: Some(public_key),
                sign: Some(sign),
                key_free: Some(key_free),
            },
            1 as N20rKey,
        )
    }
}

#[cfg(feature = "soft-crypto")]
mod backend {
    use super::*;
    use nat20_rust::soft::{
        n20r_soft_crypto_import_cdi, n20r_soft_crypto_init, N20R_SOFT_CRYPTO_SIZE,
    };

    #[repr(C, align(8))]
    struct SoftStorage([u8; N20R_SOFT_CRYPTO_SIZE]);
    static mut SOFT: SoftStorage = SoftStorage([0; N20R_SOFT_CRYPTO_SIZE]);
    static mut CDI: [u8; 32] = [0; 32];

    /// The table and the root CDI handle.
    pub fn crypto() -> (N20rCrypto, N20rKey) {
        let mut table = core::mem::MaybeUninit::<N20rCrypto>::uninit();
        let mut cdi: N20rKey = core::ptr::null_mut();
        unsafe {
            let soft = core::ptr::addr_of_mut!(SOFT) as *mut u8;
            let _ = n20r_soft_crypto_init(soft, N20R_SOFT_CRYPTO_SIZE, table.as_mut_ptr());
            let _ =
                n20r_soft_crypto_import_cdi(soft, core::ptr::addr_of!(CDI) as *const u8, &mut cdi);
            (table.assume_init(), cdi)
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let (crypto, cdi) = backend::crypto();
    unsafe {
        let handover = core::ptr::addr_of_mut!(HANDOVER) as *mut u8;
        let meas = core::ptr::addr_of!(MEASUREMENT) as *const u8;

        let mut used = 0usize;
        let _ = n20r_handover_validate(handover, 1024, &mut used);
        let _ = n20r_issue_device_id_key(&crypto, cdi, handover, 1024);

        let ctx = core::ptr::addr_of_mut!(CTX) as *mut u8;
        let _ = n20r_ctx_init(ctx, N20R_DICE_CTX_SIZE);
        let _ = n20r_set_code_hash(ctx, meas, 64, None);
        let _ = n20r_set_configuration_hash(ctx, meas, 64, None);
        let _ = n20r_set_authority_hash(ctx, meas, 64, None);
        let _ = n20r_set_mode(ctx, 1);
        let entry = N20rCborMapEntry {
            key: 1,
            uint_value: 0,
            data: meas,
            size: 64,
            kind: N20R_CBOR_BYTES,
        };
        let mut desc = [0u8; 80];
        let mut desc_size = desc.len();
        let _ = n20r_encode_cbor_map(&entry, 1, desc.as_mut_ptr(), &mut desc_size);
        let _ = n20r_set_code_descriptor(ctx, desc.as_ptr(), desc_size, None);
        let mut next_cdi: N20rKey = core::ptr::null_mut();
        let _ = n20r_issue_next_stage_cwt(&crypto, ctx, cdi, &mut next_cdi, handover, 1024);
        let _ = n20r_ctx_cleanup(ctx);

        let mut pk = [0u8; 32];
        let _ = n20r_device_id_public_key(&crypto, cdi, pk.as_mut_ptr());

        // Keep results observable so nothing is optimized away.
        core::ptr::read_volatile(handover);
        core::ptr::read_volatile(&next_cdi);
        core::ptr::read_volatile(pk.as_ptr());
        core::ptr::read_volatile(&used);
    }
    loop {
        core::hint::spin_loop();
    }
}
