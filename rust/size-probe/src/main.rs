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

#![no_std]
#![no_main]

use nat20_rust::{
    n20r_ctx_cleanup, n20r_ctx_init, n20r_device_id_public_key, n20r_encode_cbor_map,
    n20r_handover_validate, n20r_issue_device_id_cwt, n20r_issue_next_stage_cwt,
    n20r_set_authority_hash, n20r_set_code_descriptor, n20r_set_code_hash,
    n20r_set_configuration_hash, n20r_set_mode, N20rCborMapEntry, N20R_CBOR_BYTES,
    N20R_DICE_CTX_SIZE,
};

/// Storage for the DICE context, aligned as `n20r_ctx_init` requires.
#[repr(C, align(8))]
struct CtxStorage([u8; N20R_DICE_CTX_SIZE]);

static mut CDI: [u8; 32] = [0; 32];
/// The handover region, aligned as the handover header requires.
#[repr(C, align(4))]
struct HandoverStorage([u8; 1024]);

static mut HANDOVER: HandoverStorage = HandoverStorage([0; 1024]);
static mut MEASUREMENT: [u8; 64] = [0; 64];
static mut CTX: CtxStorage = CtxStorage([0; N20R_DICE_CTX_SIZE]);

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        let cdi = core::ptr::addr_of!(CDI) as *const u8;
        let handover = core::ptr::addr_of_mut!(HANDOVER) as *mut u8;
        let meas = core::ptr::addr_of!(MEASUREMENT) as *const u8;

        let mut used = 0usize;
        let _ = n20r_handover_validate(handover, 1024, &mut used);
        let _ = n20r_issue_device_id_cwt(cdi, core::ptr::null(), 0, handover, 1024);

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
        let mut next_cdi = [0u8; 32];
        let _ = n20r_issue_next_stage_cwt(ctx, cdi, next_cdi.as_mut_ptr(), handover, 1024);
        let _ = n20r_ctx_cleanup(ctx);

        let mut pk = [0u8; 32];
        let _ = n20r_device_id_public_key(cdi, pk.as_mut_ptr());

        // Keep results observable so nothing is optimized away.
        core::ptr::read_volatile(handover);
        core::ptr::read_volatile(next_cdi.as_ptr());
        core::ptr::read_volatile(pk.as_ptr());
        core::ptr::read_volatile(&used);
    }
    loop {
        core::hint::spin_loop();
    }
}
