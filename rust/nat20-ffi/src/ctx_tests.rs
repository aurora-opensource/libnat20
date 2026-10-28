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

//! Tests of the DICE context and its setters through the C ABI.

use super::*;
use crate::tests::{device_id_cert, expected_handover, start_handover, Region, CDI};
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use nat20::crypto::soft::SoftCrypto;
use nat20::open_dice::Mode;

#[repr(C, align(8))]
struct Storage([u8; N20R_DICE_CTX_SIZE + 8]);

impl Storage {
    fn new() -> Self {
        Storage([0; N20R_DICE_CTX_SIZE + 8])
    }

    fn ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn init(&mut self) -> *mut u8 {
        assert_eq!(
            unsafe { n20r_ctx_init(self.ptr(), N20R_DICE_CTX_SIZE) },
            N20rError::Ok
        );
        self.ptr()
    }
}

/// Builds a two-certificate handover through the C ABI.
fn issue_via_ffi(ctx: *mut u8) -> ([u8; 32], Vec<u8>) {
    let mut r = Region::new();
    assert_eq!(start_handover(&mut r, None), N20rError::Ok);
    let mut next_cdi = [0u8; 32];
    let rc = unsafe {
        n20r_issue_next_stage_cwt(ctx, CDI.as_ptr(), next_cdi.as_mut_ptr(), r.ptr(), r.0.len())
    };
    assert_eq!(rc, N20rError::Ok);
    (next_cdi, r.used().to_vec())
}

/// The handover `issue_via_ffi` must produce, from the library directly.
fn issue_via_library(input: &OpenDiceInput) -> ([u8; 32], Vec<u8>) {
    let mut cert = vec![0u8; 1024];
    let mut next_cdi = CdiSecret::default();
    let n = issue_next_stage_cwt(
        &mut SoftCrypto,
        &CdiSecret::from_bytes(CDI),
        input,
        &mut next_cdi,
        Some(&mut cert),
    )
    .unwrap();
    let next = &cert[cert.len() - n..];
    (
        *next_cdi.as_bytes(),
        expected_handover(&[&device_id_cert(None), next]),
    )
}

#[test]
fn init_rejects_null_undersized_and_misaligned_buffers() {
    let mut s = Storage::new();
    unsafe {
        assert_eq!(
            n20r_ctx_init(ptr::null_mut(), N20R_DICE_CTX_SIZE),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_ctx_init(s.ptr(), DiceCtx::required_size() - 1),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_ctx_init(s.ptr().add(1), N20R_DICE_CTX_SIZE),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_ctx_init(s.ptr(), DiceCtx::required_size()),
            N20rError::Ok
        );
    }
}

/// Zero-filled storage (e.g. `.bss`) is not an empty context: forgetting
/// `n20r_ctx_init` must be reported, not silently accepted.
#[test]
fn an_uninitialised_context_is_rejected() {
    let mut s = Storage::new();
    let data = [0u8; 4];
    unsafe {
        assert_eq!(
            n20r_set_code_hash(s.ptr(), data.as_ptr(), 4, None),
            N20rError::InvalidArgument
        );
        assert_eq!(n20r_set_mode(s.ptr(), 1), N20rError::InvalidArgument);
        assert_eq!(n20r_ctx_cleanup(s.ptr()), N20rError::InvalidArgument);
        assert_eq!(
            n20r_set_mode(ptr::null_mut(), 1),
            N20rError::InvalidArgument
        );
    }
    let mut r = Region::new();
    assert_eq!(start_handover(&mut r, None), N20rError::Ok);
    let before = r.0;
    let mut next_cdi = [0u8; 32];
    let rc = unsafe {
        n20r_issue_next_stage_cwt(
            s.ptr(),
            CDI.as_ptr(),
            next_cdi.as_mut_ptr(),
            r.ptr(),
            r.0.len(),
        )
    };
    assert_eq!(rc, N20rError::InvalidArgument);
    assert_eq!(r.0, before, "the handover is untouched");
    assert_eq!(next_cdi, [0; 32], "no CDI is handed out");
}

#[test]
fn a_fresh_context_issues_an_empty_not_configured_input() {
    let mut s = Storage::new();
    let ctx = s.init();
    assert_eq!(
        issue_via_ffi(ctx),
        issue_via_library(&OpenDiceInput::default())
    );
}

#[test]
fn the_setters_feed_the_certificate_and_the_cdi() {
    let code = [0x01u8; 48];
    let code_desc = [0x02u8; 7];
    let config = [0x03u8; 48];
    let config_desc = [0x04u8; 100];
    let authority = [0x05u8; 48];
    let authority_desc = [0x06u8; 3];
    let profile = b"example.dice.profile";
    let hidden = [0x07u8; 32];

    let mut s = Storage::new();
    let ctx = s.init();
    unsafe {
        let set =
            |f: unsafe extern "C" fn(*mut u8, *const u8, usize, Option<CDrop>) -> N20rError,
             d: &[u8]| assert_eq!(f(ctx, d.as_ptr(), d.len(), None), N20rError::Ok);
        set(n20r_set_code_hash, &code);
        set(n20r_set_code_descriptor, &code_desc);
        set(n20r_set_configuration_hash, &config);
        set(n20r_set_configuration_descriptor, &config_desc);
        set(n20r_set_authority_hash, &authority);
        set(n20r_set_authority_descriptor, &authority_desc);
        set(n20r_set_profile_name, profile);
        set(n20r_set_hidden, &hidden);
        assert_eq!(n20r_set_mode(ctx, 2), N20rError::Ok);
    }

    let expected = issue_via_library(&OpenDiceInput {
        code_hash: &code,
        code_descriptor: &code_desc,
        configuration_hash: &config,
        configuration_descriptor: &config_desc,
        authority_hash: &authority,
        authority_descriptor: &authority_desc,
        mode: Mode::Debug,
        profile_name: profile,
        hidden: &hidden,
    });
    assert_eq!(issue_via_ffi(ctx), expected);
}

/// No size restriction on an inline configuration value: that is the DICE
/// profile's to impose, not the library's.
#[test]
fn an_inline_configuration_of_any_size_is_accepted() {
    let config_desc = [0x04u8; 17];
    let mut s = Storage::new();
    let ctx = s.init();
    unsafe {
        n20r_set_configuration_descriptor(ctx, config_desc.as_ptr(), config_desc.len(), None);
    }
    let expected = issue_via_library(&OpenDiceInput {
        configuration_descriptor: &config_desc,
        ..OpenDiceInput::default()
    });
    assert_eq!(issue_via_ffi(ctx), expected);
}

#[test]
fn null_clears_a_field() {
    let code = [0x01u8; 48];
    let mut s = Storage::new();
    let ctx = s.init();
    unsafe {
        n20r_set_code_hash(ctx, code.as_ptr(), code.len(), None);
        assert_eq!(
            n20r_set_code_hash(ctx, ptr::null(), 48, None),
            N20rError::Ok
        );
    }
    assert_eq!(
        issue_via_ffi(ctx),
        issue_via_library(&OpenDiceInput::default())
    );
}

#[test]
fn an_invalid_mode_is_rejected_and_the_previous_one_kept() {
    let mut s = Storage::new();
    let ctx = s.init();
    unsafe {
        assert_eq!(n20r_set_mode(ctx, 3), N20rError::Ok);
        assert_eq!(n20r_set_mode(ctx, 4), N20rError::InvalidArgument);
        assert_eq!(DiceCtx::from_raw(ctx).unwrap().mode(), Ok(Mode::Recovery));
    }
}

static DROPS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn count_drop(p: *mut c_void) {
    assert!(!p.is_null());
    DROPS.fetch_add(1, Ordering::SeqCst);
}

/// An adopted buffer is released exactly once, when its field is replaced
/// or the context is cleaned up; a borrowed one never is, nor is one a
/// failed setter was given. Afterwards the context is invalid.
#[test]
fn adopted_buffers_are_released_exactly_once() {
    let a = [0u8; 4];
    let b = [0u8; 4];
    let mut s = Storage::new();
    let ctx = s.init();
    unsafe {
        n20r_set_code_hash(ctx, a.as_ptr(), 4, Some(count_drop));
        n20r_set_hidden(ctx, b.as_ptr(), 4, None);
        assert_eq!(DROPS.load(Ordering::SeqCst), 0);

        // Replacing runs the old field's destructor.
        n20r_set_code_hash(ctx, b.as_ptr(), 4, Some(count_drop));
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);

        // Cleanup releases what is still adopted, and only that.
        assert_eq!(n20r_ctx_cleanup(ctx), N20rError::Ok);
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);

        assert_eq!(n20r_set_mode(ctx, 1), N20rError::InvalidArgument);
        assert_eq!(n20r_ctx_cleanup(ctx), N20rError::InvalidArgument);
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);

        // A setter that fails does not take ownership.
        assert_eq!(
            n20r_set_code_hash(ctx, a.as_ptr(), 4, Some(count_drop)),
            N20rError::InvalidArgument
        );
        assert_eq!(DROPS.load(Ordering::SeqCst), 2);
    }
}
