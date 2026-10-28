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

//! Host unit tests of the C ABI, called the way C would call it.

use super::*;
use core::ptr;
use nat20::crypto::soft::SoftCrypto;

pub(crate) const CDI: [u8; 32] = [0x11; 32];

/// A handover region, aligned as the header requires.
#[repr(C, align(4))]
pub(crate) struct Region(pub(crate) [u8; 2048]);

impl Region {
    pub(crate) fn new() -> Box<Self> {
        Box::new(Region([0; 2048]))
    }

    pub(crate) fn ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// The bytes in use, per the validated header.
    pub(crate) fn used(&self) -> &[u8] {
        let end = u32::from_le_bytes(self.0[12..16].try_into().unwrap()) as usize + 1;
        &self.0[..end]
    }
}

/// The handover holding `certs`, each tagged COSE_Sign1, as the format
/// specifies it.
pub(crate) fn expected_handover(certs: &[&[u8]]) -> Vec<u8> {
    let mut content = vec![0x9F];
    for c in certs {
        content.push(0xD2);
        content.extend_from_slice(c);
    }
    let terminator = (16 + content.len()) as u32;
    content.push(0xFF);
    let mut h = b"DICE".to_vec();
    for v in [1u32, 16, terminator] {
        h.extend_from_slice(&v.to_le_bytes());
    }
    h.extend(content);
    h
}

/// The device-identity certificate, issued by the library directly.
pub(crate) fn device_id_cert(profile: Option<&[u8]>) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let n = issue_device_id_cwt(
        &mut SoftCrypto,
        &CdiSecret::from_bytes(CDI),
        profile,
        Some(&mut buf),
    )
    .unwrap();
    buf[buf.len() - n..].to_vec()
}

/// Starts a handover through the C ABI.
pub(crate) fn start_handover(region: &mut Region, profile: Option<&[u8]>) -> N20rError {
    let (p, n) = profile.map_or((ptr::null(), 0), |p| (p.as_ptr(), p.len()));
    unsafe { n20r_issue_device_id_cwt(CDI.as_ptr(), p, n, region.ptr(), region.0.len()) }
}

#[test]
fn device_id_cwt_starts_the_handover() {
    let mut r = Region::new();
    r.0.fill(0xAA);
    assert_eq!(start_handover(&mut r, Some(b"test.profile")), N20rError::Ok);
    assert_eq!(
        r.used(),
        expected_handover(&[&device_id_cert(Some(b"test.profile"))])
    );

    // Starting again discards the old chain.
    assert_eq!(start_handover(&mut r, None), N20rError::Ok);
    assert_eq!(r.used(), expected_handover(&[&device_id_cert(None)]));
}

#[test]
fn a_null_profile_name_is_omitted_whatever_the_size() {
    let mut r = Region::new();
    let rc = unsafe { n20r_issue_device_id_cwt(CDI.as_ptr(), ptr::null(), 5, r.ptr(), r.0.len()) };
    assert_eq!(rc, N20rError::Ok);
    assert_eq!(r.used(), expected_handover(&[&device_id_cert(None)]));
}

/// Arguments are checked before the region is touched, so a bad call
/// cannot destroy an existing chain.
#[test]
fn device_id_cwt_checks_arguments_before_touching_the_handover() {
    let mut r = Region::new();
    assert_eq!(start_handover(&mut r, None), N20rError::Ok);
    let before = r.0;
    unsafe {
        let h = r.ptr();
        assert_eq!(
            n20r_issue_device_id_cwt(ptr::null(), ptr::null(), 0, h, 2048),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_issue_device_id_cwt(CDI.as_ptr(), ptr::null(), 0, h.add(1), 2000),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_issue_device_id_cwt(CDI.as_ptr(), ptr::null(), 0, ptr::null_mut(), 2048),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_issue_device_id_cwt(CDI.as_ptr(), ptr::null(), 0, h, 15),
            N20rError::InvalidArgument
        );
    }
    assert_eq!(r.0, before);
}

/// A region too small for the certificate is reported and left as a valid,
/// empty handover.
#[test]
fn device_id_cwt_reports_a_too_small_handover() {
    let mut r = Region::new();
    let rc = unsafe { n20r_issue_device_id_cwt(CDI.as_ptr(), ptr::null(), 0, r.ptr(), 64) };
    assert_eq!(rc, N20rError::InsufficientBuffer);
    assert_eq!(r.used(), expected_handover(&[]));
}

#[test]
fn device_id_public_key_matches_the_library() {
    let mut pk = [0u8; 32];
    assert_eq!(
        unsafe { n20r_device_id_public_key(CDI.as_ptr(), pk.as_mut_ptr()) },
        N20rError::Ok
    );

    let mut c = SoftCrypto;
    let mut seed = Seed32::default();
    attest_key_seed(&mut c, &CdiSecret::from_bytes(CDI), &mut seed).unwrap();
    let mut expected = [0u8; 32];
    c.public_key(&seed, &mut expected).unwrap();
    assert_eq!(pk, expected);
}

#[test]
fn device_id_public_key_rejects_null() {
    let mut pk = [0u8; 32];
    unsafe {
        assert_eq!(
            n20r_device_id_public_key(core::ptr::null(), pk.as_mut_ptr()),
            N20rError::InvalidArgument
        );
        assert_eq!(
            n20r_device_id_public_key(CDI.as_ptr(), core::ptr::null_mut()),
            N20rError::InvalidArgument
        );
    }
}

/// A next stage that does not fit is reported, the handover keeps the chain
/// it had, and no CDI is handed out.
#[test]
fn next_stage_cwt_into_a_full_handover_changes_nothing() {
    let mut r = Region::new();
    assert_eq!(start_handover(&mut r, None), N20rError::Ok);
    let used = r.used().len();

    #[repr(C, align(8))]
    struct Ctx([u8; N20R_DICE_CTX_SIZE]);
    let mut ctx = Ctx([0; N20R_DICE_CTX_SIZE]);
    let mut next_cdi = [0u8; 32];
    unsafe {
        assert_eq!(
            n20r_ctx_init(ctx.0.as_mut_ptr(), N20R_DICE_CTX_SIZE),
            N20rError::Ok
        );
        let rc = n20r_issue_next_stage_cwt(
            ctx.0.as_mut_ptr(),
            CDI.as_ptr(),
            next_cdi.as_mut_ptr(),
            r.ptr(),
            used + 16,
        );
        assert_eq!(rc, N20rError::InsufficientBuffer);
    }
    assert_eq!(r.used(), expected_handover(&[&device_id_cert(None)]));
    assert!(
        r.0[used..].iter().all(|&b| b == 0),
        "nothing left past the chain"
    );
    assert_eq!(next_cdi, [0; 32]);
}
