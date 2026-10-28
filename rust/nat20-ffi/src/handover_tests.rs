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

//! `n20r_handover_validate` through its C ABI, on regions laid out byte by
//! byte as an earlier boot stage leaves them in memory.

use core::ptr;

use super::*;

/// A region aligned for the handover header, as a boot stage's region is.
#[repr(C, align(8))]
struct Region([u8; 64]);

fn put_le32(r: &mut Region, at: usize, v: u32) {
    r.0[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// An empty handover as nat20's `init()` writes it.
fn empty() -> Region {
    let mut r = Region([0; 64]);
    r.0[..4].copy_from_slice(b"DICE");
    put_le32(&mut r, 4, 1);
    put_le32(&mut r, 8, 16);
    put_le32(&mut r, 12, 17);
    r.0[16] = 0x9f;
    r.0[17] = 0xff;
    r
}

/// The same with one 3-byte entry appended, as `append_entry()` leaves it.
fn one_entry() -> Region {
    let mut r = empty();
    r.0[17..21].copy_from_slice(&[0xd2, 0x80, 0x00, 0xff]);
    put_le32(&mut r, 12, 20);
    r
}

fn validate(r: &mut Region, size: usize) -> (N20rError, usize) {
    let mut used = 0xabc;
    let err = unsafe { n20r_handover_validate(r.0.as_mut_ptr(), size, &mut used) };
    (err, used)
}

fn rejected(r: &mut Region, size: usize) -> bool {
    validate(r, size) == (N20rError::InvalidArgument, 0xabc)
}

#[test]
fn valid_regions_report_the_bytes_in_use() {
    let before = empty().0;
    let mut r = empty();
    assert!(validate(&mut r, 64) == (N20rError::Ok, 18));
    assert_eq!(r.0, before);
    assert!(validate(&mut one_entry(), 64) == (N20rError::Ok, 21));
    // The terminator may sit in the very last byte of the region.
    assert!(validate(&mut one_entry(), 21) == (N20rError::Ok, 21));
}

#[test]
fn rejects_bad_header_fields() {
    let mut r = empty();
    r.0[3] = b'X';
    assert!(rejected(&mut r, 64));
    for (at, v) in [(4, 2), (4, 0x0100_0000), (8, 20)] {
        let mut r = empty();
        put_le32(&mut r, at, v);
        assert!(rejected(&mut r, 64));
    }
    // Too small to hold even the header and an empty array, or the header.
    assert!(rejected(&mut empty(), 17));
    assert!(rejected(&mut empty(), 8));
}

#[test]
fn rejects_bad_terminators_and_delimiters() {
    let mut r = empty();
    put_le32(&mut r, 12, 16);
    assert!(rejected(&mut r, 64));
    assert!(rejected(&mut one_entry(), 20));
    let mut r = empty();
    put_le32(&mut r, 12, u32::MAX);
    assert!(rejected(&mut r, 64));
    let mut r = one_entry();
    put_le32(&mut r, 12, 19);
    assert!(rejected(&mut r, 64));
    let mut r = empty();
    r.0[16] = 0x80;
    assert!(rejected(&mut r, 64));
}

#[test]
fn rejects_null_and_misaligned_arguments() {
    let mut r = empty();
    let mut used = 0xabc;
    assert!(
        unsafe { n20r_handover_validate(ptr::null_mut(), 64, &mut used) }
            == N20rError::InvalidArgument
    );
    assert!(
        unsafe { n20r_handover_validate(r.0.as_mut_ptr(), 64, ptr::null_mut()) }
            == N20rError::InvalidArgument
    );
    assert!(
        unsafe { n20r_handover_validate(r.0.as_mut_ptr().add(1), 63, &mut used) }
            == N20rError::InvalidArgument
    );
    assert_eq!(used, 0xabc);
}
