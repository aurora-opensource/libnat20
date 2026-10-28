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

//! `n20r_encode_cbor_map` through its C ABI: size negotiation, placement at
//! offset 0, and argument validation.

use core::ptr;

use super::*;

fn uint(key: u64, value: u64) -> N20rCborMapEntry {
    N20rCborMapEntry {
        key,
        uint_value: value,
        data: ptr::null(),
        size: 0,
        kind: N20R_CBOR_UINT,
    }
}

fn bytes(key: u64, kind: u32, data: &[u8]) -> N20rCborMapEntry {
    N20rCborMapEntry {
        key,
        uint_value: 0,
        data: data.as_ptr(),
        size: data.len(),
        kind,
    }
}

fn encode(entries: &[N20rCborMapEntry], out: Option<&mut [u8]>, size: &mut usize) -> N20rError {
    let out = out.map_or(ptr::null_mut(), |o| o.as_mut_ptr());
    unsafe { n20r_encode_cbor_map(entries.as_ptr(), entries.len(), out, size) }
}

const CONFIG_DESCRIPTOR: &[u8] = b"\xa3\x01\x42\xab\xcd\x02\x64init\x03\x01";

fn config_entries(hash: &[u8]) -> [N20rCborMapEntry; 3] {
    [
        bytes(1, N20R_CBOR_BYTES, hash),
        bytes(2, N20R_CBOR_TEXT, b"init"),
        uint(3, 1),
    ]
}

#[test]
fn size_query_then_encode_at_offset_zero() {
    let hash = [0xab, 0xcd];
    let entries = config_entries(&hash);
    let mut size = 0;
    assert!(encode(&entries, None, &mut size) == N20rError::InsufficientBuffer);
    assert_eq!(size, CONFIG_DESCRIPTOR.len());

    let mut out = [0xeeu8; 32];
    let mut size = out.len();
    assert!(encode(&entries, Some(&mut out), &mut size) == N20rError::Ok);
    assert_eq!(size, CONFIG_DESCRIPTOR.len());
    assert_eq!(&out[..size], CONFIG_DESCRIPTOR);
    assert_eq!(out[size..], [0xee; 32][size..]);
}

#[test]
fn too_small_reports_required_and_writes_nothing() {
    let hash = [0xab, 0xcd];
    let mut out = [0xeeu8; 32];
    let mut size = CONFIG_DESCRIPTOR.len() - 1;
    assert!(
        encode(&config_entries(&hash), Some(&mut out), &mut size) == N20rError::InsufficientBuffer
    );
    assert_eq!(size, CONFIG_DESCRIPTOR.len());
    assert_eq!(out, [0xee; 32]);
}

#[test]
fn empty_map() {
    let mut out = [0u8; 1];
    let mut size = 1;
    assert!(
        unsafe { n20r_encode_cbor_map(ptr::null(), 0, out.as_mut_ptr(), &mut size) }
            == N20rError::Ok
    );
    assert_eq!((size, out[0]), (1, 0xa0));
}

#[test]
fn invalid_arguments_leave_size_unchanged() {
    let mut out = [0u8; 16];
    let bad_kind = N20rCborMapEntry {
        kind: 1,
        ..uint(1, 0)
    };
    for entries in [
        vec![uint(2, 0), uint(1, 0)],
        vec![uint(1, 0), uint(1, 0)],
        vec![bad_kind],
    ] {
        let mut size = out.len();
        assert!(encode(&entries, Some(&mut out), &mut size) == N20rError::InvalidArgument);
        assert_eq!(size, out.len());
    }
    let entries = [uint(1, 0)];
    assert!(
        unsafe { n20r_encode_cbor_map(entries.as_ptr(), 1, out.as_mut_ptr(), ptr::null_mut()) }
            == N20rError::InvalidArgument
    );
    let mut size = out.len();
    assert!(
        unsafe { n20r_encode_cbor_map(ptr::null(), 1, out.as_mut_ptr(), &mut size) }
            == N20rError::InvalidArgument
    );
}

#[test]
fn null_data_is_an_empty_string_whatever_the_size() {
    let mut out = [0u8; 8];
    let mut size = out.len();
    let entries = [N20rCborMapEntry {
        data: ptr::null(),
        size: 5,
        ..bytes(1, N20R_CBOR_TEXT, &[])
    }];
    assert!(encode(&entries, Some(&mut out), &mut size) == N20rError::Ok);
    assert_eq!(&out[..size], b"\xa1\x01\x60");
}

fn encoded(entries: &[N20rCborMapEntry]) -> Vec<u8> {
    let mut out = vec![0u8; 512];
    let mut size = out.len();
    assert!(encode(entries, Some(&mut out), &mut size) == N20rError::Ok);
    out.truncate(size);
    out
}

#[test]
fn code_descriptor_bytes() {
    // {1: h'000102…1f', 2: 0x0000000200000005}, the shape of a code
    // descriptor naming the next stage's image hash and version.
    let hash: Vec<u8> = (0..32).collect();
    let mut expected = vec![0xa2, 0x01, 0x58, 0x20];
    expected.extend_from_slice(&hash);
    expected.extend_from_slice(b"\x02\x1b\x00\x00\x00\x02\x00\x00\x00\x05");
    assert_eq!(
        encoded(&[
            bytes(1, N20R_CBOR_BYTES, &hash),
            uint(2, 0x0000_0002_0000_0005)
        ]),
        expected
    );
}

#[test]
fn shortest_heads_for_keys_values_and_lengths() {
    assert_eq!(
        encoded(&[
            uint(0, 23),
            uint(23, 24),
            bytes(24, N20R_CBOR_TEXT, b"arm"),
            bytes(255, N20R_CBOR_BYTES, &[]),
            uint(256, 65535),
            uint(65536, 0x1_0000_0000),
        ]),
        b"\xa6\x00\x17\x17\x18\x18\x18\x18\x63arm\x18\xff\x40\
          \x19\x01\x00\x19\xff\xff\x1a\x00\x01\x00\x00\x1b\x00\x00\x00\x01\x00\x00\x00\x00"
    );
    let entries: Vec<N20rCborMapEntry> = (0..24).map(|k| uint(k, 0)).collect();
    assert_eq!(encoded(&entries)[..2], [0xb8, 24]);
    let text = [b'a'; 24];
    assert_eq!(
        encoded(&[bytes(1, N20R_CBOR_TEXT, &text)])[..4],
        [0xa1, 0x01, 0x78, 24]
    );
    let long = [0xaa; 256];
    assert_eq!(
        encoded(&[bytes(1, N20R_CBOR_BYTES, &long)])[..5],
        [0xa1, 0x01, 0x59, 0x01, 0x00]
    );
}

/// Text is written verbatim: invalid UTF-8 yields a malformed text string,
/// never undefined behavior.
#[test]
fn text_is_not_validated() {
    let text = [0xff, 0xfe];
    assert_eq!(
        encoded(&[bytes(1, N20R_CBOR_TEXT, &text)]),
        [0xa1, 0x01, 0x62, 0xff, 0xfe]
    );
}
