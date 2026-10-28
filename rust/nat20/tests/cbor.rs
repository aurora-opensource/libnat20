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

//! CBOR encoder tests against RFC 8949 known encodings, plus stream
//! counting/overflow behavior.

use nat20::cbor::{self, Major};
use nat20::stream::WStream;

/// Renders with a closure into an exact-size buffer and returns the bytes,
/// asserting that counting mode reports the same size.
fn render(f: impl Fn(&mut WStream)) -> Vec<u8> {
    let mut counter = WStream::counting();
    f(&mut counter);
    let size = counter.written();
    assert!(!counter.overflowed());

    let mut buf = vec![0u8; size];
    let mut s = WStream::new(&mut buf);
    f(&mut s);
    assert!(!s.overflowed());
    assert_eq!(s.written(), size);
    let data = s.data().unwrap().to_vec();
    assert_eq!(data.len(), size);
    data
}

#[test]
fn uint_boundaries() {
    // RFC 8949 appendix A and header-width boundaries.
    assert_eq!(render(|s| cbor::write_int(s, 0)), b"\x00");
    assert_eq!(render(|s| cbor::write_int(s, 10)), b"\x0a");
    assert_eq!(render(|s| cbor::write_int(s, 23)), b"\x17");
    assert_eq!(render(|s| cbor::write_int(s, 24)), b"\x18\x18");
    assert_eq!(render(|s| cbor::write_int(s, 255)), b"\x18\xff");
    assert_eq!(render(|s| cbor::write_int(s, 256)), b"\x19\x01\x00");
    assert_eq!(render(|s| cbor::write_int(s, 1000)), b"\x19\x03\xe8");
    assert_eq!(render(|s| cbor::write_int(s, 65535)), b"\x19\xff\xff");
    assert_eq!(
        render(|s| cbor::write_int(s, 65536)),
        b"\x1a\x00\x01\x00\x00"
    );
    assert_eq!(
        render(|s| cbor::write_int(s, 1000000)),
        b"\x1a\x00\x0f\x42\x40"
    );
    assert_eq!(
        render(|s| cbor::write_header(s, Major::Uint, 1000000000000)),
        b"\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00"
    );
}

#[test]
fn negative_ints() {
    assert_eq!(render(|s| cbor::write_int(s, -1)), b"\x20");
    assert_eq!(render(|s| cbor::write_int(s, -10)), b"\x29");
    assert_eq!(render(|s| cbor::write_int(s, -24)), b"\x37");
    assert_eq!(render(|s| cbor::write_int(s, -25)), b"\x38\x18");
    assert_eq!(render(|s| cbor::write_int(s, -100)), b"\x38\x63");
    assert_eq!(render(|s| cbor::write_int(s, -1000)), b"\x39\x03\xe7");
    // The COSE EdDSA algorithm id.
    assert_eq!(render(|s| cbor::write_int(s, -8)), b"\x27");
    // An open-DICE claim label: -4670545 => major 1, value 4670544.
    assert_eq!(
        render(|s| cbor::write_int(s, -4670545)),
        b"\x3a\x00\x47\x44\x50"
    );
}

#[test]
fn strings_and_containers() {
    assert_eq!(render(|s| cbor::write_bytes(s, &[])), b"\x40");
    assert_eq!(
        render(|s| cbor::write_bytes(s, &[1, 2, 3, 4])),
        b"\x44\x01\x02\x03\x04"
    );
    assert_eq!(render(|s| cbor::write_text(s, "")), b"\x60");
    assert_eq!(render(|s| cbor::write_text(s, "IETF")), b"\x64IETF");
    assert_eq!(render(|s| cbor::write_array_header(s, 0)), b"\x80");
    assert_eq!(render(|s| cbor::write_map_header(s, 0)), b"\xa0");
    assert_eq!(render(|s| cbor::write_array_header(s, 25)), b"\x98\x19");
    // 24-byte byte string needs a one-byte length argument.
    assert_eq!(
        render(|s| cbor::write_bytes(s, &[0xaa; 24]))[..2],
        [0x58, 24]
    );
    // 256-byte byte string needs a two-byte length argument.
    assert_eq!(
        render(|s| cbor::write_bytes(s, &[0xaa; 256]))[..3],
        [0x59, 0x01, 0x00]
    );
}

#[test]
fn nested_containers_backward() {
    // {1: [2, 3]} written backward: contents first, headers last.
    let bytes = render(|s| {
        cbor::write_int(s, 3);
        cbor::write_int(s, 2);
        cbor::write_array_header(s, 2);
        cbor::write_int(s, 1);
        cbor::write_map_header(s, 1);
    });
    assert_eq!(bytes, b"\xa1\x01\x82\x02\x03");
}

#[test]
fn overflow_keeps_counting() {
    let mut buf = [0u8; 4];
    let mut s = WStream::new(&mut buf);
    s.prepend(&[1, 2, 3]);
    assert!(!s.overflowed());
    s.prepend(&[4, 5, 6]);
    assert!(s.overflowed());
    // The count still reflects everything that was attempted, so the caller
    // can size a new buffer exactly.
    assert_eq!(s.written(), 6);
    assert!(s.data().is_none());
}

#[test]
fn count_saturates_instead_of_wrapping() {
    // A size query whose count would wrap reports usize::MAX, a size no
    // buffer can have, rather than a small wrapped value.
    let mut counter = WStream::counting();
    counter.skip(usize::MAX);
    counter.prepend(&[1, 2, 3]);
    assert_eq!(counter.written(), usize::MAX);

    // A buffered stream that saturates is overflowed and writes nothing.
    let mut buf = [0u8; 4];
    let mut s = WStream::new(&mut buf);
    s.skip(usize::MAX - 1);
    s.prepend(&[1, 2, 3]);
    assert_eq!(s.written(), usize::MAX);
    assert!(s.overflowed());
    assert!(s.data().is_none());
    assert_eq!(buf, [0; 4]);
}

#[test]
fn skip_reserves_tail() {
    let mut buf = [0u8; 8];
    let mut s = WStream::new(&mut buf);
    s.skip(4);
    s.prepend(&[0xaa; 4]);
    assert_eq!(s.written(), 8);
    assert!(!s.overflowed());
    assert_eq!(&buf[..4], &[0xaa; 4]);
}

#[test]
fn output_at_buffer_tail() {
    let mut buf = [0xffu8; 8];
    let mut s = WStream::new(&mut buf);
    s.prepend(&[1, 2, 3]);
    assert_eq!(s.data().unwrap(), &[1, 2, 3]);
    assert_eq!(&buf[5..], &[1, 2, 3]);
    assert_eq!(&buf[..5], &[0xff; 5]);
}
