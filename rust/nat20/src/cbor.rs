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

//! Write-only, definite-length CBOR encoder (RFC 8949), a port of the write
//! side of `src/core/cbor.c`.
//!
//! All functions prepend into a backward-writing [`WStream`], so container
//! headers are written *after* their contents.

use crate::stream::WStream;

/// CBOR major types used by the certificate encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Major {
    /// Major type 0: unsigned integer.
    Uint = 0,
    /// Major type 1: negative integer.
    Nint = 1,
    /// Major type 2: byte string.
    Bytes = 2,
    /// Major type 3: text string.
    Text = 3,
    /// Major type 4: array.
    Array = 4,
    /// Major type 5: map.
    Map = 5,
}

/// Writes a CBOR item header: major type plus minimally-encoded argument.
pub fn write_header(s: &mut WStream, major: Major, n: u64) {
    let ib = (major as u8) << 5;
    if n < 24 {
        s.put(ib | n as u8);
    } else if n <= 0xff {
        s.put(n as u8);
        s.put(ib | 24);
    } else if n <= 0xffff {
        s.prepend(&(n as u16).to_be_bytes());
        s.put(ib | 25);
    } else if n <= 0xffff_ffff {
        s.prepend(&(n as u32).to_be_bytes());
        s.put(ib | 26);
    } else {
        s.prepend(&n.to_be_bytes());
        s.put(ib | 27);
    }
}

/// Writes a signed integer (major type 0 or 1).
pub fn write_int(s: &mut WStream, v: i64) {
    if v >= 0 {
        write_header(s, Major::Uint, v as u64);
    } else {
        write_header(s, Major::Nint, (-(v + 1)) as u64);
    }
}

/// Writes a definite-length byte string.
pub fn write_bytes(s: &mut WStream, b: &[u8]) {
    s.prepend(b);
    write_header(s, Major::Bytes, b.len() as u64);
}

/// Writes a definite-length UTF-8 text string.
pub fn write_text(s: &mut WStream, t: &str) {
    write_text_bytes(s, t.as_bytes());
}

/// Writes `t` as a definite-length text string without checking that it is
/// UTF-8.
///
/// For text that arrives as raw bytes (e.g. across the C ABI): the bytes are
/// copied verbatim, as C libnat20 does. Invalid UTF-8 yields a malformed
/// CBOR text string, never undefined behavior, and keeps UTF-8 validation
/// out of the image.
pub fn write_text_bytes(s: &mut WStream, t: &[u8]) {
    s.prepend(t);
    write_header(s, Major::Text, t.len() as u64);
}

/// Writes an array header for `items` following items.
pub fn write_array_header(s: &mut WStream, items: u64) {
    write_header(s, Major::Array, items);
}

/// Writes a map header for `pairs` following key-value pairs.
pub fn write_map_header(s: &mut WStream, pairs: u64) {
    write_header(s, Major::Map, pairs);
}
