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

//! Backward-writing output stream, a port of `n20_stream` (`src/core/stream.c`).
//!
//! The stream writes toward the *front* of the buffer: each [`WStream::prepend`]
//! places bytes immediately before everything written so far, and the final
//! output occupies the *tail* of the buffer. This lets CBOR container headers
//! be written after their contents, when the content length is known, so the
//! whole encoder is single-pass and produces exact sizes.
//!
//! A stream created with [`WStream::counting`] has no buffer and only counts
//! bytes; this implements the exact-size query mode of the C library. A
//! buffered stream that runs out of space likewise keeps counting (with
//! [`WStream::overflowed`] set) so the required size can always be reported.
//!
//! The count saturates at `usize::MAX` instead of wrapping. No buffer can be
//! that large (a slice holds at most `isize::MAX` bytes), so a saturated
//! count is a required size that is never satisfied, and a buffered stream
//! that saturates is always overflowed; no separate flag is needed.

/// Backward-writing output stream over a caller-provided buffer.
pub struct WStream<'a> {
    buf: Option<&'a mut [u8]>,
    written: usize,
    buffer_overflow: bool,
}

impl<'a> WStream<'a> {
    /// Creates a stream writing backward into `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        WStream {
            buf: Some(buf),
            written: 0,
            buffer_overflow: false,
        }
    }

    /// Creates a bufferless stream that only counts bytes (size-query mode).
    pub fn counting() -> WStream<'static> {
        WStream {
            buf: None,
            written: 0,
            buffer_overflow: false,
        }
    }

    /// Advances the write position by `n` bytes without writing.
    ///
    /// Used to reserve the signature slot at the very end of the buffer.
    /// Like the C `n20_stream_skip`, the position advances even on overflow
    /// so the required size remains available; it saturates rather than
    /// wraps (see the module documentation).
    pub fn skip(&mut self, n: usize) {
        self.written = self.written.saturating_add(n);
        if let Some(b) = &self.buf {
            if self.written > b.len() {
                self.buffer_overflow = true;
            }
        }
    }

    /// Prepends `src` in front of everything written so far.
    ///
    /// Never fails: on overflow the stream keeps counting but stops writing,
    /// mirroring `n20_stream_prepend`.
    pub fn prepend(&mut self, src: &[u8]) {
        self.skip(src.len());
        if self.buffer_overflow {
            return;
        }
        if let Some(b) = &mut self.buf {
            let end = b.len() - (self.written - src.len());
            b[end - src.len()..end].copy_from_slice(src);
        }
    }

    /// Prepends a single byte.
    pub fn put(&mut self, c: u8) {
        self.prepend(&[c]);
    }

    /// Number of bytes written (or counted) so far; `usize::MAX` if the count
    /// saturated.
    pub fn written(&self) -> usize {
        self.written
    }

    /// True if a write or skip did not fit the buffer (always false for
    /// counting streams, which have no buffer to overflow).
    pub fn overflowed(&self) -> bool {
        self.buffer_overflow
    }

    /// The bytes written so far: the tail `written()` bytes of the buffer.
    /// `None` for counting streams or after an overflow.
    pub fn data(&self) -> Option<&[u8]> {
        if self.overflowed() {
            return None;
        }
        self.buf.as_ref().map(|b| &b[b.len() - self.written..])
    }
}
