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

//! A byte buffer received across the C ABI, with optional ownership transfer.
//!
//! The C side hands attestation inputs over as a (pointer, length) pair plus
//! an optional destructor: with a destructor the buffer is adopted and
//! released on drop, without one it stays the caller's to free. A null
//! pointer means "not set", which is distinct from a zero-length buffer only
//! in intent — both read back as an empty slice.
//!
//! The buffer is only ever read; the pointer is `*const` because borrowed
//! buffers are often const data, and a destructor receives it with the
//! const cast away, as `free` would.
//!
//! [`CBuf`] deliberately carries no lifetime. It lives inside a context
//! structure that the C caller owns (see [`crate::ctx`]), so any lifetime
//! parameter would have to be invented rather than derived — a raw pointer
//! carries no provenance. Instead [`CBuf::as_slice`] is `unsafe`, which puts
//! the validity assumption where it is relied upon, and gives the returned
//! slice a real lifetime borrowed from `&self`.

/// Destructor for an adopted buffer, `void (*)(void *)` in C.
pub(crate) type CDrop = unsafe extern "C" fn(*mut core::ffi::c_void);

/// A byte buffer received across the C ABI.
///
/// `#[repr(C)]` over a pointer, a length and a nullable function pointer, so
/// every bit pattern is a valid value — which is what makes it sound to
/// reinterpret caller-provided memory as a structure containing these.
#[repr(C)]
pub(crate) struct CBuf {
    /// Start of the buffer, or null when the field is not set.
    ptr: *const u8,
    /// Length in bytes; meaningless when `ptr` is null.
    len: usize,
    /// Destructor supplied by the C caller, invoked exactly once with `ptr`
    /// when this value is dropped. `None` means the C caller kept ownership.
    /// It receives no length, so the C side must be able to release the
    /// buffer from the pointer alone.
    drop: Option<CDrop>,
}

impl CBuf {
    /// The "not set" value: a null pointer and no destructor.
    pub(crate) const fn empty() -> Self {
        CBuf {
            ptr: core::ptr::null(),
            len: 0,
            drop: None,
        }
    }

    /// Wraps raw C arguments. A null `ptr` yields [`CBuf::empty`], so
    /// clearing a field is just passing null.
    ///
    /// # Safety
    /// If `ptr` is non-null it must be valid for reads of `len` bytes, and
    /// must stay valid and unmodified until this value is replaced or
    /// dropped. When `drop` is `Some`, ownership transfers: `drop(ptr)` must
    /// be safe to call exactly once, and the C side must not release the
    /// buffer itself.
    pub(crate) unsafe fn from_raw_parts(ptr: *const u8, len: usize, drop: Option<CDrop>) -> Self {
        if ptr.is_null() {
            CBuf::empty()
        } else {
            CBuf { ptr, len, drop }
        }
    }

    /// Borrows the buffer as a slice for as long as `self` is borrowed;
    /// an unset buffer reads back as empty.
    ///
    /// # Safety
    /// The buffer must still satisfy the contract it was registered under —
    /// the C caller must not have freed or mutated it since. Nothing may
    /// alias it mutably for the duration of the returned borrow.
    pub(crate) unsafe fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() {
            &[]
        } else {
            core::slice::from_raw_parts(self.ptr, self.len)
        }
    }
}

impl Drop for CBuf {
    fn drop(&mut self) {
        if let Some(drop_fn) = self.drop {
            if !self.ptr.is_null() {
                // SAFETY: a destructor is present only when the C caller
                // transferred ownership and guaranteed `drop_fn` is safe to
                // call with `ptr`. Drop runs at most once per value, so the
                // destructor runs exactly once, and `ptr` is not touched
                // afterwards.
                unsafe { drop_fn(self.ptr.cast_mut().cast()) };
            }
        }
    }
}
