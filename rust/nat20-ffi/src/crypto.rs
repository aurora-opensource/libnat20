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

//! The crypto table: the C interface through which the integrator plugs in
//! the crypto backend (`n20r_crypto_t` in `nat20_rust.h`), and the adapter
//! that makes it a [`nat20::Crypto`].

use core::ffi::c_void;

use nat20::{Crypto, CryptoError, Digest, Error, KeyKind};

/// An opaque key handle of the integrator's backend, `n20r_key_t` in C.
pub type N20rKey = *mut c_void;

/// One part of a gather list, `n20r_slice_t` in C.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct N20rSlice {
    /// Start of the part; may be null when `size` is 0.
    pub data: *const u8,
    /// Length in bytes.
    pub size: usize,
}

impl N20rSlice {
    const EMPTY: N20rSlice = N20rSlice {
        data: core::ptr::null(),
        size: 0,
    };
}

/// SHA-512 over a gather list.
pub type N20rSha512Fn = unsafe extern "C" fn(
    ctx: *mut c_void,
    parts: *const N20rSlice,
    count: usize,
    digest: *mut u8,
) -> i32;
/// Key derivation.
pub type N20rKdfFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    cdi: N20rKey,
    kind: u32,
    context: *const N20rSlice,
    count: usize,
    key_out: *mut N20rKey,
) -> i32;
/// Ed25519 public key of a key.
pub type N20rPublicKeyFn =
    unsafe extern "C" fn(ctx: *mut c_void, key: N20rKey, public_key: *mut u8) -> i32;
/// Ed25519 signature.
pub type N20rSignFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    key: N20rKey,
    message: *const u8,
    message_size: usize,
    signature: *mut u8,
) -> i32;
/// Frees a key.
pub type N20rKeyFreeFn = unsafe extern "C" fn(ctx: *mut c_void, key: N20rKey);

/// The crypto table, `n20r_crypto_t` in C: the integrator's backend.
///
/// The contract each function must meet is documented in `nat20_rust.h`.
/// `#[repr(C)]` over a pointer and nullable function pointers, so every
/// bit pattern is a valid value; a null function is rejected.
#[repr(C)]
pub struct N20rCrypto {
    /// Passed back unchanged as the first argument of every function.
    pub ctx: *mut c_void,
    /// SHA-512 over the concatenation of the parts.
    pub sha512: Option<N20rSha512Fn>,
    /// `HKDF-Expand-SHA512(prk = cdi, info = context, L = 32)`.
    pub kdf: Option<N20rKdfFn>,
    /// The Ed25519 public key of a key.
    pub public_key: Option<N20rPublicKeyFn>,
    /// RFC 8032 Ed25519 signature with a key.
    pub sign: Option<N20rSignFn>,
    /// Frees and wipes a key.
    pub key_free: Option<N20rKeyFreeFn>,
}

/// The most parts the library ever puts in one gather list (the open-DICE
/// input digest has five), with room to spare.
const MAX_PARTS: usize = 8;

/// A key handle of the integrator's backend, owned by the library.
pub struct CKey(pub N20rKey);

/// The integrator's crypto table as a [`nat20::Crypto`].
pub struct CCrypto<'a> {
    table: &'a N20rCrypto,
    sha512: N20rSha512Fn,
    kdf: N20rKdfFn,
    public_key: N20rPublicKeyFn,
    sign: N20rSignFn,
    key_free: N20rKeyFreeFn,
}

impl<'a> CCrypto<'a> {
    /// Checks the table: every function must be set.
    ///
    /// # Safety
    /// `table` must be null (rejected) or point to a readable `n20r_crypto_t`
    /// for `'a` whose functions meet the contract in `nat20_rust.h`.
    pub unsafe fn from_raw(table: *const N20rCrypto) -> Result<Self, Error> {
        // SAFETY: the caller guarantees null or a readable table for 'a.
        let table = table.as_ref().ok_or(Error::InvalidArgument)?;
        Ok(CCrypto {
            table,
            sha512: table.sha512.ok_or(Error::InvalidArgument)?,
            kdf: table.kdf.ok_or(Error::InvalidArgument)?,
            public_key: table.public_key.ok_or(Error::InvalidArgument)?,
            sign: table.sign.ok_or(Error::InvalidArgument)?,
            key_free: table.key_free.ok_or(Error::InvalidArgument)?,
        })
    }
}

/// Lays a gather list out as an array of slices for C.
fn gather(
    parts: &mut dyn Iterator<Item = &[u8]>,
) -> Result<([N20rSlice; MAX_PARTS], usize), CryptoError> {
    let mut out = [N20rSlice::EMPTY; MAX_PARTS];
    let mut count = 0;
    for part in parts {
        let slot = out.get_mut(count).ok_or(CryptoError::InvalidInput)?;
        *slot = N20rSlice {
            data: part.as_ptr(),
            size: part.len(),
        };
        count += 1;
    }
    Ok((out, count))
}

/// Maps a backend's return code: 0 is success.
fn check(rc: i32) -> Result<(), CryptoError> {
    match rc {
        0 => Ok(()),
        rc => Err(CryptoError::Backend(rc as u32)),
    }
}

impl Digest for CCrypto<'_> {
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let (list, count) = gather(parts)?;
        // SAFETY: `list` holds `count` slices of live parts and `out` 64
        // writable bytes; the integrator guarantees the function meets its
        // contract (CCrypto::from_raw).
        check(unsafe { (self.sha512)(self.table.ctx, list.as_ptr(), count, out.as_mut_ptr()) })
    }
}

impl Crypto for CCrypto<'_> {
    type Key = CKey;

    fn kdf(
        &mut self,
        cdi: &CKey,
        kind: KeyKind,
        context: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<CKey, CryptoError> {
        let (list, count) = gather(context)?;
        let mut key: N20rKey = core::ptr::null_mut();
        // SAFETY: as in `sha512`; `key` is a writable handle.
        check(unsafe {
            (self.kdf)(
                self.table.ctx,
                cdi.0,
                kind as u32,
                list.as_ptr(),
                count,
                &mut key,
            )
        })?;
        Ok(CKey(key))
    }

    fn public_key(&mut self, key: &CKey, public_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        // SAFETY: as in `sha512`; `public_key` holds 32 writable bytes.
        check(unsafe { (self.public_key)(self.table.ctx, key.0, public_key.as_mut_ptr()) })
    }

    fn sign(
        &mut self,
        key: &CKey,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        // SAFETY: as in `sha512`; `message` is a live slice and `signature`
        // holds 64 writable bytes.
        check(unsafe {
            (self.sign)(
                self.table.ctx,
                key.0,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
            )
        })
    }

    fn key_free(&mut self, key: CKey) {
        // SAFETY: as in `sha512`; `key` came from this table's kdf and is
        // freed exactly once, since it is taken by value.
        unsafe { (self.key_free)(self.table.ctx, key.0) }
    }
}
