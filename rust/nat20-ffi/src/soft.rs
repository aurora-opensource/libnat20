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

//! The built-in software backend as a crypto table (feature `soft-crypto`):
//! `n20r_soft_crypto_*` in `nat20_rust.h`, for C callers that bring no
//! crypto of their own.
//!
//! The backend lives in caller-provided storage, like the DICE context, and
//! holds [`MIN_KEY_SLOTS`] keys. A key handle is its slot index plus one,
//! so no handle is null.

use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::slice;

use nat20::crypto::soft::{SoftCrypto, SoftKey};
use nat20::{Crypto, CryptoError, Digest, Error, KeyKind, MIN_KEY_SLOTS};

use crate::crypto::{N20rCrypto, N20rKey, N20rSlice};
use crate::{status, N20rError};

/// Storage size published to C as `N20R_SOFT_CRYPTO_SIZE`; larger than the
/// structure needs, so the header stays stable (checked at compile time).
pub const N20R_SOFT_CRYPTO_SIZE: usize = 256;

/// Stamp of initialised storage, checked before the backend is touched.
const MAGIC: u64 = 0x6e32_3072_736f_6674; // "n20rsoft"

#[repr(C)]
struct Storage {
    magic: u64,
    crypto: SoftCrypto<MIN_KEY_SLOTS>,
}

const _: () = assert!(size_of::<Storage>() <= N20R_SOFT_CRYPTO_SIZE);

/// The backend in initialised storage.
///
/// # Safety
/// `storage` must be null (rejected) or point to `N20R_SOFT_CRYPTO_SIZE`
/// bytes that nothing else accesses for `'a`.
unsafe fn backend<'a>(storage: *mut c_void) -> Result<&'a mut SoftCrypto, Error> {
    let storage = storage.cast::<Storage>();
    if storage.is_null() || !(storage as usize).is_multiple_of(align_of::<Storage>()) {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: aligned and readable; a u64 has no invalid bit patterns, so
    // the stamp can be read before anything is known about the contents.
    if core::ptr::addr_of!((*storage).magic).read() != MAGIC {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: the stamp is only written by n20r_soft_crypto_init, after a
    // valid backend; nothing else accesses the storage for 'a.
    Ok(&mut (*storage).crypto)
}

fn handle(key: SoftKey) -> N20rKey {
    (key.index() + 1) as N20rKey
}

fn soft_key(key: N20rKey) -> SoftKey {
    SoftKey::from_index((key as usize).wrapping_sub(1))
}

/// Maps a crypto error to the table's return code (nonzero).
fn code(e: CryptoError) -> i32 {
    match e {
        CryptoError::NoKeySlot => 2,
        CryptoError::InvalidKey => 3,
        CryptoError::SignatureVerification => 4,
        _ => 1,
    }
}

fn rc(r: Result<(), CryptoError>) -> i32 {
    r.map_or_else(code, |()| 0)
}

/// The gather list as slices.
///
/// # Safety
/// `parts` must point to `count` slices, each null with size 0 or pointing
/// to `size` readable bytes, for `'a`.
unsafe fn parts<'a>(parts: *const N20rSlice, count: usize) -> Result<&'a [N20rSlice], CryptoError> {
    if count == 0 {
        return Ok(&[]);
    }
    if parts.is_null() {
        return Err(CryptoError::InvalidInput);
    }
    // SAFETY: non-null, and the caller guarantees `count` slices.
    Ok(slice::from_raw_parts(parts, count))
}

/// One part's bytes.
///
/// # Safety
/// As for [`parts`].
unsafe fn bytes<'a>(part: &N20rSlice) -> &'a [u8] {
    if part.data.is_null() {
        &[]
    } else {
        // SAFETY: the caller guarantees `size` readable bytes.
        slice::from_raw_parts(part.data, part.size)
    }
}

unsafe extern "C" fn soft_sha512(
    ctx: *mut c_void,
    list: *const N20rSlice,
    count: usize,
    digest: *mut u8,
) -> i32 {
    // SAFETY: the table contract: `ctx` is this backend's storage, `list`
    // a gather list and `digest` 64 writable bytes.
    rc((|| {
        let c = backend(ctx).map_err(|_| CryptoError::InvalidInput)?;
        let list = parts(list, count)?;
        let digest = digest
            .cast::<[u8; 64]>()
            .as_mut()
            .ok_or(CryptoError::InvalidInput)?;
        c.sha512(&mut list.iter().map(|p| bytes(p)), digest)
    })())
}

unsafe extern "C" fn soft_kdf(
    ctx: *mut c_void,
    cdi: N20rKey,
    kind: u32,
    list: *const N20rSlice,
    count: usize,
    key_out: *mut N20rKey,
) -> i32 {
    // SAFETY: the table contract, as in soft_sha512; `key_out` is writable.
    rc((|| {
        let c = backend(ctx).map_err(|_| CryptoError::InvalidInput)?;
        let kind = match kind {
            0 => KeyKind::Cdi,
            1 => KeyKind::Ed25519,
            _ => return Err(CryptoError::InvalidInput),
        };
        let key_out = key_out.as_mut().ok_or(CryptoError::InvalidInput)?;
        let list = parts(list, count)?;
        let key = c.kdf(&soft_key(cdi), kind, &mut list.iter().map(|p| bytes(p)))?;
        *key_out = handle(key);
        Ok(())
    })())
}

unsafe extern "C" fn soft_public_key(ctx: *mut c_void, key: N20rKey, public_key: *mut u8) -> i32 {
    // SAFETY: the table contract; `public_key` is 32 writable bytes.
    rc((|| {
        let c = backend(ctx).map_err(|_| CryptoError::InvalidInput)?;
        let out = public_key
            .cast::<[u8; 32]>()
            .as_mut()
            .ok_or(CryptoError::InvalidInput)?;
        c.public_key(&soft_key(key), out)
    })())
}

unsafe extern "C" fn soft_sign(
    ctx: *mut c_void,
    key: N20rKey,
    message: *const u8,
    message_size: usize,
    signature: *mut u8,
) -> i32 {
    // SAFETY: the table contract; `message` is `message_size` readable
    // bytes and `signature` 64 writable ones.
    rc((|| {
        let c = backend(ctx).map_err(|_| CryptoError::InvalidInput)?;
        let message = bytes(&N20rSlice {
            data: message,
            size: message_size,
        });
        let out = signature
            .cast::<[u8; 64]>()
            .as_mut()
            .ok_or(CryptoError::InvalidInput)?;
        c.sign(&soft_key(key), message, out)
    })())
}

unsafe extern "C" fn soft_key_free(ctx: *mut c_void, key: N20rKey) {
    // SAFETY: the table contract.
    if let Ok(c) = backend(ctx) {
        c.key_free(soft_key(key));
    }
}

/// Initialises the built-in software backend in `storage` and fills
/// `crypto_out` with its table.
///
/// # Safety
/// `storage` must be null (rejected) or point to `size` writable bytes,
/// 8-byte aligned, that stay valid and unaliased while the backend is in
/// use. `crypto_out` must be null (rejected) or point to a writable
/// `n20r_crypto_t`.
#[no_mangle]
pub unsafe extern "C" fn n20r_soft_crypto_init(
    storage: *mut u8,
    size: usize,
    crypto_out: *mut N20rCrypto,
) -> N20rError {
    status((|| {
        let s = storage.cast::<Storage>();
        if s.is_null()
            || crypto_out.is_null()
            || size < size_of::<Storage>()
            || !(s as usize).is_multiple_of(align_of::<Storage>())
        {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: non-null, aligned and large enough (checked above); `write`
        // initialises without reading or dropping the old contents.
        s.write(Storage {
            magic: MAGIC,
            crypto: SoftCrypto::new(),
        });
        // SAFETY: non-null, and the caller guarantees it is writable.
        crypto_out.write(N20rCrypto {
            ctx: storage.cast(),
            sha512: Some(soft_sha512),
            kdf: Some(soft_kdf),
            public_key: Some(soft_public_key),
            sign: Some(soft_sign),
            key_free: Some(soft_key_free),
        });
        Ok(())
    })())
}

/// Imports a 32-byte root CDI into a key slot of the backend in `storage`.
///
/// # Safety
/// `storage` must be initialised by [`n20r_soft_crypto_init`]; `cdi` must be
/// null (rejected) or point to 32 readable bytes; `key_out` must be null
/// (rejected) or writable.
#[no_mangle]
pub unsafe extern "C" fn n20r_soft_crypto_import_cdi(
    storage: *mut u8,
    cdi: *const u8,
    key_out: *mut N20rKey,
) -> N20rError {
    status((|| {
        // SAFETY: as documented above.
        let c = backend(storage.cast())?;
        let cdi = cdi
            .cast::<[u8; 32]>()
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        let key_out = key_out.as_mut().ok_or(Error::InvalidArgument)?;
        *key_out = handle(c.import_cdi(cdi)?);
        Ok(())
    })())
}

/// Writes the CDI that `key` holds to `cdi_out`, e.g. the next CDI for the
/// next boot stage. `cdi_out` is the caller's to wipe.
///
/// # Safety
/// `storage` as for [`n20r_soft_crypto_import_cdi`]; `cdi_out` must be null
/// (rejected) or point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn n20r_soft_crypto_export_cdi(
    storage: *mut u8,
    key: N20rKey,
    cdi_out: *mut u8,
) -> N20rError {
    status((|| {
        // SAFETY: as documented above.
        let c = backend(storage.cast())?;
        let out = cdi_out
            .cast::<[u8; 32]>()
            .as_mut()
            .ok_or(Error::InvalidArgument)?;
        c.export_cdi(&soft_key(key), out)?;
        Ok(())
    })())
}

/// Wipes every key of the backend in `storage` and invalidates it.
///
/// # Safety
/// `storage` as for [`n20r_soft_crypto_import_cdi`].
#[no_mangle]
pub unsafe extern "C" fn n20r_soft_crypto_cleanup(storage: *mut u8) -> N20rError {
    status((|| {
        // SAFETY: as documented above.
        let c = backend(storage.cast())?;
        *c = SoftCrypto::new();
        // SAFETY: `backend` checked the storage is initialised and aligned.
        core::ptr::addr_of_mut!((*storage.cast::<Storage>()).magic).write(0);
        Ok(())
    })())
}

/// The number of keys the backend in `storage` holds, for the tests.
///
/// # Safety
/// As for [`n20r_soft_crypto_import_cdi`].
#[cfg(test)]
pub(crate) unsafe fn keys_in_use(storage: *mut u8) -> usize {
    // SAFETY: as documented above.
    backend(storage.cast()).map_or(0, |c| c.keys_in_use())
}
