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

//! Entry points for `tools/stack-probe.sh` only (feature `stack-probe`):
//! each runs one operation of the crypto backend directly, so the probe can
//! check the backend invariant of `nat20::crypto` operation by operation:
//! once the operation returns, nothing it touched below this frame may be
//! left non-zero. Never part of a firmware build.

use nat20::crypto::Seed32;
use nat20::{Digest, Ed25519Signer};

use crate::{crypto_backend, status, Error, N20rError};

/// `n20r_probe_backend_op` operations.
const OP_SHA512: u32 = 0;
const OP_HMAC: u32 = 1;
const OP_PUBLIC_KEY: u32 = 2;
const OP_SIGN: u32 = 3;

/// Runs backend operation `op` with the 32 secret bytes at `secret` as its
/// key (the HMAC key, or the Ed25519 seed) and writes up to 64 bytes of its
/// result to `out`.
///
/// # Safety
/// `secret` must point to 32 readable bytes and `out` to 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn n20r_probe_backend_op(
    op: u32,
    secret: *const u8,
    out: *mut u8,
) -> N20rError {
    status((|| {
        if secret.is_null() || out.is_null() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: the caller guarantees 32 readable bytes; `Seed32` is
        // `repr(transparent)` over `[u8; 32]`, so the key is used in place.
        let seed = &*secret.cast::<Seed32>();
        let key = seed.as_bytes();
        // SAFETY: the caller guarantees 64 writable bytes.
        let out = &mut *out.cast::<[u8; 64]>();
        let mut crypto = crypto_backend()?;
        let message: &[u8] = b"nat20 stack probe";
        match op {
            OP_SHA512 => crypto.sha512(&mut [&key[..], message].iter().copied(), out)?,
            OP_HMAC => crypto.hmac_sha512(key, &mut [message].iter().copied(), &mut out[..])?,
            OP_PUBLIC_KEY => {
                let (public_key, _) = out.split_at_mut(32);
                let public_key = public_key.try_into().map_err(|_| Error::InvalidArgument)?;
                crypto.public_key(seed, public_key)?;
            }
            OP_SIGN => crypto.sign(seed, message, out)?,
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    })())
}
