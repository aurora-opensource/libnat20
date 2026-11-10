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
//! each runs one operation of the built-in software backend directly, so
//! the probe can check, operation by operation, the contract every backend
//! must meet (`nat20::crypto`): once the operation returns, nothing it
//! touched below this frame may be left non-zero. Never part of a firmware
//! build.

use nat20::crypto::soft::{KeySlots, SoftCrypto};
use nat20::{Crypto, Digest, Error, KeyKind};

use crate::{status, N20rError};

/// `n20r_probe_backend_op` operations.
const OP_SHA512: u32 = 0;
const OP_KDF: u32 = 1;
const OP_PUBLIC_KEY: u32 = 2;
const OP_SIGN: u32 = 3;

/// The backend's storage: static, so that its key slots are not counted as
/// stack residue.
static mut SLOTS: KeySlots<3> = KeySlots::new();

/// Runs backend operation `op` with the 32 secret bytes at `secret` as the
/// CDI and writes up to 64 bytes of its result to `out`.
///
/// The backend lives in static storage, so only frames are on the probe's
/// stack. It is reset (which wipes the keys of the previous run) and given
/// the keys the operation needs before the operation runs, and nothing runs
/// after it: whatever is left below this frame is the operation's.
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
        // SAFETY: the caller guarantees 32 readable bytes.
        let cdi_bytes = secret
            .cast::<[u8; 32]>()
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        // SAFETY: the caller guarantees 64 writable bytes.
        let out = out
            .cast::<[u8; 64]>()
            .as_mut()
            .ok_or(Error::InvalidArgument)?;
        // SAFETY: the probe is single-threaded and calls one operation at a
        // time, so nothing else accesses the storage meanwhile.
        let slots = &mut *core::ptr::addr_of_mut!(SLOTS);
        *slots = KeySlots::new();
        let mut crypto = SoftCrypto::new(slots);
        let cdi = crypto.import_cdi(cdi_bytes)?;
        let message: &[u8] = b"nat20 stack probe";
        let context: [&[u8]; 1] = [b"stack probe"];
        let (public_key, _) = out.split_at_mut(32);
        let public_key =
            <&mut [u8; 32]>::try_from(public_key).map_err(|_| Error::InvalidArgument)?;
        match op {
            OP_SHA512 => crypto.sha512(&mut [&cdi_bytes[..], message].iter().copied(), out)?,
            OP_KDF => {
                crypto.kdf(&cdi, KeyKind::Cdi, &mut context.iter().copied())?;
            }
            OP_PUBLIC_KEY => {
                let key = crypto.kdf(&cdi, KeyKind::Ed25519, &mut context.iter().copied())?;
                crypto.public_key(&key, public_key)?;
            }
            OP_SIGN => {
                let key = crypto.kdf(&cdi, KeyKind::Ed25519, &mut context.iter().copied())?;
                crypto.sign(&key, message, out)?;
            }
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    })())
}
