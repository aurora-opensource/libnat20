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

//! Monocypher crypto backend: SHA-512/HMAC and Ed25519 provided by the
//! vendored Monocypher C library (`third_party/monocypher`), compiled by
//! this crate's build script.
//!
//! Roughly 8 KB smaller than the `soft-crypto` backend on armv7 (see
//! `SIZE.md`): Monocypher's arithmetic is written for compactness where
//! ed25519-dalek's is unrolled for speed.
//! Both are constant-time by design; dalek has the broader audit history,
//! Monocypher 3.x was independently audited (Cure53, 2020).

#![allow(unsafe_code)]

use super::{CryptoError, Digest, Ed25519Signer, Seed32};
use zeroize::Zeroize;

// Incremental-hash contexts are opaque buffers sized and aligned to hold
// Monocypher's structs (crypto_sha512_ctx is 200 bytes, the HMAC context
// 328; sizes are locked by a build-script assertion compiled into the C
// glue, see build.rs).
#[repr(C, align(8))]
struct Sha512Ctx([u8; 256]);
#[repr(C, align(8))]
struct HmacCtx([u8; 416]);

extern "C" {
    fn crypto_sha512_init(ctx: *mut Sha512Ctx);
    fn crypto_sha512_update(ctx: *mut Sha512Ctx, message: *const u8, message_size: usize);
    fn crypto_sha512_final(ctx: *mut Sha512Ctx, hash: *mut u8);
    fn crypto_sha512_hmac_init(ctx: *mut HmacCtx, key: *const u8, key_size: usize);
    fn crypto_sha512_hmac_update(ctx: *mut HmacCtx, message: *const u8, message_size: usize);
    fn crypto_sha512_hmac_final(ctx: *mut HmacCtx, hmac: *mut u8);
    fn crypto_ed25519_key_pair(secret_key: *mut u8, public_key: *mut u8, seed: *mut u8);
    fn crypto_ed25519_sign(
        signature: *mut u8,
        secret_key: *const u8,
        message: *const u8,
        message_size: usize,
    );
    fn crypto_wipe(secret: *mut u8, size: usize);
    /// Size-lock helper from the build-script glue; returns nonzero when the
    /// opaque context buffers above are large enough.
    fn nat20_mono_ctx_sizes_ok(sha_ctx_size: usize, hmac_ctx_size: usize) -> i32;
}

/// Crypto backend backed by Monocypher (feature `mono-crypto`).
pub struct MonoCrypto;

impl MonoCrypto {
    /// Creates the backend after checking the opaque context buffer sizes
    /// against the actual Monocypher struct sizes.
    pub fn new() -> Result<Self, CryptoError> {
        let ok = unsafe {
            nat20_mono_ctx_sizes_ok(
                core::mem::size_of::<Sha512Ctx>(),
                core::mem::size_of::<HmacCtx>(),
            )
        };
        if ok != 0 {
            Ok(MonoCrypto)
        } else {
            Err(CryptoError::Backend(1))
        }
    }
}

impl Digest for MonoCrypto {
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let mut ctx = Sha512Ctx([0; 256]);
        unsafe {
            crypto_sha512_init(&mut ctx);
            for p in parts {
                crypto_sha512_update(&mut ctx, p.as_ptr(), p.len());
            }
            crypto_sha512_final(&mut ctx, out.as_mut_ptr());
        }
        Ok(())
    }

    fn hmac_sha512(
        &mut self,
        key: &[u8],
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let mut ctx = HmacCtx([0; 416]);
        unsafe {
            crypto_sha512_hmac_init(&mut ctx, key.as_ptr(), key.len());
            for p in parts {
                crypto_sha512_hmac_update(&mut ctx, p.as_ptr(), p.len());
            }
            crypto_sha512_hmac_final(&mut ctx, out.as_mut_ptr());
            // The context holds key material.
            crypto_wipe(ctx.0.as_mut_ptr(), ctx.0.len());
        }
        Ok(())
    }
}

impl Ed25519Signer for MonoCrypto {
    fn public_key(&mut self, seed: &Seed32, public_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        // crypto_ed25519_key_pair wipes the seed input; give it a copy.
        let mut seed_copy = *seed.as_bytes();
        let mut secret_key = [0u8; 64];
        unsafe {
            crypto_ed25519_key_pair(
                secret_key.as_mut_ptr(),
                public_key.as_mut_ptr(),
                seed_copy.as_mut_ptr(),
            );
        }
        secret_key.zeroize();
        seed_copy.zeroize();
        Ok(())
    }

    fn sign(
        &mut self,
        seed: &Seed32,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let mut seed_copy = *seed.as_bytes();
        let mut secret_key = [0u8; 64];
        let mut public_key = [0u8; 32];
        unsafe {
            crypto_ed25519_key_pair(
                secret_key.as_mut_ptr(),
                public_key.as_mut_ptr(),
                seed_copy.as_mut_ptr(),
            );
            crypto_ed25519_sign(
                signature.as_mut_ptr(),
                secret_key.as_ptr(),
                message.as_ptr(),
                message.len(),
            );
        }
        secret_key.zeroize();
        seed_copy.zeroize();
        Ok(())
    }
}
