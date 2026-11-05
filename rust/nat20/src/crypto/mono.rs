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

use super::{scrubbed, truncate_into, CryptoError, Digest, Ed25519Signer, Seed32};
use zeroize::Zeroize;

/// Stack the digest operations reach below the method's frame, with margin;
/// what [`scrubbed`] wipes after each. `tools/stack-probe.sh` measures the
/// depths (on armv7, about 850 bytes) and checks the sizes cover them.
const DIGEST_STACK: usize = 1280;
/// As [`DIGEST_STACK`], for the Ed25519 operations (about 1.5 KiB; 2 KiB
/// when the signature is verified as well).
#[cfg(not(feature = "verify-after-sign"))]
const ED25519_STACK: usize = 2048;
/// See the other variant.
#[cfg(feature = "verify-after-sign")]
const ED25519_STACK: usize = 2560;

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
    #[cfg(feature = "verify-after-sign")]
    fn crypto_ed25519_check(
        signature: *const u8,
        public_key: *const u8,
        message: *const u8,
        message_size: usize,
    ) -> i32;
    fn crypto_wipe(secret: *mut u8, size: usize);
    /// Size-lock helper from the build-script glue; returns nonzero when the
    /// opaque context buffers above are large enough.
    fn nat20_mono_ctx_sizes_ok(sha_ctx_size: usize, hmac_ctx_size: usize) -> i32;
}

/// Crypto backend backed by Monocypher (feature `mono-crypto`).
///
/// Every operation runs [`scrubbed`]. Monocypher is C and the glue here has
/// no panicking paths, so nothing can stop the scrub from running.
pub struct MonoCrypto;

impl MonoCrypto {
    /// Creates the backend after checking the opaque context buffer sizes
    /// against the actual Monocypher struct sizes.
    pub fn new() -> Result<Self, CryptoError> {
        // SAFETY: takes two sizes and reads no memory.
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
        scrubbed::<DIGEST_STACK, _>(|| {
            let mut ctx = Sha512Ctx([0; 256]);
            // SAFETY: `ctx` is large and aligned enough for the C context
            // (checked in `new`); every pointer/length pair comes from a
            // live slice, and `out` holds the 64 bytes final writes.
            unsafe {
                crypto_sha512_init(&mut ctx);
                for p in parts {
                    crypto_sha512_update(&mut ctx, p.as_ptr(), p.len());
                }
                crypto_sha512_final(&mut ctx, out.as_mut_ptr());
            }
            Ok(())
        })
    }

    fn hmac_sha512(
        &mut self,
        key: &[u8],
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        scrubbed::<DIGEST_STACK, _>(|| {
            if out.len() > 64 {
                return Err(CryptoError::InvalidInput);
            }
            let mut ctx = HmacCtx([0; 416]);
            let mut mac = [0u8; 64];
            // SAFETY: as in `sha512`; `mac` holds the 64 bytes final writes.
            unsafe {
                crypto_sha512_hmac_init(&mut ctx, key.as_ptr(), key.len());
                for p in parts {
                    crypto_sha512_hmac_update(&mut ctx, p.as_ptr(), p.len());
                }
                crypto_sha512_hmac_final(&mut ctx, mac.as_mut_ptr());
                // The context holds key material.
                crypto_wipe(ctx.0.as_mut_ptr(), ctx.0.len());
            }
            truncate_into(out, &mac);
            mac.zeroize();
            Ok(())
        })
    }
}

impl Ed25519Signer for MonoCrypto {
    fn public_key(&mut self, seed: &Seed32, public_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        scrubbed::<ED25519_STACK, _>(|| {
            // crypto_ed25519_key_pair wipes the seed input; give it a copy.
            let mut seed_copy = *seed.as_bytes();
            let mut secret_key = [0u8; 64];
            // SAFETY: fixed-size arrays of exactly the sizes the C function
            // takes.
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
        })
    }

    fn sign(
        &mut self,
        seed: &Seed32,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        scrubbed::<ED25519_STACK, _>(|| {
            let mut seed_copy = *seed.as_bytes();
            let mut secret_key = [0u8; 64];
            let mut public_key = [0u8; 32];
            let mut sig = [0u8; 64];
            // SAFETY: fixed-size arrays of exactly the sizes the C functions
            // take, and `message` is a live slice.
            unsafe {
                crypto_ed25519_key_pair(
                    secret_key.as_mut_ptr(),
                    public_key.as_mut_ptr(),
                    seed_copy.as_mut_ptr(),
                );
                crypto_ed25519_sign(
                    sig.as_mut_ptr(),
                    secret_key.as_ptr(),
                    message.as_ptr(),
                    message.len(),
                );
            }
            secret_key.zeroize();
            seed_copy.zeroize();

            // Checked before it is released: a faulty signature over a
            // message also signed correctly can give the key away.
            #[cfg(feature = "verify-after-sign")]
            {
                // SAFETY: as above.
                let rc = unsafe {
                    crypto_ed25519_check(
                        sig.as_ptr(),
                        public_key.as_ptr(),
                        message.as_ptr(),
                        message.len(),
                    )
                };
                if rc != 0 {
                    sig.zeroize();
                    return Err(CryptoError::SignatureVerification);
                }
            }

            // Array to array: a memcpy with no length check left.
            signature.copy_from_slice(&sig);
            Ok(())
        })
    }
}
