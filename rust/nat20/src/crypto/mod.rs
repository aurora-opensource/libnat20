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

//! Pluggable crypto boundary.
//!
//! The library needs exactly three primitives: SHA-512, HMAC-SHA-512, and
//! Ed25519 signing. They are expressed as the [`Digest`] and
//! [`Ed25519Signer`] traits so that hardware implementations can be plugged
//! in later; HKDF is implemented here generically on top of [`Digest`], so
//! implementations never provide it themselves.
//!
//! The digest inputs are gather lists, mirroring the C
//! `n20_crypto_gather_list_t`, so implementations backed by multi-update
//! hardware engines need no intermediate buffers. A gather list is an
//! iterator over the parts (`&mut dyn Iterator<Item = &[u8]>`): callers
//! compose it by chaining, without a bound on the number of parts, and
//! each backend is compiled once rather than for every caller's iterator
//! type.
//!
//! The software implementation ([`soft::SoftCrypto`]) lives behind the
//! `soft-crypto` feature, the Monocypher one (`mono::MonoCrypto`) behind
//! `mono-crypto`.
//!
//! # Secrets
//!
//! Two invariants keep secrets out of memory nobody wipes:
//!
//! 1. **Backends.** When a [`Digest`] or [`Ed25519Signer`] method returns,
//!    on success or on error, nothing it derived from its inputs is left in
//!    memory it does not own: not in the stack below its caller, not in the
//!    registers a call may clobber. Its outputs are written only to the
//!    buffers it is given. The built-in backends get there with
//!    [`scrubbed`]; a hardware backend typically by keeping keys in the
//!    engine.
//! 2. **Everything else.** Outside the backends a secret only ever lives in
//!    a container that is filled in place through `&mut`, read through `&`,
//!    never moved or copied, and wiped when it goes out of scope:
//!    [`Seed32`], [`CdiSecret`](crate::CdiSecret), a caller's buffer. The
//!    code between a secret's creation and its wiping does not panic: a
//!    panic would never come back to wipe it.
//!
//! So once an operation of this crate returns, the only copies of a secret
//! are in the containers its caller owns.

#[cfg(feature = "mono-crypto")]
pub mod mono;
mod scrub;
#[cfg(feature = "soft-crypto")]
pub mod soft;

pub use scrub::scrubbed;

use core::iter::once;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Errors reported by crypto implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Initialization of the crypto backend failed.
    InitializationFailed,
    /// An input violated an implementation limit (e.g. message too long).
    InvalidInput,
    /// Post-signing verification failed (`verify-after-sign` feature),
    /// indicating a computation fault.
    SignatureVerification,
    /// Implementation-specific error code (for hardware backends).
    Backend(u32),
}

/// An RFC 8032 Ed25519 private key seed. Zeroized on drop.
///
/// Like `CdiSecret`, filled in place rather than returned; [`Default`] (all
/// zeros) gives the container. The Zeroize impls are hand-written (not
/// derived) to keep proc-macro crates out of the dependency graph; see the
/// note in derive.rs.
///
/// As for `CdiSecret`, the layout is guaranteed to be that of `[u8; 32]`
/// (`repr(transparent)`), so 32 bytes the caller owns can be used as a
/// `&Seed32` in place.
#[derive(Default)]
#[repr(transparent)]
pub struct Seed32(pub(crate) [u8; 32]);

impl Zeroize for Seed32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Seed32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Seed32 {}

impl Seed32 {
    /// Wraps raw seed bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Seed32(bytes)
    }

    /// The raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// SHA-512 and HMAC-SHA-512 over gather lists.
///
/// Implementations must meet the backend invariant of the
/// [module](self#secrets).
pub trait Digest {
    /// Computes SHA-512 over the concatenation of `parts`.
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError>;

    /// Computes HMAC-SHA-512 with `key` over the concatenation of `parts`
    /// and writes its first `out.len()` bytes to `out`, which must not be
    /// longer than 64 bytes (`InvalidInput`).
    ///
    /// Truncating here, rather than in the caller, keeps the rest of the
    /// MAC, which is key material in HKDF, inside the backend.
    fn hmac_sha512(
        &mut self,
        key: &[u8],
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8],
    ) -> Result<(), CryptoError>;
}

/// Deterministic Ed25519 (RFC 8032) signing.
///
/// Implementations must meet the backend invariant of the
/// [module](self#secrets).
pub trait Ed25519Signer {
    /// Derives the 32-byte public key for `seed`.
    fn public_key(&mut self, seed: &Seed32, public_key: &mut [u8; 32]) -> Result<(), CryptoError>;

    /// Signs `message` with the key derived from `seed`.
    ///
    /// The message is one slice: Ed25519 hashes it twice, so a gather list,
    /// which can be walked only once, would have to be copied anyway.
    fn sign(
        &mut self,
        seed: &Seed32,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError>;
}

/// Everything the certificate issuance API needs.
pub trait Crypto: Digest + Ed25519Signer {}
impl<T: Digest + Ed25519Signer> Crypto for T {}

/// Copies the first `out.len()` bytes of `mac` (all of it if `out` is
/// longer) into `out`: the truncation of [`Digest::hmac_sha512`], for the
/// backends. Without a panic path, unlike `copy_from_slice`, and not inlined
/// so the copy keeps knowing the two do not overlap (a `memcpy`, not the
/// larger `memmove`).
#[inline(never)]
pub(crate) fn truncate_into(out: &mut [u8], mac: &[u8; 64]) {
    for (o, m) in out.iter_mut().zip(mac) {
        *o = *m;
    }
}

/// HKDF-Expand with SHA-512 (RFC 5869, section 2.3).
///
/// `info` is a gather list; the effective info string is the concatenation of
/// its parts. `okm.len()` must not exceed 255 * 64 bytes. Each block is
/// written straight into `okm`, and T(i-1) is read back from there: no
/// copy of the key material is made. On error `okm` may hold part of the
/// output, so it must be a container that is wiped.
pub fn hkdf_expand_sha512<D: Digest>(
    d: &mut D,
    prk: &[u8],
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    if okm.len().div_ceil(64) > 255 {
        return Err(CryptoError::InvalidInput);
    }

    // T(i) = HMAC(prk, T(i-1) || info || i), with T(0) empty.
    let mut done = 0;
    let mut counter = 0u8;
    while done < okm.len() {
        counter = counter.wrapping_add(1);
        let (head, rest) = okm
            .split_at_mut_checked(done)
            .ok_or(CryptoError::InvalidInput)?;
        let prev = head.get(done.saturating_sub(64)..).unwrap_or_default();
        let block_len = rest.len().min(64);
        let block = rest.get_mut(..block_len).unwrap_or_default();
        let counter = [counter];
        let mut parts = once(prev)
            .chain(info.iter().copied())
            .chain(once(&counter[..]));
        d.hmac_sha512(prk, &mut parts, block)?;
        done += block_len;
    }
    Ok(())
}

/// Full HKDF (extract + expand) with SHA-512 (RFC 5869).
///
/// The intermediate PRK lives in a container of its own and is wiped on
/// every path out.
pub fn hkdf_sha512<D: Digest>(
    d: &mut D,
    ikm: &[u8],
    salt: &[u8],
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let mut prk = Zeroizing::new([0u8; 64]);
    d.hmac_sha512(salt, &mut [ikm].iter().copied(), &mut prk[..])?;
    hkdf_expand_sha512(d, &prk[..], info, okm)
}
