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
//! `soft-crypto` feature.

#[cfg(feature = "mono-crypto")]
pub mod mono;
#[cfg(feature = "soft-crypto")]
pub mod soft;

use core::iter::once;

use zeroize::{Zeroize, ZeroizeOnDrop};

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
#[derive(Default)]
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
pub trait Digest {
    /// Computes SHA-512 over the concatenation of `parts`.
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError>;

    /// Computes HMAC-SHA-512 with `key` over the concatenation of `parts`.
    fn hmac_sha512(
        &mut self,
        key: &[u8],
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError>;
}

/// Deterministic Ed25519 (RFC 8032) signing.
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

/// HKDF-Expand with SHA-512 (RFC 5869, section 2.3).
///
/// `info` is a gather list; the effective info string is the concatenation of
/// its parts. Intermediate blocks are zeroized. `okm.len()` must not exceed
/// 255 * 64 bytes.
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
    let mut prev = [0u8; 64];
    let mut prev_len = 0;
    for (i, chunk) in okm.chunks_mut(64).enumerate() {
        let counter = [(i + 1) as u8];
        let mut parts = once(&prev[..prev_len])
            .chain(info.iter().copied())
            .chain(once(&counter[..]));

        let mut block = [0u8; 64];
        let result = d.hmac_sha512(prk, &mut parts, &mut block);
        if let Err(e) = result {
            prev.zeroize();
            block.zeroize();
            return Err(e);
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
        prev = block;
        block.zeroize();
        prev_len = prev.len();
    }
    prev.zeroize();
    Ok(())
}

/// Full HKDF (extract + expand) with SHA-512 (RFC 5869).
///
/// The intermediate PRK is zeroized.
pub fn hkdf_sha512<D: Digest>(
    d: &mut D,
    ikm: &[u8],
    salt: &[u8],
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let mut prk = [0u8; 64];
    let result = d
        .hmac_sha512(salt, &mut [ikm].iter().copied(), &mut prk)
        .and_then(|()| hkdf_expand_sha512(d, &prk, info, okm));
    prk.zeroize();
    result
}
