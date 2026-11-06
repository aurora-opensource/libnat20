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
//! The library needs SHA-512, a key derivation function and Ed25519
//! signing. Keys are opaque handles ([`Crypto::Key`]): the library never
//! sees a secret, so a backend may keep its keys in a hardware engine or a
//! secure element. That is the model of the C libnat20 `crypto.h`, and the
//! key derivation is the same, so a given CDI yields the same keys and
//! certificates whichever backend computes them.
//!
//! Digest inputs are gather lists, mirroring the C
//! `n20_crypto_gather_list_t`, so implementations backed by multi-update
//! hardware engines need no intermediate buffers. A gather list is an
//! iterator over the parts (`&mut dyn Iterator<Item = &[u8]>`): callers
//! compose it by chaining, and each backend is compiled once rather than
//! for every caller's iterator type.
//!
//! The software implementation (`soft::SoftCrypto`) lives behind the
//! `soft-crypto` feature.
//!
//! # Key slots
//!
//! The library holds at most [`MIN_KEY_SLOTS`] (3) keys at any time,
//! counting the CDI its caller passes in: issuing the next-stage
//! certificate derives the next CDI first, then one attestation key at a
//! time, each freed before the next is derived. A backend without dynamic
//! allocation can therefore reserve three key slots and never run out.
//! Every key the library derives is freed before the call returns, except
//! the next CDI, which goes to the caller.
//!
//! # Secrets
//!
//! A backend must not leave secrets behind: when a [`Crypto`] method
//! returns, on success or on error, nothing it computed from a key may be
//! left in memory it does not own, which includes the stack below its
//! caller and the registers a call may clobber. Its outputs are written
//! only to the buffers it is given, and a freed key is wiped. The software
//! backend gets there with [`scrubbed`]; a hardware backend typically by
//! keeping its keys in the engine. The library itself handles no secret
//! bytes, only handles, so beyond the backend there is nothing to wipe.
//! It has no panics either: a panic in a backend would never come back to
//! wipe anything.

mod scrub;
#[cfg(feature = "soft-crypto")]
pub mod soft;

pub use scrub::scrubbed;

use core::iter::once;

/// Errors reported by crypto implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Initialization of the crypto backend failed.
    InitializationFailed,
    /// An input violated an implementation limit (e.g. message too long).
    InvalidInput,
    /// A key handle does not name a key of the kind the operation needs.
    InvalidKey,
    /// The backend has no free key slot.
    NoKeySlot,
    /// Post-signing verification failed (`verify-after-sign` feature),
    /// indicating a computation fault.
    SignatureVerification,
    /// Implementation-specific error code (for hardware backends).
    Backend(u32),
}

/// The most keys the library holds at once, the root CDI included (see the
/// [module](self#key-slots)).
pub const MIN_KEY_SLOTS: usize = 3;

/// What a derived key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyKind {
    /// A CDI: the input of further derivations.
    Cdi = 0,
    /// An Ed25519 key pair, for signing.
    Ed25519 = 1,
}

/// SHA-512 over a gather list.
pub trait Digest {
    /// Computes SHA-512 over the concatenation of `parts`, which are
    /// public.
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError>;
}

/// Key derivation and Ed25519 signing on opaque key handles.
///
/// Implementations must keep the secrets invariant of the
/// [module](self#secrets), and must provide at least [`MIN_KEY_SLOTS`]
/// keys at a time.
pub trait Crypto: Digest {
    /// An opaque key handle. Each key is freed exactly once, with
    /// [`key_free`](Self::key_free), which takes it by value.
    type Key;

    /// Derives a key of `kind` from `cdi`, a [`KeyKind::Cdi`] key, and the
    /// concatenation of `context`:
    /// `HKDF-Expand-SHA512(prk = cdi, info = context, L = 32)`, which is
    /// the next CDI or the RFC 8032 seed of the key pair. The same as the
    /// `kdf` of C libnat20's BoringSSL backend.
    fn kdf(
        &mut self,
        cdi: &Self::Key,
        kind: KeyKind,
        context: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<Self::Key, CryptoError>;

    /// Writes the public key of `key`, a [`KeyKind::Ed25519`] key.
    fn public_key(&mut self, key: &Self::Key, public_key: &mut [u8; 32])
        -> Result<(), CryptoError>;

    /// Signs `message` with `key`, a [`KeyKind::Ed25519`] key (RFC 8032).
    ///
    /// The message is one slice: Ed25519 hashes it twice, so a gather list,
    /// which can be walked only once, would have to be copied anyway.
    fn sign(
        &mut self,
        key: &Self::Key,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError>;

    /// Frees `key` and wipes it.
    fn key_free(&mut self, key: Self::Key);
}

/// Runs `f` on `key`, then frees `key`, on every path.
pub fn with_key<C: Crypto + ?Sized, R>(
    c: &mut C,
    key: C::Key,
    f: impl FnOnce(&mut C, &C::Key) -> R,
) -> R {
    let result = f(c, &key);
    c.key_free(key);
    result
}

/// HMAC-SHA-512 (RFC 2104) on [`Digest::sha512`], for public keys and
/// data: nothing it computes is wiped.
pub fn hmac_sha512<D: Digest + ?Sized>(
    d: &mut D,
    key: &[u8],
    parts: &mut dyn Iterator<Item = &[u8]>,
    out: &mut [u8; 64],
) -> Result<(), CryptoError> {
    let mut block = [0u8; 128];
    if key.len() > block.len() {
        let mut hashed = [0u8; 64];
        d.sha512(&mut once(key), &mut hashed)?;
        for (b, k) in block.iter_mut().zip(hashed) {
            *b = k;
        }
    } else {
        for (b, k) in block.iter_mut().zip(key) {
            *b = *k;
        }
    }
    let mut pad = block.map(|b| b ^ 0x36);
    let mut inner = [0u8; 64];
    d.sha512(&mut once(&pad[..]).chain(parts.map(shorten)), &mut inner)?;
    pad = block.map(|b| b ^ 0x5c);
    d.sha512(&mut [&pad[..], &inner[..]].iter().copied(), out)
}

/// Lets a gather list's parts join a chain with shorter-lived ones.
fn shorten<'s, 'l: 's>(part: &'l [u8]) -> &'s [u8] {
    part
}

/// HKDF-Expand with SHA-512 (RFC 5869, section 2.3), for public inputs.
///
/// `info` is a gather list; the effective info string is the concatenation
/// of its parts. `okm.len()` must not exceed 255 * 64 bytes.
pub fn hkdf_expand_sha512<D: Digest + ?Sized>(
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
        let mut parts = once(prev.get(..prev_len).unwrap_or_default())
            .chain(info.iter().copied())
            .chain(once(&counter[..]));
        let mut block = [0u8; 64];
        hmac_sha512(d, prk, &mut parts, &mut block)?;
        for (o, b) in chunk.iter_mut().zip(block) {
            *o = b;
        }
        prev = block;
        prev_len = prev.len();
    }
    Ok(())
}

/// Full HKDF (extract + expand) with SHA-512 (RFC 5869), for public inputs.
pub fn hkdf_sha512<D: Digest + ?Sized>(
    d: &mut D,
    ikm: &[u8],
    salt: &[u8],
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let mut prk = [0u8; 64];
    hmac_sha512(d, salt, &mut once(ikm), &mut prk)?;
    hkdf_expand_sha512(d, &prk, info, okm)
}
