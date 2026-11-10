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

//! Software crypto backend: `sha2`, `hmac` and `ed25519-dalek`, with keys
//! in a fixed number of slots.
//!
//! The slots are a [`KeySlots`] the caller owns, and the backend,
//! [`SoftCrypto`], borrows them: a move of a value holding live keys would
//! leave a copy of them behind, which nothing wipes, so the storage must
//! not move while it holds any. Each key handle ([`SoftKey`]) carries the
//! borrow, so while a key is live, the compiler rejects a move of its
//! storage; once every key is freed, which wipes it, the storage is all
//! zeros. A key that is never freed is wiped when its storage is dropped,
//! and only then.
//!
//! ```
//! use nat20::crypto::soft::{KeySlots, SoftCrypto};
//! use nat20::Crypto;
//!
//! let mut slots = KeySlots::<3>::new();
//! let mut c = SoftCrypto::new(&mut slots);
//! let cdi = c.import_cdi(&[0x11; 32])?;
//! c.key_free(cdi);
//! let moved = slots; // Fine: no key is live, and the slots are zeros.
//! # Ok::<(), nat20::CryptoError>(())
//! ```
//!
//! A move while a key is live does not compile:
//!
//! ```compile_fail,E0505
//! # use nat20::crypto::soft::{KeySlots, SoftCrypto};
//! # use nat20::Crypto;
//! let mut slots = KeySlots::<3>::new();
//! let mut c = SoftCrypto::new(&mut slots);
//! let cdi = c.import_cdi(&[0x11; 32])?;
//! let moved = slots; // error: `slots` is borrowed by `cdi`
//! c.key_free(cdi);
//! # Ok::<(), nat20::CryptoError>(())
//! ```

use core::marker::PhantomData;

use ed25519_dalek::{Signer as _, SigningKey};
use hmac::digest::generic_array::GenericArray;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha512};
use zeroize::Zeroize;

use super::{scrubbed, Crypto, CryptoError, Digest, KeyKind, MIN_KEY_SLOTS};

/// Stack the digest and key derivation operations reach below the method's
/// frame, with margin; what [`scrubbed`] wipes after each.
/// `tools/stack-probe.sh` measures the depths (on armv7, about 2.2 KiB) and
/// checks the sizes cover them.
const DIGEST_STACK: usize = 3072;
/// As [`DIGEST_STACK`], for the Ed25519 operations (about 5.7 KiB; 9 KiB
/// when the signature is verified as well).
#[cfg(not(feature = "verify-after-sign"))]
const ED25519_STACK: usize = 7168;
/// See the other variant.
#[cfg(feature = "verify-after-sign")]
const ED25519_STACK: usize = 10240;
/// As [`DIGEST_STACK`], for copying a CDI into or out of a slot: the frame
/// of the `memcpy` the copy calls, with margin.
const COPY_STACK: usize = 256;

/// One key slot: a CDI, or the RFC 8032 seed of an Ed25519 key pair.
struct Slot {
    kind: Option<KeyKind>,
    bytes: [u8; 32],
}

impl Slot {
    const EMPTY: Slot = Slot {
        kind: None,
        bytes: [0; 32],
    };
}

/// A key held by [`SoftCrypto`]: the index of its slot. It carries the
/// borrow of the slots (`'a`), so they cannot move while it is live.
#[derive(Debug, PartialEq, Eq)]
pub struct SoftKey<'a> {
    index: usize,
    slots: PhantomData<&'a ()>,
}

impl SoftKey<'_> {
    /// The slot index, for handing the key across an FFI.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The key in slot `index`, as handed across an FFI.
    pub fn from_index(index: usize) -> Self {
        SoftKey {
            index,
            slots: PhantomData,
        }
    }
}

/// Storage for the keys of a [`SoftCrypto`]: `SLOTS` key slots, by default
/// the [`MIN_KEY_SLOTS`] the library needs. No allocation: the slots are
/// part of the value. A key is wiped when it is freed, and every slot when
/// the value is dropped. The [module](self) says why it must not move.
pub struct KeySlots<const SLOTS: usize = MIN_KEY_SLOTS> {
    slots: [Slot; SLOTS],
}

impl<const SLOTS: usize> Default for KeySlots<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> Drop for KeySlots<SLOTS> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            slot.bytes.zeroize();
            slot.kind = None;
        }
    }
}

impl<const SLOTS: usize> KeySlots<SLOTS> {
    /// Storage with all slots free.
    pub const fn new() -> Self {
        KeySlots {
            slots: [Slot::EMPTY; SLOTS],
        }
    }

    /// The number of slots that hold a key.
    pub fn keys_in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.kind.is_some()).count()
    }
}

/// Software crypto implementation, with its keys in the [`KeySlots`] it
/// borrows. The value itself holds no secret and may move freely.
///
/// Every operation runs [`scrubbed`]. The secrets invariant then also rests
/// on `sha2`, `hmac` and `ed25519-dalek` not panicking, which their bounds
/// checks do not let the compiler prove.
pub struct SoftCrypto<'a, const SLOTS: usize = MIN_KEY_SLOTS> {
    slots: &'a mut [Slot; SLOTS],
}

impl<'a, const SLOTS: usize> SoftCrypto<'a, SLOTS> {
    /// A backend keeping its keys in `slots`.
    pub fn new(slots: &'a mut KeySlots<SLOTS>) -> Self {
        SoftCrypto {
            slots: &mut slots.slots,
        }
    }

    /// Takes a copy of `cdi` (a root CDI, read in place) into a free slot.
    pub fn import_cdi(&mut self, cdi: &[u8; 32]) -> Result<SoftKey<'a>, CryptoError> {
        let index = self.free_slot()?;
        let slot = self.slots.get_mut(index).ok_or(CryptoError::NoKeySlot)?;
        // Scrubbed, as the copy passes through registers.
        scrubbed::<COPY_STACK, _>(|| slot.bytes.copy_from_slice(cdi));
        slot.kind = Some(KeyKind::Cdi);
        Ok(SoftKey::from_index(index))
    }

    /// Writes the CDI `key` holds to `out`, e.g. to hand the next CDI to
    /// the next boot stage. `out` is the caller's to wipe.
    pub fn export_cdi(&mut self, key: &SoftKey, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        let cdi = self.bytes(key, KeyKind::Cdi)?;
        scrubbed::<COPY_STACK, _>(|| out.copy_from_slice(cdi));
        Ok(())
    }

    /// The number of slots that hold a key.
    pub fn keys_in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.kind.is_some()).count()
    }

    fn free_slot(&self) -> Result<usize, CryptoError> {
        self.slots
            .iter()
            .position(|s| s.kind.is_none())
            .ok_or(CryptoError::NoKeySlot)
    }

    fn bytes(&self, key: &SoftKey, kind: KeyKind) -> Result<&[u8; 32], CryptoError> {
        match self.slots.get(key.index) {
            Some(slot) if slot.kind == Some(kind) => Ok(&slot.bytes),
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

impl<const SLOTS: usize> Digest for SoftCrypto<'_, SLOTS> {
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        scrubbed::<DIGEST_STACK, _>(|| {
            let mut h = Sha512::new();
            for p in parts {
                h.update(p);
            }
            // Hash straight into `out`: a returned array would be a copy.
            FixedOutput::finalize_into(h, GenericArray::from_mut_slice(out));
            Ok(())
        })
    }
}

impl<'a, const SLOTS: usize> Crypto for SoftCrypto<'a, SLOTS> {
    type Key = SoftKey<'a>;

    fn kdf(
        &mut self,
        cdi: &SoftKey<'a>,
        kind: KeyKind,
        context: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<SoftKey<'a>, CryptoError> {
        let index = self.free_slot()?;
        let (prk, slot) = {
            // Two distinct slots: the input key and the free one.
            if index == cdi.index {
                return Err(CryptoError::InvalidKey);
            }
            let (lo, hi) = self
                .slots
                .split_at_mut_checked(index.max(cdi.index))
                .ok_or(CryptoError::InvalidKey)?;
            let (input, out) = if cdi.index < index {
                (lo.get(cdi.index), hi.first_mut())
            } else {
                (hi.first(), lo.get_mut(index))
            };
            match (input, out) {
                (Some(input), Some(out)) if input.kind == Some(KeyKind::Cdi) => (&input.bytes, out),
                _ => return Err(CryptoError::InvalidKey),
            }
        };
        scrubbed::<DIGEST_STACK, _>(|| {
            // One HKDF-Expand block, T(1) = HMAC(prk, info || 0x01), of
            // which the key is the first 32 bytes.
            let mut m =
                Hmac::<Sha512>::new_from_slice(prk).map_err(|_| CryptoError::InvalidInput)?;
            for p in context {
                m.update(p);
            }
            m.update(&[1]);
            let mut block = [0u8; 64];
            FixedOutput::finalize_into(m, GenericArray::from_mut_slice(&mut block));
            for (b, t) in slot.bytes.iter_mut().zip(block) {
                *b = t;
            }
            block.zeroize();
            Ok(())
        })?;
        slot.kind = Some(kind);
        Ok(SoftKey::from_index(index))
    }

    fn public_key(
        &mut self,
        key: &SoftKey<'a>,
        public_key: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let seed = self.bytes(key, KeyKind::Ed25519)?;
        scrubbed::<ED25519_STACK, _>(|| {
            let key = SigningKey::from_bytes(seed);
            public_key.copy_from_slice(key.verifying_key().as_bytes());
            Ok(())
        })
    }

    fn sign(
        &mut self,
        key: &SoftKey<'a>,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let seed = self.bytes(key, KeyKind::Ed25519)?;
        scrubbed::<ED25519_STACK, _>(|| {
            let key = SigningKey::from_bytes(seed);
            let sig = key.sign(message);

            // Checked before it is released: a faulty signature over a
            // message also signed correctly can give the key away.
            #[cfg(feature = "verify-after-sign")]
            key.verifying_key()
                .verify_strict(message, &sig)
                .map_err(|_| CryptoError::SignatureVerification)?;

            signature.copy_from_slice(&sig.to_bytes());
            Ok(())
        })
    }

    fn key_free(&mut self, key: SoftKey<'a>) {
        if let Some(slot) = self.slots.get_mut(key.index) {
            slot.bytes.zeroize();
            slot.kind = None;
        }
    }
}
