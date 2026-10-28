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

//! Software crypto backend: `sha2`, `hmac`, and `ed25519-dalek`.

use ed25519_dalek::{Signer as _, SigningKey};
use hmac::digest::generic_array::GenericArray;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha512};

use super::{CryptoError, Digest, Ed25519Signer, Seed32};

/// Zero-sized software crypto implementation.
///
/// Monomorphized use of this type compiles to direct calls into `sha2`,
/// `hmac`, and `ed25519-dalek` with no indirection.
pub struct SoftCrypto;

impl Digest for SoftCrypto {
    fn sha512(
        &mut self,
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let mut h = Sha512::new();
        for p in parts {
            h.update(p);
        }
        // Hash straight into `out`: a returned array would be a stack copy
        // nobody wipes.
        FixedOutput::finalize_into(h, GenericArray::from_mut_slice(out));
        Ok(())
    }

    fn hmac_sha512(
        &mut self,
        key: &[u8],
        parts: &mut dyn Iterator<Item = &[u8]>,
        out: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        // HMAC accepts keys of any length.
        let mut m = Hmac::<Sha512>::new_from_slice(key).map_err(|_| CryptoError::InvalidInput)?;
        for p in parts {
            m.update(p);
        }
        // As in `sha512`; HMAC outputs here are HKDF blocks, i.e. key
        // material.
        FixedOutput::finalize_into(m, GenericArray::from_mut_slice(out));
        Ok(())
    }
}

impl Ed25519Signer for SoftCrypto {
    fn public_key(&mut self, seed: &Seed32, public_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        let key = SigningKey::from_bytes(seed.as_bytes());
        public_key.copy_from_slice(key.verifying_key().as_bytes());
        Ok(())
    }

    fn sign(
        &mut self,
        seed: &Seed32,
        message: &[u8],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let key = SigningKey::from_bytes(seed.as_bytes());
        let sig = key.sign(message);
        signature.copy_from_slice(&sig.to_bytes());

        #[cfg(feature = "verify-after-sign")]
        key.verifying_key()
            .verify_strict(message, &sig)
            .map_err(|_| CryptoError::SignatureVerification)?;

        Ok(())
    }
}
