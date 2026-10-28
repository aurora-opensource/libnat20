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

//! Deterministic DICE derivations and certificate issuance.
//! Port of the COSE path of `src/core/functionality.c`.
//!
//! All derivations are HKDF-Expand-SHA512 from a 32-byte CDI secret with the
//! same salts and tags as the C library, so a given CDI yields the same keys
//! and identifiers as C libnat20 with the BoringSSL crypto backend.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cose::{self, SIG_SIZE_ED25519};
// The Zeroize impls below are written by hand instead of derived: the
// zeroize_derive proc macro would drag syn/quote/proc-macro2 into the
// build, which direct-rustc environments (build systems that invoke rustc
// without cargo) cannot host-compile.
use crate::crypto::{hkdf_expand_sha512, hkdf_sha512, Crypto, CryptoError, Digest, Seed32};
use crate::cwt::{self, CwtParams};
use crate::error::Error;
use crate::open_dice::OpenDiceInput;
use crate::stream::WStream;

/// KDF tag for deriving the next-level attestation CDI (`CDI_ATTEST_STR`).
pub const CDI_ATTEST: &[u8] = b"CDI_Attest";
/// KDF tag for deriving an attestation key pair (`ATTEST_KEY_PAIR_STR`).
pub const ATTEST_KEY_PAIR: &[u8] = b"Key Pair Attest";
/// HKDF info for deriving a CDI_ID from a public key (`ID_STR`).
pub const ID_INFO: &[u8] = b"ID";

/// Salt for asymmetric key derivation (`ASYM_SALT`, functionality.c).
pub const ASYM_SALT: [u8; 64] = [
    0x63, 0xb6, 0xa0, 0x4d, 0x2c, 0x07, 0x7f, 0xc1, 0x0f, 0x63, 0x9f, 0x21, 0xda, 0x79, 0x38, 0x44,
    0x35, 0x6c, 0xc2, 0xb0, 0xb4, 0x41, 0xb3, 0xa7, 0x71, 0x24, 0x03, 0x5c, 0x03, 0xf8, 0xe1, 0xbe,
    0x60, 0x35, 0xd3, 0x1f, 0x28, 0x28, 0x21, 0xa7, 0x45, 0x0a, 0x02, 0x22, 0x2a, 0xb1, 0xb3, 0xcf,
    0xf1, 0x67, 0x9b, 0x05, 0xab, 0x1c, 0xa5, 0xd1, 0xaf, 0xfb, 0x78, 0x9c, 0xcd, 0x2b, 0x0b, 0x3b,
];

/// Salt for CDI_ID derivation (`ID_SALT`, functionality.c).
pub const ID_SALT: [u8; 64] = [
    0xdb, 0xdb, 0xae, 0xbc, 0x80, 0x20, 0xda, 0x9f, 0xf0, 0xdd, 0x5a, 0x24, 0xc8, 0x3a, 0xa5, 0xa5,
    0x42, 0x86, 0xdf, 0xc2, 0x63, 0x03, 0x1e, 0x32, 0x9b, 0x4d, 0xa1, 0x48, 0x43, 0x06, 0x59, 0xfe,
    0x62, 0xcd, 0xb5, 0xb7, 0xe1, 0xe0, 0x0f, 0xc6, 0x80, 0x30, 0x67, 0x11, 0xeb, 0x44, 0x4a, 0xf7,
    0x72, 0x09, 0x35, 0x94, 0x96, 0xfc, 0xff, 0x1d, 0xb9, 0x52, 0x0b, 0xa5, 0x1c, 0x7b, 0x29, 0xea,
];

/// A 32-byte Compound Device Identifier secret. Zeroized on drop.
///
/// Moving a value leaves a copy behind that drop never sees, so the
/// derivations write into a `CdiSecret` the caller owns instead of
/// returning one; [`Default`] (all zeros) gives the container to fill.
#[derive(Default)]
pub struct CdiSecret([u8; 32]);

impl Zeroize for CdiSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CdiSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CdiSecret {}

impl CdiSecret {
    /// Wraps raw CDI bytes. The array is moved in, so wiping any copy the
    /// caller still holds is up to the caller; [`as_mut_bytes`] fills a
    /// container in place instead.
    ///
    /// [`as_mut_bytes`]: Self::as_mut_bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        CdiSecret(bytes)
    }

    /// The raw CDI bytes (e.g. to hand the next-stage CDI to the next boot
    /// stage).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The raw CDI bytes, writable, to fill the container in place.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

/// A CDI_ID: 20 bytes derived from a public key, used as issuer/subject
/// identifier and rendered as 40 hex characters in the CWT.
pub type CdiId = [u8; 20];

/// Compresses the open-DICE input into the 64-byte digest that salts the
/// next-CDI derivation:
/// `SHA512(code_hash, config_hash-or-descriptor, authority_hash, mode, hidden)`.
/// Port of `n20_compress_input`.
pub fn compress_input<D: Digest>(
    d: &mut D,
    input: &OpenDiceInput,
) -> Result<[u8; 64], CryptoError> {
    let mode = [input.mode as u8];
    let config: &[u8] = if input.configuration_hash.is_empty() {
        input.configuration_descriptor
    } else {
        input.configuration_hash
    };
    let mut digest = [0u8; 64];
    let parts: [&[u8]; 5] = [
        input.code_hash,
        config,
        input.authority_hash,
        &mode,
        input.hidden,
    ];
    let mut parts = parts.iter().copied();
    d.sha512(&mut parts, &mut digest)?;
    Ok(digest)
}

/// Derives the next-level attestation CDI into `next`:
/// `HKDF-Expand-SHA512(cdi, input_digest || "CDI_Attest", 32)`.
/// Port of `n20_next_level_cdi_attest`.
pub fn next_cdi_attest<D: Digest>(
    d: &mut D,
    cdi: &CdiSecret,
    input_digest: &[u8; 64],
    next: &mut CdiSecret,
) -> Result<(), CryptoError> {
    hkdf_expand_sha512(d, &cdi.0, &[input_digest, CDI_ATTEST], &mut next.0)
}

/// Derives the attestation key seed for a CDI into `seed`:
/// `HKDF-Expand-SHA512(cdi, ASYM_SALT || "Key Pair Attest", 32)`.
/// Port of `n20_derive_cdi_attestation_key` (Ed25519: the 32 bytes are the
/// RFC 8032 seed, as in the BoringSSL backend).
pub fn attest_key_seed<D: Digest>(
    d: &mut D,
    cdi: &CdiSecret,
    seed: &mut Seed32,
) -> Result<(), CryptoError> {
    hkdf_expand_sha512(d, &cdi.0, &[&ASYM_SALT, ATTEST_KEY_PAIR], &mut seed.0)
}

/// Derives the CDI_ID for a public key:
/// `HKDF-SHA512(ikm = public_key, salt = ID_SALT, info = "ID", 20)` with the
/// high bit of the first byte cleared. Port of `n20_open_dice_cdi_id`.
pub fn cdi_id<D: Digest>(d: &mut D, public_key: &[u8; 32]) -> Result<CdiId, CryptoError> {
    let mut id: CdiId = [0; 20];
    hkdf_sha512(d, public_key, &ID_SALT, &[ID_INFO], &mut id)?;
    id[0] &= 0x7f;
    Ok(id)
}

/// Computes the exact certificate size for `params` without any crypto,
/// mirroring the C NULL-buffer size query.
fn size_query(params: &CwtParams) -> Error {
    let mut s = WStream::counting();
    cose::render_sign1(&mut s, &[0; SIG_SIZE_ED25519], |s| {
        cwt::write_cwt_payload(s, params)
    });
    Error::InsufficientBuffer {
        required: s.written(),
    }
}

/// Renders the signed COSE_Sign1 into the tail of `buf`.
///
/// Ed25519 needs the signed message in one piece, so `buf` stages it: the
/// Sig_structure is rendered into it and signed, then the COSE_Sign1, which
/// is longer, is rendered over it. The payload is rendered twice; no other
/// buffer is needed, so the certificate size is bounded only by `buf`.
fn render_and_sign<C: Crypto>(
    c: &mut C,
    signing_seed: &Seed32,
    params: &CwtParams,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let tbs_len = {
        let mut s = WStream::new(buf);
        cose::render_sig_structure(&mut s, |s| cwt::write_cwt_payload(s, params));
        if s.overflowed() {
            return Err(size_query(params));
        }
        s.written()
    };
    let mut signature = [0u8; SIG_SIZE_ED25519];
    c.sign(signing_seed, &buf[buf.len() - tbs_len..], &mut signature)?;

    let mut s = WStream::new(buf);
    cose::render_sign1(&mut s, &signature, |s| cwt::write_cwt_payload(s, params));
    if s.overflowed() {
        return Err(Error::InsufficientBuffer {
            required: s.written(),
        });
    }
    Ok(s.written())
}

/// Dummy CDI_ID used in size-query mode (`0x7f` filler, like the C library;
/// the hex rendering is fixed-width so any value yields the exact size).
const SIZE_QUERY_ID: CdiId = [0x7f; 20];

/// Issues the self-signed device-identity CWT from the root CDI.
///
/// Derives the device-identity key (`attest_key_seed`), uses its CDI_ID as
/// both issuer and subject, and signs the certificate with the key it
/// certifies. This extends the C library, which does not currently support
/// COSE for self-signed certificates.
///
/// With `buf = None` this is an exact-size query: no crypto runs and the
/// result is `Err(Error::InsufficientBuffer { required })`. On success the
/// encoded certificate occupies `buf[buf.len() - n ..]` where `n` is the
/// returned byte count.
pub fn issue_device_id_cwt<C: Crypto>(
    c: &mut C,
    cdi: &CdiSecret,
    profile_name: Option<&[u8]>,
    buf: Option<&mut [u8]>,
) -> Result<usize, Error> {
    let Some(buf) = buf else {
        return Err(size_query(&CwtParams {
            issuer_id: &SIZE_QUERY_ID,
            subject_id: &SIZE_QUERY_ID,
            input: None,
            subject_public_key: &[0; 32],
            profile_name,
        }));
    };

    let mut seed = Seed32::default();
    attest_key_seed(c, cdi, &mut seed)?;
    let mut public_key = [0u8; 32];
    c.public_key(&seed, &mut public_key)?;
    let id = cdi_id(c, &public_key)?;

    let params = CwtParams {
        issuer_id: &id,
        subject_id: &id,
        input: None,
        subject_public_key: &public_key,
        profile_name,
    };
    render_and_sign(c, &seed, &params, buf)
}

/// Derives the next-stage CDI and key pair from `cdi` and the open-DICE
/// `input`, and issues the next-stage CWT signed by the device-identity key.
///
/// Writes the next-stage CDI (to be handed to the next boot stage) to
/// `next_cdi` and returns the certificate size. The certificate certifies
/// the next-stage public key and carries the open-DICE claims; the
/// profile-name claim is taken from `input.profile_name`.
///
/// With `buf = None` this is an exact-size query: no crypto runs, no CDI is
/// derived, and the result is `Err(Error::InsufficientBuffer { required })`.
/// On success the encoded certificate occupies `buf[buf.len() - n ..]`. On
/// any error `next_cdi` is left zeroed.
pub fn issue_next_stage_cwt<C: Crypto>(
    c: &mut C,
    cdi: &CdiSecret,
    input: &OpenDiceInput,
    next_cdi: &mut CdiSecret,
    buf: Option<&mut [u8]>,
) -> Result<usize, Error> {
    let result = issue_next_stage_cwt_into(c, cdi, input, next_cdi, buf);
    if result.is_err() {
        next_cdi.zeroize();
    }
    result
}

fn issue_next_stage_cwt_into<C: Crypto>(
    c: &mut C,
    cdi: &CdiSecret,
    input: &OpenDiceInput,
    next_cdi: &mut CdiSecret,
    buf: Option<&mut [u8]>,
) -> Result<usize, Error> {
    let profile_name = (!input.profile_name.is_empty()).then_some(input.profile_name);

    let Some(buf) = buf else {
        return Err(size_query(&CwtParams {
            issuer_id: &SIZE_QUERY_ID,
            subject_id: &SIZE_QUERY_ID,
            input: Some(input),
            subject_public_key: &[0; 32],
            profile_name,
        }));
    };

    let input_digest = compress_input(c, input)?;
    next_cdi_attest(c, cdi, &input_digest, next_cdi)?;

    // One seed container serves both keys, so the subject seed is
    // overwritten rather than left behind.
    let mut seed = Seed32::default();
    attest_key_seed(c, next_cdi, &mut seed)?;
    let mut subject_public_key = [0u8; 32];
    c.public_key(&seed, &mut subject_public_key)?;
    let subject_id = cdi_id(c, &subject_public_key)?;

    attest_key_seed(c, cdi, &mut seed)?;
    let issuer_seed = &seed;
    let mut issuer_public_key = [0u8; 32];
    c.public_key(issuer_seed, &mut issuer_public_key)?;
    let issuer_id = cdi_id(c, &issuer_public_key)?;

    let params = CwtParams {
        issuer_id: &issuer_id,
        subject_id: &subject_id,
        input: Some(input),
        subject_public_key: &subject_public_key,
        profile_name,
    };
    render_and_sign(c, issuer_seed, &params, buf)
}
