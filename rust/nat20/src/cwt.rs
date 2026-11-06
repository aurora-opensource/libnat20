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

//! CWT payload rendering with Open Profile for DICE claims.
//! Port of `n20_open_dice_cwt_write` (`src/core/cwt.c`).

use crate::cbor::{self, Major};
use crate::cose;
use crate::derive::CdiId;
use crate::open_dice::{Mode, OpenDiceInput};
use crate::stream::WStream;

/// CWT claim key: issuer (RFC 8392).
pub const LABEL_ISSUER: i64 = 1;
/// CWT claim key: subject (RFC 8392).
pub const LABEL_SUBJECT: i64 = 2;
/// Open DICE profile claim: code hash.
pub const LABEL_CODE_HASH: i64 = -4670545;
/// Open DICE profile claim: code descriptor.
pub const LABEL_CODE_DESCRIPTOR: i64 = -4670546;
/// Open DICE profile claim: configuration hash.
pub const LABEL_CONFIGURATION_HASH: i64 = -4670547;
/// Open DICE profile claim: configuration descriptor.
pub const LABEL_CONFIGURATION_DESCRIPTOR: i64 = -4670548;
/// Open DICE profile claim: authority hash.
pub const LABEL_AUTHORITY_HASH: i64 = -4670549;
/// Open DICE profile claim: authority descriptor.
pub const LABEL_AUTHORITY_DESCRIPTOR: i64 = -4670550;
/// Open DICE profile claim: mode.
pub const LABEL_MODE: i64 = -4670551;
/// Open DICE profile claim: subject public key (bstr-wrapped COSE_Key).
pub const LABEL_SUBJECT_PUBLIC_KEY: i64 = -4670552;
/// Open DICE profile claim: key usage.
pub const LABEL_KEY_USAGE: i64 = -4670553;
/// Open DICE profile claim: profile name.
pub const LABEL_PROFILE: i64 = -4670554;

/// Key usage byte: keyCertSign, the only usage nat20 CWT keys carry
/// (`N20_OPEN_DICE_KEY_USAGE_SET_KEY_CERT_SIGN`).
pub const KEY_USAGE_KEY_CERT_SIGN: u8 = 0x20;

/// Everything that goes into a CWT payload.
pub struct CwtParams<'a> {
    /// Issuer CDI_ID (rendered as 40 hex characters).
    pub issuer_id: &'a CdiId,
    /// Subject CDI_ID (rendered as 40 hex characters).
    pub subject_id: &'a CdiId,
    /// Measurements of the certified target environment; `None` for a
    /// self-signed device-identity certificate.
    pub input: Option<&'a OpenDiceInput<'a>>,
    /// The certified Ed25519 public key.
    pub subject_public_key: &'a [u8; 32],
    /// Profile name claim, if any. Should be UTF-8; written verbatim without
    /// validation (see [`cbor::write_text_bytes`]).
    pub profile_name: Option<&'a [u8]>,
}

/// Renders a CDI_ID as a 40-character lowercase-hex CBOR text string.
///
/// The C original (`n20_open_dice_write_name_as_hex`) iterates the bytes in
/// reverse to compensate for the backward writer; the rendered string is the
/// hex of `id[0..20]` in natural order.
fn write_id_hex(s: &mut WStream, id: &CdiId) {
    fn hex_nibble(n: u8) -> u8 {
        if n < 10 {
            b'0' + n
        } else {
            b'a' + (n - 10)
        }
    }
    for byte in id.iter().rev() {
        s.prepend(&[hex_nibble(byte >> 4), hex_nibble(byte & 0x0f)]);
    }
    cbor::write_header(s, Major::Text, (id.len() * 2) as u64);
}

/// Writes the CWT claims map. Emission order (reverse; the encoded map reads
/// front-to-back as issuer, subject, code_hash, ..., profile) matches
/// `n20_open_dice_cwt_write` byte for byte.
pub fn write_cwt_payload(s: &mut WStream, p: &CwtParams) {
    let mut pairs = 0u64;

    if let Some(profile) = p.profile_name {
        cbor::write_text_bytes(s, profile);
        cbor::write_int(s, LABEL_PROFILE);
        pairs += 1;
    }

    cbor::write_bytes(s, &[KEY_USAGE_KEY_CERT_SIGN]);
    cbor::write_int(s, LABEL_KEY_USAGE);
    pairs += 1;

    let mark = s.written();
    cose::write_cose_key_ed25519(s, p.subject_public_key);
    cbor::write_header(s, Major::Bytes, (s.written() - mark) as u64);
    cbor::write_int(s, LABEL_SUBJECT_PUBLIC_KEY);
    pairs += 1;

    let mode = [p.input.map_or(Mode::NotConfigured, |i| i.mode) as u8];
    cbor::write_bytes(s, &mode);
    cbor::write_int(s, LABEL_MODE);
    pairs += 1;

    if let Some(input) = p.input {
        let optional_claims = [
            (input.authority_descriptor, LABEL_AUTHORITY_DESCRIPTOR),
            (input.authority_hash, LABEL_AUTHORITY_HASH),
            (
                input.configuration_descriptor,
                LABEL_CONFIGURATION_DESCRIPTOR,
            ),
            (input.configuration_hash, LABEL_CONFIGURATION_HASH),
            (input.code_descriptor, LABEL_CODE_DESCRIPTOR),
            (input.code_hash, LABEL_CODE_HASH),
        ];
        for (data, label) in optional_claims {
            if !data.is_empty() {
                cbor::write_bytes(s, data);
                cbor::write_int(s, label);
                pairs += 1;
            }
        }
    }

    write_id_hex(s, p.subject_id);
    cbor::write_int(s, LABEL_SUBJECT);
    pairs += 1;

    write_id_hex(s, p.issuer_id);
    cbor::write_int(s, LABEL_ISSUER);
    pairs += 1;

    cbor::write_map_header(s, pairs);
}
