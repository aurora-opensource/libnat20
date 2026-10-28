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

//! COSE_Sign1 and COSE_Key encoding (RFC 8152), Ed25519 only.
//! Port of `src/core/cose.c`.

use crate::cbor::{self, Major};
use crate::stream::WStream;

/// COSE algorithm identifier for EdDSA (RFC 8152 section 8.2).
pub const ALG_EDDSA: i64 = -8;
/// Ed25519 signature size in bytes.
pub const SIG_SIZE_ED25519: usize = 64;

/// First element of the COSE Sig_structure: the array(4) header followed by
/// the context text string `"Signature1"`.
pub const SIG1_CONTEXT: &[u8] = b"\x84\x6aSignature1";
/// Empty byte string: the `external_aad` element of the Sig_structure.
pub const EMPTY_BSTR: &[u8] = b"\x40";

// COSE_Key labels and values (RFC 8152 section 13).
/// COSE key type: octet key pair.
pub const KEY_TYPE_OKP: i64 = 1;
/// COSE curve identifier: Ed25519.
pub const CURVE_ED25519: i64 = 6;
/// COSE_Key label: key type.
pub const LABEL_KEY_TYPE: i64 = 1;
/// COSE_Key label: algorithm identifier.
pub const LABEL_ALGORITHM_ID: i64 = 3;
/// COSE_Key label: key operations.
pub const LABEL_KEY_OPS: i64 = 4;
/// COSE_Key label: curve.
pub const LABEL_CURVE: i64 = -1;
/// COSE_Key label: x coordinate / public key.
pub const LABEL_X_COORDINATE: i64 = -2;
/// COSE key operation: verify.
pub const KEY_OP_VERIFY: i64 = 2;

/// The encoded protected header for EdDSA: `bstr(3){map{1: -8}}`.
/// Constant because the algorithm is fixed.
pub const PROTECTED_EDDSA: &[u8] = &[0x43, 0xa1, 0x01, 0x27];

/// Writes an Ed25519 COSE_Key for a verification-only public key:
/// `{1: OKP, 3: EdDSA, 4: [verify], -1: Ed25519, -2: x}`.
pub fn write_cose_key_ed25519(s: &mut WStream, public_key: &[u8; 32]) {
    cbor::write_bytes(s, public_key);
    cbor::write_int(s, LABEL_X_COORDINATE);

    cbor::write_int(s, CURVE_ED25519);
    cbor::write_int(s, LABEL_CURVE);

    cbor::write_int(s, KEY_OP_VERIFY);
    cbor::write_array_header(s, 1);
    cbor::write_int(s, LABEL_KEY_OPS);

    cbor::write_int(s, ALG_EDDSA);
    cbor::write_int(s, LABEL_ALGORITHM_ID);

    cbor::write_int(s, KEY_TYPE_OKP);
    cbor::write_int(s, LABEL_KEY_TYPE);

    cbor::write_map_header(s, 5);
}

/// Writes the payload written by `payload` wrapped in a byte string.
fn write_payload_bstr<F: FnOnce(&mut WStream)>(s: &mut WStream, payload: F) {
    let mark = s.written();
    payload(s);
    cbor::write_header(s, Major::Bytes, (s.written() - mark) as u64);
}

/// Renders the Sig_structure that a COSE_Sign1 around the payload written
/// by `payload` signs: `["Signature1", protected, h'', payload]`.
///
/// It is the COSE_Sign1 without the unprotected map and the signature, and
/// with the context and empty `external_aad` added: 55 bytes shorter, so a
/// buffer that fits the COSE_Sign1 also fits its Sig_structure.
pub fn render_sig_structure<F: FnOnce(&mut WStream)>(s: &mut WStream, payload: F) {
    write_payload_bstr(s, payload);
    s.prepend(EMPTY_BSTR);
    s.prepend(PROTECTED_EDDSA);
    s.prepend(SIG1_CONTEXT);
}

/// Renders a COSE_Sign1 with `signature` around the payload written by
/// `payload`. Port of `n20_cose_render_sign1_with_payload`.
pub fn render_sign1<F: FnOnce(&mut WStream)>(
    s: &mut WStream,
    signature: &[u8; SIG_SIZE_ED25519],
    payload: F,
) {
    cbor::write_bytes(s, signature);
    write_payload_bstr(s, payload);
    // Empty unprotected header map.
    cbor::write_map_header(s, 0);
    // Protected header (constant for EdDSA).
    s.prepend(PROTECTED_EDDSA);
    cbor::write_array_header(s, 4);
}
