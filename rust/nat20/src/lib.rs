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

//! Minimal `no_std` port of libnat20: deterministic DICE key derivation and
//! CWT (COSE_Sign1) certificate issuance with Ed25519.
//!
//! This crate reimplements the CWT/COSE subset of the C libnat20 library with
//! full derivation and wire compatibility:
//!
//! * The KDF is HKDF-Expand-SHA512 with the same salts and tags
//!   (`"CDI_Attest"`, `"Key Pair Attest"`, `ASYM_SALT`, `ID_SALT`, `"ID"`).
//! * Certificates are CWTs wrapped in COSE_Sign1 with byte-identical CBOR
//!   layout to `n20_issue_certificate` with `n20_certificate_format_cose_e`.
//!
//! It extends the C library in one way: self-signed device-identity
//! certificates can be issued as CWTs (the C library currently rejects COSE
//! for `n20_cert_type_self_signed_e`).
//!
//! No allocation, no floating point, no panicking paths on correct usage.
//! Cryptographic primitives are pluggable through the traits in [`crypto`];
//! a software implementation backed by `sha2`/`hmac`/`ed25519-dalek` is
//! available behind the `soft-crypto` feature.

#![no_std]
// unsafe is forbidden everywhere except the FFI bindings of the optional
// Monocypher backend (crypto/mono.rs), which carries its own allow.
#![cfg_attr(not(feature = "mono-crypto"), forbid(unsafe_code))]
#![cfg_attr(feature = "mono-crypto", deny(unsafe_code))]
#![deny(missing_docs)]

pub mod cbor;
pub mod cose;
pub mod crypto;
pub mod cwt;
pub mod derive;
pub mod error;
pub mod handover;
pub mod open_dice;
pub mod stream;

pub use crypto::{Crypto, CryptoError, Digest, Ed25519Signer, Seed32};
pub use derive::{issue_device_id_cwt, issue_next_stage_cwt, CdiId, CdiSecret};
pub use error::Error;
pub use open_dice::{Mode, OpenDiceInput};
