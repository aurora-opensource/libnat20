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

//! Differential tests for the Monocypher backend: it must produce exactly
//! the same certificates as the soft (dalek/sha2) backend and the C
//! implementations. Run with `cargo test --features mono-crypto,soft-crypto`.

#![cfg(feature = "mono-crypto")]

use nat20::crypto::mono::MonoCrypto;
use nat20::derive::CdiSecret;
use nat20::{issue_device_id_cwt, issue_next_stage_cwt, Crypto, Error, Mode, OpenDiceInput};

/// Golden next-stage certificate produced by C libnat20 + BoringSSL; same
/// value as in differential.rs.
const C_GOLDEN_CERT_HEX: &str = concat!(
    "8443a10127a05901aeab0178283035366534333265653933613933393733373436636361343135353864323439383039",
    "326135306602782837643438376538633033333534366533313766663431316131646338303066663264306535663163",
    "3a0047445058401111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    "11111111111111111111111111111111111111111111113a004744514f6e6578742073746167652076312e303a004744",
    "525840222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
    "222222222222222222222222222222222222223a004744534b626f6f7420636f6e6669673a0047445458403333333333",
    "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333",
    "33333333333333333333333a0047445641013a00474457582da50101032704810220062158206f1b6c111449b06e7a92",
    "f410ab4d2112a6cdbe8f86d54c0157ec57fdb224aae53a0047445841203a00474459746578616d706c652e646963652e",
    "70726f66696c6558406995c4b1aa69bbb804d71005106858b326586dc080d68efe247406b3b8688144a79bffcb662064",
    "f1a1a3b663d83f457def52f3d37e746396666441fc8958420f",
);

fn issue_both<C: Crypto>(c: &mut C) -> (Vec<u8>, Vec<u8>) {
    let cdi = CdiSecret::from_bytes([0x42; 32]);
    let input = OpenDiceInput {
        code_hash: &[0x11; 64],
        code_descriptor: b"next stage v1.0",
        configuration_hash: &[0x22; 64],
        configuration_descriptor: b"boot config",
        authority_hash: &[0x33; 64],
        authority_descriptor: &[],
        mode: Mode::Normal,
        profile_name: b"example.dice.profile",
        hidden: &[0x44; 32],
    };

    let Err(Error::InsufficientBuffer { required }) = issue_device_id_cwt(c, &cdi, None, None)
    else {
        panic!()
    };
    let mut id_buf = vec![0u8; required];
    let n = issue_device_id_cwt(c, &cdi, None, Some(&mut id_buf)).unwrap();
    let id_cert = id_buf[id_buf.len() - n..].to_vec();

    let Err(Error::InsufficientBuffer { required }) =
        issue_next_stage_cwt(c, &cdi, &input, &mut CdiSecret::default(), None)
    else {
        panic!()
    };
    let mut ns_buf = vec![0u8; required];
    let mut next_cdi = CdiSecret::default();
    let n = issue_next_stage_cwt(c, &cdi, &input, &mut next_cdi, Some(&mut ns_buf)).unwrap();
    let ns_cert = ns_buf[ns_buf.len() - n..].to_vec();

    (id_cert, ns_cert)
}

#[test]
fn mono_backend_matches_c_golden() {
    let mut mono = MonoCrypto::new().unwrap();
    let (_, ns_cert) = issue_both(&mut mono);
    assert_eq!(ns_cert, hex::decode(C_GOLDEN_CERT_HEX).unwrap());
}

#[cfg(feature = "soft-crypto")]
#[test]
fn mono_backend_matches_soft_backend() {
    let mut mono = MonoCrypto::new().unwrap();
    let mut soft = nat20::crypto::soft::SoftCrypto;
    assert_eq!(issue_both(&mut mono), issue_both(&mut soft));
}
