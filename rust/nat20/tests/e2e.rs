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

//! End-to-end tests: issue both CWTs, check the COSE_Sign1/CWT structure
//! with an independent CBOR decoder (ciborium), and verify the Ed25519
//! signatures with ed25519-dalek's strict verifier.

use ciborium::value::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use nat20::crypto::soft::SoftCrypto;
use nat20::crypto::Seed32;
use nat20::derive::{attest_key_seed, cdi_id, CdiSecret};
use nat20::{issue_device_id_cwt, issue_next_stage_cwt, Ed25519Signer, Error, Mode, OpenDiceInput};

const CDI: [u8; 32] = [0x42; 32];

fn test_input() -> OpenDiceInput<'static> {
    OpenDiceInput {
        code_hash: &[0x11; 64],
        code_descriptor: b"next stage v1.0",
        configuration_hash: &[0x22; 64],
        configuration_descriptor: b"boot config",
        authority_hash: &[0x33; 64],
        authority_descriptor: &[],
        mode: Mode::Normal,
        profile_name: b"example.dice.profile",
        hidden: &[0x44; 32],
    }
}

fn issue_device_id(profile: Option<&[u8]>) -> Vec<u8> {
    let mut c = SoftCrypto;
    let cdi = CdiSecret::from_bytes(CDI);
    let Err(Error::InsufficientBuffer { required }) =
        issue_device_id_cwt(&mut c, &cdi, profile, None)
    else {
        panic!("size query must return InsufficientBuffer");
    };
    let mut buf = vec![0u8; required];
    let n = issue_device_id_cwt(&mut c, &cdi, profile, Some(&mut buf)).unwrap();
    assert_eq!(n, required, "size query must be exact");
    buf[buf.len() - n..].to_vec()
}

fn issue_next_stage() -> (CdiSecret, Vec<u8>) {
    issue_next_stage_with(&test_input())
}

fn issue_next_stage_with(input: &OpenDiceInput) -> (CdiSecret, Vec<u8>) {
    let mut c = SoftCrypto;
    let cdi = CdiSecret::from_bytes(CDI);
    let Err(Error::InsufficientBuffer { required }) =
        issue_next_stage_cwt(&mut c, &cdi, input, &mut CdiSecret::default(), None)
    else {
        panic!("size query must return InsufficientBuffer");
    };
    let mut buf = vec![0u8; required];
    let mut next_cdi = CdiSecret::default();
    let n = issue_next_stage_cwt(&mut c, &cdi, input, &mut next_cdi, Some(&mut buf)).unwrap();
    assert_eq!(n, required, "size query must be exact");
    (next_cdi, buf[buf.len() - n..].to_vec())
}

/// Decodes a COSE_Sign1, returning (protected bytes, payload bytes,
/// signature), after asserting its shape.
fn split_sign1(cert: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let value: Value = ciborium::de::from_reader(cert).expect("valid CBOR");
    let Value::Array(items) = value else {
        panic!("COSE_Sign1 must be an array");
    };
    assert_eq!(items.len(), 4);
    let Value::Bytes(protected) = &items[0] else {
        panic!("protected must be bstr");
    };
    let Value::Map(unprotected) = &items[1] else {
        panic!("unprotected must be a map");
    };
    assert!(unprotected.is_empty());
    let Value::Bytes(payload) = &items[2] else {
        panic!("payload must be bstr");
    };
    let Value::Bytes(signature) = &items[3] else {
        panic!("signature must be bstr");
    };

    // Protected header is the canonical 4 bytes: bstr(3){map{1: -8}}.
    let prot: Value = ciborium::de::from_reader(protected.as_slice()).unwrap();
    assert_eq!(
        prot,
        Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-8).into())
        )])
    );

    (protected.clone(), payload.clone(), signature.clone())
}

/// Reconstructs the COSE Sig_structure for a Sign1 with empty external_aad.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let value = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).unwrap();
    out
}

fn claims(payload: &[u8]) -> Vec<(Value, Value)> {
    let value: Value = ciborium::de::from_reader(payload).expect("payload is CBOR");
    let Value::Map(pairs) = value else {
        panic!("CWT payload must be a map");
    };
    pairs
}

fn claim(pairs: &[(Value, Value)], label: i64) -> Option<&Value> {
    pairs
        .iter()
        .find_map(|(k, v)| (k == &Value::Integer(label.into())).then_some(v))
}

fn cose_key_x(subject_public_key: &Value) -> Vec<u8> {
    let Value::Bytes(cose_key_bytes) = subject_public_key else {
        panic!("subject_public_key must be a bstr-wrapped COSE_Key");
    };
    let key: Value = ciborium::de::from_reader(cose_key_bytes.as_slice()).unwrap();
    let Value::Map(pairs) = key else {
        panic!("COSE_Key must be a map");
    };
    // kty = OKP, alg = EdDSA, key_ops = [verify], crv = Ed25519.
    assert_eq!(claim(&pairs, 1), Some(&Value::Integer(1.into())));
    assert_eq!(claim(&pairs, 3), Some(&Value::Integer((-8).into())));
    assert_eq!(
        claim(&pairs, 4),
        Some(&Value::Array(vec![Value::Integer(2.into())]))
    );
    assert_eq!(claim(&pairs, -1), Some(&Value::Integer(6.into())));
    let Some(Value::Bytes(x)) = claim(&pairs, -2) else {
        panic!("COSE_Key must contain x");
    };
    x.clone()
}

fn expected_device_id_hex() -> (String, [u8; 32]) {
    let mut c = SoftCrypto;
    let cdi = CdiSecret::from_bytes(CDI);
    let mut seed = Seed32::default();
    attest_key_seed(&mut c, &cdi, &mut seed).unwrap();
    let mut pk = [0u8; 32];
    c.public_key(&seed, &mut pk).unwrap();
    let id = cdi_id(&mut c, &pk).unwrap();
    (hex::encode(id), pk)
}

#[test]
fn device_id_cwt_is_self_signed_and_well_formed() {
    let cert = issue_device_id(Some(b"test.profile"));
    let (protected, payload, signature) = split_sign1(&cert);

    let pairs = claims(&payload);
    let (id_hex, pk) = expected_device_id_hex();

    // Issuer == subject == hex CDI_ID of the embedded key.
    assert_eq!(claim(&pairs, 1), Some(&Value::Text(id_hex.clone())));
    assert_eq!(claim(&pairs, 2), Some(&Value::Text(id_hex)));
    // Mode claim present: 1-byte bstr "not configured".
    assert_eq!(claim(&pairs, -4670551), Some(&Value::Bytes(vec![0])));
    // Key usage: keyCertSign.
    assert_eq!(claim(&pairs, -4670553), Some(&Value::Bytes(vec![0x20])));
    // Profile claim.
    assert_eq!(
        claim(&pairs, -4670554),
        Some(&Value::Text("test.profile".into()))
    );
    // No measurement claims on a self-signed device-identity cert.
    for label in [
        -4670545i64,
        -4670546,
        -4670547,
        -4670548,
        -4670549,
        -4670550,
    ] {
        assert!(claim(&pairs, label).is_none(), "unexpected claim {label}");
    }
    // Embedded key is the device-identity key...
    let x = cose_key_x(claim(&pairs, -4670552).unwrap());
    assert_eq!(x, pk);

    // ...and the certificate verifies against it (self-signed).
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let sig = Signature::from_slice(&signature).unwrap();
    vk.verify_strict(&sig_structure(&protected, &payload), &sig)
        .expect("self-signed signature must verify");
}

#[test]
fn device_id_cwt_without_profile_omits_claim() {
    let cert = issue_device_id(None);
    let (_, payload, _) = split_sign1(&cert);
    let pairs = claims(&payload);
    assert!(claim(&pairs, -4670554).is_none());
    // issuer, subject, mode, subject_public_key, key_usage.
    assert_eq!(pairs.len(), 5);
}

#[test]
fn next_stage_cwt_carries_measurements_and_verifies_against_device_id() {
    let (_next_cdi, cert) = issue_next_stage();
    let (protected, payload, signature) = split_sign1(&cert);
    let pairs = claims(&payload);

    let (device_id_hex, device_pk) = expected_device_id_hex();
    let input = test_input();

    // Issuer is the device identity; subject differs.
    assert_eq!(claim(&pairs, 1), Some(&Value::Text(device_id_hex.clone())));
    let Some(Value::Text(subject_hex)) = claim(&pairs, 2) else {
        panic!("subject must be present");
    };
    assert_ne!(subject_hex, &device_id_hex);
    assert_eq!(subject_hex.len(), 40);

    // Measurement claims.
    assert_eq!(
        claim(&pairs, -4670545),
        Some(&Value::Bytes(input.code_hash.to_vec()))
    );
    assert_eq!(
        claim(&pairs, -4670546),
        Some(&Value::Bytes(input.code_descriptor.to_vec()))
    );
    assert_eq!(
        claim(&pairs, -4670547),
        Some(&Value::Bytes(input.configuration_hash.to_vec()))
    );
    assert_eq!(
        claim(&pairs, -4670548),
        Some(&Value::Bytes(input.configuration_descriptor.to_vec()))
    );
    assert_eq!(
        claim(&pairs, -4670549),
        Some(&Value::Bytes(input.authority_hash.to_vec()))
    );
    // Empty authority descriptor omitted.
    assert!(claim(&pairs, -4670550).is_none());
    // Mode = normal.
    assert_eq!(claim(&pairs, -4670551), Some(&Value::Bytes(vec![1])));
    assert_eq!(
        claim(&pairs, -4670554),
        Some(&Value::Text("example.dice.profile".into()))
    );

    // The subject key differs from the issuer key, and the subject id is its
    // CDI_ID.
    let subject_pk = cose_key_x(claim(&pairs, -4670552).unwrap());
    assert_ne!(subject_pk, device_pk);
    let mut c = SoftCrypto;
    let expected_subject_id = cdi_id(&mut c, subject_pk.as_slice().try_into().unwrap()).unwrap();
    assert_eq!(subject_hex, &hex::encode(expected_subject_id));

    // Signed by the device-identity key.
    let vk = VerifyingKey::from_bytes(&device_pk).unwrap();
    let sig = Signature::from_slice(&signature).unwrap();
    vk.verify_strict(&sig_structure(&protected, &payload), &sig)
        .expect("next-stage signature must verify against device id key");
}

/// The message is staged in the certificate buffer, so the certificate size
/// is bounded by nothing else.
#[test]
fn a_large_certificate_is_signed() {
    let descriptor = vec![0x5a; 8192];
    let input = OpenDiceInput {
        code_descriptor: &descriptor,
        ..test_input()
    };
    let (_next_cdi, cert) = issue_next_stage_with(&input);
    let (protected, payload, signature) = split_sign1(&cert);
    assert_eq!(
        claim(&claims(&payload), -4670546),
        Some(&Value::Bytes(descriptor.clone()))
    );
    let (_, device_pk) = expected_device_id_hex();
    let vk = VerifyingKey::from_bytes(&device_pk).unwrap();
    let sig = Signature::from_slice(&signature).unwrap();
    vk.verify_strict(&sig_structure(&protected, &payload), &sig)
        .expect("signature must verify");
}

#[test]
fn next_stage_derivation_is_deterministic_and_input_sensitive() {
    let (next_a, cert_a) = issue_next_stage();
    let (next_b, cert_b) = issue_next_stage();
    assert_eq!(next_a.as_bytes(), next_b.as_bytes());
    assert_eq!(cert_a, cert_b);

    // A different measurement changes the derived CDI and the cert.
    let mut c = SoftCrypto;
    let cdi = CdiSecret::from_bytes(CDI);
    let mut input = test_input();
    input.code_hash = &[0x12; 64];
    let mut buf = vec![0u8; 1024];
    let mut next_c = CdiSecret::default();
    issue_next_stage_cwt(&mut c, &cdi, &input, &mut next_c, Some(&mut buf)).unwrap();
    assert_ne!(next_a.as_bytes(), next_c.as_bytes());
}

#[test]
fn too_small_buffer_reports_exact_size() {
    let mut c = SoftCrypto;
    let cdi = CdiSecret::from_bytes(CDI);
    let Err(Error::InsufficientBuffer { required }) = issue_device_id_cwt(&mut c, &cdi, None, None)
    else {
        panic!()
    };
    // Short by one, the buffer still stages the shorter Sig_structure; short
    // by more, it does not. Both report the certificate size.
    for short in [1, 64, required] {
        let mut small = vec![0u8; required - short];
        match issue_device_id_cwt(&mut c, &cdi, None, Some(&mut small)) {
            Err(Error::InsufficientBuffer { required: r }) => assert_eq!(r, required),
            other => panic!("expected InsufficientBuffer, got {other:?}"),
        }
    }
}

#[test]
fn failed_next_stage_leaves_next_cdi_zeroed() {
    let mut c = SoftCrypto;
    let cdi = CdiSecret::from_bytes(CDI);
    let input = test_input();
    // Too small for the certificate, which is only found out after the next
    // CDI has been derived into `next_cdi`.
    let mut small = vec![0u8; 16];
    let mut next_cdi = CdiSecret::from_bytes([0xaa; 32]);
    assert!(matches!(
        issue_next_stage_cwt(&mut c, &cdi, &input, &mut next_cdi, Some(&mut small)),
        Err(Error::InsufficientBuffer { .. })
    ));
    assert_eq!(next_cdi.as_bytes(), &[0; 32]);
}

#[test]
fn protected_header_is_canonical_bytes() {
    // The protected header must be exactly bstr(3){a1 01 27}.
    let cert = issue_device_id(None);
    let pos = cert
        .windows(4)
        .position(|w| w == [0x43, 0xa1, 0x01, 0x27])
        .expect("canonical protected header bytes present");
    // It must directly follow the array(4) header.
    assert_eq!(pos, 1);
    assert_eq!(cert[0], 0x84);
}
