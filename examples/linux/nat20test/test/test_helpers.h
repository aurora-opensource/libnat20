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

#pragma once

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Compute the compressed input for a CDI level given the OpenDICE parameters.
 * Uses the libnat20 software digest implementation.
 */
n20_error_t test_compress_cdi_input(uint8_t const* code_hash,
                                    size_t code_hash_size,
                                    uint8_t const* config_hash,
                                    size_t config_hash_size,
                                    uint8_t const* authority_hash,
                                    size_t authority_hash_size,
                                    uint8_t mode,
                                    uint8_t const* hidden,
                                    size_t hidden_size,
                                    uint8_t* compressed_out,
                                    size_t compressed_out_size);

/**
 * Verify an X.509 DER certificate's signature against an issuer public key.
 * For self-signed certs, pass the cert's own public key.
 *
 * @param cert_der       DER-encoded certificate
 * @param cert_der_size  Size of the certificate
 * @param issuer_pubkey  Raw public key (x||y for EC, compressed for Ed25519)
 * @param issuer_pubkey_size  Size of the public key
 * @param key_type       Key type of the issuer
 * @return true if signature is valid
 */
bool test_verify_x509_signature(uint8_t const* cert_der,
                                size_t cert_der_size,
                                uint8_t const* issuer_pubkey,
                                size_t issuer_pubkey_size,
                                n20_crypto_key_type_t key_type);

/**
 * Extract the subject public key from a DER-encoded X.509 certificate.
 * For EC keys, the output is the uncompressed point (0x04 || x || y).
 * For Ed25519, it's the 32-byte compressed point.
 *
 * @param cert_der       DER-encoded certificate
 * @param cert_der_size  Size of the certificate
 * @param pubkey_out     Output buffer for the public key
 * @param pubkey_size_in_out  In: buffer size, Out: bytes written
 * @return true on success
 */
bool test_extract_x509_pubkey(uint8_t const* cert_der,
                              size_t cert_der_size,
                              uint8_t* pubkey_out,
                              size_t* pubkey_size_in_out);

/**
 * Parsed COSE_Sign1 structure.
 */
typedef struct {
    n20_slice_t protected_header;
    n20_slice_t payload;
    n20_slice_t signature;
} test_cose_sign1_t;

/**
 * Parse a COSE_Sign1 structure from CBOR-encoded bytes.
 * The returned slices point into the input buffer.
 */
bool test_parse_cose_sign1(uint8_t const* data, size_t size, test_cose_sign1_t* out);

/**
 * Verify a COSE_Sign1 signature.
 * Reconstructs the Sig_structure1 and verifies against the given public key.
 *
 * @param sign1          Parsed COSE_Sign1 (from test_parse_cose_sign1)
 * @param issuer_pubkey  Raw public key bytes (without 0x04 prefix for EC)
 * @param issuer_pubkey_size  Size of the public key
 * @param key_type       Key type of the issuer
 * @return true if signature is valid
 */
bool test_verify_cose_sign1(test_cose_sign1_t const* sign1,
                            uint8_t const* issuer_pubkey,
                            size_t issuer_pubkey_size,
                            n20_crypto_key_type_t key_type);

/**
 * Verify a raw ECDSA/EdDSA signature over a message.
 *
 * @param pubkey       Raw public key (x||y for EC, 32 bytes for Ed25519)
 * @param pubkey_size  Size of the public key
 * @param message      Message that was signed
 * @param message_size Size of the message
 * @param sig          Signature (r||s for ECDSA, 64 bytes for Ed25519)
 * @param sig_size     Size of the signature
 * @param key_type     Key type
 * @return true if signature is valid
 */
bool test_verify_raw_signature(uint8_t const* pubkey,
                               size_t pubkey_size,
                               uint8_t const* message,
                               size_t message_size,
                               uint8_t const* sig,
                               size_t sig_size,
                               n20_crypto_key_type_t key_type);

/**
 * Extract the subject public key from a COSE_Sign1 certificate.
 *
 * Assumes the COSE_Sign1 payload is a CWT containing a claim with label
 * -4670552 (N20_OPEN_DICE_CWT_LABEL_SUBJECT_PUBLIC_KEY) whose value is
 * a COSE_Key map. Extracts the x (and y for EC2) coordinates and writes
 * them as raw 0x04||x||y (for EC) or raw 32-byte key (for OKP/Ed25519).
 *
 * @param cose_sign1       COSE_Sign1 encoded certificate bytes
 * @param cose_sign1_size  Size of the COSE_Sign1 data
 * @param pubkey_out       Output buffer for the raw public key
 * @param pubkey_size_in_out  In: buffer size, Out: bytes written
 * @param key_type_out     Output: detected key type
 * @return true on success
 */
bool test_extract_cose_pubkey(uint8_t const* cose_sign1,
                              size_t cose_sign1_size,
                              uint8_t* pubkey_out,
                              size_t* pubkey_size_in_out,
                              n20_crypto_key_type_t* key_type_out);
