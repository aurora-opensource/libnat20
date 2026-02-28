/*
 * Copyright 2025 Aurora Operations, Inc.
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

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/oid.h>
#include <nat20/open_dice.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>
#include <nat20/x509_ext_tcg_dice_tcb_freshness.h>

/*
 * Buffer holding the utf-8 encoded string "CDI_Attest".
 */
uint8_t const CDI_ATTEST_STR[] = {
    0x43,
    0x44,
    0x49,
    0x5f,
    0x41,
    0x74,
    0x74,
    0x65,
    0x73,
    0x74,
};
n20_slice_t const CDI_ATTEST_STR_SLICE = {
    .buffer = CDI_ATTEST_STR,
    .size = 10,
};

/**
 * @brief Buffer holding the salt used for the asymmetric key derivation.
 *
 * This buffer is used to derive the asymmetric key pair from the
 * CDI secret. The buffer is 64 bytes long and is used as input to
 * the KDF function.
 */
uint8_t const ASYM_SALT[] = {
    0x63, 0xb6, 0xa0, 0x4d, 0x2c, 0x07, 0x7f, 0xc1, 0x0f, 0x63, 0x9f, 0x21, 0xda, 0x79, 0x38, 0x44,
    0x35, 0x6c, 0xc2, 0xb0, 0xb4, 0x41, 0xb3, 0xa7, 0x71, 0x24, 0x03, 0x5c, 0x03, 0xf8, 0xe1, 0xbe,
    0x60, 0x35, 0xd3, 0x1f, 0x28, 0x28, 0x21, 0xa7, 0x45, 0x0a, 0x02, 0x22, 0x2a, 0xb1, 0xb3, 0xcf,
    0xf1, 0x67, 0x9b, 0x05, 0xab, 0x1c, 0xa5, 0xd1, 0xaf, 0xfb, 0x78, 0x9c, 0xcd, 0x2b, 0x0b, 0x3b};
n20_slice_t const ASYM_SALT_SLICE = {
    .buffer = ASYM_SALT,
    .size = 64,
};

/*
 * Buffer holding the utf-8 encoded string "Key Pair Attest".
 */
uint8_t const ATTEST_KEY_PAIR_STR[] = {
    0x4b, 0x65, 0x79, 0x20, 0x50, 0x61, 0x69, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74};
n20_slice_t const ATTEST_KEY_PAIR_STR_SLICE = {
    .buffer = ATTEST_KEY_PAIR_STR,
    .size = 15,
};

uint8_t const ECA_KEY_PAIR_STR[] = {'E', 'C', 'A', '_', 'K', 'e', 'y', '_', 'P', 'a', 'i', 'r'};
n20_slice_t const ECA_KEY_PAIR_STR_SLICE = {
    .buffer = ECA_KEY_PAIR_STR,
    .size = sizeof(ECA_KEY_PAIR_STR),
};

uint8_t const ECA_EE_KEY_PAIR_STR[] = {
    'E', 'C', 'A', '_', 'E', 'E', '_', 'K', 'e', 'y', '_', 'P', 'a', 'i', 'r'};
n20_slice_t const ECA_EE_KEY_PAIR_STR_SLICE = {
    .buffer = ECA_EE_KEY_PAIR_STR,
    .size = sizeof(ECA_EE_KEY_PAIR_STR),
};

/**
 * @brief Buffer holding the salt used for the ID derivation.
 *
 * This buffer is used to derive the ID from the attestation public key.
 * The buffer is 64 bytes long and is used as input to the KDF function.
 */
uint8_t const ID_SALT[] = {
    0xdb, 0xdb, 0xae, 0xbc, 0x80, 0x20, 0xda, 0x9f, 0xf0, 0xdd, 0x5a, 0x24, 0xc8, 0x3a, 0xa5, 0xa5,
    0x42, 0x86, 0xdf, 0xc2, 0x63, 0x03, 0x1e, 0x32, 0x9b, 0x4d, 0xa1, 0x48, 0x43, 0x06, 0x59, 0xfe,
    0x62, 0xcd, 0xb5, 0xb7, 0xe1, 0xe0, 0x0f, 0xc6, 0x80, 0x30, 0x67, 0x11, 0xeb, 0x44, 0x4a, 0xf7,
    0x72, 0x09, 0x35, 0x94, 0x96, 0xfc, 0xff, 0x1d, 0xb9, 0x52, 0x0b, 0xa5, 0x1c, 0x7b, 0x29, 0xea};

n20_slice_t const ID_SALT_SLICE = {
    .buffer = ID_SALT,
    .size = sizeof(ID_SALT),
};

/*
 * Buffer holding the utf-8 encoded string "ID".
 */
uint8_t const ID_STR[] = {
    0x49,
    0x44,
};

n20_slice_t const ID_STR_SLICE = {
    .buffer = ID_STR,
    .size = 2,
};

n20_error_t n20_compress_input(n20_crypto_digest_context_t *crypto_ctx,
                               n20_open_dice_cert_info_t const *input,
                               n20_compressed_input_t digest) {
    // Check if the crypto context is valid
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    if (input == NULL) {
        return n20_error_unexpected_null_certificate_info_e;
    }

    n20_slice_t input_list[5];
    size_t input_list_count = 0;
    uint8_t mode = 0;

    switch (input->cert_type) {
        case n20_cert_type_cdi_e:
            mode = (uint8_t)input->open_dice_input.mode;
            input_list[0] = input->open_dice_input.code_hash;
            input_list[1] = input->open_dice_input.configuration_hash.size
                                ? input->open_dice_input.configuration_hash
                                : input->open_dice_input.configuration_descriptor;
            input_list[2] = input->open_dice_input.authority_hash;
            input_list[3] = (n20_slice_t){.buffer = &mode, .size = 1};
            input_list[4] = input->open_dice_input.hidden;
            input_list_count = 5;
            break;
        case n20_cert_type_eca_ee_e:
            input_list[0] =
                (n20_slice_t){.size = sizeof(input->key_usage), .buffer = input->key_usage};
            input_list[1] = (n20_slice_t){.size = input->eca_ee.name.size,
                                          .buffer = (uint8_t const *)input->eca_ee.name.buffer};
            input_list_count = 2;
            break;
        case n20_cert_type_self_signed_e:
        case n20_cert_type_eca_e:
        default:
            break;
    }

    n20_crypto_gather_list_t input_gather_list = {
        .count = input_list_count,
        .list = &input_list[0],
    };

    size_t digest_size = N20_FUNC_COMPRESSED_INPUT_SIZE;
    n20_error_t err = crypto_ctx->digest(crypto_ctx,
                                         N20_FUNC_COMPRESSED_INPUT_ALGORITHM,
                                         &input_gather_list,
                                         1,
                                         digest,
                                         &digest_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    return n20_error_ok_e;
}

n20_error_t n20_derive_key(n20_crypto_context_t *crypto_ctx,
                           n20_crypto_key_t cdi_secret,
                           n20_crypto_key_t *derived,
                           n20_crypto_key_type_t key_type,
                           n20_slice_t const salt,
                           n20_slice_t const tag) {
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }
    if (derived == NULL) {
        return n20_error_unexpected_null_key_handle_e;
    }

    n20_slice_t derivation_context_list[] = {salt, tag};

    n20_crypto_gather_list_t derivation_context = {
        .count = 2,
        .list = &derivation_context_list[0],
    };

    return crypto_ctx->kdf(crypto_ctx, cdi_secret, key_type, &derivation_context, derived);
}

n20_error_t n20_next_level_cdi_attest(n20_crypto_context_t *crypto_ctx,
                                      n20_crypto_key_t current_cdi,
                                      n20_crypto_key_t *next,
                                      n20_compressed_input_t info) {

    return n20_derive_key(crypto_ctx,
                          current_cdi,
                          next,
                          n20_crypto_key_type_cdi_e,
                          (n20_slice_t){.size = N20_FUNC_COMPRESSED_INPUT_SIZE, .buffer = &info[0]},
                          CDI_ATTEST_STR_SLICE);
}

/**
 * @brief Derives an attestation key from the given CDI secret.
 *
 * This function derives an attestation key from the given CDI
 * secret using the given salt and tag. The derived key is returned
 * in the given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret The CDI secret to derive the key from.
 * @param derived The derived key.
 * @param key_type The type of the derived key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
n20_error_t n20_derive_cdi_attestation_key(n20_crypto_context_t *crypto_ctx,
                                           n20_crypto_key_t cdi_secret,
                                           n20_crypto_key_t *derived,
                                           n20_crypto_key_type_t key_type) {
    return n20_derive_key(
        crypto_ctx, cdi_secret, derived, key_type, ASYM_SALT_SLICE, ATTEST_KEY_PAIR_STR_SLICE);
}

n20_error_t n20_derive_eca_key(n20_crypto_context_t *crypto_ctx,
                               n20_crypto_key_t cdi_secret,
                               n20_crypto_key_t *derived,
                               n20_crypto_key_type_t key_type) {
    return n20_derive_key(
        crypto_ctx, cdi_secret, derived, key_type, ASYM_SALT_SLICE, ECA_KEY_PAIR_STR_SLICE);
}

n20_error_t n20_derive_eca_ee_key(n20_crypto_context_t *crypto_ctx,
                                  n20_crypto_key_t cdi_secret,
                                  n20_slice_t const salt,
                                  n20_crypto_key_t *derived,
                                  n20_crypto_key_type_t key_type) {
    return n20_derive_key(
        crypto_ctx, cdi_secret, derived, key_type, salt, ECA_EE_KEY_PAIR_STR_SLICE);
}

/**
 * @brief Initializes the algorithm identifier structure.
 *
 * This function initializes the algorithm identifier structure
 * with the given key type.
 *
 * @param algorithm_identifier The algorithm identifier structure to initialize.
 * @param key_type The type of the key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
n20_error_t n20_init_algorithm_identifier(n20_x509_algorithm_identifier_t *algorithm_identifier,
                                          n20_crypto_key_type_t key_type) {

    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            algorithm_identifier->oid = &OID_ED25519;
            break;
        case n20_crypto_key_type_secp256r1_e:
            algorithm_identifier->oid = &OID_ECDSA_WITH_SHA256;
            break;
        case n20_crypto_key_type_secp384r1_e:
            algorithm_identifier->oid = &OID_ECDSA_WITH_SHA384;
            break;
        default:
            /* The key type is not supported. */
            return n20_error_crypto_invalid_key_type_e;
    }
    algorithm_identifier->params.variant = n20_x509_pv_none_e;
    algorithm_identifier->params.ec_curve = NULL;

    return n20_error_ok_e;
}

/**
 * @brief Initializes the key info structure.
 *
 * This function initializes the key info structure with the
 * given key type and public key.
 *
 * @param key_info The key info structure to initialize.
 * @param key_type The type of the key.
 * @param public_key The public key to use.
 * @param public_key_size The size of the public key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
n20_error_t n20_init_key_info(n20_x509_public_key_info_t *key_info,
                              n20_crypto_key_type_t key_type,
                              n20_slice_t const *public_key) {
    if (key_info == NULL) {
        return n20_error_unexpected_null_key_info_e;
    }

    if (public_key == NULL) {
        return n20_error_unexpected_null_public_key_e;
    }

    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            key_info->algorithm_identifier.oid = &OID_ED25519;
            key_info->algorithm_identifier.params.variant = n20_x509_pv_none_e;
            break;
        case n20_crypto_key_type_secp256r1_e:
            key_info->algorithm_identifier.oid = &OID_EC_PUBLIC_KEY;
            key_info->algorithm_identifier.params.variant = n20_x509_pv_ec_curve_e;
            key_info->algorithm_identifier.params.ec_curve = &OID_SECP256R1;
            break;
        case n20_crypto_key_type_secp384r1_e:
            key_info->algorithm_identifier.oid = &OID_EC_PUBLIC_KEY;
            key_info->algorithm_identifier.params.variant = n20_x509_pv_ec_curve_e;
            key_info->algorithm_identifier.params.ec_curve = &OID_SECP384R1;
            break;
        default:
            /* The key type is not supported. */
            return n20_error_crypto_invalid_key_type_e;
    }
    key_info->public_key_bits = public_key->size * 8;
    key_info->public_key = public_key->buffer;

    return n20_error_ok_e;
}

n20_error_t n20_signer_callback(void *ctx,
                                n20_slice_t tbs,
                                uint8_t *signature,
                                size_t *signature_size) {

    n20_signer_t *signer = (n20_signer_t *)ctx;

    n20_crypto_gather_list_t tbs_der_gather = {
        .count = 1,
        .list = &tbs,
    };

    return signer->crypto_ctx->sign(
        signer->crypto_ctx, signer->signing_key, &tbs_der_gather, signature, signature_size);
}

/**
 * @brief Maps OpenDICE key usage to X.509 key usage.
 *
 * This function maps the key usage values from the OpenDICE certificate
 * information to the corresponding X.509 key usage values.
 *
 * Both use the same flags with the same bit positions. But
 * the bit endianness is reversed.
 *
 * @param cert_info The OpenDICE certificate information.
 * @param key_usage The X.509 key usage information to populate.
 */
void n20_func_key_usage_open_dice_to_x509(n20_open_dice_cert_info_t const *cert_info,
                                          n20_x509_ext_key_usage_t *key_usage) {
    if (!cert_info || !key_usage) {
        return;
    }

    /* Map OpenDICE key usage to X.509 key usage.
     * Both use the same flags with the same bit positions. But
     * the bit endianness is reversed. */
    for (int i = 0; i < 8; ++i) {
        key_usage->key_usage_mask[0] |= ((cert_info->key_usage[0] >> i) & 1) << (7 - i);
        key_usage->key_usage_mask[1] |= ((cert_info->key_usage[1] >> i) & 1) << (7 - i);
    }
}

n20_error_t n20_issue_x509_cert(n20_open_dice_cert_info_t const *cert_info,
                                n20_signer_t *signer,
                                n20_crypto_key_type_t issuer_key_type,
                                uint8_t *certificate,
                                size_t *certificate_size) {
    n20_error_t err = n20_error_ok_e;
    n20_x509_ext_key_usage_t key_usage = {0};
    n20_x509_tbs_t tbs = {0};
    n20_x509_extension_t extensions_buffer[3] = {0};

    n20_func_key_usage_open_dice_to_x509(cert_info, &key_usage);

    n20_x509_ext_basic_constraints_t basic_constraints = {
        /* ECA end-entity certificates are not CA certificates */
        .is_ca = cert_info->cert_type == n20_cert_type_eca_ee_e ? 0 : 1,
        /* ECA CA certificates have a path length constraint of 0,
         * i.e., they cannot issue other intermediate CA certs,
         * only end-entity certificates. */
        .has_path_length = cert_info->cert_type == n20_cert_type_eca_e,
        /* The path length constraint is 0 for ECA CA certificates.
         * otherwise this field is ignored, because .has_path_length is false. */
        .path_length = 0,
    };

    tbs.extensions.extensions = &extensions_buffer[0];

    switch (cert_info->cert_type) {
        case n20_cert_type_cdi_e:
            extensions_buffer[tbs.extensions.extensions_count++] = (n20_x509_extension_t){
                .oid = &OID_OPEN_DICE_INPUT,
                .critical = 1,
                .content_cb = n20_x509_ext_open_dice_input_content,
                .context = (void *)&cert_info->open_dice_input,
            };
            break;
        case n20_cert_type_eca_e:
            if (cert_info->eca.nonce.size > 0) {
                extensions_buffer[tbs.extensions.extensions_count++] = (n20_x509_extension_t){
                    .oid = &OID_TCG_DICE_TCB_FRESHNESS,
                    .critical = 1,
                    .content_cb = n20_x509_ext_tcg_dice_tcb_freshness_content,
                    .context = (void *)&cert_info->eca.nonce,
                };
            }
            break;
        case n20_cert_type_eca_ee_e:
            if (cert_info->eca_ee.nonce.size > 0) {
                extensions_buffer[tbs.extensions.extensions_count++] = (n20_x509_extension_t){
                    .oid = &OID_TCG_DICE_TCB_FRESHNESS,
                    .critical = 1,
                    .content_cb = n20_x509_ext_tcg_dice_tcb_freshness_content,
                    .context = (void *)&cert_info->eca_ee.nonce,
                };
            }
            break;
        case n20_cert_type_self_signed_e:
            break;
        default:
            return n20_error_unsupported_certificate_type_e;
    }

    extensions_buffer[tbs.extensions.extensions_count++] = (n20_x509_extension_t){
        .oid = &OID_KEY_USAGE,
        .critical = 1,
        .content_cb = n20_x509_ext_key_usage_content,
        .context = &key_usage,
    };
    extensions_buffer[tbs.extensions.extensions_count++] = (n20_x509_extension_t){
        .oid = &OID_BASIC_CONSTRAINTS,
        .critical = 1,
        .content_cb = n20_x509_ext_basic_constraints_content,
        .context = &basic_constraints,
    };

    tbs.validity = (n20_x509_validity_t){
        .not_before = N20_STR_NULL,
        .not_after = N20_STR_NULL,
    };

    tbs.serial_number = cert_info->subject;

    err = n20_init_algorithm_identifier(&tbs.signature_algorithm, issuer_key_type);
    if (err != n20_error_ok_e) {
        return err;
    }

    err = n20_init_key_info(&tbs.subject_public_key_info,
                            cert_info->subject_public_key.algorithm,
                            &cert_info->subject_public_key.key);
    if (err != n20_error_ok_e) {
        return err;
    }

    tbs.issuer_name.element_count = 1;
    tbs.issuer_name.elements[0] = (n20_x509_rdn_t){&OID_SERIAL_NUMBER, .bytes = cert_info->issuer};

    tbs.subject_name.element_count = 1;
    tbs.subject_name.elements[0] =
        (n20_x509_rdn_t){&OID_SERIAL_NUMBER, .bytes = cert_info->subject};

    // Create a new stream for the attestation certificate
    n20_stream_t stream;
    n20_stream_init(&stream, certificate, *certificate_size);
    n20_x509_cert_tbs(&stream, &tbs);
    if (n20_stream_has_buffer_overflow(&stream)) {
        if (n20_stream_has_write_position_overflow(&stream)) {
            return n20_error_write_position_overflow_e;
        }
        *certificate_size = n20_stream_byte_count(&stream);
        return n20_error_insufficient_buffer_size_e;
    }

    // Sign the to-be-signed part of the certificate.
    uint8_t signature[96];
    size_t signature_size = sizeof(signature);

    err = signer->cb(
        signer,
        (n20_slice_t){.size = n20_stream_byte_count(&stream), .buffer = n20_stream_data(&stream)},
        signature,
        &signature_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    /* Reinitialize the stream. */
    n20_stream_init(&stream, certificate, *certificate_size);
    n20_x509_t cert = {
        .tbs = &tbs,
        .signature_algorithm = tbs.signature_algorithm,
        .signature_bits = signature_size * 8,
        .signature = signature,
    };

    n20_x509_cert(&stream, &cert);
    *certificate_size = n20_stream_byte_count(&stream);
    if (n20_stream_has_buffer_overflow(&stream)) {
        if (n20_stream_has_write_position_overflow(&stream)) {
            /* This is not reachable because any malformed input
             * would have been caught when generating the tbs part
             * of the certificate. */
            return n20_error_write_position_overflow_e;
        }
        return n20_error_insufficient_buffer_size_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_open_dice_cdi_id(n20_crypto_digest_context_t *digest_ctx,
                                 n20_slice_t const public_key,
                                 n20_cdi_id_t cdi_id) {
    n20_error_t rc = digest_ctx->hkdf(digest_ctx,
                                      n20_crypto_digest_algorithm_sha2_512_e,
                                      public_key,
                                      ID_SALT_SLICE,
                                      ID_STR_SLICE,
                                      20,
                                      &cdi_id[0]);
    if (rc != n20_error_ok_e) {
        return rc;
    }

    /* Ensure that the most significant bit is not set so that it
     * is a valid positive integer that can be represented as no
     * more than 20 bytes in ASN1.
     */
    cdi_id[0] &= 0x7F;
    return rc;
}

n20_error_t n20_eca_ee_sign_message(n20_crypto_context_t *crypto_ctx,
                                    n20_crypto_key_t parent_secret,
                                    n20_crypto_key_type_t key_type,
                                    n20_string_slice_t name,
                                    n20_slice_t key_usage,
                                    n20_slice_t message,
                                    uint8_t *signature,
                                    size_t *signature_size_in_out) {
    /* Check if the crypto context is valid. */
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    if (signature_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    cert_info.eca_ee.name = name;
    switch (key_usage.size) {
        default:
            cert_info.key_usage[1] = key_usage.buffer[1];
            fallthrough;
        case 1:
            cert_info.key_usage[0] = key_usage.buffer[0];
            break;
        case 0:
            break;
    }

    n20_compressed_input_t input_digest = {0};
    n20_error_t err = n20_compress_input(&crypto_ctx->digest_ctx, &cert_info, input_digest);
    if (err != n20_error_ok_e) {
        return err;
    }

    /* Derive the ECA signing key */
    n20_crypto_key_t eca_ee_key = NULL;
    err = n20_derive_eca_ee_key(
        crypto_ctx,
        parent_secret,
        (n20_slice_t){.size = sizeof(input_digest), .buffer = &input_digest[0]},
        &eca_ee_key,
        key_type);
    if (err != n20_error_ok_e) {
        return err;
    }

    /* Sign the message */
    n20_crypto_gather_list_t message_gather = {
        .count = 1,
        .list = &message,
    };

    size_t signature_size_local = 0;
    err = crypto_ctx->sign(crypto_ctx, eca_ee_key, &message_gather, NULL, &signature_size_local);

    if (err != n20_error_crypto_insufficient_buffer_size_e) {
        /* We expect insufficient buffer size error here. */
        crypto_ctx->key_free(crypto_ctx, eca_ee_key);
        return err;
    }

    if (*signature_size_in_out < signature_size_local) {
        *signature_size_in_out = signature_size_local;
        /* Clean up the ECA key */
        crypto_ctx->key_free(crypto_ctx, eca_ee_key);
        return n20_error_insufficient_buffer_size_e;
    }

    err = crypto_ctx->sign(crypto_ctx,
                           eca_ee_key,
                           &message_gather,
                           signature + *signature_size_in_out - signature_size_local,
                           &signature_size_local);
    if (err == n20_error_ok_e) {
        *signature_size_in_out = signature_size_local;
    }

    /* Clean up the ECA key */
    crypto_ctx->key_free(crypto_ctx, eca_ee_key);

    return err;
}

n20_error_t n20_compute_certificate_context(n20_crypto_context_t *crypto_ctx,
                                            n20_crypto_key_t issuer_cdi,
                                            n20_open_dice_cert_info_t const *cert_info,
                                            n20_crypto_key_type_t const issuer_key_type,
                                            n20_crypto_key_type_t const subject_key_type,
                                            n20_crypto_key_t *issuer_key_out,
                                            n20_cdi_id_t issuer_serial_number_out,
                                            n20_cdi_id_t subject_serial_number_out,
                                            uint8_t *subject_public_key_buffer_out,
                                            size_t *subject_public_key_buffer_size_in_out) {

    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    if (subject_public_key_buffer_out == NULL) {
        return n20_error_unexpected_null_public_key_buffer_e;
    }

    if (subject_public_key_buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    if (cert_info == NULL) {
        return n20_error_unexpected_null_certificate_info_e;
    }

    n20_compressed_input_t input_digest = {0};
    n20_crypto_key_t subject_cdi = issuer_cdi;
    n20_error_t err = n20_error_ok_e;

    if (cert_info->cert_type == n20_cert_type_eca_ee_e ||
        cert_info->cert_type == n20_cert_type_cdi_e) {
        err = n20_compress_input(&crypto_ctx->digest_ctx, cert_info, input_digest);
        if (err != n20_error_ok_e) {
            return err;
        }
    }

    /* 1. Derive subject CDI. Alive handles 1 -> 2
     * If the certificate type is CDI, we need to derive the next level
     * CDI secret first. Otherwise, the issuer CDI is the same as the subject CDI.*/
    if (cert_info->cert_type == n20_cert_type_cdi_e) {
        /* Precondition number of live key handles: 1 */
        err = n20_next_level_cdi_attest(crypto_ctx, issuer_cdi, &subject_cdi, input_digest);
        if (err != n20_error_ok_e) {
            return err;
        }
        /* Post condition number of live key handles: 2 */
    }
    /* Postcondition
     *   (cert_type = n20_cert_type_cdi_e AND handle_count == 2) OR
     *   (cert_type != n20_cert_type_cdi_e AND handle_count == 1)
     * In the following the number of key handles will be expressed as tuple
     * where the first element is the number of live handles if
     * cert_type == n20_cert_type_cdi_e and the second element is the
     * number of live handles if cert_type != n20_cert_type_cdi_e. */

    /* 2. Derive subject key pair */
    /* Precondition:
     *   handle_count = (2, 1)*/
    n20_crypto_key_t subject_key = NULL;
    switch (cert_info->cert_type) {
        case n20_cert_type_self_signed_e:
        case n20_cert_type_cdi_e:
            err = n20_derive_cdi_attestation_key(
                crypto_ctx, subject_cdi, &subject_key, subject_key_type);
            break;
        case n20_cert_type_eca_e:
            err = n20_derive_eca_key(crypto_ctx, subject_cdi, &subject_key, subject_key_type);
            break;
        case n20_cert_type_eca_ee_e:
            err = n20_derive_eca_ee_key(
                crypto_ctx,
                subject_cdi,
                (n20_slice_t){.size = sizeof(input_digest), .buffer = &input_digest[0]},
                &subject_key,
                subject_key_type);
            break;
        default:
            err = n20_error_unsupported_certificate_type_e;
            break;
    }
    /* Postcondition:
     *   (err = n20_error_ok_e AND handle_count = (3, 2))
     *   OR
     *   (err != n20_error_ok_e AND handle_count = (2, 1)) */

    /* 3. Free subject cdi handle.
     * If the certificate type is CDI, we need to free the subject cdi handle.
     * That is regardless of whether the key derivation was successful or not.
     * Precondition:
     *   (err = n20_error_ok_e AND handle_count = (3, 2))
     *   OR
     *   (err != n20_error_ok_e AND handle_count = (2, 1)) */
    if (cert_info->cert_type == n20_cert_type_cdi_e) {
        crypto_ctx->key_free(crypto_ctx, subject_cdi);
    }
    /* Postcondition:
     *   (err = n20_error_ok_e AND handle_count = (2, 2))
     *   OR
     *   (err != n20_error_ok_e AND handle_count = (1, 1)) */

    /* The handle count no longer diverges based on cert_type:
     * Precondition:
     *   (err = n20_error_ok_e AND handle_count = 2)
     *   OR
     *   (err != n20_error_ok_e AND handle_count = 1) */
    if (err != n20_error_ok_e) {
        /* Precondition (return): handle_count = 1 */
        return err;
    }
    /* Postcondition:
     *   handle_count = 2 */

    /* 4. Derive issuer key pair.
     * CDI certificates and ECA certificates are issued by the CDI key pair.
     * End entity certificates are issued by the ECA key pair. */
    /* Precondition: handle_count = 2 */
    n20_crypto_key_t issuer_key = NULL;
    switch (cert_info->cert_type) {
        case n20_cert_type_self_signed_e:
        case n20_cert_type_cdi_e:
        case n20_cert_type_eca_e:
            err = n20_derive_cdi_attestation_key(
                crypto_ctx, issuer_cdi, &issuer_key, issuer_key_type);
            break;
        case n20_cert_type_eca_ee_e:
            err = n20_derive_eca_key(crypto_ctx, issuer_cdi, &issuer_key, issuer_key_type);
            break;
        default:
            /* This is not reachable because any unknown certificate type
             * would have tripped up subject key generation above. */
            err = n20_error_unsupported_certificate_type_e;
            break;
    }
    /* Postcondition:
     *   (err = n20_error_ok_e AND handle_count = 3)
     *   OR
     *   (err != n20_error_ok_e AND handle_count = 2) */

    if (err != n20_error_ok_e) {
        /* If the key derivation failed the subject_key handle needs to be freed here. */
        /* Precondition: handle_count = 2 */
        crypto_ctx->key_free(crypto_ctx, subject_key);
        /* Postcondition: handle_count = 1 */
        return err;
    }
    /* Postcondition: handle_count = 3 */

    size_t subject_public_key_size = *subject_public_key_buffer_size_in_out;

    /* If the issuer serial number is requested, the public key needs
     * to be retrieved and the cdi_id computed. Otherwise this
     * can be skipped. */
    if (issuer_serial_number_out != NULL) {
        /* 5. Get issuer public key. Alive handles 3 */
        err = crypto_ctx->key_get_public_key(crypto_ctx,
                                             issuer_key,
                                             subject_public_key_buffer_out,
                                             subject_public_key_buffer_size_in_out);
        if (err != n20_error_ok_e) {
            /* Precondition: handle_count = 3 */
            crypto_ctx->key_free(crypto_ctx, subject_key);
            crypto_ctx->key_free(crypto_ctx, issuer_key);
            /* Postcondition: handle_count = 1 */
            return err;
        }

        /* 6. Compute issuer CDI ID. Alive handles 3 */
        err = n20_open_dice_cdi_id(
            &crypto_ctx->digest_ctx,
            (n20_slice_t){*subject_public_key_buffer_size_in_out, subject_public_key_buffer_out},
            issuer_serial_number_out);
        if (err != n20_error_ok_e) {
            /* Precondition: handle_count = 3 */
            crypto_ctx->key_free(crypto_ctx, subject_key);
            crypto_ctx->key_free(crypto_ctx, issuer_key);
            /* Postcondition: handle_count = 1 */
            return err;
        }
    }

    /* 7. Get subject public key. Alive handles 3 */
    *subject_public_key_buffer_size_in_out = subject_public_key_size;
    err = crypto_ctx->key_get_public_key(crypto_ctx,
                                         subject_key,
                                         subject_public_key_buffer_out,
                                         subject_public_key_buffer_size_in_out);

    /* 8. Free subject key handle. Alive handles 3 -> 2
     * The subject key handle needs to be freed regardless of whether the previous
     * call was successful or not. */
    /* Precondition: handle_count = 3 */
    crypto_ctx->key_free(crypto_ctx, subject_key);
    /* Postcondition: handle_count = 2 */

    if (err != n20_error_ok_e) {
        /* Precondition: handle_count = 2 */
        crypto_ctx->key_free(crypto_ctx, issuer_key);
        /* Postcondition: handle_count = 1 */
        return err;
    }

    /* If the subject serial number is requested, the cdi_id needs to be computed.
     * Otherwise this can be skipped. */
    if (subject_serial_number_out != NULL) {
        /* 9. Compute subject CDI ID. Alive handles 2 */
        err = n20_open_dice_cdi_id(
            &crypto_ctx->digest_ctx,
            (n20_slice_t){*subject_public_key_buffer_size_in_out, subject_public_key_buffer_out},
            subject_serial_number_out);
        if (err != n20_error_ok_e) {
            /* Precondition: handle_count = 2 */
            crypto_ctx->key_free(crypto_ctx, issuer_key);
            /* Postcondition: handle_count = 1 */
            return err;
        }
        /* Postcondition: handle_count = 2 */
    }

    /* Precondition: handle_count = 2 */
    if (issuer_key_out != NULL) {
        *issuer_key_out = issuer_key;
    } else {
        /* Release issuer key handle if not requested. Alive handles 2 -> 1 */
        /* Precondition: handle_count = 2 */
        crypto_ctx->key_free(crypto_ctx, issuer_key);
        /* Postcondition: handle_count = 1 */
    }
    /* Postcondition:
     * (issuer_key_out != NULL AND handle_count = 2) OR
     * (issuer_key_out == NULL AND handle_count = 1) */

    return n20_error_ok_e;
}

n20_error_t n20_issue_certificate(n20_crypto_context_t *crypto_ctx,
                                  n20_crypto_key_t issuer_secret_in,
                                  n20_crypto_key_type_t issuer_key_type_in,
                                  n20_crypto_key_type_t subject_key_type_in,
                                  n20_open_dice_cert_info_t *cert_info_in,
                                  n20_certificate_format_t certificate_format_in,
                                  uint8_t *certificate_out,
                                  size_t *certificate_size_in_out) {
    /* Check if the crypto context is valid. */
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    if (cert_info_in == NULL) {
        return n20_error_unexpected_null_certificate_info_e;
    }

    n20_crypto_key_t signing_key = NULL;
    n20_cdi_id_t issuer_serial_number = {0};
    n20_cdi_id_t subject_serial_number = {0};

    /* The maximum expected public key size is 96 bytes (P-384).
     * This buffer leaves room for an additional 0x04 prefix
     * indicating uncompressed format. */
    uint8_t public_key_buffer[97];
    uint8_t *public_key = &public_key_buffer[1];
    size_t public_key_size = sizeof(public_key_buffer) - 1;

    switch (cert_info_in->cert_type) {
        case n20_cert_type_cdi_e:
        case n20_cert_type_self_signed_e:
        case n20_cert_type_eca_e:
            cert_info_in->key_usage[0] = 0;
            cert_info_in->key_usage[1] = 0;
            N20_OPEN_DICE_KEY_USAGE_SET_KEY_CERT_SIGN(cert_info_in->key_usage);
            break;
        case n20_cert_type_eca_ee_e:
            /* Key usage is set by the caller. */
            break;
        default:
            return n20_error_unsupported_certificate_type_e;
    }

    if (cert_info_in->cert_type == n20_cert_type_self_signed_e) {
        /* Override subject key type with issuer key type. */
        subject_key_type_in = issuer_key_type_in;
    }

    n20_error_t err = n20_compute_certificate_context(crypto_ctx,
                                                      issuer_secret_in,
                                                      cert_info_in,
                                                      issuer_key_type_in,
                                                      subject_key_type_in,
                                                      &signing_key,
                                                      issuer_serial_number,
                                                      subject_serial_number,
                                                      public_key,
                                                      &public_key_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    /* If the key type is one of the supported NIST curves,
     * prepend the "uncompressed" prefix 0x04. */
    switch (subject_key_type_in) {
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e:
            public_key_buffer[0] = 0x04;
            public_key = &public_key_buffer[0];
            public_key_size += 1;
            break;
        case n20_crypto_key_type_ed25519_e:
            /* No prefix for Ed25519 keys */
            break;
        default:
            /* This is not reachable, because an unsupported
             * key type cannot have been derived in the first
             * place. */
            crypto_ctx->key_free(crypto_ctx, signing_key);
            return n20_error_crypto_invalid_key_type_e;
    }

    cert_info_in->issuer.buffer = issuer_serial_number;
    cert_info_in->issuer.size = sizeof(n20_cdi_id_t);
    cert_info_in->subject.buffer = subject_serial_number;
    cert_info_in->subject.size = sizeof(n20_cdi_id_t);

    cert_info_in->subject_public_key = (n20_open_dice_public_key_info_t){
        .key =
            {
                .buffer = public_key,
                .size = public_key_size,
            },
        .algorithm = subject_key_type_in,
    };

    switch (certificate_format_in) {
        case n20_certificate_format_x509_e:
            err = n20_issue_x509_cert(cert_info_in,
                                      &(n20_signer_t){
                                          .crypto_ctx = crypto_ctx,
                                          .signing_key = signing_key,
                                          .cb = n20_signer_callback,
                                      },
                                      issuer_key_type_in,
                                      certificate_out,
                                      certificate_size_in_out);
            break;
        default:
            err = n20_error_unsupported_certificate_format_e;
    }

    crypto_ctx->key_free(crypto_ctx, signing_key);

    return err;
}
