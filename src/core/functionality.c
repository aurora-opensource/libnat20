/*
 * Copyright 2025 Aurora Operations, Inc.
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
 */

#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/oid.h>
#include <nat20/service/service.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static n20_x509_ext_open_dice_modes_t n20_open_dice_mode_2_x509_mode(n20_open_dice_mode_t mode) {
    switch (mode) {
        case n20_open_dice_mode_not_configured_e:
            return n20_x509_ext_open_dice_not_configured_e;
        case n20_open_dice_mode_normal_e:
            return n20_x509_ext_open_dice_normal_e;
        case n20_open_dice_mode_debug_e:
            return n20_x509_ext_open_dice_debug_e;
        case n20_open_dice_mode_recovery_e:
            return n20_x509_ext_open_dice_recovery_e;
        default:
            return n20_x509_ext_open_dice_not_configured_e;
    }
}

/**
 * @brief Converts n20_open_dice_mode_t to n20_cwt_open_dice_modes_t
 *
 */
static n20_cwt_open_dice_modes_t n20_open_dice_mode_2_cwt_mode(n20_open_dice_mode_t mode) {
    switch (mode) {
        case n20_open_dice_mode_not_configured_e:
            return n20_cwt_open_dice_not_configured_e;
        case n20_open_dice_mode_normal_e:
            return n20_cwt_open_dice_normal_e;
        case n20_open_dice_mode_debug_e:
            return n20_cwt_open_dice_debug_e;
        case n20_open_dice_mode_recovery_e:
            return n20_cwt_open_dice_recovery_e;
        default:
            return n20_cwt_open_dice_not_configured_e;
    }
}

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

/**
 * @brief Buffer holding the salt used for the ID derivation.
 *
 * This buffer is used to derive the ID from the attestation public key.
 & The buffer is 64 bytes long and is used as input to the KDF function.
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
                               n20_open_dice_input_t const *context,
                               n20_compressed_input_t digest) {
    // Check if the crypto context is valid
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    uint8_t mode = (uint8_t)context->mode;

    n20_slice_t input_list[] = {
        context->code_hash,
        context->configuration_hash,
        context->authority_hash,
        {.buffer = &mode, .size = 1},
        context->hidden,
    };

    n20_crypto_gather_list_t input = {
        .count = 5,
        .list = &input_list[0],
    };

    size_t digest_size = N20_FUNC_COMPRESSED_INPUT_SIZE;
    n20_error_t err = crypto_ctx->digest(
        crypto_ctx, N20_FUNC_COMPRESSED_INPUT_ALGORITHM, &input, 1, digest, &digest_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    return n20_error_ok_e;
}

/**
 * @brief Derives a key from the given CDI secret.
 *
 * This function derives a key from the given CDI secret using
 * the given salt and tag. The derived key is returned in the
 * given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret The CDI secret to derive the key from.
 * @param derived The derived key.
 * @param key_type The type of the derived key.
 * @param salt The salt to use for the derivation.
 * @param tag The tag to use for the derivation.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
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

/**
 * @brief Derives the next level CDI secret from the given CDI secret.
 *
 * This function derives the next level CDI secret from the given
 * CDI secret using the given salt and tag. The derived key is
 * returned in the given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param current The current CDI secret to derive the key from.
 * @param next The derived key.
 * @param info The information to use for the derivation.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
n20_error_t n20_next_level_cdi_attest(n20_crypto_context_t *crypto_ctx,
                                      n20_crypto_key_t current,
                                      n20_crypto_key_t *next,
                                      n20_compressed_input_t info) {

    return n20_derive_key(crypto_ctx,
                          current,
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
n20_error_t n20_derive_attestation_key(n20_crypto_context_t *crypto_ctx,
                                       n20_crypto_key_t cdi_secret,
                                       n20_crypto_key_t *derived,
                                       n20_crypto_key_type_t key_type) {
    return n20_derive_key(
        crypto_ctx, cdi_secret, derived, key_type, ASYM_SALT_SLICE, ATTEST_KEY_PAIR_STR_SLICE);
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
                              uint8_t *public_key,
                              size_t public_key_size) {
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
    key_info->public_key_bits = public_key_size * 8;
    key_info->public_key = public_key;

    return n20_error_ok_e;
}

typedef n20_error_t (*n20_signer_callback_t)(void *signer,
                                             n20_slice_t tbs,
                                             uint8_t *signature,
                                             size_t *signature_size);

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
 * @brief Initializes the X.509 name structure.
 *
 * This function initializes the X.509 name structure with the
 * given name.
 *
 * @param name The X.509 name structure to initialize.
 * @param n The name to use.
 */
void n20_init_x509_name(n20_x509_name_t *name, n20_name_t const *n) {
    size_t i = 0;
    if (n->country_name.buffer != NULL) {
        name->elements[i++] = (n20_x509_rdn_t){&OID_COUNTRY_NAME, .string = n->country_name};
    }
    if (n->locality_name.buffer != NULL) {
        name->elements[i++] = (n20_x509_rdn_t){&OID_LOCALITY_NAME, .string = n->locality_name};
    }
    if (n->organization_name.buffer != NULL) {
        name->elements[i++] =
            (n20_x509_rdn_t){&OID_ORGANIZATION_NAME, .string = n->organization_name};
    }
    if (n->organization_unit_name.buffer != NULL) {
        name->elements[i++] =
            (n20_x509_rdn_t){&OID_ORGANIZATION_UNIT_NAME, .string = n->organization_unit_name};
    }
    if (n->common_name.buffer != NULL) {
        name->elements[i++] = (n20_x509_rdn_t){&OID_COMMON_NAME, .string = n->common_name};
    }
    if (n->serial_number.buffer != NULL) {
        name->elements[i++] = (n20_x509_rdn_t){&OID_SERIAL_NUMBER, .bytes = n->serial_number};
    }
    name->element_count = i;
}

/**
 * @brief Prepares the X.509 certificate.
 *
 * This function prepares the X.509 certificate with the given
 * context information and signs it using the given signer.
 *
 * @param context The context information to use.
 * @param signer The signer to use.
 * @param issuer_key_type The type of the issuer key.
 * @param issuer_name The name of the issuer.
 * @param subject_key_type The type of the subject key.
 * @param subject_name The name of the subject.
 * @param public_key The public key to use.
 * @param public_key_size The size of the public key.
 * @param attestation_certificate The attestation certificate to use.
 * @param attestation_certificate_size The size of the attestation certificate.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
n20_error_t n20_prepare_x509_cert(n20_open_dice_input_t const *context,
                                  n20_signer_t *signer,
                                  n20_crypto_key_type_t issuer_key_type,
                                  n20_name_t *issuer_name,
                                  n20_crypto_key_type_t subject_key_type,
                                  n20_name_t *subject_name,
                                  uint8_t *public_key,
                                  size_t public_key_size,
                                  uint8_t *attestation_certificate,
                                  size_t *attestation_certificate_size) {
    n20_error_t err = n20_error_ok_e;
    n20_x509_ext_key_usage_t key_usage = {0};
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_x509_ext_basic_constraints_t basic_constraints = {
        .is_ca = 1,
        .has_path_length = false,
    };

    n20_x509_ext_open_dice_input_t open_dice_extension = {
        .code_hash = context->code_hash,
        .code_descriptor = context->code_descriptor,
        .configuration_hash = context->configuration_hash,
        .configuration_descriptor = context->configuration_descriptor,
        .authority_hash = context->authority_hash,
        .authority_descriptor = context->authority_descriptor,
        .mode = n20_open_dice_mode_2_x509_mode(context->mode),
        .profile_name = context->profile_name,
    };

    n20_x509_extension_t extensions[3] = {
        {
            .oid = &OID_OPEN_DICE_INPUT,
            .critical = 1,
            .content_cb = n20_x509_ext_open_dice_input_content,
            .context = &open_dice_extension,
        },
        {
            .oid = &OID_KEY_USAGE,
            .critical = 1,
            .content_cb = n20_x509_ext_key_usage_content,
            .context = &key_usage,
        },
        {
            .oid = &OID_BASIC_CONSTRAINTS,
            .critical = 1,
            .content_cb = n20_x509_ext_basic_constraints_content,
            .context = &basic_constraints,
        },
    };

    n20_x509_tbs_t tbs = {0};
    tbs.validity = (n20_x509_validity_t){
        .not_before = N20_STR_NULL,
        .not_after = N20_STR_NULL,
    };

    tbs.serial_number = subject_name->serial_number;

    err = n20_init_algorithm_identifier(&tbs.signature_algorithm, issuer_key_type);
    if (err != n20_error_ok_e) {
        return err;
    }

    err = n20_init_key_info(
        &tbs.subject_public_key_info, subject_key_type, public_key, public_key_size);
    if (err != n20_error_ok_e) {
        return err;
    }

    n20_init_x509_name(&tbs.issuer_name, issuer_name);
    n20_init_x509_name(&tbs.subject_name, subject_name);

    tbs.issuer_unique_id = issuer_name->serial_number;
    tbs.subject_unique_id = subject_name->serial_number;

    tbs.extensions = (n20_x509_extensions_t){
        .extensions_count = 3,
        .extensions = &extensions[0],
    };

    // Create a new stream for the attestation certificate
    n20_stream_t stream;
    n20_stream_init(&stream, attestation_certificate, *attestation_certificate_size);
    n20_x509_cert_tbs(&stream, &tbs);
    if (n20_stream_has_buffer_overflow(&stream) ||
        n20_stream_has_write_position_overflow(&stream)) {
        *attestation_certificate_size = n20_stream_byte_count(&stream);

        return n20_error_insufficient_buffer_size_e;
    }

    // Sign the to-be-signed part of the certificate.
    uint8_t signature[128];
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
    n20_stream_init(&stream, attestation_certificate, *attestation_certificate_size);
    n20_x509_t cert = {
        .tbs = &tbs,
        .signature_algorithm = tbs.signature_algorithm,
        .signature_bits = signature_size * 8,
        .signature = signature,
    };

    n20_x509_cert(&stream, &cert);
    if (n20_stream_has_buffer_overflow(&stream) ||
        n20_stream_has_write_position_overflow(&stream)) {
        *attestation_certificate_size = n20_stream_byte_count(&stream);
        return n20_error_insufficient_buffer_size_e;
    }
    *attestation_certificate_size = n20_stream_byte_count(&stream);

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
    /* Ensure that the most significant bit is not set so that it
     * is a valid positive integer that can be represented as no
     * more than 20 bytes in ASN1.
     */
    cdi_id[0] &= 0x7F;
    return rc;
}

static void payload_callback_open_dice_cwt(n20_stream_t *s, void *payload_ctx) {
    n20_open_dice_cwt_write(s, (n20_open_dice_cwt_t const *)payload_ctx);
}

/**
 * @brief Issues a new attestation certificate.
 *
 * This function generates a new CDI secret from a CDI or UDS given
 * as opaque crypto key handle and context information. It uses the
 * crypto context to generate a new CDI secret and then issues a
 * new attestation certificate for the given CDI level.
 * To that end it uses the derived CDI secret to derive a new
 * attestation key pair and formats the attestation certificate
 * using the given context information to generate the OpenDICE input
 * extension.
 * The attestation certificate is then signed using the attestation
 * key pair of the given CDI level.
 * The attestation certificate is then returned in the given
 * buffer.
 * The size of the attestation certificate buffer is given as
 * pointer which is updated to the actual size of the attestation
 * certificate.
 *
 * Important: Because of the way the attestation certificate is
 * rendered, the resulting certificate is not written to the
 * beginning of the buffer but to the end. Thus the certificate
 * is located at
 * `attestation_certificate + in_buffer_size - out_buffer_size`.
 *
 * The function returns @ref n20_error_ok_e on success, or an error
 * code on failure.
 */
n20_error_t n20_opendice_attestation_key_and_certificate(n20_crypto_context_t *crypto_ctx,
                                                         n20_crypto_key_t parent_secret,
                                                         n20_crypto_key_t parent_attestation_key,
                                                         n20_crypto_key_type_t parent_key_type,
                                                         n20_crypto_key_type_t key_type,
                                                         n20_open_dice_input_t const *context,
                                                         n20_certificate_format_t certificate_format,
                                                         uint8_t *attestation_certificate,
                                                         size_t *attestation_certificate_size) {

    /* Check if the crypto context is valid. */
    if (crypto_ctx == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    bool cose = (certificate_format == n20_certificate_format_cose_e);

    n20_compressed_input_t input_digest = {0};

    n20_error_t err = n20_compress_input(&crypto_ctx->digest_ctx, context, input_digest);
    if (err != n20_error_ok_e) {
        return err;
    }

    n20_cdi_id_t issuer_serial_number = {0};

    uint8_t public_key_buffer[97];

    /* Get the public key of the parent attestation key. */
    uint8_t *public_key = &public_key_buffer[1];
    size_t public_key_size = sizeof(public_key_buffer) - 1;
    err = crypto_ctx->key_get_public_key(
        crypto_ctx, parent_attestation_key, public_key, &public_key_size);

    if (err != n20_error_ok_e) {
        return err;
    }

    err = n20_open_dice_cdi_id(&crypto_ctx->digest_ctx,
                               (n20_slice_t){.buffer = public_key, .size = public_key_size},
                               issuer_serial_number);

    if (err != n20_error_ok_e) {
        return err;
    }

    if (!cose && parent_key_type != n20_crypto_key_type_ed25519_e) {
        public_key_buffer[0] = 0x04;
        public_key = &public_key_buffer[0];
        public_key_size += 1;
    }

    n20_crypto_key_t child_secret = NULL;

    err = n20_next_level_cdi_attest(crypto_ctx, parent_secret, &child_secret, input_digest);
    if (err != n20_error_ok_e) {
        return err;
    }

    n20_crypto_key_t child_attestation_key = NULL;
    err = n20_derive_attestation_key(crypto_ctx, child_secret, &child_attestation_key, key_type);

    /* Regardless of whether the last call was successful
     * the child secret is no longer needed. */
    crypto_ctx->key_free(crypto_ctx, child_secret);

    if (err != n20_error_ok_e) {
        return err;
    }

    /* Get the public key of the derived key. */
    public_key = &public_key_buffer[1];
    public_key_size = sizeof(public_key_buffer) - 1;
    err = crypto_ctx->key_get_public_key(
        crypto_ctx, child_attestation_key, public_key, &public_key_size);

    /* Regardless of whether the last call was successful
     * the child attestation key is no longer needed. */
    crypto_ctx->key_free(crypto_ctx, child_attestation_key);

    if (err != n20_error_ok_e) {
        return err;
    }

    n20_cdi_id_t subject_serial_number = {0};
    err = n20_open_dice_cdi_id(&crypto_ctx->digest_ctx,
                               (n20_slice_t){.buffer = public_key, .size = public_key_size},
                               subject_serial_number);
    if (err != n20_error_ok_e) {
        return err;
    }

    if (!cose && key_type != n20_crypto_key_type_ed25519_e) {
        public_key_buffer[0] = 0x04;
        public_key = &public_key_buffer[0];
        public_key_size += 1;
    }

    if (!cose) {
        return n20_prepare_x509_cert(context,
                                     &(n20_signer_t){
                                         .crypto_ctx = crypto_ctx,
                                         .signing_key = parent_attestation_key,
                                         .cb = n20_signer_callback,
                                     },
                                     parent_key_type,
                                     &(n20_name_t){
                                         .country_name = N20_STR_C("US"),
                                         .locality_name = N20_STR_C("Scranton"),
                                         .organization_name = N20_STR_C("Test DICE CA"),
                                         .organization_unit_name = N20_STR_NULL,
                                         .common_name = N20_STR_C("DICE Layer 0"),
                                         .serial_number =
                                             {
                                                 .buffer = (uint8_t *)issuer_serial_number,
                                                 .size = sizeof(issuer_serial_number),
                                             },
                                     },
                                     key_type,
                                     &(n20_name_t){
                                         .country_name = N20_STR_C("US"),
                                         .locality_name = N20_STR_C("Scranton"),
                                         .organization_name = N20_STR_C("Test DICE CA"),
                                         .organization_unit_name = N20_STR_NULL,
                                         .common_name = N20_STR_C("DICE Layer 1"),
                                         .serial_number =
                                             {
                                                 .buffer = (uint8_t *)subject_serial_number,
                                                 .size = sizeof(subject_serial_number),
                                             },
                                     },
                                     public_key,
                                     public_key_size,
                                     attestation_certificate,
                                     attestation_certificate_size);
    } else {
        n20_open_dice_cwt_t cwt = {
            .code_hash = context->code_hash,
            .configuration_hash = context->configuration_hash,
            .authority_hash = context->authority_hash,
            .mode = n20_open_dice_mode_2_cwt_mode(context->mode),
            .subject =
                {
                    .buffer = (uint8_t *)subject_serial_number,
                    .size = sizeof(subject_serial_number),
                },
            .issuer =
                {
                    .buffer = (uint8_t *)issuer_serial_number,
                    .size = sizeof(issuer_serial_number),
                },
            .code_descriptor = context->code_descriptor,
            .configuration_descriptor = context->configuration_descriptor,
            .subject_public_key = {
                .algorithm_id = 0,
                .x = N20_SLICE_NULL,
                .y = N20_SLICE_NULL,
                .d = N20_SLICE_NULL,
            },
        };

        switch (key_type) {
            case n20_crypto_key_type_ed25519_e:
                cwt.subject_public_key.algorithm_id = -8;
                cwt.subject_public_key.x.buffer = public_key;
                cwt.subject_public_key.x.size = public_key_size;
                break;
            case n20_crypto_key_type_secp256r1_e:
                cwt.subject_public_key.algorithm_id = -7;
                cwt.subject_public_key.x.buffer = public_key;
                cwt.subject_public_key.x.size = public_key_size/2;
                cwt.subject_public_key.y.buffer = &public_key[public_key_size / 2];
                cwt.subject_public_key.y.size = public_key_size / 2;
                break;
            case n20_crypto_key_type_secp384r1_e:
                cwt.subject_public_key.algorithm_id = -35;
                cwt.subject_public_key.x.buffer = public_key;
                cwt.subject_public_key.x.size = public_key_size;
                cwt.subject_public_key.y.buffer = &public_key[public_key_size / 2];
                cwt.subject_public_key.y.size = public_key_size / 2;
                break;
            default:
                return n20_error_crypto_invalid_key_type_e;
        }

        n20_set_cose_key_ops(&cwt.subject_public_key.key_ops, n20_cose_key_op_sign_e);
        n20_set_cose_key_ops(&cwt.subject_public_key.key_ops, n20_cose_key_op_verify_e);

        int32_t signing_key_algorithm_id = 0;

        switch (parent_key_type) {
            case n20_crypto_key_type_ed25519_e:
                signing_key_algorithm_id = -8;
                break;
            case n20_crypto_key_type_secp256r1_e:
                signing_key_algorithm_id = -7;
                break;
            case n20_crypto_key_type_secp384r1_e:
                signing_key_algorithm_id = -35;
                break;
            default:
                return n20_error_crypto_invalid_key_type_e;
        }

        return n20_cose_sign1_payload(crypto_ctx, parent_attestation_key, signing_key_algorithm_id, payload_callback_open_dice_cwt, &cwt, attestation_certificate, attestation_certificate_size);
    }
}
