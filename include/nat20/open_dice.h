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

#pragma once

#include <nat20/crypto.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif
/** @file */

/**
 * @brief Mode inputs to the DICE.
 */
enum n20_open_dice_modes_s {
    /**
     * @brief No security features (e.g. verified boot) have been configured on the device.
     */
    n20_open_dice_mode_not_configured_e = 0,
    /**
     * @brief Device is operating normally with security features enabled.
     */
    n20_open_dice_mode_normal_e = 1,
    /**
     * @brief Device is in debug mode, which is a non-secure state.
     */
    n20_open_dice_mode_debug_e = 2,
    /**
     * @brief Device is in a debug or maintenance mode.
     */
    n20_open_dice_mode_recovery_e = 3,
};

/**
 * @brief Alias for @ref n20_open_dice_modes_s
 */
typedef enum n20_open_dice_modes_s n20_open_dice_modes_t;

/**
 * @brief OpenDICE input content context.
 *
 * This data structure is used to hold the internal representation
 * of the OpenDICE input content as defined in the Open Profile for DICE.
 * It is used by a variety of function to derive the CDI and
 * for formatting the OpenDICE input content in X.509 certificates
 * and CWT (CBOR web token) claims.
 *
 */
struct n20_open_dice_input_s {
    /**
     * @brief Digest of the code used as input to the DICE.
     *
     * This field is used during CDI derivation. It must be set to the digest
     * of the @ref code_descriptor if the latter is present.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t code_hash;

    /**
     * @brief Additional data used in the code input to the DICE.
     *
     * Implementation specific data about the code used to compute the CDI values.
     * If the data pointed to by @ref code_descriptor changes, this implies a change in the value
     * of @ref code_hash.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t code_descriptor;
    /**
     * @brief Digest of the configuration descriptor used as input to the DICE.
     *
     * This field is optional and may be set to @ref N20_SLICE_NULL to indicate that it is
     * to be omitted.
     * If present, it must be set to the digest of the configuration descriptor.
     * In this case this digest was used to compute the CDI secret.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t configuration_hash;
    /**
     * @brief The configuration data used to calculate the digest used for the configuration input
     * to the DICE.
     *
     * H( @ref configuration_descriptor ) must equal the value stored in @ref configuration_hash.
     * if @ref configuration_hash is present. Otherwise, this field holds the exact
     * 64 bytes of the configuration data used to calculate the CDI secret.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t configuration_descriptor;
    /**
     * @brief Digest of the authority used as input to the DICE.
     *
     * This field is used during CDI derivation. It must be set to the digest
     * of the @ref authority_descriptor if the latter is present.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t authority_hash;
    /**
     * @brief Additional data used in the authority input to the DICE.
     *
     * Implementation specific data about the authority used to compute the CDI values.
     * If the data pointed to by @ref authority_descriptor changes, this implies a change in the
     * value of @ref authority_hash.
     *
     * This field is included in the CDI certificate.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t authority_descriptor;
    /**
     * @brief The DICE mode input.
     *
     * @sa n20_open_dice_modes_s
     */
    n20_open_dice_modes_t mode;

    /**
     * @brief The DICE profile that defines the contents of this certificate.
     *
     * Must be a UTF-8 encoded string.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_string_slice_t profile_name;

    /**
     * @brief Hidden information about the device state.
     *
     * Hidden information is included in the CDI derivation
     * but not included in the certificate.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_slice_t hidden;
};

/**
 * @brief Alias for @ref n20_open_dice_input_s.
 */
typedef struct n20_open_dice_input_s n20_open_dice_input_t;

/**
 * @brief Subject public key information for the DICE certificate.
 */
struct n20_open_dice_public_key_info_s {
    /**
     * @brief The public key.
     *
     * This field contains the raw public key material.
     * The format depends on the key algorithm.
     *
     * For ED25519, the public key is the 32 byte compressed point format as described in
     * RFC8032 Section 5.1.5.
     *
     * For P-256 and P-384, the public key is the concatenation of the big-endian
     * representation of the x and y coordinates prefixed with 0x04. Both integers
     * always have the same size as the signing key in octets, i.e.,
     * 32 for P-256 and 48 for P-384, and they are padded with
     * leading zeroes if necessary. This corresponds to the uncompressed
     * point encoding as specified in X9.62.
     */
    n20_slice_t key;
    /**
     * @brief The key algorithm used for the public key.
     *
     * This field indicates the algorithm used to generate the public key.
     *
     * Possible values are:
     * - @ref n20_crypto_key_type_ed25519_e
     * - @ref n20_crypto_key_type_secp256r1_e
     * - @ref n20_crypto_key_type_secp384r1_e
     */
    n20_crypto_key_type_t algorithm;
};

/**
 * @brief Alias for @ref n20_open_dice_public_key_info_s.
 */
typedef struct n20_open_dice_public_key_info_s n20_open_dice_public_key_info_t;

/**
 * @defgroup open_dice_key_usage_macros "Key Usage Macros"
 *
 * These macros set the corresponding flags in the key
 * usage field of @ref n20_open_dice_cert_info_s.
 * Each macro expects a pointer to a uint8_t array of length 2.
 *
 * The key usage flags are defined in RFC5280 Section 4.2.1.3,
 * however, they are expressed in a different bit order here
 * following the OpenDICE specification for CWTs (CBOR web tokens).
 *
 * OpenDICE places Bit 0 (DigitalSignature) at the least significant bit
 * in the first byte.
 *
 * This is in contrast to X509 certificates where the key usage bits
 * are expressed as a ASN.1 BIT STRING, which index bits from most to least
 * significant, e.g., Bit 0 (DigitalSignature) would be the most significant bit.
 *
 * The choice for using the OpenDICE CWT bit ordering over X509's was made
 * to optimize for the former. The CWT implementation turns out compacter
 * than the X509 variant also supported by libnat20. So X509 implementation
 * will have to eat the overhead of reversing the bit order before encoding.
 *
 * # Example
 *
 * @code{.c}
 * n20_open_dice_cert_info_t key_usage = {0};
 * N20_OPEN_DICE_KEY_USAGE_SET_KEY_CERT_SIGN(key_usage.key_usage);
 * @endcode
 * @{
 */

/**
 * @brief The subject key can be used to issue digital signatures.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_DIGITAL_SIGNATURE(key_usage) ((key_usage)[0] |= 0x1)
/**
 * @brief The subject key can be used to sign statements of commitment.
 *
 * This field was formerly known as nonRepudiation flag.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_CONTENT_COMMITMENT(key_usage) ((key_usage)[0] |= 0x2)
/**
 * @brief The subject key can be used for encryption of key material.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_KEY_ENCIPHERMENT(key_usage) ((key_usage)[0] |= 0x4)
/**
 * @brief The subject key can be used for encryption of arbitrary messages.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_DATA_ENCIPHERMENT(key_usage) ((key_usage)[0] |= 0x8)
/**
 * @brief The subject key can be used for key agreement.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_KEY_AGREEMENT(key_usage) ((key_usage)[0] |= 0x10)
/**
 * @brief The subject key can be used for signing certificates.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_KEY_CERT_SIGN(key_usage) ((key_usage)[0] |= 0x20)
/**
 * @brief The subject key can be used for signing certificate revocation lists.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_CRL_SIGN(key_usage) ((key_usage)[0] |= 0x40)
/**
 * @brief The subject key can be used only for enciphering data during key agreement.
 *
 * The key agreement flag must also be set.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_ENCIPHER_ONLY(key_usage) ((key_usage)[0] |= 0x80)
/**
 * @brief the subject key can be used only for deciphering data during key agreement.
 *
 * The key agreement flag must also be set.
 */
#define N20_OPEN_DICE_KEY_USAGE_SET_DECIPHER_ONLY(key_usage) ((key_usage)[1] |= 0x1)

/**
 * @}
 */

/**
 * @defgroup Key Usage Test Macros
 *
 * These macros test whether the corresponding flags are set in the key
 * usage field of @ref n20_open_dice_cert_info_s.
 * Each macro expects a pointer to a uint8_t array of length 2 and returns
 * a non-zero value if the flag is set, zero if not set.
 *
 * @sa open_dice_key_usage_macros
 *
 * # Example
 *
 * @code{.c}
 * n20_open_dice_cert_info_t cert_info = {0};
 * N20_OPEN_DICE_KEY_USAGE_SET_KEY_CERT_SIGN(cert_info.key_usage);
 *
 * if (N20_OPEN_DICE_KEY_USAGE_IS_DIGITAL_SIGNATURE_SET(&cert_info.key_usage)) {
 *     // Digital signature flag is set
 * }
 * @endcode
 * @{
 */

/**
 * @brief Test if the subject key can be used to issue digital signatures.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_DIGITAL_SIGNATURE_SET(key_usage) ((key_usage)[0] & 0x1)

/**
 * @brief Test if the subject key can be used to sign statements of commitment.
 *
 * This field was formerly known as nonRepudiation flag.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_CONTENT_COMMITMENT_SET(key_usage) ((key_usage)[0] & 0x2)

/**
 * @brief Test if the subject key can be used for encryption of key material.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_KEY_ENCIPHERMENT_SET(key_usage) ((key_usage)[0] & 0x4)

/**
 * @brief Test if the subject key can be used for encryption of arbitrary messages.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_DATA_ENCIPHERMENT_SET(key_usage) ((key_usage)[0] & 0x8)

/**
 * @brief Test if the subject key can be used for key agreement.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_KEY_AGREEMENT_SET(key_usage) ((key_usage)[0] & 0x10)

/**
 * @brief Test if the subject key can be used for signing certificates.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_KEY_CERT_SIGN_SET(key_usage) ((key_usage)[0] & 0x20)

/**
 * @brief Test if the subject key can be used for signing certificate revocation lists.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_CRL_SIGN_SET(key_usage) ((key_usage)[0] & 0x40)

/**
 * @brief Test if the subject key can be used only for enciphering data during key agreement.
 *
 * The key agreement flag must also be set.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_ENCIPHER_ONLY_SET(key_usage) ((key_usage)[0] & 0x80)

/**
 * @brief Test if the subject key can be used only for deciphering data during key agreement.
 *
 * The key agreement flag must also be set.
 */
#define N20_OPEN_DICE_KEY_USAGE_IS_DECIPHER_ONLY_SET(key_usage) ((key_usage)[1] & 0x1)

/**
 * @}
 */

/**
 * @brief Enumeration of OpenDICE certificate types.
 */
enum n20_cert_type_s {
    /**
     * @brief Compound device identifier certificate.
     *
     * This certificate type is used for compound device identifiers
     * and is associated with the OpenDICE protocol.
     */
    n20_cert_type_cdi_e = 0,
    /**
     * @brief Embedded certificate authority certificate.
     *
     * This certificate type is used for embedded certificate authorities
     * and is associated with the OpenDICE protocol.
     * ECA certificates are issued by the corresponding level CDI certificate
     * and can be used to issue end-entity certificates.
     */
    n20_cert_type_eca_e = 1,
    /**
     * @brief Embedded certificate authority End-entity certificate.
     *
     * This certificate type is used for end-entity certificates
     * issued by embedded certificate authorities.
     * This certificate is issued by the corresponding level ECA certificate.
     */
    n20_cert_type_eca_ee_e = 2,
    /**
     * @brief Self-signed certificate.
     *
     * This certificate type is used for self-signed certificates
     * that are not issued by a certificate authority.
     */
    n20_cert_type_self_signed_e = 3,
};

/**
 * @brief Alias for @ref n20_cert_type_s.
 */
typedef enum n20_cert_type_s n20_cert_type_t;

/**
 * @brief Structure to hold ECA specific certificate information.
 *
 */
struct n20_cert_eca_s {
    /**
     * @brief The nonce is included in the ECA certificate using the TCG DICE Freshness extension.
     *
     * If this field is @ref N20_SLICE_NULL, the extension is omitted.
     */
    n20_slice_t nonce;
};

/**
 * @brief Alias for @ref n20_cert_eca_s.
 *
 */
typedef struct n20_cert_eca_s n20_cert_eca_t;

/**
 * @brief Structure to hold ECA End-entity certificate information.
 */
struct n20_cert_eca_ee_s {
    /**
     * @brief The nonce is included in the ECA end-entity certificate using the TCG DICE Freshness
     * extension.
     *
     * If this field is @ref N20_SLICE_NULL, the extension is omitted.
     */
    n20_slice_t nonce;
    /**
     * @brief The end entity name.
     *
     * This field is a free form field that allows the caller
     * to disambiguate end-entity keys. This field is included in the
     * derivation of the corresponding signing key.
     */
    n20_string_slice_t name;
};

/**
 * @brief Alias for @ref n20_cert_eca_ee_s.
 *
 */
typedef struct n20_cert_eca_ee_s n20_cert_eca_ee_t;

/**
 * @brief Structure to hold OpenDICE certificate information.
 *
 * This structure is used to hold the information about the OpenDICE certificate
 * that is used in the CWT (CBOR Web Token) and X.509 extensions.
 */
struct n20_open_dice_cert_info_s {
    /**
     * @brief Certificate issuer.
     *
     * This field is populated with the CDI_ID computed by
     * digesting the issuer's public key.
     *
     * It is used as issuer claim in a CWT or in the issuer name
     * field of the corresponding X.509 certificate. In the X509 RDN
     * it is treated as serial number @sa N20_OID_SERIAL_NUMBER.
     */
    n20_slice_t issuer;
    /**
     * @brief Certificate subject.
     *
     * This field is populated with the CDI_ID computed by
     * digesting the subject's public key.
     *
     * It is used as subject claim in a CWT or in the subject name
     * field of the corresponding X.509 certificate. In the X509 RDN
     * it is treated as serial number @sa N20_OID_SERIAL_NUMBER.
     * In X.509 certificates this is also used as the serial number.
     */
    n20_slice_t subject;
    /**
     * @brief Subject public key.
     *
     * This field informs the subject public key info foa CWT or X.509
     * certificate.
     */
    n20_open_dice_public_key_info_t subject_public_key;
    /**
     * @brief Key usage.
     *
     * This field uses the key usage extension from the X.509 certificate.
     * However, the bit order is reversed. Use the @ref open_dice_key_usage_macros
     * to access the key usage flags.
     */
    uint8_t key_usage[2];
    /**
     * @brief The certificate type.
     *
     * This field controls certificate and key generation.
     * And which of the union fields below is populated.
     * See @ref n20_cert_type_s for details.
     */
    n20_cert_type_t cert_type;
    union {
        /**
         * @brief OpenDICE input.
         *
         * This must be populated when the certificate type is
         * @ref n20_cert_type_cdi_e is chose.
         */
        n20_open_dice_input_t open_dice_input;
        /**
         * @brief ECA certificate information.
         *
         * This must be populated when the certificate type is
         * @ref n20_cert_type_eca_e is chose.
         *
         * The @p eca.nonce is optional and must be set to
         * @ref N20_SLICE_NULL to indicate that the TCG DICE
         * freshness extension shall be omitted.
         */
        n20_cert_eca_t eca;
        /**
         * @brief ECA EE certificate information.
         *
         * This must be populated when the certificate type is
         * @ref n20_cert_type_eca_ee_e is chose.
         *
         * The @p eca_ee.nonce is optional and must be set to
         * @ref N20_SLICE_NULL to indicate that the TCG DICE
         * freshness extension shall be omitted.
         *
         * The @p eca_ee.name is required but is freely
         * chosen by the caller.
         */
        n20_cert_eca_ee_t eca_ee;
    };
};

/**
 * @brief Alias for @ref n20_open_dice_cert_info_s.
 */
typedef struct n20_open_dice_cert_info_s n20_open_dice_cert_info_t;

#ifdef __cplusplus
}
#endif
