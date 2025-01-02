/*
 * Copyright 2024 Aurora Operations, Inc.
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

/** @file */

#pragma once

#include <nat20/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Length of the digests used in OpenDICE.
 */
#define N20_X509_EXT_OPEN_DICE_HASH_LENGTH 64

/**
 * @brief Length of the inline configuration used in OpenDICE.
 */
#define N20_X509_EXT_OPEN_DICE_CONFIGURATION_INLINE_LENGTH 64

/**
 * @brief Length of the hidden input used in OpenDICE.
 */
#define N20_X509_EXT_OPEN_DICE_HIDDEN_LENGTH 64

/**
 * @brief Mode inputs to the DICE.
 */
typedef enum n20_x509_ext_open_dice_modes_s {
    /**
     * @brief No security features (e.g. verified boot) have been configured on the device.
     */
    n20_x509_ext_open_dice_not_configured_e = 0,
    /**
     * @brief Device is operating normally with security features enabled.
     */
    n20_x509_ext_open_dice_normal_e = 1,
    /**
     * @brief Device is in debug mode, which is a non-secure state.
     */
    n20_x509_ext_open_dice_debug_e = 2,
    /**
     * @brief Device is in a debug or maintenance mode.
     */
    n20_x509_ext_open_dice_recovery_e = 3,
} n20_x509_ext_open_dice_modes_t;

/**
 * @brief Format of the configuration data used as input to the DICE.
 */
typedef enum n20_x509_ext_open_dice_configuration_format_s {
    /**
     * @brief Format of the configuration data is an implementation defined inline value (not a
     * hash).
     */
    n20_x509_ext_open_dice_configuration_format_inline_e = 0,
    /**
     * @brief Format of the configuration data is a hash over an implementation defined
     * configuration descriptor.
     */
    n20_x509_ext_open_dice_configuration_format_descriptor_e = 1,
} n20_x509_ext_open_dice_configuration_format_t;

/**
 * @brief Inputs to the DICE.
 *
 * This structure represents all the security-relevant properties to calculate the CDI values
 * for the next layer.
 */
typedef struct n20_x509_ext_open_dice_inputs_s {
    /**
     * @brief Digest of the code used as input to the DICE.
     */
    n20_asn1_slice_t code_hash;

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
    n20_asn1_slice_t code_descriptor;
    /**
     * @brief Configuration type (inline or descriptor).
     *
     * If @ref configuration_format is set to @ref
     * n20_x509_ext_open_dice_configuration_format_inline_e, @ref configuration_inline is used as
     * the configuration input to the DICE. @ref configuration_descriptor and
     * @ref configuration_hash are ignored.
     *
     * If @ref configuration_format is set to @ref
     * n20_x509_ext_open_dice_configuration_format_descriptor_e,
     * @ref configuration_descriptor and @ref configuration_hash are used.
     * @ref configuration_inline is ignored.
     *
     * @sa n20_x509_ext_open_dice_configuration_t
     */
    n20_x509_ext_open_dice_configuration_format_t configuration_format;
    /**
     * @brief Implementation defined inline configuration input to the DICE.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_x509_ext_open_dice_configuration_format_inline_e.
     *
     * (TODO): This will be defined in detail in a later PR. Per the OpenDICE profile,
     * it is @ref N20_X509_EXT_OPEN_DICE_CONFIGURATION_INLINE_LENGTH bytes in length.
     */
    n20_asn1_slice_t configuration_inline;
    /**
     * @brief Digest of the configuration descriptor used as input to the DICE.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_x509_ext_open_dice_configuration_format_descriptor_e.
     */
    n20_asn1_slice_t configuration_hash;
    /**
     * @brief The configuration data used to calculate the digest used for the configuration input
     * to the DICE.
     *
     * H( @ref configuration_descriptor ) must equal the value stored in @ref configuration_hash.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_x509_ext_open_dice_configuration_format_descriptor_e.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_asn1_slice_t configuration_descriptor;
    /**
     * @brief Digest of the authority used as input to the DICE.
     */
    n20_asn1_slice_t authority_hash;
    /**
     * @brief Additional data used in the authority input to the DICE.
     *
     * Implementation specific data about the authority used to compute the CDI values.
     * If the data pointed to by @ref authority_descriptor changes, this implies a change in the
     * value of @ref authority_hash.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_asn1_slice_t authority_descriptor;
    /**
     * @brief The DICE mode input.
     *
     * @sa n20_x509_ext_open_dice_modes_t
     */
    n20_x509_ext_open_dice_modes_t mode;
    /**
     * @brief The hidden input to the DICE.
     *
     * This value does not appear in certificates.
     */
    n20_asn1_slice_t hidden;
} n20_x509_ext_open_dice_inputs_t;

/**
 * @brief OpenDICE input content context.
 *
 * This is the context expected by
 * @ref n20_x509_ext_open_dice_input_content.
 * An instance of this object must be passed to the callback.
 * This is typically done using @ref n20_x509_extension by
 * initializing @ref n20_x509_extension_t.content_cb with
 * @ref n20_x509_ext_open_dice_input_content and setting
 * @ref n20_x509_extension_t.context to an instance of this
 * struct.
 *
 * (See Open Profile for DICE, Section X.509 CDI Certificates)
 * @sa OID_OPEN_DICE_INPUT
 */
typedef struct n20_x509_ext_open_dice_input_s {
    /**
     * @brief The DICE inputs to include in the certificate extension.
     *
     * @sa n20_x509_ext_open_dice_inputs_t
     */
    n20_x509_ext_open_dice_inputs_t const *inputs;

    /**
     * @brief The DICE profile that defines the contents of this certificate.
     *
     * Must be a nul terminated string of characters of the
     * following set; `[A..Z][a..z][0..9][ '()+,-./:=?]`.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     *
     * @sa n20_asn1_printablestring
     */
    char const *profile_name;
} n20_x509_ext_open_dice_input_t;

/**
 * @brief Renders the value of a OpenDice Input extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_open_dice_input_t as @ref context argument.
 *
 * If @ref context is NULL, nothing is rendered, which would leave
 * the resulting OpenDice Input extension malformed.
 *
 * This function is typically not used directly but instead
 * passed to @ref n20_x509_extension by initializing an
 * instance of @ref n20_x509_extensions_t
 * (See @ref n20_x509_extension for an example).
 */
extern void n20_x509_ext_open_dice_input_content(n20_asn1_stream_t *const s, void *context);

#ifdef __cplusplus
}
#endif
