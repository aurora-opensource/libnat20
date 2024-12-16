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

#include "asn1.h"
#include "open_dice.h"

#ifdef __cplusplus
extern "C" {
#endif

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
     * @sa n20_open_dice_inputs_t
     */
    n20_open_dice_inputs_t const *inputs;

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
