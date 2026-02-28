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

/** @file */

#pragma once

#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TCG DICE UEID X509 extension context.
 *
 * This is the context expected by
 * @ref n20_x509_ext_tcg_dice_ueid_content.
 * An instance of this object must be passed to the callback.
 * This is typically done using @ref n20_x509_extension by
 * initializing @ref n20_x509_extension_t.content_cb with
 * @ref n20_x509_ext_tcg_dice_ueid_content and setting
 * @ref n20_x509_extension_t.context to an instance of this
 * struct.
 *
 * (See TCG DICE Attestation Architecture Version 1.1, Section 6.1.4.)
 * @sa OID_TCG_DICE_UEID
 */
struct n20_x509_ext_tcg_dice_ueid_s {
    /**
     * @brief  Universal Entity ID (UEID) that identifies the device containing the private key and
     * is identified by the certificate’s subjectPublicKey.
     *
     * If ueid.buffer is NULL or ueid.size is 0, no UEID is rendered in the extension.
     */
    n20_slice_t ueid;
};

/**
 * @brief Alias for @ref n20_x509_ext_tcg_dice_ueid_s
 */
typedef struct n20_x509_ext_tcg_dice_ueid_s n20_x509_ext_tcg_dice_ueid_t;

/**
 * @brief Renders the value of a TCG DICE UEID X509 extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_tcg_dice_ueid_t as @p context argument.
 *
 * If @p context is NULL, nothing is rendered, which would leave the resulting TCG DICE UEID
 * extension malformed.
 *
 * This function is typically not used directly but instead
 * passed to @ref n20_x509_extension by initializing an
 * instance of @ref n20_x509_extensions_t
 * (See @ref n20_x509_extension for an example).
 */
extern void n20_x509_ext_tcg_dice_ueid_content(n20_stream_t *const s, void *context);

#ifdef __cplusplus
}
#endif
