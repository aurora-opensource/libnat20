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

/** @file */

#pragma once

#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <stddef.h>
#include <stdint.h>

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
typedef struct n20_x509_ext_tcg_dice_ueid_s {
    /**
     * @brief  Universal Entity ID (UEID) that identifies the device containing the private key and
     * is identified by the certificate’s subjectPublicKey.
     *
     * If ueid.buffer is NULL or ueid.size is 0, no UEID is rendered in the extension.
     */
    n20_asn1_slice_t ueid;
} n20_x509_ext_tcg_dice_ueid_t;

/**
 * @brief Renders the value of a TCG DICE UEID X509 extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_tcg_dice_ueid_t as @ref context argument.
 *
 * If @ref context is NULL, nothing is rendered, which would leave the resulting TCG DICE UEID
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
