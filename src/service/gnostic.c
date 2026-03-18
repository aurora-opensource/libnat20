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

#include <nat20/crypto.h>
#include <nat20/cwt.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/types.h>

static n20_error_t n20_check_node_state(n20_gnostic_node_state_t* node_state) {
    if (node_state == NULL) {
        return n20_error_unexpected_null_service_state_e;
    }

    if (node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    if (node_state->min_cdi == NULL) {
        return n20_error_service_disabled_e;
    }

    return n20_error_ok_e;
}

static n20_error_t n20_gnostic_promote(void* ctx, n20_msg_promote_request_t* request) {
    n20_gnostic_node_state_t* node_state = (n20_gnostic_node_state_t*)ctx;

    if (request == NULL) {
        return n20_error_unexpected_null_service_request_e;
    }

    n20_error_t error = n20_check_node_state(node_state);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_crypto_key_t* min_cdi = &node_state->min_cdi;
    n20_crypto_key_t next = NULL;

    error = n20_next_level_cdi_attest(
        node_state->crypto_context, *min_cdi, &next, request->compressed_context);

    /* The previous CDI is no longer needed, free it. */
    node_state->crypto_context->key_free(node_state->crypto_context, *min_cdi);
    /* Set the min CDI key handle to NULL to avoid dangling references or double free.
     * Even if the derivation of the next CDI failed, it is better to
     * disable the mechanism and prevent further key derivations
     * than to continue with a potentially defined state. */
    *min_cdi = NULL;

    if (error != n20_error_ok_e) {
        return error;
    }

    /* Promote the given CDI to the specified client slot. */
    *min_cdi = next;
    return n20_error_ok_e;
}

typedef struct n20_resolve_path_iterator_ctx_s {
    n20_crypto_context_t* crypto_ctx;
    n20_crypto_key_t current_secret;
    size_t index;
} n20_resolve_path_iterator_ctx_t;

static n20_error_t n20_resolve_path_iterator_cb(void* ctx, n20_slice_t element) {
    n20_resolve_path_iterator_ctx_t* ictx = (n20_resolve_path_iterator_ctx_t*)ctx;

    n20_crypto_key_t next = NULL;
    n20_error_t error =
        n20_next_level_cdi_attest(ictx->crypto_ctx,
                                  ictx->current_secret,
                                  &next,
                                  element); /* crypto_ctx is not needed for path resolution */
    if (ictx->index > 0) {
        /* Free the previous secret if this is not the first element. */
        ictx->crypto_ctx->key_free(ictx->crypto_ctx, ictx->current_secret);
    }
    if (error != n20_error_ok_e) {
        ictx->current_secret = NULL;
        return error;
    }

    ictx->current_secret = next;
    ictx->index++;
    return n20_error_ok_e;
}

static n20_error_t n20_resolve_path(n20_crypto_context_t* crypto_ctx,
                                    n20_crypto_key_t parent_secret,
                                    n20_parent_path_t const* parent_path,
                                    n20_crypto_key_t* resolved_key) {
    n20_crypto_key_t current_secret = parent_secret;

    if (parent_path == NULL || parent_path->length == 0) {
        *resolved_key = current_secret;
        return n20_error_ok_e;
    }

    n20_resolve_path_iterator_ctx_t ictx = {
        .crypto_ctx = crypto_ctx,
        .current_secret = current_secret,
        .index = 0,
    };

    n20_error_t error =
        n20_msg_parent_path_iterate(parent_path, n20_resolve_path_iterator_cb, &ictx);
    if (error != n20_error_ok_e) {
        return error;
    }

    *resolved_key = ictx.current_secret;

    return n20_error_ok_e;
}

static n20_error_t n20_check_node_state_and_resolve_path(n20_gnostic_node_state_t* node_state,
                                                         n20_parent_path_t const* parent_path,
                                                         n20_crypto_key_t* resolved_key) {
    n20_error_t error = n20_check_node_state(node_state);
    if (error != n20_error_ok_e) {
        return error;
    }

    return n20_resolve_path(
        node_state->crypto_context, node_state->min_cdi, parent_path, resolved_key);
}

static n20_error_t n20_gnostic_issue_cdi_certificate(void* ctx,
                                                     n20_msg_issue_cdi_cert_request_t* request,
                                                     uint8_t* certificate_out,
                                                     size_t* certificate_size_in_out) {

    n20_gnostic_node_state_t* node_state = (n20_gnostic_node_state_t*)ctx;
    n20_crypto_key_t issuer_secret = NULL;

    if (request == NULL) {
        return n20_error_unexpected_null_service_request_e;
    }

    n20_error_t error =
        n20_check_node_state_and_resolve_path(node_state, &request->parent_path, &issuer_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input = request->next_context;

    error = n20_issue_certificate(node_state->crypto_context,
                                  issuer_secret,
                                  request->issuer_key_type,
                                  request->subject_key_type,
                                  &cert_info,
                                  request->certificate_format,
                                  certificate_out,
                                  certificate_size_in_out);

    /* Do not release the issuer secret if it is the node's min_cdi. */
    if (request->parent_path.length > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, issuer_secret);
    }
    return error;
}

static n20_error_t n20_gnostic_issue_eca_certificate(void* ctx,
                                                     n20_msg_issue_eca_cert_request_t* request,
                                                     uint8_t* certificate_out,
                                                     size_t* certificate_size_in_out) {

    n20_gnostic_node_state_t* node_state = (n20_gnostic_node_state_t*)ctx;
    n20_crypto_key_t parent_secret = NULL;

    if (request == NULL) {
        return n20_error_unexpected_null_service_request_e;
    }

    n20_error_t error =
        n20_check_node_state_and_resolve_path(node_state, &request->parent_path, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_eca_e;
    cert_info.eca.nonce = request->challenge;

    error = n20_issue_certificate(node_state->crypto_context,
                                  parent_secret,
                                  request->issuer_key_type,
                                  request->subject_key_type,
                                  &cert_info,
                                  request->certificate_format,
                                  certificate_out,
                                  certificate_size_in_out);

    if (request->parent_path.length > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}

static n20_error_t n20_gnostic_issue_eca_ee_certificate(
    void* ctx,
    n20_msg_issue_eca_ee_cert_request_t* request,
    uint8_t* certificate_out,
    size_t* certificate_size_in_out) {

    n20_gnostic_node_state_t* node_state = (n20_gnostic_node_state_t*)ctx;
    n20_crypto_key_t parent_secret = NULL;

    if (request == NULL) {
        return n20_error_unexpected_null_service_request_e;
    }

    n20_error_t error =
        n20_check_node_state_and_resolve_path(node_state, &request->parent_path, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_eca_ee_e;
    cert_info.eca_ee.nonce = request->challenge;
    cert_info.eca_ee.name = request->name;

    uint8_t key_usage_mask[2] = {0, 0};
    N20_OPEN_DICE_KEY_USAGE_SET_DIGITAL_SIGNATURE(key_usage_mask);

    if (request->key_usage.size > 1) {
        for (size_t i = 1; i < request->key_usage.size; ++i) {
            if (request->key_usage.buffer[i] != 0) {
                error = n20_error_unsupported_key_usage_e;
                goto err_out;
            }
        }
    }
    if (request->key_usage.size >= 1) {
        if ((request->key_usage.buffer[0] & ~key_usage_mask[0]) != 0) {
            error = n20_error_unsupported_key_usage_e;
            goto err_out;
        }
        cert_info.key_usage[0] = request->key_usage.buffer[0];
    }

    error = n20_issue_certificate(node_state->crypto_context,
                                  parent_secret,
                                  request->issuer_key_type,
                                  request->subject_key_type,
                                  &cert_info,
                                  request->certificate_format,
                                  certificate_out,
                                  certificate_size_in_out);

err_out:
    if (request->parent_path.length > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}

static n20_error_t n20_gnostic_eca_ee_sign(void* ctx,
                                           n20_msg_eca_ee_sign_request_t* request,
                                           uint8_t* signature,
                                           size_t* signature_size) {

    n20_gnostic_node_state_t* node_state = (n20_gnostic_node_state_t*)ctx;
    n20_crypto_key_t parent_secret = NULL;

    if (request == NULL) {
        return n20_error_unexpected_null_service_request_e;
    }

    n20_error_t error =
        n20_check_node_state_and_resolve_path(node_state, &request->parent_path, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    if (request->key_usage.size < 1 ||
        N20_OPEN_DICE_KEY_USAGE_IS_DIGITAL_SIGNATURE_SET(request->key_usage.buffer) == 0) {
        error = n20_error_key_usage_not_permitted_e;
        goto err_out;
    }

    error = n20_eca_ee_sign_message(node_state->crypto_context,
                                    parent_secret,
                                    request->subject_key_type,
                                    request->name,
                                    request->key_usage,
                                    request->message,
                                    signature,
                                    signature_size);

err_out:
    if (request->parent_path.length > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}

n20_service_ops_t n20_gnostic_service_ops = {
    .n20_srv_promote = n20_gnostic_promote,
    .n20_srv_issue_cdi_certificate = n20_gnostic_issue_cdi_certificate,
    .n20_srv_issue_eca_certificate = n20_gnostic_issue_eca_certificate,
    .n20_srv_issue_eca_ee_certificate = n20_gnostic_issue_eca_ee_certificate,
    .n20_srv_eca_ee_sign = n20_gnostic_eca_ee_sign,
};
