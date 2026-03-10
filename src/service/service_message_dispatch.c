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

#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/service/service_message_dispatch.h>
#include <nat20/stream.h>
#include <nat20/types.h>

static n20_error_t sanitize_parent_path(size_t parent_path_length, n20_slice_t const* parent_path) {
    if (parent_path_length > N20_STATELESS_MAX_PATH_LENGTH) {
        /*
         * This is not reachable by tests because the message parser will
         * reject messages with too long parent paths, but we
         * include this check for completeness and future-proofing.
         */
        return n20_error_parent_path_size_exceeds_max_e;
    }

    for (size_t i = 0; i < parent_path_length; ++i) {
        if (parent_path[i].size != sizeof(n20_compressed_input_t)) {
            // Handle error: invalid parent path size
            return n20_error_incompatible_compressed_input_size_e;
        }
    }
    return n20_error_ok_e;
}

static n20_error_t prefix_response_header(uint8_t* response_buffer,
                                          size_t* response_size_in_out,
                                          size_t total_buffer_size,
                                          uint64_t label) {
    n20_stream_t s;
    n20_stream_init(&s, response_buffer, total_buffer_size);
    s.write_position = *response_size_in_out;
    s.buffer_overflow = response_buffer == NULL || total_buffer_size < *response_size_in_out;

    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, *response_size_in_out);
    n20_cbor_write_int(&s, label);
    n20_cbor_write_map_header(&s, 1);

    if (n20_stream_has_write_position_overflow(&s)) {
        return n20_error_write_position_overflow_e;
    }

    *response_size_in_out = n20_stream_byte_count(&s);

    return n20_stream_has_buffer_overflow(&s) ? n20_error_insufficient_buffer_size_e
                                              : n20_error_ok_e;
}

static n20_error_t dispatch_promote_request(n20_service_message_dispatch_ctx_t* ctx,
                                            uint8_t* response_buffer,
                                            size_t* response_size_in_out,
                                            n20_msg_promote_request_t* request) {
    if (ctx->ops->n20_srv_promote == NULL) {
        return n20_error_request_type_not_implemented_e;
    }

    if (request->compressed_context.size != sizeof(n20_compressed_input_t)) {
        // Handle error: invalid compressed context size
        return n20_error_incompatible_compressed_input_size_e;
    }

    n20_error_t rc = ctx->ops->n20_srv_promote(ctx->ctx, request);

    if (rc != n20_error_ok_e) {
        // Handle error: promotion failed
        return rc;
    }

    // Prepare the response message.
    n20_msg_error_response_t response = {
        .error_code = n20_error_ok_e,
    };
    return n20_msg_error_response_write(&response, response_buffer, response_size_in_out);
}

static n20_error_t dispatch_issue_cdi_cert_request(n20_service_message_dispatch_ctx_t* ctx,
                                                   uint8_t* response_buffer,
                                                   size_t* response_size_in_out,
                                                   n20_msg_issue_cdi_cert_request_t* request) {
    if (ctx->ops->n20_srv_issue_cdi_certificate == NULL) {
        return n20_error_request_type_not_implemented_e;
    }

    n20_error_t rc = sanitize_parent_path(request->parent_path_length, request->parent_path);
    if (rc != n20_error_ok_e) {
        return rc;
    }

    size_t const total_buffer_size = *response_size_in_out;

    rc = ctx->ops->n20_srv_issue_cdi_certificate(
        ctx->ctx, request, response_buffer, response_size_in_out);

    if (rc != n20_error_ok_e && rc != n20_error_insufficient_buffer_size_e) {
        return rc;
    }

    return prefix_response_header(
        response_buffer, response_size_in_out, total_buffer_size, N20_MSG_LABEL_CERTIFICATE);
}

static n20_error_t dispatch_issue_eca_cert_request(n20_service_message_dispatch_ctx_t* ctx,
                                                   uint8_t* response_buffer,
                                                   size_t* response_size_in_out,
                                                   n20_msg_issue_eca_cert_request_t* request) {
    if (ctx->ops->n20_srv_issue_eca_certificate == NULL) {
        return n20_error_request_type_not_implemented_e;
    }

    n20_error_t rc = sanitize_parent_path(request->parent_path_length, request->parent_path);
    if (rc != n20_error_ok_e) {
        return rc;
    }

    size_t const total_buffer_size = *response_size_in_out;

    rc = ctx->ops->n20_srv_issue_eca_certificate(
        ctx->ctx, request, response_buffer, response_size_in_out);

    if (rc != n20_error_ok_e && rc != n20_error_insufficient_buffer_size_e) {
        return rc;
    }

    return prefix_response_header(
        response_buffer, response_size_in_out, total_buffer_size, N20_MSG_LABEL_CERTIFICATE);
}

static n20_error_t dispatch_issue_eca_ee_cert_request(
    n20_service_message_dispatch_ctx_t* ctx,
    uint8_t* response_buffer,
    size_t* response_size_in_out,
    n20_msg_issue_eca_ee_cert_request_t* request) {
    if (ctx->ops->n20_srv_issue_eca_ee_certificate == NULL) {
        return n20_error_request_type_not_implemented_e;
    }

    n20_error_t rc = sanitize_parent_path(request->parent_path_length, request->parent_path);
    if (rc != n20_error_ok_e) {
        return rc;
    }

    size_t const total_buffer_size = *response_size_in_out;

    rc = ctx->ops->n20_srv_issue_eca_ee_certificate(
        ctx->ctx, request, response_buffer, response_size_in_out);
    if (rc != n20_error_ok_e && rc != n20_error_insufficient_buffer_size_e) {
        return rc;
    }

    return prefix_response_header(
        response_buffer, response_size_in_out, total_buffer_size, N20_MSG_LABEL_CERTIFICATE);
}

static n20_error_t dispatch_eca_ee_sign_request(n20_service_message_dispatch_ctx_t* ctx,
                                                uint8_t* response_buffer,
                                                size_t* response_size_in_out,
                                                n20_msg_eca_ee_sign_request_t* request) {
    if (ctx->ops->n20_srv_eca_ee_sign == NULL) {
        return n20_error_request_type_not_implemented_e;
    }

    n20_error_t rc = sanitize_parent_path(request->parent_path_length, request->parent_path);
    if (rc != n20_error_ok_e) {
        return rc;
    }

    size_t const total_buffer_size = *response_size_in_out;

    rc = ctx->ops->n20_srv_eca_ee_sign(ctx->ctx, request, response_buffer, response_size_in_out);
    if (rc != n20_error_ok_e && rc != n20_error_insufficient_buffer_size_e) {
        return rc;
    }

    return prefix_response_header(
        response_buffer, response_size_in_out, total_buffer_size, N20_MSG_LABEL_SIGNATURE);
}

n20_error_t n20_service_message_dispatch(n20_service_message_dispatch_ctx_t* ctx,
                                         uint8_t* response_buffer,
                                         size_t* response_size_in_out,
                                         n20_slice_t message) {
    if (ctx == NULL) {
        return n20_error_unexpected_null_dispatch_context_e;
    }

    if (ctx->ops == NULL) {
        return n20_error_unexpected_null_service_ops_e;
    }

    if (response_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }
    size_t const total_buffer_size = *response_size_in_out;

    n20_msg_request_t request;
    n20_error_t error = n20_msg_request_read(&request, message);

    if (error == n20_error_ok_e) {
        switch (request.request_type) {
            case n20_msg_request_type_promote_e:
                error = dispatch_promote_request(
                    ctx, response_buffer, response_size_in_out, &request.payload.promote);
                break;
            case n20_msg_request_type_issue_cdi_cert_e:
                error = dispatch_issue_cdi_cert_request(
                    ctx, response_buffer, response_size_in_out, &request.payload.issue_cdi_cert);
                break;
            case n20_msg_request_type_issue_eca_cert_e:
                error = dispatch_issue_eca_cert_request(
                    ctx, response_buffer, response_size_in_out, &request.payload.issue_eca_cert);
                break;
            case n20_msg_request_type_issue_eca_ee_cert_e:
                error = dispatch_issue_eca_ee_cert_request(
                    ctx, response_buffer, response_size_in_out, &request.payload.issue_eca_ee_cert);
                break;
            case n20_msg_request_type_eca_ee_sign_e:
                error = dispatch_eca_ee_sign_request(
                    ctx, response_buffer, response_size_in_out, &request.payload.eca_ee_sign);
                break;
            default:
                /* This is only reachable if a new request type is added in messages.c/.h without
                 * updating this switch.
                 * In this case n20_msg_request_read would return n20_error_ok_e, but the dispatch
                 * function would not know how to handle it.
                 */
                error = n20_error_request_type_unknown_e;
                break;
        }
    }

    if (error == n20_error_insufficient_buffer_size_e) {
        return error;
    }

    if (error != n20_error_ok_e) {
        // Prepare an error response.
        n20_msg_error_response_t error_response = {.error_code = error};
        *response_size_in_out = total_buffer_size;  // Reset response size.
        return n20_msg_error_response_write(&error_response, response_buffer, response_size_in_out);
    }
    return n20_error_ok_e;
}
