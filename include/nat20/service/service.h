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

/** @file */

#pragma once

#include <nat20/error.h>
#include <nat20/service/messages.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Operations table for the NAT20 service.
 *
 * This structure is a vtable of function pointers that define the operations
 * a NAT20 service implementation must provide. The message dispatcher calls
 * these functions after decoding an incoming request message.
 *
 * All function pointers must be non-NULL when the dispatch function is called.
 * Each function receives an opaque @p ctx pointer that the implementation may
 * use to access its own state.
 *
 * @sa n20_service_message_dispatch_ctx_s
 */
struct n20_service_ops_s {
    /**
     * @brief Promote the caller to the next CDI level.
     *
     * Called in response to a @ref n20_msg_request_type_promote_e request.
     * The implementation should derive the next CDI from the current one using
     * the compressed context in @p request and update its internal state
     * accordingly.
     *
     * @param ctx  Opaque implementation context.
     * @param request  Promote request payload carrying the compressed context.
     * @return @ref n20_error_ok_e on success, an error code otherwise.
     */
    n20_error_t (*n20_srv_promote)(void* ctx, n20_msg_promote_request_t* request);

    /**
     * @brief Issue a CDI certificate.
     *
     * Called in response to a @ref n20_msg_request_type_issue_cdi_cert_e request.
     * The implementation should derive the CDI key identified by @p request,
     * generate the corresponding certificate, and write it into the provided buffer.
     *
     * The serialized certificate is placed at the end of the buffer.
     * On entry @p *attestation_certificate_size is the total size of the buffer.
     * On success it must be set to the number of certificate bytes written.
     *
     * @param ctx  Opaque implementation context.
     * @param request  CDI certificate request payload.
     * @param attestation_certificate  Output buffer for the certificate.
     * @param attestation_certificate_size  In: buffer capacity. Out: bytes written.
     * @return @ref n20_error_ok_e on success, an error code otherwise.
     */
    n20_error_t (*n20_srv_issue_cdi_certificate)(void* ctx,
                                                 n20_msg_issue_cdi_cert_request_t* request,
                                                 uint8_t* attestation_certificate,
                                                 size_t* attestation_certificate_size);

    /**
     * @brief Issue an ECA certificate.
     *
     * Called in response to a @ref n20_msg_request_type_issue_eca_cert_e request.
     * The implementation should derive the ECA key identified by @p request,
     * generate the corresponding certificate, and write it into the provided buffer.
     *
     * The serialized certificate is placed at the end of the buffer.
     * On entry @p *certificate_size is the total size of the buffer.
     * On success it must be set to the number of certificate bytes written.
     *
     * @param ctx  Opaque implementation context.
     * @param request  ECA certificate request payload.
     * @param certificate  Output buffer for the certificate.
     * @param certificate_size  In: buffer capacity. Out: bytes written.
     * @return @ref n20_error_ok_e on success, an error code otherwise.
     */
    n20_error_t (*n20_srv_issue_eca_certificate)(void* ctx,
                                                 n20_msg_issue_eca_cert_request_t* request,
                                                 uint8_t* certificate,
                                                 size_t* certificate_size);

    /**
     * @brief Issue an ECA end-entity certificate.
     *
     * Called in response to a @ref n20_msg_request_type_issue_eca_ee_cert_e request.
     * The implementation should derive the ECA end-entity key identified by @p request,
     * generate the corresponding certificate, and write it into the provided buffer.
     *
     * The serialized certificate is placed at the end of the buffer.
     * On entry @p *certificate_size is the total size of the buffer.
     * On success it must be set to the number of certificate bytes written.
     *
     * @param ctx  Opaque implementation context.
     * @param request  ECA end-entity certificate request payload.
     * @param certificate  Output buffer for the certificate.
     * @param certificate_size  In: buffer capacity. Out: bytes written.
     * @return @ref n20_error_ok_e on success, an error code otherwise.
     */
    n20_error_t (*n20_srv_issue_eca_ee_certificate)(void* ctx,
                                                    n20_msg_issue_eca_ee_cert_request_t* request,
                                                    uint8_t* certificate,
                                                    size_t* certificate_size);

    /**
     * @brief Sign a message with an ECA end-entity key.
     *
     * Called in response to a @ref n20_msg_request_type_eca_ee_sign_e request.
     * The implementation should derive the ECA end-entity signing key identified
     * by @p request, produce the signature over @p request->message, and write
     * it into the provided buffer.
     *
     * The serialized signature is placed at the end of the buffer.
     * On entry @p *signature_size is the total size of the buffer.
     * On success it must be set to the number of signature bytes written.
     *
     * @param ctx  Opaque implementation context.
     * @param request  ECA end-entity sign request payload.
     * @param signature  Output buffer for the signature.
     * @param signature_size  In: buffer capacity. Out: bytes written.
     * @return @ref n20_error_ok_e on success, an error code otherwise.
     */
    n20_error_t (*n20_srv_eca_ee_sign)(void* ctx,
                                       n20_msg_eca_ee_sign_request_t* request,
                                       uint8_t* signature,
                                       size_t* signature_size);
};

/**
 * @brief Alias for @ref n20_service_ops_s.
 */
typedef struct n20_service_ops_s n20_service_ops_t;

#ifdef __cplusplus
}
#endif
