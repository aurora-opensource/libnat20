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
#include <nat20/service/service.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Context for the NAT20 service message dispatcher.
 *
 * Bundles the service operations vtable and the implementation-specific
 * state pointer that are needed by @ref n20_service_message_dispatch.
 * Both members must be non-NULL when the dispatch function is called.
 */
struct n20_service_message_dispatch_ctx_s {
    /**
     * @brief Pointer to the service operations vtable.
     *
     * Must point to a fully populated @ref n20_service_ops_t whose function
     * pointers correspond to the service implementation that should handle
     * incoming requests.
     */
    n20_service_ops_t* ops;

    /**
     * @brief Opaque implementation context.
     *
     * Passed verbatim as the first argument to every function in @ref ops.
     * The dispatcher does not interpret this value; the service implementation
     * is free to use it to carry any state it requires.
     */
    void* ctx;
};

/**
 * @brief Alias for @ref n20_service_message_dispatch_ctx_s.
 */
typedef struct n20_service_message_dispatch_ctx_s n20_service_message_dispatch_ctx_t;

/**
 * @brief Dispatch a service message.
 *
 * This function decodes the incoming @p message, calls the appropriate
 * operation from the service's vtable, and writes the response into
 * @p response_buffer.
 *
 * @see messages.h for the expected structure of incoming messages and
 * the structure of response messages.
 *
 * @param ctx  Dispatch context containing the service operations and state.
 * @param response_buffer  Buffer to write the response message.
 * @param response_size_in_out  In: buffer capacity. Out: bytes written.
 * @param message  Incoming message to dispatch.
 * @return @ref n20_error_ok_e on success, an error code otherwise.
 */
extern n20_error_t n20_service_message_dispatch(n20_service_message_dispatch_ctx_t* ctx,
                                                uint8_t* response_buffer,
                                                size_t* response_size_in_out,
                                                n20_slice_t message);

#ifdef __cplusplus
}
#endif
