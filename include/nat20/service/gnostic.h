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

#include <nat20/crypto.h>
#include <nat20/functionality.h>
#include <nat20/service/service.h>
#include <nat20/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Service node state for the Gnostic Stateless service implementation.
 *
 * This implementation is gnostic in the sense that it has direct access to
 * cryptographic material and can perform cryptographic operations.
 * It is stateless in that, with the exception of the minimal CDI, it does not
 * maintain any state, and with the exception of the promote call, all
 * operations are one shot, independent, and do not affect each other or the
 * services node's state.
 *
 * The service node state includes a pointer to a crypto context and the minimal CDI
 * that the service node can use to derive other CDIs. The service operations
 * for this implementation are defined in @ref src/service/gnostic.c, and is based
 * on the DICE functionality implemented in @ref src/core/functionality.c.
 * The supported operations include CDI promotion, issuing CDI certificates,
 * issuing ECA certificates, issuing ECA end-entity certificates, signing with ECA
 * end-entity keys.
 *
 * The service allows for indefinite nested hierarchies by allowing service calls
 * to specify a path from the minimal CDI to a parent CDI in terms of compressed
 * DICE input. This is useful to reflect dynamic hierarchies in software architecture
 * such as Secure Element -> Hypervisor -> VM(s) -> OS Kernel(s) -> Application(s).
 */
struct n20_gnostic_node_state_s {
    /**
     * @brief The cryptographic context for the node.
     *
     * A nat20_crypto_context_t that the service node can use to perform cryptographic
     * operations such as key derivation, digest, signing, and freeing keys.
     * This context is provided by the service integrator and may be implemented
     * using any crypto backend (hardware accellerated or otherwise) that conforms
     * to the n20_crypto_context_t interface.
     */
    n20_crypto_context_t *crypto_context;
    /**
     * @brief The minimal compound device identifier (CDI) usable by client.
     *
     * A handle to the base CDI from which all other CDIs can be derived.
     * It is an opaque handle that must be understood by the crypto_context
     * of the service node.
     */
    n20_crypto_key_t min_cdi;
};

typedef struct n20_gnostic_node_state_s n20_gnostic_node_state_t;

extern n20_service_ops_t n20_gnostic_service_ops;

#ifdef __cplusplus
}
#endif
