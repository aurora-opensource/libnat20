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

#pragma once

#include <nat20/crypto.h>
#include <nat20/types.h>
#include <stddef.h>

#ifndef N20_GNOSTIC_MAX_CLIENT_SLOTS
/**
 * @brief The maximum number of client slots in a gnostic node.
 *
 * This is the maximum number of clients that can be registered
 * with a gnostic node. It is used to allocate the array of
 * client states in @ref n20_gnostic_node_state_t.
 */
#define N20_GNOSTIC_MAX_CLIENT_SLOTS 3
#endif  // N20_GNOSTIC_MAX_CLIENT_SLOTS

#ifdef __cplusplus
extern "C" {
#endif

struct n20_gnostic_client_state_s {
    /**
     * @brief The minimal compound device identifier (CDI) usable by client.
     */
    n20_crypto_key_t min_cdi;
};

typedef struct n20_gnostic_client_state_s n20_gnostic_client_state_t;

struct n20_gnostic_node_state_s {
    /** The cryptographic context for the node. */
    n20_crypto_context_t *crypto_context;
    /** Array of client states. */
    n20_gnostic_client_state_t client_slots[N20_GNOSTIC_MAX_CLIENT_SLOTS];
};

typedef struct n20_gnostic_node_state_s n20_gnostic_node_state_t;

#ifdef __cplusplus
}
#endif
