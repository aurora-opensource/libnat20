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

#include "nat20/functionality.h"

#ifndef N20_PROXY_MAX_CLIENT_SLOTS
/**
 * @brief The maximum number of client slots in a proxy node.
 *
 * This is the maximum number of clients that can be registered
 * with a proxy node. It is used to allocate the array of
 * client states in @ref n20_proxy_node_state_t.
 */
#define N20_PROXY_MAX_CLIENT_SLOTS 3
#endif  // N20_PROXY_MAX_CLIENT_SLOTS

#ifndef N20_PROXY_MAX_PARENT_PATH_SIZE
/**
 * @brief The maximum size of the parent path in a proxy node.
 *
 * This is the maximum size of the parent path that can be stored
 * in a proxy node. It is used to allocate the array of parent paths
 * in @ref n20_proxy_client_state_t.
 */
#define N20_PROXY_MAX_PARENT_PATH_SIZE 8
#endif  // N20_PROXY_MAX_PARENT_PATH_SIZE

#ifdef __cplusplus
extern "C" {
#endif

struct n20_parent_service_s {
    /**
     * @brief Promote the caller to become the child identified by the given
     * compressed context.
     *
     * @param compressed_context The compressed context that identifies the child.
     * @return n20_error_t Error code indicating success or failure.
     */
    n20_error_t (*promote)(struct n20_parent_service_s *self,
                           n20_compressed_input_t compressed_context);
    /**
     * @brief Issues a CDI certificate for the given parent key type and key type.
     *
     * @param parent_key_type The type of the parent key.
     * @param key_type The type of the key to be issued.
     * @param parent_path The path to the parent in compressed form.
     * @param parent_path_size The size of the parent path.
     * @param next_context The next context for the Open DICE input.
     * @param attestation_certificate Output buffer for the generated attestation certificate.
     * @param attestation_certificate_size Size of the output buffer.
     * @return n20_error_t Error code indicating success or failure.
     */
    n20_error_t (*issue_cdi_certificate)(struct n20_parent_service_s *self,
                                         n20_crypto_key_type_t parent_key_type,
                                         n20_crypto_key_type_t key_type,
                                         n20_compressed_input_t const *parent_path,
                                         size_t parent_path_size,
                                         n20_open_dice_input_t const *next_context,
                                         uint8_t *attestation_certificate,
                                         size_t *attestation_certificate_size);
};

typedef struct n20_parent_service_s n20_parent_service_t;

struct n20_proxy_client_state_s {
    size_t parent_path_size;

    n20_compressed_input_t parent_path[N20_PROXY_MAX_PARENT_PATH_SIZE];
};

typedef struct n20_proxy_client_state_s n20_proxy_client_state_t;

struct n20_proxy_node_state_s {
    n20_parent_service_t *parent_service;
    /** The cryptographic context for the node. */
    n20_crypto_digest_context_t *crypto_digest_context;
    /** Array of client states. */
    n20_proxy_client_state_t client_slots[N20_PROXY_MAX_CLIENT_SLOTS];
};

typedef struct n20_proxy_node_state_s n20_proxy_node_state_t;

#ifdef __cplusplus
}
#endif
