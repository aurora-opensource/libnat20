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

#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/service/proxy.h>
#include <nat20/service/service.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void n20_proxy_init(n20_proxy_node_state_t *node_state,
                    n20_crypto_digest_context_t *crypto_ctx,
                    n20_compressed_input_t client_identity[N20_PROXY_MAX_CLIENT_SLOTS]) {
    if (node_state == NULL) {
        return;
    }

    node_state->crypto_digest_context = crypto_ctx;

    if (client_identity == NULL) {
        // If no client CDIs are provided, initialize them to NULL.
        for (size_t i = 0; i < N20_PROXY_MAX_CLIENT_SLOTS; ++i) {
            node_state->client_slots[i].parent_path_size = 0;
        }
        return;
    }

    // If client CDIs are provided, copy them into the client slots.
    for (size_t i = 0; i < N20_PROXY_MAX_CLIENT_SLOTS; ++i) {
        memcpy(&node_state->client_slots[i].parent_path[0],
               client_identity[i],
               sizeof(n20_compressed_input_t));
        node_state->client_slots[i].parent_path_size = 1;
    }
}

n20_error_t n20_proxy_promote(n20_proxy_node_state_t *node_state,
                              size_t client_slot_index,
                              n20_compressed_input_t compressed_context) {
    if (node_state == NULL) {
        return n20_error_missing_node_state_e;
    }

    if (client_slot_index >= N20_PROXY_MAX_CLIENT_SLOTS) {
        return n20_error_client_slot_index_out_of_range_e;
    }

    if (node_state->client_slots[client_slot_index].parent_path_size == 0) {
        // If the client slot is empty, we cannot promote.
        return n20_error_client_slot_empty_e;
    }

    if (node_state->client_slots[client_slot_index].parent_path_size >=
        N20_PROXY_MAX_PARENT_PATH_SIZE) {
        // If the parent path size exceeds the maximum, we cannot promote.
        return n20_error_parent_path_size_exceeds_max_e;
    }

    size_t parent_path_size = node_state->client_slots[client_slot_index].parent_path_size;
    n20_compressed_input_t(*parent_path)[] =
        &node_state->client_slots[client_slot_index].parent_path;
    memcpy((*parent_path)[parent_path_size], compressed_context, sizeof(n20_compressed_input_t));

    node_state->client_slots[client_slot_index].parent_path_size += 1;

    return n20_error_ok_e;
}

n20_error_t n20_proxy_issue_cdi_certificate(n20_proxy_node_state_t *node_state,
                                            size_t client_slot_index,
                                            n20_crypto_key_type_t parent_key_type,
                                            n20_crypto_key_type_t key_type,
                                            n20_compressed_input_t *parent_path,
                                            size_t parent_path_size,
                                            n20_open_dice_input_t const *next_context,
                                            uint8_t *attestation_certificate,
                                            size_t *attestation_certificate_size) {

    if (node_state == NULL) {
        return n20_error_missing_node_state_e;
    }

    n20_parent_service_t *parent_service = node_state->parent_service;
    if (parent_service == NULL) {
        return n20_error_missing_parent_service_e;
    }
    size_t client_parent_path_size = node_state->client_slots[client_slot_index].parent_path_size;

    size_t total_parent_path_size = client_parent_path_size + parent_path_size;

    /* Overflow check. */
    if (total_parent_path_size < client_parent_path_size) {
        return n20_error_parent_path_size_exceeds_max_e;
    }

    /* Parent path limit check. */
    if (total_parent_path_size > N20_PROXY_MAX_PARENT_PATH_SIZE) {
        return n20_error_parent_path_size_exceeds_max_e;
    }

    memcpy(&node_state->client_slots[client_slot_index].parent_path[client_parent_path_size],
           parent_path,
           parent_path_size * sizeof(n20_compressed_input_t));

    return parent_service->issue_cdi_certificate(
        parent_service,
        parent_key_type,
        key_type,
        (n20_compressed_input_t const*)&node_state->client_slots[client_slot_index].parent_path[0],
        total_parent_path_size,
        next_context,
        attestation_certificate,
        attestation_certificate_size);
}
