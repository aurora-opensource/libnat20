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
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>

void n20_gnostic_init(n20_gnostic_node_state_t *node_state,
                      n20_crypto_context_t *crypto_ctx,
                      n20_crypto_key_t client_min_cdis[N20_GNOSTIC_MAX_CLIENT_SLOTS]) {
    if (node_state == NULL) {
        return;
    }

    node_state->crypto_context = crypto_ctx;

    if (client_min_cdis == NULL) {
        // If no client CDIs are provided, initialize them to NULL.
        for (size_t i = 0; i < N20_GNOSTIC_MAX_CLIENT_SLOTS; ++i) {
            node_state->client_slots[i].min_cdi = NULL;
        }
        return;
    }

    // If client CDIs are provided, copy them into the client slots.
    for (size_t i = 0; i < N20_GNOSTIC_MAX_CLIENT_SLOTS; ++i) {
        node_state->client_slots[i].min_cdi = client_min_cdis[i];
    }
}

n20_error_t n20_gnostic_promote(n20_gnostic_node_state_t *node_state,
                                size_t client_slot_index,
                                n20_compressed_input_t compressed_context) {
    if (node_state == NULL) {
        return n20_error_missing_node_state_e;
    }

    if (client_slot_index >= N20_GNOSTIC_MAX_CLIENT_SLOTS) {
        return n20_error_client_slot_index_out_of_range_e;
    }

    if (node_state->client_slots[client_slot_index].min_cdi == NULL) {
        return n20_error_client_slot_empty_e;
    }

    n20_crypto_key_t *client_min_cdi = &node_state->client_slots[client_slot_index].min_cdi;
    n20_crypto_key_t next = NULL;

    n20_error_t error = n20_next_level_cdi_attest(
        node_state->crypto_context, *client_min_cdi, &next, compressed_context);
    if (error != n20_error_ok_e) {
        return error;
    }

    error = node_state->crypto_context->key_free(node_state->crypto_context, *client_min_cdi);
    if (error != n20_error_ok_e) {
        return error;
    }

    // Promote the given CDI to the specified client slot.
    *client_min_cdi = next;
    return n20_error_ok_e;
}

static n20_error_t n20_resolve_path(n20_crypto_context_t *crypto_ctx,
                                    n20_crypto_key_t parent_secret,
                                    n20_compressed_input_t *parent_path,
                                    size_t parent_path_size,
                                    n20_crypto_key_t *resolved_key) {
    n20_crypto_key_t current_secret = parent_secret;

    if (parent_path_size == 0) {
        *resolved_key = current_secret;
        return n20_error_ok_e;
    }

    size_t i = 0;

    n20_crypto_key_t next = NULL;
    n20_error_t error =
        n20_next_level_cdi_attest(crypto_ctx, current_secret, &next, parent_path[i]);
    if (error != n20_error_ok_e) {
        return error;
    }
    current_secret = next;
    ++i;

    while (i < parent_path_size) {
        error = n20_next_level_cdi_attest(crypto_ctx, current_secret, &next, parent_path[i]);
        crypto_ctx->key_free(crypto_ctx, current_secret);
        if (error != n20_error_ok_e) {
            return error;
        }
        current_secret = next;
        ++i;
    }

    *resolved_key = current_secret;
    return n20_error_ok_e;
}

n20_error_t n20_gnostic_issue_cdi_certificate(n20_gnostic_node_state_t *node_state,
                                              size_t client_slot_index,
                                              n20_crypto_key_type_t parent_key_type,
                                              n20_crypto_key_type_t key_type,
                                              n20_compressed_input_t *parent_path,
                                              size_t parent_path_size,
                                              n20_open_dice_input_t const *next_context,
                                              n20_certificate_format_t certificate_format,
                                              uint8_t *attestation_certificate,
                                              size_t *attestation_certificate_size) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_crypto_key_t parent_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, parent_secret, parent_path, parent_path_size, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_crypto_key_t parent_attestation_key = NULL;

    error = n20_derive_attestation_key(
        node_state->crypto_context, parent_secret, &parent_attestation_key, parent_key_type);
    if (error != n20_error_ok_e) {
        goto out;
    }

    error = n20_opendice_attestation_key_and_certificate(node_state->crypto_context,
                                                         parent_secret,
                                                         parent_attestation_key,
                                                         parent_key_type,
                                                         key_type,
                                                         next_context,
                                                         certificate_format,
                                                         attestation_certificate,
                                                         attestation_certificate_size);

    node_state->crypto_context->key_free(node_state->crypto_context, parent_attestation_key);

out:
    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}

n20_error_t n20_gnostic_issue_eca_certificate(n20_gnostic_node_state_t *node_state,
                                             size_t client_slot_index,
                                             n20_crypto_key_type_t parent_key_type,
                                             n20_crypto_key_type_t key_type,
                                             n20_compressed_input_t *parent_path,
                                             size_t parent_path_size,
                                             n20_string_slice_t context,
                                             n20_slice_t key_usage,
                                             n20_slice_t challenge,
                                             n20_certificate_format_t certificate_format,
                                             uint8_t *attestation_certificate,
                                             size_t *attestation_certificate_size) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_crypto_key_t parent_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, parent_secret, parent_path, parent_path_size, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_crypto_key_t parent_attestation_key = NULL;

    error = n20_derive_attestation_key(
        node_state->crypto_context, parent_secret, &parent_attestation_key, parent_key_type);
    if (error != n20_error_ok_e) {
        goto out;
    }

    error = n20_eca_attestation_key_and_certificate(node_state->crypto_context,
                                                   parent_secret,
                                                   parent_attestation_key,
                                                   parent_key_type,
                                                   key_type,
                                                   context,
                                                   key_usage,
                                                   challenge,
                                                   certificate_format,
                                                   attestation_certificate,
                                                   attestation_certificate_size);

    node_state->crypto_context->key_free(node_state->crypto_context, parent_attestation_key);

out:
    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}


n20_error_t n20_gnostic_eca_sign(n20_gnostic_node_state_t *node_state,
                                 size_t client_slot_index,
                                 n20_crypto_key_type_t key_type,
                                 n20_compressed_input_t *parent_path,
                                 size_t parent_path_size,
                                 n20_string_slice_t context,
                                 n20_slice_t key_usage,
                                 n20_slice_t challenge,
                                 n20_slice_t message,
                                 uint8_t *signature,
                                 size_t *signature_size) {

    if (node_state == NULL || node_state->crypto_context == NULL) {
        return n20_error_missing_crypto_context_e;
    }

    n20_crypto_key_t parent_secret = node_state->client_slots[client_slot_index].min_cdi;

    n20_error_t error = n20_resolve_path(
        node_state->crypto_context, parent_secret, parent_path, parent_path_size, &parent_secret);
    if (error != n20_error_ok_e) {
        return error;
    }

    error = n20_eca_sign_message(node_state->crypto_context,
                                parent_secret,
                                key_type,
                                context,
                                key_usage,
                                challenge,
                                message,
                                signature,
                                signature_size);

    if (parent_path_size > 0) {
        node_state->crypto_context->key_free(node_state->crypto_context, parent_secret);
    }
    return error;
}
