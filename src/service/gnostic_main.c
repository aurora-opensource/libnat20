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

#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/gnostic_n20_service.sock"
#define BACKLOG 1

n20_error_t init_gnostic_node_with_bssl_crypto(n20_gnostic_node_state_t *node_state) {

    if (node_state == NULL) {
        return n20_error_missing_node_state_e;
    }

    *node_state = (n20_gnostic_node_state_t){0};

    // OpenSSL BSSL crypto context initialization.
    n20_crypto_context_t *crypto_bssl_context;
    n20_crypto_boringssl_open(&crypto_bssl_context);
    if (crypto_bssl_context == NULL) {
        return n20_error_crypto_no_resources_e;
    }

    n20_slice_t info = {.size = 18, .buffer = (uint8_t *)"example_info_value"};

    n20_slice_t salt = {.size = 18, .buffer = (uint8_t *)"example_salt_value"};

    n20_slice_t ikm = {.size = 22, .buffer = (uint8_t *)"example_uds_passphrase"};

    uint8_t uds[32] = {0};  // Example UDS passphrase buffer.

    n20_error_t rc = crypto_bssl_context->digest_ctx.hkdf(&crypto_bssl_context->digest_ctx,
                                                          n20_crypto_digest_algorithm_sha2_256_e,
                                                          ikm,
                                                          salt,
                                                          info,
                                                          32,
                                                          uds);
    if (rc != n20_error_ok_e) {
        n20_crypto_boringssl_close(crypto_bssl_context);
        return rc;
    }

    n20_slice_t uds_slice = {.size = sizeof(uds), .buffer = uds};

    n20_crypto_key_t uds_handle = NULL;

    rc = n20_crypto_boringssl_make_secret(crypto_bssl_context, &uds_slice, &uds_handle);
    if (rc != n20_error_ok_e) {
        n20_crypto_boringssl_close(crypto_bssl_context);
        return rc;
    }

    n20_crypto_key_t client_min_cdis[N20_GNOSTIC_MAX_CLIENT_SLOTS] = {0};
    client_min_cdis[0] = uds_handle;  // Example: Use the UDS as the first client CDI.

    n20_gnostic_init(node_state, crypto_bssl_context, client_min_cdis);

    return n20_error_ok_e;
}

static n20_error_t export_uds_public_key_as_cose(n20_gnostic_node_state_t *node_state,
                                                 n20_crypto_key_type_t key_type,
                                                 uint8_t *response_buffer,
                                                 size_t *response_size_in_out) {
    if (node_state == NULL || response_buffer == NULL || response_size_in_out == NULL) {
        return n20_error_insufficient_buffer_size_e;
    }

    // Get the UDS public key from the node state.
    n20_crypto_key_t uds_public_key = node_state->client_slots[0].min_cdi;

    n20_crypto_key_t derived_key = NULL;

    n20_error_t error = n20_derive_attestation_key(
        node_state->crypto_context, uds_public_key, &derived_key, key_type);
    if (error != n20_error_ok_e) {
        return error;
    }

    uint8_t public_key_buffer[97];
    uint8_t *public_key = &public_key_buffer[1];
    size_t public_key_size = sizeof(public_key_buffer) - 1;

    error = node_state->crypto_context->key_get_public_key(
        node_state->crypto_context, derived_key, public_key, &public_key_size);
    node_state->crypto_context->key_free(node_state->crypto_context, derived_key);
    if (error != n20_error_ok_e) {
        return error;
    }

    n20_cose_key_t cose_key = {0};

    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            cose_key.algorithm_id = -8;
            cose_key.x.buffer = public_key;
            cose_key.x.size = public_key_size;
            break;
        case n20_crypto_key_type_secp256r1_e:
            cose_key.algorithm_id = -7;
            cose_key.x.buffer = public_key;
            cose_key.x.size = public_key_size / 2;
            cose_key.y.buffer = &public_key[public_key_size / 2];
            cose_key.y.size = public_key_size / 2;
            break;
        case n20_crypto_key_type_secp384r1_e:
            cose_key.algorithm_id = -35;
            cose_key.x.buffer = public_key;
            cose_key.x.size = public_key_size;
            cose_key.y.buffer = &public_key[public_key_size / 2];
            cose_key.y.size = public_key_size / 2;
            break;
        default:
            return n20_error_crypto_invalid_key_type_e;
    }

    n20_set_cose_key_ops(&cose_key.key_ops, n20_cose_key_op_sign_e);
    n20_set_cose_key_ops(&cose_key.key_ops, n20_cose_key_op_verify_e);

    n20_stream_t stream;
    n20_stream_init(&stream, response_buffer, *response_size_in_out);

    // Write the COSE key to the response buffer.
    n20_cose_write_key(&stream, &cose_key);

    if (n20_stream_has_write_position_overflow(&stream)) {
        // If the write position overflows, we need to return an error.
        return n20_error_write_position_overflow_e;
    }

    *response_size_in_out = n20_stream_byte_count(&stream);

    if (n20_stream_has_buffer_overflow(&stream)) {
        return n20_error_insufficient_buffer_size_e;
    }

    return n20_error_ok_e;
}

static n20_gnostic_node_state_t service_node_state = {0};

n20_error_t dispatch_promote_request(n20_gnostic_node_state_t *node_state,
                                     uint8_t *response_buffer,
                                     size_t *response_size_in_out,
                                     n20_msg_promote_request_t *request,
                                     size_t client_index) {

    if (request->compressed_context.size != sizeof(n20_compressed_input_t)) {
        // Handle error: invalid compressed context size
        return n20_error_incompatible_compressed_input_size_e;
    }

    n20_error_t rc = n20_gnostic_promote(
        node_state, client_index, (uint8_t *)request->compressed_context.buffer);
    if (rc != n20_error_ok_e) {
        // Handle error: promotion failed
        return rc;
    }

    // Prepare the response message.
    n20_msg_error_response_t response = {
        .error_code = n20_error_ok_e,
    };
    return n20_msg_error_response_write(&response, response_buffer, response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: failed to write response
        return rc;
    }
}

n20_error_t dispatch_issue_cdi_cert_request(n20_gnostic_node_state_t *node_state,
                                            uint8_t *response_buffer,
                                            size_t *response_size_in_out,
                                            n20_msg_issue_cdi_cert_request_t *request,
                                            size_t client_index) {

    n20_compressed_input_t parent_path[N20_STATELESS_MAX_PATH_LENGTH];
    size_t parent_path_size = request->parent_path_length;

    if (parent_path_size > N20_STATELESS_MAX_PATH_LENGTH) {
        // Handle error: parent path size exceeds maximum
        return n20_error_parent_path_size_exceeds_max_e;
    }

    for (size_t i = 0; i < parent_path_size; ++i) {
        if (request->parent_path[i].size != sizeof(n20_compressed_input_t)) {
            // Handle error: invalid parent path size
            return n20_error_incompatible_compressed_input_size_e;
        }
        memcpy(&parent_path[i], request->parent_path[i].buffer, sizeof(n20_compressed_input_t));
    }

    size_t const total_buffer_size = *response_size_in_out;

    n20_error_t rc = n20_gnostic_issue_cdi_certificate(node_state,
                                                       client_index,
                                                       request->parent_key_type,
                                                       request->key_type,
                                                       parent_path,
                                                       parent_path_size,
                                                       &request->next_context,
                                                       request->certificate_format,
                                                       response_buffer,
                                                       response_size_in_out);
    if (rc != n20_error_ok_e) {
        // Handle error: issuing CDI certificate failed
        return rc;
    }

    if (*response_size_in_out > total_buffer_size) {
        // Handle error: response size exceeds buffer size
        return n20_error_insufficient_buffer_size_e;
    }

    n20_stream_t s;
    n20_stream_init(&s, response_buffer, total_buffer_size - *response_size_in_out);

    n20_cbor_write_header(&s, n20_cbor_type_bytes_e, *response_size_in_out);
    n20_cbor_write_int(&s, 2);
    n20_cbor_write_map_header(&s, 1);

    if (n20_stream_has_buffer_overflow(&s)) {
        return n20_error_insufficient_buffer_size_e;
    }

    *response_size_in_out += n20_stream_byte_count(&s);

    return n20_error_ok_e;
}

n20_error_t dispatch_message(n20_gnostic_node_state_t *node_state,
                             uint8_t *response_buffer,
                             size_t *response_size_in_out,
                             n20_slice_t message,
                             size_t client_index) {

    // Print message in hex format for debugging.
    printf("Received message: ");
    for (size_t i = 0; i < message.size; ++i) {
        printf("%02x", message.buffer[i]);
    }
    printf("\n");

    n20_msg_request_t request;
    n20_error_t error = n20_msg_request_read(&request, message);
    if (error != n20_error_ok_e) {
        // Handle error: failed to read message
        printf(
            "Dispatching message of type: %d failed with error: %d\n", request.request_type, error);
        return error;
    }

    // Example message dispatch function.
    // This function would handle incoming messages and perform actions
    // based on the message type.
    printf("Dispatching message of type: %d\n", request.request_type);

    size_t const total_buffer_size = *response_size_in_out;

    switch (request.request_type) {
        case n20_msg_request_type_promote_e:
            error = dispatch_promote_request(node_state,
                                             response_buffer,
                                             response_size_in_out,
                                             &request.payload.promote,
                                             client_index);
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            error = dispatch_issue_cdi_cert_request(node_state,
                                                    response_buffer,
                                                    response_size_in_out,
                                                    &request.payload.issue_cdi_cert,
                                                    client_index);
            break;
        default:
            // Handle unknown request type
            error = n20_error_unrecognized_request_type_e;
            break;
    }
    if (error != n20_error_ok_e) {
        // Prepare an error response.
        n20_msg_error_response_t error_response = {.error_code = error};
        *response_size_in_out = total_buffer_size;  // Reset response size.
        return n20_msg_error_response_write(&error_response, response_buffer, response_size_in_out);
    }
    return n20_error_ok_e;
}

static void print_uds_public_keys(n20_gnostic_node_state_t *node_state) {
    if (node_state == NULL) {
        printf("Node state is NULL\n");
        return;
    }

    uint8_t key_formatting_buffer[256];
    size_t key_formatting_size = sizeof(key_formatting_buffer);

    n20_error_t error = export_uds_public_key_as_cose(
        node_state, n20_crypto_key_type_ed25519_e, key_formatting_buffer, &key_formatting_size);
    if (error != n20_error_ok_e) {
        printf("Failed to export UDS public key as COSE: %d\n", error);
        return;
    }

    printf("UDS Public Key ED25519 (COSE format): ");
    for (size_t i = 0; i < key_formatting_size; ++i) {
        printf("%02x",
               key_formatting_buffer[sizeof(key_formatting_buffer) - key_formatting_size + i]);
    }
    printf("\n");

    key_formatting_size = sizeof(key_formatting_buffer);
    error = export_uds_public_key_as_cose(
        node_state, n20_crypto_key_type_secp256r1_e, key_formatting_buffer, &key_formatting_size);
    if (error != n20_error_ok_e) {
        printf("Failed to export UDS public key as COSE: %d\n", error);
        return;
    }

    printf("UDS Public Key P256 (COSE format): ");
    for (size_t i = 0; i < key_formatting_size; ++i) {
        printf("%02x",
               key_formatting_buffer[sizeof(key_formatting_buffer) - key_formatting_size + i]);
    }
    printf("\n");

    key_formatting_size = sizeof(key_formatting_buffer);
    error = export_uds_public_key_as_cose(
        node_state, n20_crypto_key_type_secp384r1_e, key_formatting_buffer, &key_formatting_size);
    if (error != n20_error_ok_e) {
        printf("Failed to export UDS public key as COSE: %d\n", error);
        return;
    }

    printf("UDS Public Key P384 (COSE format): ");
    for (size_t i = 0; i < key_formatting_size; ++i) {
        printf("%02x",
               key_formatting_buffer[sizeof(key_formatting_buffer) - key_formatting_size + i]);
    }
    printf("\n");
}

int main(void /*int argc, char *argv[]*/) {

    // Initialize the gnostic node state and crypto context.
    init_gnostic_node_with_bssl_crypto(&service_node_state);

    // Print the UDS public keys in COSE format.
    print_uds_public_keys(&service_node_state);

    int server_fd;
    struct sockaddr_un addr;

    // Create socket
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Remove any existing socket file
    unlink(SOCKET_PATH);

    // Set up the address structure
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, BACKLOG) == -1) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s\n", SOCKET_PATH);

    bool run = true;

    while (run) {
        // Accept loop (example, not handling clients here)
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        printf("Client connected\n");
        uint8_t buffer[1024];
        uint8_t response_buffer[1024];
        size_t response_size = sizeof(buffer);
        n20_slice_t message = {.size = 0, .buffer = buffer};
        // Read message from client
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            perror("read");
            close(client_fd);
            continue;
        } else if (bytes_read == 0) {
            printf("Client disconnected\n");
            close(client_fd);
            continue;
        }
        message.size = (size_t)bytes_read;
        printf("Received message of size: %zu\n", message.size);
        // Dispatch the message
        n20_error_t error =
            dispatch_message(&service_node_state, response_buffer, &response_size, message, 0);
        if (error != n20_error_ok_e) {
            printf("Error dispatching message: %d\n", error);
            close(client_fd);
            continue;
        }
        // Write response back to client
        // The response is written to the end of the response_buffer.
        ssize_t bytes_written = write(
            client_fd, &response_buffer[sizeof(response_buffer) - response_size], response_size);
        if (bytes_written < 0) {
            perror("write");
        }
    }

    // Cleanup
    close(server_fd);
    unlink(SOCKET_PATH);

    return 0;
}
