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

#include <getopt.h>
#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/service/service.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void print_usage(char const *prog) {
    fprintf(stderr,
            "Usage: %s -r <promote|cdi-cert|eca-cert|eca-sign> -p <ed25519|p256|p384> -k "
            "<ed25519|p256|p384> "
            "-c <code_hash> -C <code_desc> -g <conf_hash> -G <conf_desc> -a <auth_hash> -A "
            "<auth_desc> -m "
            "<not-configured|normal|debug|recovery> -h <hidden>\n"
            "-k <compressed_input> -P <profile_name> -n <path_element> -o <output_file>\n"
            "-f <x509|cose> -x <context> -u <key_usage> -l <challenge> -M <message>\n",
            prog);
}

int parse_key_type(char const *str) {
    if (strcmp(str, "ed25519") == 0) return n20_crypto_key_type_ed25519_e;
    if (strcmp(str, "p256") == 0) return n20_crypto_key_type_secp256r1_e;
    if (strcmp(str, "p384") == 0) return n20_crypto_key_type_secp384r1_e;
    return n20_crypto_key_type_none_e;
}

int parse_request_type(char const *str) {
    if (strcmp(str, "promote") == 0) return n20_msg_request_type_promote_e;
    if (strcmp(str, "cdi-cert") == 0) return n20_msg_request_type_issue_cdi_cert_e;
    if (strcmp(str, "eca-cert") == 0) return n20_msg_request_type_issue_eca_cert_e;
    if (strcmp(str, "eca-sign") == 0) return n20_msg_request_type_eca_sign_e;
    return n20_msg_request_type_none_e;
}

int parse_mode(char const *str) {
    if (strcmp(str, "not-configured") == 0) return n20_open_dice_mode_not_configured_e;
    if (strcmp(str, "normal") == 0) return n20_open_dice_mode_normal_e;
    if (strcmp(str, "debug") == 0) return n20_open_dice_mode_debug_e;
    if (strcmp(str, "recovery") == 0) return n20_open_dice_mode_recovery_e;
    return n20_open_dice_mode_not_configured_e;
}

int parse_output_format(char const *str) {
    if (strcmp(str, "x509") == 0) return n20_certificate_format_x509_e;
    if (strcmp(str, "cose") == 0) return n20_certificate_format_cose_e;
    return n20_certificate_format_none_e;
}

char nibble2bits(uint8_t nibble) {
    nibble -= 0x30;  // Convert ASCII to numeric value
    if (nibble <= 9) return nibble;
    nibble &= 0xDF;  // Convert to uppercase
    nibble -= 7;     // Adjust for A-F
    if (nibble < 0x10) return nibble;
    return -1;
}

int hex_string_to_bytes_in_place(char *hex) {
    size_t len = strlen(hex);
    uint8_t *out_pos = (uint8_t *)hex;
    size_t pos = 0;
    if ((len & 1) != 0) {
        // Odd length, assume leading zero
        *out_pos++ = nibble2bits(hex[0]);
        pos++;
    }

    while (pos < len) {
        uint8_t high = nibble2bits(hex[pos++]);
        uint8_t low = nibble2bits(hex[pos++]);
        if (high < 0 || low < 0) {
            return -1;  // Invalid hex character
        }
        *out_pos++ = (high << 4) | low;
    }

    return out_pos - (uint8_t *)hex;  // Return number of bytes written
}

static n20_crypto_digest_context_t *digest_ctx = NULL;

int main(int argc, char *argv[]) {

    n20_error_t err = n20_crypto_nat20_open(&digest_ctx);
    if (err != n20_error_ok_e) {
        fprintf(stderr, "Failed to open digest context: %d\n", err);
        return -1;
    }

    int opt;
    n20_msg_request_t request = {0};
    char const *output_file = NULL;
    char const *shortopts = "r:p:k:c:C:g:G:a:A:m:h:i:P:n:o:f:x:u:l:M:";

    opt = getopt(argc, argv, shortopts);
    if (opt != 'r') {
        fprintf(stderr, "Request type (-r) is required as first flag\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    request.request_type = parse_request_type(optarg);
    if (request.request_type == n20_msg_request_type_none_e) {
        fprintf(stderr, "Invalid request type: %s\n", optarg);
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    switch (request.request_type) {
        case n20_msg_request_type_promote_e:
            while ((opt = getopt(argc, argv, shortopts)) != -1) {
                switch (opt) {
                    case 'i':
                        request.payload.promote.compressed_context.buffer = (uint8_t *)optarg;
                        break;
                    default:
                        print_usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
            }

            if (request.payload.promote.compressed_context.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.promote.compressed_context.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for compressed input: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.promote.compressed_context.size = bytes_written;
            }

            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            while ((opt = getopt(argc, argv, shortopts)) != -1) {
                switch (opt) {
                    case 'r':
                        request.request_type = parse_request_type(optarg);
                        break;
                    case 'p':
                        request.payload.issue_cdi_cert.parent_key_type = parse_key_type(optarg);
                        break;
                    case 'k':
                        request.payload.issue_cdi_cert.key_type = parse_key_type(optarg);
                        break;
                    case 'c':
                        request.payload.issue_cdi_cert.next_context.code_hash.buffer =
                            (uint8_t *)optarg;
                        break;
                    case 'C':
                        request.payload.issue_cdi_cert.next_context.code_descriptor.buffer =
                            (uint8_t *)optarg;
                        break;
                    case 'g':
                        request.payload.issue_cdi_cert.next_context.configuration_hash.buffer =
                            (uint8_t *)optarg;
                        break;
                    case 'G':
                        request.payload.issue_cdi_cert.next_context.configuration_descriptor
                            .buffer = (uint8_t *)optarg;
                        break;
                    case 'a':
                        request.payload.issue_cdi_cert.next_context.authority_hash.buffer =
                            (uint8_t *)optarg;
                        break;
                    case 'A':
                        request.payload.issue_cdi_cert.next_context.authority_descriptor.buffer =
                            (uint8_t *)optarg;
                        break;
                    case 'm':
                        request.payload.issue_cdi_cert.next_context.mode = parse_mode(optarg);
                        break;
                    case 'h':
                        request.payload.issue_cdi_cert.next_context.hidden.buffer =
                            (uint8_t *)optarg;
                        break;
                    case 'P':
                        request.payload.issue_cdi_cert.next_context.profile_name.buffer = optarg;
                        request.payload.issue_cdi_cert.next_context.profile_name.size =
                            strlen(optarg);
                        break;
                    case 'n':
                        if (request.payload.issue_cdi_cert.parent_path_length <
                            N20_STATELESS_MAX_PATH_LENGTH) {
                            request.payload.issue_cdi_cert
                                .parent_path[request.payload.issue_cdi_cert.parent_path_length]
                                .buffer = (uint8_t *)optarg;
                            request.payload.issue_cdi_cert.parent_path_length++;
                        } else {
                            fprintf(stderr, "Parent path size exceeds maximum length\n");
                            print_usage(argv[0]);
                            exit(EXIT_FAILURE);
                        }
                        break;
                    case 'o':
                        output_file = optarg;
                        break;
                    case 'f':
                        request.payload.issue_cdi_cert.certificate_format =
                            parse_output_format(optarg);
                        break;
                    default:
                        print_usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
            }
            if (request.payload.issue_cdi_cert.key_type == n20_crypto_key_type_none_e) {
                fprintf(stderr, "Invalid parent key type: %s\n", optarg);
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }

            if (request.payload.issue_cdi_cert.key_type == n20_crypto_key_type_none_e) {
                fprintf(stderr, "Invalid key type: %s\n", optarg);
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }

            // Convert hex strings to byte arrays
            if (request.payload.issue_cdi_cert.next_context.code_hash.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_cdi_cert.next_context.code_hash.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for code_hash: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.code_hash.size = bytes_written;
            }

            if (request.payload.issue_cdi_cert.next_context.code_descriptor.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_cdi_cert.next_context.code_descriptor.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for code_desc: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.code_descriptor.size = bytes_written;
            }
            if (request.payload.issue_cdi_cert.next_context.configuration_hash.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_cdi_cert.next_context.configuration_hash.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for configuration_hash: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.configuration_hash.size = bytes_written;
            }
            if (request.payload.issue_cdi_cert.next_context.configuration_descriptor.buffer) {
                int bytes_written =
                    hex_string_to_bytes_in_place((char *)request.payload.issue_cdi_cert.next_context
                                                     .configuration_descriptor.buffer);
                if (bytes_written < 0) {
                    fprintf(
                        stderr, "Invalid hex string for configuration_descriptor: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.configuration_descriptor.size =
                    bytes_written;
            }
            if (request.payload.issue_cdi_cert.next_context.authority_hash.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_cdi_cert.next_context.authority_hash.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for authority_hash: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.authority_hash.size = bytes_written;
            }
            if (request.payload.issue_cdi_cert.next_context.authority_descriptor.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)
                        request.payload.issue_cdi_cert.next_context.authority_descriptor.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for authority_descriptor: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.authority_descriptor.size =
                    bytes_written;
            }
            if (request.payload.issue_cdi_cert.next_context.hidden.buffer) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_cdi_cert.next_context.hidden.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for hidden: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.next_context.hidden.size = bytes_written;
            }

            for (size_t i = 0; i < request.payload.issue_cdi_cert.parent_path_length; ++i) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_cdi_cert.parent_path[i].buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for parent path element: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_cdi_cert.parent_path[i].size = bytes_written;
            }

            if (request.payload.issue_cdi_cert.certificate_format ==
                n20_certificate_format_none_e) {
                fprintf(stderr, "Invalid certificate format: %s\n", optarg);
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            while ((opt = getopt(argc, argv, shortopts)) != -1) {
                switch (opt) {
                    case 'r':
                        request.request_type = parse_request_type(optarg);
                        break;
                    case 'p':
                        request.payload.issue_eca_cert.parent_key_type = parse_key_type(optarg);
                        break;
                    case 'k':
                        request.payload.issue_eca_cert.key_type = parse_key_type(optarg);
                        break;
                    case 'n':
                        if (request.payload.issue_eca_cert.parent_path_length <
                            N20_STATELESS_MAX_PATH_LENGTH) {
                            request.payload.issue_eca_cert
                                .parent_path[request.payload.issue_eca_cert.parent_path_length]
                                .buffer = (uint8_t *)optarg;
                            request.payload.issue_eca_cert.parent_path_length++;
                        } else {
                            fprintf(stderr, "Parent path size exceeds maximum length\n");
                            print_usage(argv[0]);
                            exit(EXIT_FAILURE);
                        }
                        break;
                    case 'o':
                        output_file = optarg;
                        break;
                    case 'f':
                        request.payload.issue_eca_cert.certificate_format =
                            parse_output_format(optarg);
                        break;
                    case 'x': /* context */
                        request.payload.issue_eca_cert.context.buffer = (uint8_t *)optarg;
                        request.payload.issue_eca_cert.context.size = strlen(optarg);
                        break;
                    case 'u': /* key_usage */
                        request.payload.issue_eca_cert.key_usage.buffer = (uint8_t *)optarg;
                        request.payload.issue_eca_cert.key_usage.size = strlen(optarg);
                        break;
                    case 'l': /* challenge */
                        request.payload.issue_eca_cert.challenge.buffer = (uint8_t *)optarg;
                        request.payload.issue_eca_cert.challenge.size = strlen(optarg);
                        break;
                    default:
                        print_usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
            }
            if (request.payload.issue_eca_cert.parent_key_type == n20_crypto_key_type_none_e) {
                fprintf(stderr, "Invalid parent key type\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }

            if (request.payload.issue_eca_cert.key_type == n20_crypto_key_type_none_e) {
                fprintf(stderr, "Invalid key type\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }

            // Convert hex strings to byte arrays for parent path
            for (size_t i = 0; i < request.payload.issue_eca_cert.parent_path_length; ++i) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_eca_cert.parent_path[i].buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for parent path element: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_eca_cert.parent_path[i].size = bytes_written;
            }

            // Convert key_usage from hex string to bytes if provided
            if (request.payload.issue_eca_cert.key_usage.buffer != NULL) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_eca_cert.key_usage.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for key_usage\n");
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_eca_cert.key_usage.size = bytes_written;
            }

            // Convert challenge from hex string to bytes if provided
            if (request.payload.issue_eca_cert.challenge.buffer != NULL) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.issue_eca_cert.challenge.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for challenge\n");
                    exit(EXIT_FAILURE);
                }
                request.payload.issue_eca_cert.challenge.size = bytes_written;
            }

            if (request.payload.issue_eca_cert.certificate_format ==
                n20_certificate_format_none_e) {
                fprintf(stderr, "Invalid certificate format: %s\n", optarg);
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case n20_msg_request_type_eca_sign_e:
            while ((opt = getopt(argc, argv, shortopts)) != -1) {
                switch (opt) {
                    case 'r':
                        request.request_type = parse_request_type(optarg);
                        break;
                    case 'p':
                        request.payload.eca_sign.parent_key_type = parse_key_type(optarg);
                        break;
                    case 'k':
                        request.payload.eca_sign.key_type = parse_key_type(optarg);
                        break;
                    case 'n':
                        if (request.payload.eca_sign.parent_path_length <
                            N20_STATELESS_MAX_PATH_LENGTH) {
                            request.payload.eca_sign
                                .parent_path[request.payload.eca_sign.parent_path_length]
                                .buffer = (uint8_t *)optarg;
                            request.payload.eca_sign.parent_path_length++;
                        } else {
                            fprintf(stderr, "Parent path size exceeds maximum length\n");
                            print_usage(argv[0]);
                            exit(EXIT_FAILURE);
                        }
                        break;
                    case 'o':
                        output_file = optarg;
                        break;
                    case 'x': /* context */
                        request.payload.eca_sign.context.buffer = (uint8_t *)optarg;
                        request.payload.eca_sign.context.size = strlen(optarg);
                        break;
                    case 'u': /* key_usage */
                        request.payload.eca_sign.key_usage.buffer = (uint8_t *)optarg;
                        request.payload.eca_sign.key_usage.size = strlen(optarg);
                        break;
                    case 'l': /* challenge */
                        request.payload.eca_sign.challenge.buffer = (uint8_t *)optarg;
                        request.payload.eca_sign.challenge.size = strlen(optarg);
                        break;
                    case 'M': /* message */
                        request.payload.eca_sign.message.buffer = (uint8_t *)optarg;
                        request.payload.eca_sign.message.size = strlen(optarg);
                        break;
                    default:
                        print_usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
            }
            if (request.payload.eca_sign.parent_key_type == n20_crypto_key_type_none_e) {
                fprintf(stderr, "Invalid parent key type\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }

            if (request.payload.eca_sign.key_type == n20_crypto_key_type_none_e) {
                fprintf(stderr, "Invalid key type\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }

            // Convert hex strings to byte arrays for parent path
            for (size_t i = 0; i < request.payload.eca_sign.parent_path_length; ++i) {
                int bytes_written = hex_string_to_bytes_in_place(
                    (char *)request.payload.eca_sign.parent_path[i].buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for parent path element: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                request.payload.eca_sign.parent_path[i].size = bytes_written;
            }

            // Convert key_usage from hex string to bytes if provided
            if (request.payload.eca_sign.key_usage.buffer != NULL) {
                int bytes_written =
                    hex_string_to_bytes_in_place((char *)request.payload.eca_sign.key_usage.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for key_usage\n");
                    exit(EXIT_FAILURE);
                }
                request.payload.eca_sign.key_usage.size = bytes_written;
            }

            // Convert challenge from hex string to bytes if provided
            if (request.payload.eca_sign.challenge.buffer != NULL) {
                int bytes_written =
                    hex_string_to_bytes_in_place((char *)request.payload.eca_sign.challenge.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for challenge\n");
                    exit(EXIT_FAILURE);
                }
                request.payload.eca_sign.challenge.size = bytes_written;
            }

            // Convert message from hex string to bytes
            if (request.payload.eca_sign.message.buffer != NULL) {
                int bytes_written =
                    hex_string_to_bytes_in_place((char *)request.payload.eca_sign.message.buffer);
                if (bytes_written < 0) {
                    fprintf(stderr, "Invalid hex string for message\n");
                    exit(EXIT_FAILURE);
                }
                request.payload.eca_sign.message.size = bytes_written;
            }
            break;
        default:
            fprintf(stderr, "Unsupported request type: %d\n", request.request_type);
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
    }

    uint8_t msg_buffer[1024];

    size_t msg_size = sizeof(msg_buffer);

    err = n20_msg_request_write(&request, msg_buffer, &msg_size);
    if (err != n20_error_ok_e) {
        fprintf(stderr, "Failed to write request: %d\n", err);
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Connect to the service
    int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/gnostic_n20_service.sock", sizeof(addr.sun_path) - 1);
    int rc = connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        perror("connect");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    uint8_t *msg_begin = &msg_buffer[sizeof(msg_buffer) - msg_size];

    // Send the request based on the request type
    if (send(socket_fd, msg_begin, msg_size, 0) < 0) {
        perror("send");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    // Read the response
    uint8_t response_buffer[1024];
    ssize_t bytes_received = recv(socket_fd, response_buffer, sizeof(response_buffer), 0);
    if (bytes_received < 0) {
        perror("recv");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    n20_slice_t response_slice = {
        .buffer = response_buffer,
        .size = (size_t)bytes_received,
    };

    switch (request.request_type) {
        case n20_msg_request_type_promote_e: {
            n20_msg_error_response_t response;
            err = n20_msg_error_response_read(&response, response_slice);
            if (err != n20_error_ok_e) {
                fprintf(stderr, "Failed to read promote response: %d\n", err);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            if (response.error_code != n20_error_ok_e) {
                fprintf(stderr,
                        "Promote request failed with error: %d (0x%x\n",
                        response.error_code,
                        response.error_code);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            printf("Promote request successful\n");
            break;
        }
        case n20_msg_request_type_issue_cdi_cert_e: {
            n20_compressed_input_t next_compressed_input;

            err = n20_compress_input(
                digest_ctx, &request.payload.issue_cdi_cert.next_context, next_compressed_input);
            if (err != n20_error_ok_e) {
                fprintf(stderr, "Failed to compress input: %d\n", err);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }

            n20_msg_issue_cdi_cert_response_t response;
            err = n20_msg_issue_cdi_cert_response_read(&response, response_slice);
            if (err != n20_error_ok_e) {
                fprintf(stderr, "Failed to read CDI cert response: %d\n", err);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            if (response.error_code != n20_error_ok_e) {
                fprintf(stderr, "CDI cert request failed with error: %d\n", response.error_code);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            printf("CDI cert request successful, certificate size: %zu\n",
                   response.certificate.size);

            if (output_file) {
                FILE *file = fopen(output_file, "wb");
                if (!file) {
                    perror("fopen");
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                size_t written =
                    fwrite(response.certificate.buffer, 1, response.certificate.size, file);
                if (written != response.certificate.size) {
                    fprintf(stderr, "Failed to write full certificate to file\n");
                    fclose(file);
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                fclose(file);
                printf("Certificate written to %s\n", output_file);
            } else {
                printf("Certificate data: ");
                for (size_t i = 0; i < response.certificate.size; ++i) {
                    printf("%02x", response.certificate.buffer[i]);
                }
                printf("\n");
            }
            // Write the compressed input to standard output
            printf("Compressed input: ");
            for (size_t i = 0; i < sizeof(next_compressed_input); ++i) {
                printf("%02x", next_compressed_input[i]);
            }
            printf("\n");

            break;
        }
        case n20_msg_request_type_issue_eca_cert_e: {
            // Debug: print raw response
            printf("Raw response (%zu bytes): ", response_slice.size);
            for (size_t i = 0; i < response_slice.size && i < 32; ++i) {
                printf("%02x", response_slice.buffer[i]);
            }
            if (response_slice.size > 32) printf("...");
            printf("\n");

            // First try to read as an error response
            n20_msg_error_response_t error_response;
            err = n20_msg_error_response_read(&error_response, response_slice);
            if (err == n20_error_ok_e && error_response.error_code != n20_error_ok_e) {
                fprintf(stderr,
                        "ECA cert request failed with server error: %d\n",
                        error_response.error_code);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }

            // If not an error response, try to read as certificate response
            n20_msg_issue_eca_cert_response_t response;
            err = n20_msg_issue_eca_cert_response_read(&response, response_slice);
            if (err != n20_error_ok_e) {
                fprintf(stderr, "Failed to read ECA cert response: %d\n", err);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            if (response.error_code != n20_error_ok_e) {
                fprintf(stderr, "ECA cert request failed with error: %d\n", response.error_code);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            printf("ECA cert request successful, certificate size: %zu\n",
                   response.certificate.size);

            if (output_file) {
                FILE *file = fopen(output_file, "wb");
                if (!file) {
                    perror("fopen");
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                size_t written =
                    fwrite(response.certificate.buffer, 1, response.certificate.size, file);
                if (written != response.certificate.size) {
                    fprintf(stderr, "Failed to write full certificate to file\n");
                    fclose(file);
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                fclose(file);
                printf("Certificate written to %s\n", output_file);
            } else {
                printf("Certificate data: ");
                for (size_t i = 0; i < response.certificate.size; ++i) {
                    printf("%02x", response.certificate.buffer[i]);
                }
                printf("\n");
            }

            break;
        }
        case n20_msg_request_type_eca_sign_e: {
            // First try to read as an error response
            n20_msg_error_response_t error_response;
            err = n20_msg_error_response_read(&error_response, response_slice);
            if (err == n20_error_ok_e && error_response.error_code != n20_error_ok_e) {
                fprintf(stderr,
                        "ECA sign request failed with server error: %d\n",
                        error_response.error_code);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }

            // If not an error response, try to read as sign response
            n20_msg_eca_sign_response_t response;
            err = n20_msg_eca_sign_response_read(&response, response_slice);
            if (err != n20_error_ok_e) {
                fprintf(stderr, "Failed to read ECA sign response: %d\n", err);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            if (response.error_code != n20_error_ok_e) {
                fprintf(stderr, "ECA sign request failed with error: %d\n", response.error_code);
                close(socket_fd);
                exit(EXIT_FAILURE);
            }
            printf("ECA sign request successful, signature size: %zu\n", response.signature.size);

            if (output_file) {
                FILE *file = fopen(output_file, "wb");
                if (!file) {
                    perror("fopen");
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                size_t written =
                    fwrite(response.signature.buffer, 1, response.signature.size, file);
                if (written != response.signature.size) {
                    fprintf(stderr, "Failed to write full signature to file\n");
                    fclose(file);
                    close(socket_fd);
                    exit(EXIT_FAILURE);
                }
                fclose(file);
                printf("Signature written to %s\n", output_file);
            } else {
                printf("Signature data: ");
                for (size_t i = 0; i < response.signature.size; ++i) {
                    printf("%02x", response.signature.buffer[i]);
                }
                printf("\n");
            }

            break;
        }
        default:
            fprintf(stderr, "Unknown request type in response\n");
            close(socket_fd);
            exit(EXIT_FAILURE);
    }

    return 0;
}
