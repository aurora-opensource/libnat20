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

#include <fcntl.h>
#include <getopt.h>
#include <nat20/crypto.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/messages.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// CLI tool specific error codes
typedef enum {
    cli_error_ok = 0,
    cli_error_invalid_argument,
    cli_error_io,
    cli_error_memory,
    cli_error_libnat20,
    cli_error_server,
} cli_error_t;

char const *usage_format_str =
    "Usage: %s <command> <options>\n"
    "Commands:\n"
    "  promote        Instruct the service to promote the caller to the next "
    "level.\n"
    "  cdi-cert       Instruct the service to issue a CDI certificate.\n"
    "  eca-cert       Instruct the service to issue an ECA certificate.\n"
    "  eca-ee-cert    Instruct the service to issue an ECA End-Entity "
    "certificate.\n"
    "  eca-ee-sign    Instruct the service to sign a message with an ECA EE "
    "key.\n"
    "Options promote:\n"
    "  --compressed-input -i <input>:\n"
    "                 A hex string. "
    "H(<code_hash>|<conf_hash>|<auth_hash>|<mode>|<hidden>)\n"
    "\n"
    "Options common (all commands except promote):\n"
    "  --key-type -k <ed25519|p256|p384>\n"
    "  --parent-path-element -n <path_element>\n"
    "                 A parent path element. May be given multiple times. Each "
    "element\n"
    "                 is a compressed input. The inputs are used to derive the "
    "effective\n"
    "                 parent CDI and thus the key material for the operation.\n"
    "  --output -o <output_file>\n"
    "                 The output file to write the resulting certificate or "
    "signature to.\n"
    "\n"
    "Options (*-cert commands):\n"
    "  --parent-key-type -p <ed25519|p256|p384>\n"
    "                 The key type of the parent key. This is used to identify "
    "the\n"
    "                 issuer key algorithm.\n"
    "  --certificate-format -f <x509|cose>\n"
    "                 The format of the certificate to be issued.\n"
    "\n"
    "Options (cdi-cert):\n"
    "  --code -c <code_hash>\n"
    "                 The code hash as hex string.\n"
    "  --code-desc -C <code_desc>\n"
    "                 The code description as hex string.\n"
    "  --conf -g <conf_hash>\n"
    "                 The configuration hash as hex string.\n"
    "  --conf-desc -G <conf_desc>\n"
    "                 The configuration description as hex string.\n"
    "  --auth -a <auth_hash>\n"
    "                 The authorization hash as hex string.\n"
    "  --auth-desc -A <auth_desc>\n"
    "                 The authorization description as hex string.\n"
    "  --mode -m <not-configured|normal|debug|recovery>\n"
    "                 The mode.\n"
    "  --hidden -H <hidden>\n"
    "                 The hidden context as hex string. Hidden is part of the "
    "CDI derivation "
    "context.\n"
    "                 But does not appear in the CDI certificate.\n"
    "  --profile-name -P <profile_name>\n"
    "                 The profile name. The DICE profile name is used to "
    "identify the\n"
    "                 specific DICE profile being used.\n"
    "\n"
    "Options (eca-ee-cert and eca-ee-sign)\n"
    "  --name -N <name>\n"
    "                 The application specific name of the end-entity key. It "
    "is not\n"
    "                 included in the issued end-entity certificate, but it is "
    "part of\n"
    "                 the key derivation context. Thus keys with different "
    "names are\n"
    "                 never identical.\n"
    "  --key-usage -u <sign|cert-sign>\n"
    "                 The key usage.\n"
    "\n"
    "Options (eca-cert and eca-ee-cert)\n"
    "  --challenge -l <challenge>\n"
    "                 The challenge. Will be included in the certificate. "
    "Using the\n"
    "                 TCG DICE Freshness extension.\n"
    "\n"
    "Options (eca-ee-sign)\n"
    "  --message -M <message>\n"
    "                 The message.\n";

void print_usage(char const *prog) { fprintf(stderr, usage_format_str, prog); }

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
    if (strcmp(str, "eca-ee-cert") == 0) return n20_msg_request_type_issue_eca_ee_cert_e;
    if (strcmp(str, "eca-ee-sign") == 0) return n20_msg_request_type_eca_ee_sign_e;
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

void parse_key_usage(char const *str, uint8_t key_usage[2]) {
    if (strcmp(str, "sign") == 0) {
        N20_OPEN_DICE_KEY_USAGE_SET_DIGITAL_SIGNATURE(key_usage);
    } else if (strcmp(str, "cert-sign") == 0) {
        N20_OPEN_DICE_KEY_USAGE_SET_KEY_CERT_SIGN(key_usage);
    }
}

typedef struct owned_buffer {
    uint8_t *data;
    size_t size;
} owned_buffer_t;

owned_buffer_t make_owned_buffer(size_t size) {
    owned_buffer_t buf;
    buf.data = malloc(size);
    if (buf.data != NULL) {
        memset(buf.data, 0, size);
        buf.size = size;
    } else {
        buf.size = 0;
    }
    return buf;
}

void free_owned_buffer(owned_buffer_t *buf) {
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
        buf->size = 0;
    }
}

// Intermediate structure to hold parsed command-line options
typedef struct {
    // Common fields
    int request_type;
    char const *output_file;

    // Key-related fields
    int subject_key_type;  // -k
    int issuer_key_type;   // -p

    // Parent path (used by most commands except promote)
    struct {
        char const **elements;  // Array of hex strings
        size_t count;
        size_t capacity;
    } parent_path;

    // Certificate-related
    int certificate_format;  // -f
    char const *challenge;   // -l

    // CDI-specific fields
    struct {
        owned_buffer_t code_hash;  // -c
        owned_buffer_t code_desc;  // -C
        owned_buffer_t conf_hash;  // -g
        owned_buffer_t conf_desc;  // -G
        owned_buffer_t auth_hash;  // -a
        owned_buffer_t auth_desc;  // -A
        owned_buffer_t hidden;     // -H
        int mode;                  // -m
        char const *profile_name;  // -P
    } cdi_fields;

    // ECA EE-specific fields
    struct {
        char const *name;           // -N
        char const *key_usage_str;  // -u
    } ee_fields;

    // Command-specific fields
    owned_buffer_t compressed_input;  // -i (promote)
    owned_buffer_t message;           // -M (eca-ee-sign)
} parsed_options_t;

// Convert a hex nibble character to its 4-bit value
static int8_t nibble2bits(uint8_t nibble) {
    nibble -= 0x30;  // Convert ASCII to numeric value
    if (nibble <= 9) return nibble;
    nibble &= 0xDF;  // Convert to uppercase
    nibble -= 7;     // Adjust for A-F
    if (nibble < 0x10) return nibble;
    return -1;
}

static owned_buffer_t hex_string_to_bytes(char const *hex) {
    owned_buffer_t buf = {0};
    size_t len = strlen(hex);
    buf = make_owned_buffer((len + 1) / 2);  // Allocate enough memory for bytes
    if (buf.data == NULL) {
        return buf;  // Memory allocation failed
    }
    uint8_t *out_pos = buf.data;
    size_t pos = 0;
    if ((len & 1) != 0) {
        // Odd length, assume leading zero
        int8_t low = nibble2bits(hex[0]);
        if (low < 0) {
            free_owned_buffer(&buf);
            return buf;  // Invalid hex character
        }
        *out_pos++ = low;
        pos++;
    }

    while (pos < len) {
        int8_t high = nibble2bits(hex[pos++]);
        int8_t low = nibble2bits(hex[pos++]);
        if (high < 0 || low < 0) {
            free_owned_buffer(&buf);
            return buf;  // Invalid hex character
        }
        *out_pos++ = (high << 4) | low;
    }

    return buf;
}

static n20_slice_t owned_buffer_to_slice(owned_buffer_t const *buf) {
    n20_slice_t slice;
    slice.buffer = buf->data;
    slice.size = buf->size;
    return slice;
}

// Helper function to add parent path element to options
static bool add_parent_path_element(parsed_options_t *opts, char const *element) {
    if (opts->parent_path.count >= opts->parent_path.capacity) {
        size_t new_capacity = opts->parent_path.capacity == 0 ? 4 : opts->parent_path.capacity * 2;
        char const **new_elements =
            reallocarray((void *)opts->parent_path.elements, new_capacity, sizeof(char const *));
        if (new_elements == NULL) {
            return false;
        }
        opts->parent_path.elements = new_elements;
        opts->parent_path.capacity = new_capacity;
    }
    opts->parent_path.elements[opts->parent_path.count++] = element;
    return true;
}

// Helper function to clean up parsed options
static void cleanup_parsed_options(parsed_options_t *opts) {
    if (opts->parent_path.elements != NULL) {
        free((void *)opts->parent_path.elements);
        opts->parent_path.elements = NULL;
    }
    free_owned_buffer(&opts->cdi_fields.code_hash);
    free_owned_buffer(&opts->cdi_fields.code_desc);
    free_owned_buffer(&opts->cdi_fields.conf_hash);
    free_owned_buffer(&opts->cdi_fields.conf_desc);
    free_owned_buffer(&opts->cdi_fields.auth_hash);
    free_owned_buffer(&opts->cdi_fields.auth_desc);
    free_owned_buffer(&opts->cdi_fields.hidden);
    free_owned_buffer(&opts->compressed_input);
    free_owned_buffer(&opts->message);
}

static bool add_parent_path_decoded(n20_parent_path_t *path, char const *hex_str) {
    if (path->is_encoded) {
        fprintf(stderr, "Cannot add parent path element to already encoded path\n");
        return false;
    }
    n20_slice_t *new_slices =
        reallocarray((void *)path->decoded, path->length + 1, sizeof(n20_slice_t));
    if (new_slices == NULL) {
        free((void *)path->decoded);
        path->decoded = NULL;
        return false;
    }
    path->decoded = new_slices;
    new_slices[path->length].buffer = (uint8_t *)hex_str;
    new_slices[path->length].size = strlen(hex_str) / 2;  // Assuming hex string represents bytes
    path->length++;
    return true;
}

static void clean_up_request(n20_msg_request_t *request) {
    n20_parent_path_t *path = NULL;
    switch (request->request_type) {
        case n20_msg_request_type_issue_cdi_cert_e:
            path = &request->payload.issue_cdi_cert.parent_path;
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            path = &request->payload.issue_eca_cert.parent_path;
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            path = &request->payload.issue_eca_ee_cert.parent_path;
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            path = &request->payload.eca_ee_sign.parent_path;
            break;
        default:
            return;  // No parent path to clean up
    }
    if (!path->is_encoded && path->decoded != NULL) {
        free((void *)path->decoded);
        path->decoded = NULL;
    }
}
// Unified option parsing function
static int parse_command_options(int argc, char *argv[], parsed_options_t *opts) {
    // Define all possible long options
    static struct option long_options[] = {// Common options
                                           {"key-type", required_argument, 0, 'k'},
                                           {"parent-path-element", required_argument, 0, 'n'},
                                           {"output", required_argument, 0, 'o'},
                                           {"parent-key-type", required_argument, 0, 'p'},
                                           {"certificate-format", required_argument, 0, 'f'},
                                           {"challenge", required_argument, 0, 'l'},
                                           {"help", no_argument, 0, '?'},

                                           // Promote options
                                           {"compressed-input", required_argument, 0, 'i'},

                                           // CDI cert options
                                           {"code", required_argument, 0, 'c'},
                                           {"code-desc", required_argument, 0, 'C'},
                                           {"conf", required_argument, 0, 'g'},
                                           {"conf-desc", required_argument, 0, 'G'},
                                           {"auth", required_argument, 0, 'a'},
                                           {"auth-desc", required_argument, 0, 'A'},
                                           {"mode", required_argument, 0, 'm'},
                                           {"hidden", required_argument, 0, 'H'},
                                           {"profile-name", required_argument, 0, 'P'},

                                           // ECA EE options
                                           {"name", required_argument, 0, 'N'},
                                           {"key-usage", required_argument, 0, 'u'},

                                           // ECA EE sign options
                                           {"message", required_argument, 0, 'M'},

                                           {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(
                argc, argv, "i:k:n:o:p:f:c:C:g:G:a:A:m:H:P:l:N:u:M:?", long_options, NULL)) != -1) {
        switch (opt) {
            // Common options
            case 'k':
                opts->subject_key_type = parse_key_type(optarg);
                break;
            case 'p':
                opts->issuer_key_type = parse_key_type(optarg);
                break;
            case 'n':
                if (!add_parent_path_element(opts, optarg)) {
                    fprintf(stderr, "Failed to add parent path element\n");
                    return -1;
                }
                break;
            case 'o':
                opts->output_file = optarg;
                break;
            case 'f':
                opts->certificate_format = parse_output_format(optarg);
                break;
            case 'l':
                opts->challenge = optarg;
                break;

            // Promote options
            case 'i':
                opts->compressed_input = hex_string_to_bytes(optarg);
                if (opts->compressed_input.data == NULL) {
                    fprintf(stderr, "Invalid compressed input hex string\n");
                    return -1;
                }
                break;

            // CDI cert options
            case 'c':
                opts->cdi_fields.code_hash = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.code_hash.data == NULL) {
                    fprintf(stderr, "Invalid code hash hex string\n");
                    return -1;
                }
                break;
            case 'C':
                opts->cdi_fields.code_desc = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.code_desc.data == NULL) {
                    fprintf(stderr, "Invalid code descriptor hex string\n");
                    return -1;
                }
                break;
            case 'g':
                opts->cdi_fields.conf_hash = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.conf_hash.data == NULL) {
                    fprintf(stderr, "Invalid conf hash hex string\n");
                    return -1;
                }
                break;
            case 'G':
                opts->cdi_fields.conf_desc = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.conf_desc.data == NULL) {
                    fprintf(stderr, "Invalid configuration descriptor hex string\n");
                    return -1;
                }
                break;
            case 'a':
                opts->cdi_fields.auth_hash = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.auth_hash.data == NULL) {
                    fprintf(stderr, "Invalid auth hash hex string\n");
                    return -1;
                }
                break;
            case 'A':
                opts->cdi_fields.auth_desc = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.auth_desc.data == NULL) {
                    fprintf(stderr, "Invalid authority descriptor hex string\n");
                    return -1;
                }
                break;
            case 'm':
                opts->cdi_fields.mode = parse_mode(optarg);
                break;
            case 'H':
                opts->cdi_fields.hidden = hex_string_to_bytes(optarg);
                if (opts->cdi_fields.hidden.data == NULL) {
                    fprintf(stderr, "Invalid hidden hex string\n");
                    return -1;
                }
                break;
            case 'P':
                opts->cdi_fields.profile_name = optarg;
                break;

            // ECA EE options
            case 'N':
                opts->ee_fields.name = optarg;
                break;
            case 'u':
                opts->ee_fields.key_usage_str = optarg;
                break;

            // ECA EE sign options
            case 'M':
                opts->message = hex_string_to_bytes(optarg);
                if (opts->message.data == NULL) {
                    fprintf(stderr, "Invalid message hex string\n");
                    return -1;
                }
                break;

            case '?':
                // Help requested
                return -1;
            default:
                // Unknown option
                return -1;
        }
    }

    return 0;
}

// Initialize promote request from parsed options
static cli_error_t init_promote_request(n20_msg_request_t *request, parsed_options_t const *opts) {
    if (opts->compressed_input.data == NULL) {
        fprintf(stderr, "Promote requires --compressed-input\n");
        return cli_error_invalid_argument;
    }

    request->request_type = n20_msg_request_type_promote_e;
    request->payload.promote.compressed_context = owned_buffer_to_slice(&opts->compressed_input);
    return cli_error_ok;
}

// Initialize CDI cert request from parsed options
static cli_error_t init_cdi_cert_request(n20_msg_request_t *request, parsed_options_t const *opts) {
    cli_error_t err;

    request->request_type = n20_msg_request_type_issue_cdi_cert_e;
    request->payload.issue_cdi_cert.subject_key_type = opts->subject_key_type;
    request->payload.issue_cdi_cert.issuer_key_type = opts->issuer_key_type;
    request->payload.issue_cdi_cert.certificate_format = opts->certificate_format;

    // Validate required fields
    if (opts->subject_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --key-type\n");
        return cli_error_invalid_argument;
    }
    if (opts->issuer_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --parent-key-type\n");
        return cli_error_invalid_argument;
    }
    if (opts->certificate_format == n20_certificate_format_none_e) {
        fprintf(stderr, "Invalid or missing --certificate-format\n");
        return cli_error_invalid_argument;
    }

    // Parse CDI fields
    request->payload.issue_cdi_cert.next_context.code_hash =
        owned_buffer_to_slice(&opts->cdi_fields.code_hash);
    request->payload.issue_cdi_cert.next_context.code_descriptor =
        owned_buffer_to_slice(&opts->cdi_fields.code_desc);
    request->payload.issue_cdi_cert.next_context.configuration_hash =
        owned_buffer_to_slice(&opts->cdi_fields.conf_hash);
    request->payload.issue_cdi_cert.next_context.configuration_descriptor =
        owned_buffer_to_slice(&opts->cdi_fields.conf_desc);
    request->payload.issue_cdi_cert.next_context.authority_hash =
        owned_buffer_to_slice(&opts->cdi_fields.auth_hash);
    request->payload.issue_cdi_cert.next_context.authority_descriptor =
        owned_buffer_to_slice(&opts->cdi_fields.auth_desc);
    request->payload.issue_cdi_cert.next_context.hidden =
        owned_buffer_to_slice(&opts->cdi_fields.hidden);

    request->payload.issue_cdi_cert.next_context.mode = opts->cdi_fields.mode;

    if (opts->cdi_fields.profile_name) {
        request->payload.issue_cdi_cert.next_context.profile_name.buffer =
            opts->cdi_fields.profile_name;
        request->payload.issue_cdi_cert.next_context.profile_name.size =
            strlen(opts->cdi_fields.profile_name);
    }

    // Build parent path
    for (size_t i = 0; i < opts->parent_path.count; ++i) {
        if (!add_parent_path_decoded(&request->payload.issue_cdi_cert.parent_path,
                                     opts->parent_path.elements[i])) {
            fprintf(stderr, "Failed to add parent path element\n");
            return cli_error_invalid_argument;
        }
    }

    // Parse parent path hex strings
    for (size_t i = 0; i < request->payload.issue_cdi_cert.parent_path.length; ++i) {
        err = parse_hex_to_slice(
            (n20_slice_t *)&request->payload.issue_cdi_cert.parent_path.decoded[i],
            (char const *)request->payload.issue_cdi_cert.parent_path.decoded[i].buffer,
            "parent path element");
        if (err != cli_error_ok) return err;
    }

    return cli_error_ok;
}

// Initialize ECA cert request from parsed options
static cli_error_t init_eca_cert_request(n20_msg_request_t *request, parsed_options_t const *opts) {
    cli_error_t err;

    request->request_type = n20_msg_request_type_issue_eca_cert_e;
    request->payload.issue_eca_cert.subject_key_type = opts->subject_key_type;
    request->payload.issue_eca_cert.issuer_key_type = opts->issuer_key_type;
    request->payload.issue_eca_cert.certificate_format = opts->certificate_format;

    // Validate required fields
    if (opts->subject_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --key-type\n");
        return cli_error_invalid_argument;
    }
    if (opts->issuer_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --parent-key-type\n");
        return cli_error_invalid_argument;
    }
    if (opts->certificate_format == n20_certificate_format_none_e) {
        fprintf(stderr, "Invalid or missing --certificate-format\n");
        return cli_error_invalid_argument;
    }

    // Parse challenge if provided
    err = parse_hex_to_slice(
        &request->payload.issue_eca_cert.challenge, opts->challenge, "challenge");
    if (err != cli_error_ok) return err;

    // Build parent path
    for (size_t i = 0; i < opts->parent_path.count; ++i) {
        if (!add_parent_path_decoded(&request->payload.issue_eca_cert.parent_path,
                                     opts->parent_path.elements[i])) {
            fprintf(stderr, "Failed to add parent path element\n");
            return cli_error_invalid_argument;
        }
    }

    // Parse parent path hex strings
    for (size_t i = 0; i < request->payload.issue_eca_cert.parent_path.length; ++i) {
        err = parse_hex_to_slice(
            (n20_slice_t *)&request->payload.issue_eca_cert.parent_path.decoded[i],
            (char const *)request->payload.issue_eca_cert.parent_path.decoded[i].buffer,
            "parent path element");
        if (err != cli_error_ok) return err;
    }

    return cli_error_ok;
}

// Initialize ECA EE cert request from parsed options
static cli_error_t init_eca_ee_cert_request(n20_msg_request_t *request,
                                            parsed_options_t const *opts,
                                            uint8_t key_usage[2]) {
    cli_error_t err;

    request->request_type = n20_msg_request_type_issue_eca_ee_cert_e;
    request->payload.issue_eca_ee_cert.subject_key_type = opts->subject_key_type;
    request->payload.issue_eca_ee_cert.issuer_key_type = opts->issuer_key_type;
    request->payload.issue_eca_ee_cert.certificate_format = opts->certificate_format;

    // Validate required fields
    if (opts->subject_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --key-type\n");
        return cli_error_invalid_argument;
    }
    if (opts->issuer_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --parent-key-type\n");
        return cli_error_invalid_argument;
    }
    if (opts->certificate_format == n20_certificate_format_none_e) {
        fprintf(stderr, "Invalid or missing --certificate-format\n");
        return cli_error_invalid_argument;
    }

    // Set name
    if (opts->ee_fields.name) {
        request->payload.issue_eca_ee_cert.name.buffer = opts->ee_fields.name;
        request->payload.issue_eca_ee_cert.name.size = strlen(opts->ee_fields.name);
    }

    // Parse key usage
    if (opts->ee_fields.key_usage_str) {
        parse_key_usage(opts->ee_fields.key_usage_str, key_usage);
        request->payload.issue_eca_ee_cert.key_usage.buffer = key_usage;
        request->payload.issue_eca_ee_cert.key_usage.size = 2;
    }

    // Parse challenge if provided
    err = parse_hex_to_slice(
        &request->payload.issue_eca_ee_cert.challenge, opts->challenge, "challenge");
    if (err != cli_error_ok) return err;

    // Build parent path
    for (size_t i = 0; i < opts->parent_path.count; ++i) {
        if (!add_parent_path_decoded(&request->payload.issue_eca_ee_cert.parent_path,
                                     opts->parent_path.elements[i])) {
            fprintf(stderr, "Failed to add parent path element\n");
            return cli_error_invalid_argument;
        }
    }

    // Parse parent path hex strings
    for (size_t i = 0; i < request->payload.issue_eca_ee_cert.parent_path.length; ++i) {
        err = parse_hex_to_slice(
            (n20_slice_t *)&request->payload.issue_eca_ee_cert.parent_path.decoded[i],
            (char const *)request->payload.issue_eca_ee_cert.parent_path.decoded[i].buffer,
            "parent path element");
        if (err != cli_error_ok) return err;
    }

    return cli_error_ok;
}

// Initialize ECA EE sign request from parsed options
static cli_error_t init_eca_ee_sign_request(n20_msg_request_t *request,
                                            parsed_options_t const *opts,
                                            uint8_t key_usage[2]) {
    cli_error_t err;

    request->request_type = n20_msg_request_type_eca_ee_sign_e;
    request->payload.eca_ee_sign.subject_key_type = opts->subject_key_type;

    // Validate required fields
    if (opts->subject_key_type == n20_crypto_key_type_none_e) {
        fprintf(stderr, "Invalid or missing --key-type\n");
        return cli_error_invalid_argument;
    }

    // Set name
    if (opts->ee_fields.name) {
        request->payload.eca_ee_sign.name.buffer = opts->ee_fields.name;
        request->payload.eca_ee_sign.name.size = strlen(opts->ee_fields.name);
    }

    // Parse key usage
    if (opts->ee_fields.key_usage_str) {
        parse_key_usage(opts->ee_fields.key_usage_str, key_usage);
        request->payload.eca_ee_sign.key_usage.buffer = key_usage;
        request->payload.eca_ee_sign.key_usage.size = 2;
    }

    // Parse message
    err = parse_hex_to_slice(&request->payload.eca_ee_sign.message, opts->message, "message");
    if (err != cli_error_ok) return err;

    // Build parent path
    for (size_t i = 0; i < opts->parent_path.count; ++i) {
        if (!add_parent_path_decoded(&request->payload.eca_ee_sign.parent_path,
                                     opts->parent_path.elements[i])) {
            fprintf(stderr, "Failed to add parent path element\n");
            return cli_error_invalid_argument;
        }
    }

    // Parse parent path hex strings
    for (size_t i = 0; i < request->payload.eca_ee_sign.parent_path.length; ++i) {
        err = parse_hex_to_slice(
            (n20_slice_t *)&request->payload.eca_ee_sign.parent_path.decoded[i],
            (char const *)request->payload.eca_ee_sign.parent_path.decoded[i].buffer,
            "parent path element");
        if (err != cli_error_ok) return err;
    }

    return cli_error_ok;
}

// Helper to write binary data to file or print as hex
static cli_error_t output_binary_data(uint8_t const *data,
                                      size_t size,
                                      char const *output_file,
                                      char const *data_type) {
    if (output_file) {
        FILE *file = fopen(output_file, "wb");
        if (!file) {
            perror("fopen");
            return cli_error_io;
        }
        size_t written = fwrite(data, 1, size, file);
        if (written != size) {
            fprintf(stderr, "Failed to write full %s to file\n", data_type);
            fclose(file);
            return cli_error_io;
        }
        fclose(file);
        printf("%s written to %s\n", data_type, output_file);
    } else {
        printf("%s data: ", data_type);
        for (size_t i = 0; i < size; ++i) {
            printf("%02x", data[i]);
        }
        printf("\n");
    }
    return cli_error_ok;
}

// Handle promote response
static cli_error_t handle_promote_response(n20_slice_t response_slice) {
    n20_msg_error_response_t response;
    n20_error_t n20_err = n20_msg_error_response_read(&response, response_slice);
    if (n20_err != n20_error_ok_e) {
        fprintf(stderr,
                "Failed to read promote response. libnat20 error: %d (0x%x)\n",
                n20_err,
                n20_err);
        return cli_error_libnat20;
    }
    if (response.error_code != n20_error_ok_e) {
        fprintf(stderr,
                "Promote request failed. Server returned libnat20 error: %d (0x%x)\n",
                response.error_code,
                response.error_code);
        return cli_error_server;
    }
    printf("Promote request successful\n");
    return cli_error_ok;
}

// Handle certificate response (common for cdi-cert, eca-cert, eca-ee-cert)
static cli_error_t handle_cert_response(n20_slice_t response_slice,
                                        char const *output_file,
                                        char const *cert_type_name,
                                        bool print_debug) {
    if (print_debug) {
        printf("Raw response (%zu bytes): ", response_slice.size);
        size_t preview_len = response_slice.size < 32 ? response_slice.size : 32;
        for (size_t i = 0; i < preview_len; ++i) {
            printf("%02x", response_slice.buffer[i]);
        }
        if (response_slice.size > 32) printf("...");
        printf("\n");
    }

    n20_msg_issue_cert_response_t response;
    n20_error_t n20_err = n20_msg_issue_cert_response_read(&response, response_slice);
    if (n20_err != n20_error_ok_e) {
        fprintf(stderr,
                "Failed to read %s response. libnat20 error: %d (0x%x)\n",
                cert_type_name,
                n20_err,
                n20_err);
        return cli_error_libnat20;
    }
    if (response.error_code != n20_error_ok_e) {
        fprintf(stderr,
                "%s request failed. Server returned libnat20 error: %d (0x%x)\n",
                cert_type_name,
                response.error_code,
                response.error_code);
        return cli_error_server;
    }
    printf("%s request successful, certificate size: %zu\n",
           cert_type_name,
           response.certificate.size);

    return output_binary_data(
        response.certificate.buffer, response.certificate.size, output_file, "Certificate");
}

// Handle CDI cert response (includes compressed input output)
static cli_error_t handle_cdi_cert_response(n20_slice_t response_slice,
                                            char const *output_file,
                                            n20_open_dice_input_t const *next_context) {
    cli_error_t err = handle_cert_response(response_slice, output_file, "CDI cert", true);
    if (err != cli_error_ok) return err;

    // Compute and output compressed input
    n20_compressed_input_t next_compressed_input;
    n20_open_dice_cert_info_t cert_info;
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input = *next_context;

    n20_crypto_digest_context_t *digest_ctx = NULL;

    n20_error_t n20_err = n20_crypto_nat20_open(&digest_ctx);
    if (n20_err != n20_error_ok_e) {
        fprintf(
            stderr, "Failed to open digest context. libnat20 error: %d (0x%x)\n", n20_err, n20_err);
        return cli_error_libnat20;
    }

    n20_err = n20_compress_input(digest_ctx, &cert_info, next_compressed_input);
    n20_crypto_nat20_close(digest_ctx);
    if (n20_err != n20_error_ok_e) {
        fprintf(stderr, "Failed to compress input. libnat20 error: %d (0x%x)\n", n20_err, n20_err);
        return cli_error_libnat20;
    }

    printf("Compressed input: ");
    for (size_t i = 0; i < sizeof(next_compressed_input); ++i) {
        printf("%02x", next_compressed_input[i]);
    }
    printf("\n");

    return cli_error_ok;
}

// Handle ECA EE sign response
static cli_error_t handle_eca_ee_sign_response(n20_slice_t response_slice,
                                               char const *output_file) {
    // First try to read as an error response
    n20_msg_error_response_t error_response;
    n20_error_t n20_err = n20_msg_error_response_read(&error_response, response_slice);
    if (n20_err == n20_error_ok_e && error_response.error_code != n20_error_ok_e) {
        fprintf(stderr,
                "ECA sign request failed. Server returned libnat20 error: %d (0x%x)\n",
                error_response.error_code,
                error_response.error_code);
        return cli_error_server;
    }

    // If not an error response, try to read as sign response
    n20_msg_eca_ee_sign_response_t response;
    n20_err = n20_msg_eca_ee_sign_response_read(&response, response_slice);
    if (n20_err != n20_error_ok_e) {
        fprintf(stderr,
                "Failed to read ECA sign response. libnat20 error: %d (0x%x)\n",
                n20_err,
                n20_err);
        return cli_error_libnat20;
    }
    if (response.error_code != n20_error_ok_e) {
        fprintf(stderr,
                "ECA sign request failed. Server returned libnat20 error: %d (0x%x)\n",
                response.error_code,
                response.error_code);
        return cli_error_server;
    }
    printf("ECA sign request successful, signature size: %zu\n", response.signature.size);

    return output_binary_data(
        response.signature.buffer, response.signature.size, output_file, "Signature");
}

int main(int argc, char *argv[]) {
    int err = EXIT_FAILURE;
    int dice_dev_fd = -1;
    // Stage 1: Parse command options
    parsed_options_t opts = {
        .request_type = n20_msg_request_type_none_e,
        .subject_key_type = n20_crypto_key_type_none_e,
        .issuer_key_type = n20_crypto_key_type_none_e,
        .certificate_format = n20_certificate_format_none_e,
        .cdi_fields = {.mode = n20_open_dice_mode_not_configured_e},
    };

    if (parse_command_options(argc, argv, &opts) != 0) {
        print_usage(argv[0]);
        goto out;
    }

    // Stage 2: Determine command
    if (optind >= argc) {
        fprintf(stderr, "No command specified\n");
        print_usage(argv[0]);
        goto out;
    }

    int request_type = parse_request_type(argv[optind]);
    if (request_type == n20_msg_request_type_none_e) {
        fprintf(stderr, "Unknown command: %s\n", argv[optind]);
        print_usage(argv[0]);
        goto out;
    }

    opts.request_type = request_type;

    // Stage 3: Initialize request from parsed options
    n20_msg_request_t request = {0};
    uint8_t key_usage[2] = {0};
    cli_error_t cli_err = cli_error_ok;

    switch (request_type) {
        case n20_msg_request_type_promote_e:
            cli_err = init_promote_request(&request, &opts);
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            cli_err = init_cdi_cert_request(&request, &opts);
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            cli_err = init_eca_cert_request(&request, &opts);
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            cli_err = init_eca_ee_cert_request(&request, &opts, key_usage);
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            cli_err = init_eca_ee_sign_request(&request, &opts, key_usage);
            break;
        default:
            fprintf(stderr, "Unsupported request type: %d\n", request_type);
            print_usage(argv[0]);
            goto out;
    }

    if (cli_err != cli_error_ok) {
        fprintf(stderr, "Failed to initialize request. CLI error: %d\n", cli_err);
        print_usage(argv[0]);
        goto out;
    }

    uint8_t msg_buffer[1024];

    size_t msg_size = sizeof(msg_buffer);

    n20_error_t n20_err = n20_msg_request_write(&request, msg_buffer, &msg_size);
    if (n20_err != n20_error_ok_e) {
        fprintf(stderr, "Failed to write request. libnat20 error: %d (0x%x)\n", n20_err, n20_err);
        print_usage(argv[0]);
        goto out;
    }

    clean_up_request(&request);

    dice_dev_fd = open("/dev/nat200", O_RDWR);
    if (dice_dev_fd < 0) {
        perror("open");
        goto out;
    }

    ssize_t bytes_written =
        write(dice_dev_fd, msg_buffer + (sizeof(msg_buffer) - msg_size), msg_size);
    if (bytes_written < 0) {
        perror("write");
        goto out;
    }

    uint8_t response_buffer[1024];

    ssize_t bytes_received = read(dice_dev_fd, response_buffer, sizeof(response_buffer));
    if (bytes_received < 0) {
        perror("read");
        goto out;
    }

    printf("Bytes written: %zd, Bytes received: %zd\n", bytes_written, bytes_received);

    n20_slice_t response_slice = {
        .buffer = response_buffer,
        .size = (size_t)bytes_received,
    };

    // Handle response based on request type
    switch (request.request_type) {
        case n20_msg_request_type_promote_e:
            cli_err = handle_promote_response(response_slice);
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            cli_err = handle_cdi_cert_response(
                response_slice, opts.output_file, &request.payload.issue_cdi_cert.next_context);
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            cli_err = handle_cert_response(response_slice, opts.output_file, "ECA cert", true);
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            cli_err =
                handle_cert_response(response_slice, opts.output_file, "ECA end-entity cert", true);
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            cli_err = handle_eca_ee_sign_response(response_slice, opts.output_file);
            break;
        default:
            fprintf(stderr, "Unknown request type in response\n");
            goto out;
    }

    if (cli_err != cli_error_ok) {
        goto out;
    }

    err = 0;
out:
    if (dice_dev_fd >= 0) {
        close(dice_dev_fd);
    }
    cleanup_parsed_options(&opts);
    return err;
}
