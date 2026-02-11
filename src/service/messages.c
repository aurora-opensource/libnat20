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
#include <nat20/error.h>
#include <nat20/service/messages.h>
#include <nat20/stream.h>
#include <nat20/types.h>

#define N20_MSG_LABEL_ISSUER_KEY_TYPE 1
#define N20_MSG_LABEL_SUBJECT_KEY_TYPE 2
#define N20_MSG_LABEL_OPEN_DICE_INPUT 3
#define N20_MSG_LABEL_PARENT_PATH 4
#define N20_MSG_LABEL_CERTIFICATE_FORMAT 5
#define N20_MSG_LABEL_NAME 6
#define N20_MSG_LABEL_KEY_USAGE 7
#define N20_MSG_LABEL_CHALLENGE 8
#define N20_MSG_LABEL_MESSAGE 9
#define N20_MSG_LABEL_CODE_HASH 10
#define N20_MSG_LABEL_CODE_DESCRIPTOR 11
#define N20_MSG_LABEL_CONFIGURATION_HASH 12
#define N20_MSG_LABEL_CONFIGURATION_DESCRIPTOR 13
#define N20_MSG_LABEL_AUTHORITY_HASH 14
#define N20_MSG_LABEL_AUTHORITY_DESCRIPTOR 15
#define N20_MSG_LABEL_MODE 16
#define N20_MSG_LABEL_HIDDEN 17
#define N20_MSG_LABEL_PROFILE_NAME 18
#define N20_MSG_LABEL_COMPRESSED_CONTEXT 19
#define N20_MSG_LABEL_ERROR_CODE 20
#define N20_MSG_LABEL_CERTIFICATE 21
#define N20_MSG_LABEL_SIGNATURE 22

n20_error_t n20_msg_read_map_with_int_key(n20_istream_t *istream,
                                          n20_error_t (*cb)(n20_istream_t *istream,
                                                            int64_t key,
                                                            void *context),
                                          void *context) {
    n20_cbor_type_t cbor_type;
    uint64_t map_size;
    uint64_t cbor_value;

    if (!n20_cbor_read_header(istream, &cbor_type, &map_size) || cbor_type != n20_cbor_type_map_e) {
        /* The type must be a CBOR map. */
        return n20_error_unexpected_message_structure_e;
    }

    for (uint64_t i = 0; i < map_size; ++i) {
        if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value)) {
            return n20_error_unexpected_message_structure_e;
        }
        if ((cbor_type != n20_cbor_type_uint_e && cbor_type != n20_cbor_type_nint_e)) {
            /* The key must be an integer (either unsigned or negative). */
            if (!n20_cbor_read_skip_item(istream)) {
                return n20_error_unexpected_message_structure_e;
            }
            continue;
        }
        int64_t key =
            cbor_type == n20_cbor_type_nint_e ? -1 - (int64_t)cbor_value : (int64_t)cbor_value;
        n20_error_t error = cb(istream, key, context);
        if (error != n20_error_ok_e) {
            /* If the callback returns an error, propagate it. */
            return error;
        }
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_promote_request_read_cb(n20_istream_t *istream, int64_t key, void *context) {
    n20_msg_promote_request_t *request = (n20_msg_promote_request_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case N20_MSG_LABEL_COMPRESSED_CONTEXT:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The compressed context must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &request->compressed_context, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_promote_request_read(n20_istream_t *istream,
                                         n20_msg_promote_request_t *request) {
    return n20_msg_read_map_with_int_key(istream, n20_msg_promote_request_read_cb, request);
}

n20_error_t n20_msg_open_dice_input_read_cb(n20_istream_t *istream, int64_t key, void *context) {
    n20_open_dice_input_t *input = (n20_open_dice_input_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case N20_MSG_LABEL_CODE_HASH:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The code hash must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->code_hash, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_CODE_DESCRIPTOR:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The code descriptor must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->code_descriptor, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_CONFIGURATION_HASH:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The configuration hash must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->configuration_hash, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_CONFIGURATION_DESCRIPTOR:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The configuration descriptor must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->configuration_descriptor, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_AUTHORITY_HASH:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The authority hash must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->authority_hash, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_AUTHORITY_DESCRIPTOR:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The authority descriptor must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->authority_descriptor, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_MODE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The mode must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            if (cbor_value > n20_open_dice_mode_recovery_e) {
                /* The mode value is out of range. */
                return n20_error_unexpected_message_structure_e;
            }
            input->mode = (n20_open_dice_modes_t)cbor_value;
            break;
        case N20_MSG_LABEL_HIDDEN:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The hidden field must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &input->hidden, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_PROFILE_NAME:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_string_e) {
                /* The profile name must be a string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_string_slice(istream, &input->profile_name, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            if (!n20_cbor_read_skip_item(istream)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
    }
    return n20_error_ok_e;
}

n20_error_t n20_msg_open_dice_input_read(n20_istream_t *istream, void *context) {
    n20_open_dice_input_t *input = (n20_open_dice_input_t *)context;

    *input = (n20_open_dice_input_t){
        .code_hash = N20_SLICE_NULL,
        .code_descriptor = N20_SLICE_NULL,
        .configuration_hash = N20_SLICE_NULL,
        .configuration_descriptor = N20_SLICE_NULL,
        .authority_hash = N20_SLICE_NULL,
        .authority_descriptor = N20_SLICE_NULL,
        .mode = n20_open_dice_mode_not_configured_e,
        .hidden = N20_SLICE_NULL,
        .profile_name = N20_STR_NULL,
    };

    return n20_msg_read_map_with_int_key(istream, n20_msg_open_dice_input_read_cb, input);
}

static void n20_msg_compressed_context_array_write(
    n20_stream_t *s,
    n20_slice_t const *const compressed_context_array,
    size_t const compressed_context_array_size) {
    size_t i = compressed_context_array_size;
    do {
        --i;
        n20_cbor_write_byte_string(s, compressed_context_array[i]);
    } while (i != 0);
    n20_cbor_write_array_header(s, compressed_context_array_size);
    n20_cbor_write_int(s, N20_MSG_LABEL_PARENT_PATH);
}

n20_error_t n20_msg_compressed_context_array_read(n20_istream_t *istream,
                                                  n20_slice_t *compressed_context,
                                                  size_t *path_length_in_out) {
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
        cbor_type != n20_cbor_type_array_e) {
        /* The compressed context must be an array. */
        return n20_error_unexpected_message_structure_e;
    }

    if (cbor_value > *path_length_in_out) {
        /* The path length exceeds the maximum allowed. */
        return n20_error_parent_path_size_exceeds_max_e;
    }

    *path_length_in_out = cbor_value;

    for (uint64_t i = 0; i < *path_length_in_out; ++i) {
        if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
            cbor_type != n20_cbor_type_bytes_e) {
            /* Each item in the array must be a byte string. */
            return n20_error_unexpected_message_structure_e;
        }
        if (!n20_istream_get_slice(istream, &compressed_context[i], cbor_value)) {
            return n20_error_unexpected_message_structure_e;
        }
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_cdi_cert_request_read_cb(n20_istream_t *istream,
                                                   int64_t key,
                                                   void *context) {
    n20_msg_issue_cdi_cert_request_t *request = (n20_msg_issue_cdi_cert_request_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    n20_error_t error;

    switch (key) {
        case N20_MSG_LABEL_ISSUER_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The issuer key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->issuer_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_SUBJECT_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->subject_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_OPEN_DICE_INPUT:
            error = n20_msg_open_dice_input_read(istream, &request->next_context);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case N20_MSG_LABEL_PARENT_PATH:
            request->parent_path_length = N20_STATELESS_MAX_PATH_LENGTH;
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case N20_MSG_LABEL_CERTIFICATE_FORMAT:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The certificate format must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->certificate_format = (n20_certificate_format_t)cbor_value;
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_cdi_cert_request_read(n20_istream_t *istream,
                                                n20_msg_issue_cdi_cert_request_t *request) {
    request->parent_path_length = 0;
    request->issuer_key_type = n20_crypto_key_type_none_e;
    request->subject_key_type = n20_crypto_key_type_none_e;
    request->next_context = (n20_open_dice_input_t){0};

    return n20_msg_read_map_with_int_key(istream, n20_msg_issue_cdi_cert_request_read_cb, request);
}

n20_error_t n20_msg_issue_eca_cert_request_read_cb(n20_istream_t *istream,
                                                   int64_t key,
                                                   void *context) {
    n20_msg_issue_eca_cert_request_t *request = (n20_msg_issue_eca_cert_request_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    n20_error_t error;

    switch (key) {
        case N20_MSG_LABEL_ISSUER_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The issuer key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->issuer_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_SUBJECT_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->subject_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_PARENT_PATH:
            request->parent_path_length = N20_STATELESS_MAX_PATH_LENGTH;
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case N20_MSG_LABEL_CERTIFICATE_FORMAT:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The certificate format must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->certificate_format = (n20_certificate_format_t)cbor_value;
            break;
        case N20_MSG_LABEL_CHALLENGE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The challenge must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &request->challenge, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_eca_cert_request_read(n20_istream_t *istream,
                                                n20_msg_issue_eca_cert_request_t *request) {
    request->parent_path_length = 0;
    request->issuer_key_type = n20_crypto_key_type_none_e;
    request->subject_key_type = n20_crypto_key_type_none_e;
    request->certificate_format = n20_certificate_format_none_e;
    request->challenge = N20_SLICE_NULL;

    return n20_msg_read_map_with_int_key(istream, n20_msg_issue_eca_cert_request_read_cb, request);
}

n20_error_t n20_msg_issue_eca_ee_cert_request_read_cb(n20_istream_t *istream,
                                                      int64_t key,
                                                      void *context) {
    n20_msg_issue_eca_ee_cert_request_t *request = (n20_msg_issue_eca_ee_cert_request_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    n20_error_t error;

    switch (key) {
        case N20_MSG_LABEL_ISSUER_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The issuer key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->issuer_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_SUBJECT_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->subject_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_PARENT_PATH:
            request->parent_path_length = N20_STATELESS_MAX_PATH_LENGTH;
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case N20_MSG_LABEL_CERTIFICATE_FORMAT:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The certificate format must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->certificate_format = (n20_certificate_format_t)cbor_value;
            break;
        case N20_MSG_LABEL_NAME:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_string_e) {
                /* The name must be a text string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_string_slice(istream, &request->name, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_KEY_USAGE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The key usage must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &request->key_usage, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_CHALLENGE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The challenge must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &request->challenge, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_eca_ee_cert_request_read(n20_istream_t *istream,
                                                   n20_msg_issue_eca_ee_cert_request_t *request) {
    request->parent_path_length = 0;
    request->issuer_key_type = n20_crypto_key_type_none_e;
    request->subject_key_type = n20_crypto_key_type_none_e;
    request->certificate_format = n20_certificate_format_none_e;
    request->name = N20_STR_NULL;
    request->key_usage = N20_SLICE_NULL;
    request->challenge = N20_SLICE_NULL;

    return n20_msg_read_map_with_int_key(
        istream, n20_msg_issue_eca_ee_cert_request_read_cb, request);
}

n20_error_t n20_msg_eca_ee_sign_request_read_cb(n20_istream_t *istream,
                                                int64_t key,
                                                void *context) {
    n20_msg_eca_ee_sign_request_t *request = (n20_msg_eca_ee_sign_request_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    n20_error_t error;

    switch (key) {
        case N20_MSG_LABEL_SUBJECT_KEY_TYPE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The key type must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            request->subject_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case N20_MSG_LABEL_PARENT_PATH:
            request->parent_path_length = N20_STATELESS_MAX_PATH_LENGTH;
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case N20_MSG_LABEL_NAME:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_string_e) {
                /* The name must be a text string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_string_slice(istream, &request->name, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_KEY_USAGE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The key usage must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &request->key_usage, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        case N20_MSG_LABEL_MESSAGE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The message must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &request->message, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_eca_ee_sign_request_read(n20_istream_t *istream,
                                             n20_msg_eca_ee_sign_request_t *request) {
    request->parent_path_length = 0;
    request->subject_key_type = n20_crypto_key_type_none_e;
    request->name = N20_STR_NULL;
    request->key_usage = N20_SLICE_NULL;
    request->message = N20_SLICE_NULL;

    return n20_msg_read_map_with_int_key(istream, n20_msg_eca_ee_sign_request_read_cb, request);
}

n20_error_t n20_msg_request_read(n20_msg_request_t *request, n20_slice_t const msg_buffer) {
    if (request == NULL) {
        return n20_error_unexpected_null_request_e;
    }

    n20_istream_t istream;
    n20_istream_init(&istream, msg_buffer.buffer, msg_buffer.size);

    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    if (!n20_cbor_read_header(&istream, &cbor_type, &cbor_value)) {
        return n20_error_unexpected_message_structure_e;
    }

    if (cbor_type != n20_cbor_type_array_e || cbor_value != 2) {
        /* The request must be an array of length 2. */
        return n20_error_unexpected_message_structure_e;
    }

    /* Read the first element, which is the request type. */
    if (!n20_cbor_read_header(&istream, &cbor_type, &cbor_value) ||
        cbor_type != n20_cbor_type_uint_e) {
        return n20_error_unexpected_message_structure_e;
    }

    request->request_type = (n20_msg_request_type_t)cbor_value;

    switch (cbor_value) {
        case n20_msg_request_type_promote_e:
            return n20_msg_promote_request_read(&istream, &request->payload.promote);
        case n20_msg_request_type_issue_cdi_cert_e:
            return n20_msg_issue_cdi_cert_request_read(&istream, &request->payload.issue_cdi_cert);
        case n20_msg_request_type_issue_eca_cert_e:
            return n20_msg_issue_eca_cert_request_read(&istream, &request->payload.issue_eca_cert);
        case n20_msg_request_type_issue_eca_ee_cert_e:
            return n20_msg_issue_eca_ee_cert_request_read(&istream,
                                                          &request->payload.issue_eca_ee_cert);
        case n20_msg_request_type_eca_ee_sign_e:
            return n20_msg_eca_ee_sign_request_read(&istream, &request->payload.eca_ee_sign);
        default:
            break;
    }
    return n20_error_request_type_unknown_e;
}

void n20_msg_promote_request_write(n20_stream_t *stream, n20_msg_promote_request_t const *request) {
    n20_cbor_write_byte_string(stream, request->compressed_context);
    n20_cbor_write_int(stream, N20_MSG_LABEL_COMPRESSED_CONTEXT);

    n20_cbor_write_map_header(stream, 1);
}

void n20_msg_open_dice_input_write(n20_stream_t *stream, n20_open_dice_input_t const *input) {
    int pairs = 0;

    if (input->profile_name.size != 0) {
        n20_cbor_write_text_string(stream, input->profile_name);
        n20_cbor_write_int(stream, N20_MSG_LABEL_PROFILE_NAME);
        ++pairs;
    }

    if (input->hidden.size != 0) {
        n20_cbor_write_byte_string(stream, input->hidden);
        n20_cbor_write_int(stream, N20_MSG_LABEL_HIDDEN);
        ++pairs;
    }

    if (input->mode != n20_open_dice_mode_not_configured_e) {
        n20_cbor_write_int(stream, (uint64_t)input->mode);
        n20_cbor_write_int(stream, N20_MSG_LABEL_MODE);
        ++pairs;
    }

    if (input->authority_descriptor.size != 0) {
        n20_cbor_write_byte_string(stream, input->authority_descriptor);
        n20_cbor_write_int(stream, N20_MSG_LABEL_AUTHORITY_DESCRIPTOR);
        ++pairs;
    }

    if (input->authority_hash.size != 0) {
        n20_cbor_write_byte_string(stream, input->authority_hash);
        n20_cbor_write_int(stream, N20_MSG_LABEL_AUTHORITY_HASH);
        ++pairs;
    }

    if (input->configuration_descriptor.size != 0) {
        n20_cbor_write_byte_string(stream, input->configuration_descriptor);
        n20_cbor_write_int(stream, N20_MSG_LABEL_CONFIGURATION_DESCRIPTOR);
        ++pairs;
    }

    if (input->configuration_hash.size != 0) {
        n20_cbor_write_byte_string(stream, input->configuration_hash);
        n20_cbor_write_int(stream, N20_MSG_LABEL_CONFIGURATION_HASH);
        ++pairs;
    }

    if (input->code_descriptor.size != 0) {
        n20_cbor_write_byte_string(stream, input->code_descriptor);
        n20_cbor_write_int(stream, N20_MSG_LABEL_CODE_DESCRIPTOR);
        ++pairs;
    }

    if (input->code_hash.size != 0) {
        n20_cbor_write_byte_string(stream, input->code_hash);
        n20_cbor_write_int(stream, N20_MSG_LABEL_CODE_HASH);
        ++pairs;
    }
    n20_cbor_write_map_header(stream, pairs);
}

void n20_msg_issue_cdi_cert_request_write(n20_stream_t *s,
                                          n20_msg_issue_cdi_cert_request_t const *request) {
    int pairs = 4;

    n20_cbor_write_int(s, (uint64_t)request->certificate_format);
    n20_cbor_write_int(s, N20_MSG_LABEL_CERTIFICATE_FORMAT);

    if (request->parent_path_length > 0) {
        n20_msg_compressed_context_array_write(
            s, request->parent_path, request->parent_path_length);
        ++pairs;
    }

    n20_msg_open_dice_input_write(s, &request->next_context);
    n20_cbor_write_int(s, N20_MSG_LABEL_OPEN_DICE_INPUT);

    n20_cbor_write_int(s, (uint64_t)request->subject_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_SUBJECT_KEY_TYPE);

    n20_cbor_write_int(s, (uint64_t)request->issuer_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_ISSUER_KEY_TYPE);

    n20_cbor_write_map_header(s, pairs);
}

void n20_msg_issue_eca_cert_request_write(n20_stream_t *s,
                                          n20_msg_issue_eca_cert_request_t const *request) {
    int pairs = 3;

    /* Write fields in reverse order */
    if (request->challenge.size > 0) {
        n20_cbor_write_byte_string(s, request->challenge);
        n20_cbor_write_int(s, N20_MSG_LABEL_CHALLENGE);
        ++pairs;
    }

    n20_cbor_write_int(s, (uint64_t)request->certificate_format);
    n20_cbor_write_int(s, N20_MSG_LABEL_CERTIFICATE_FORMAT);

    if (request->parent_path_length > 0) {
        n20_msg_compressed_context_array_write(
            s, request->parent_path, request->parent_path_length);
        ++pairs;
    }

    n20_cbor_write_int(s, (uint64_t)request->subject_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_SUBJECT_KEY_TYPE);

    n20_cbor_write_int(s, (uint64_t)request->issuer_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_ISSUER_KEY_TYPE);

    n20_cbor_write_map_header(s, pairs);
}

void n20_msg_issue_eca_ee_cert_request_write(n20_stream_t *s,
                                             n20_msg_issue_eca_ee_cert_request_t const *request) {
    int pairs = 3;

    /* Write fields in reverse order */
    if (request->challenge.size > 0) {
        n20_cbor_write_byte_string(s, request->challenge);
        n20_cbor_write_int(s, N20_MSG_LABEL_CHALLENGE);
        ++pairs;
    }

    if (request->key_usage.size > 0) {
        n20_cbor_write_byte_string(s, request->key_usage);
        n20_cbor_write_int(s, N20_MSG_LABEL_KEY_USAGE);
        ++pairs;
    }

    if (request->name.size > 0) {
        n20_cbor_write_text_string(s, request->name);
        n20_cbor_write_int(s, N20_MSG_LABEL_NAME);
        ++pairs;
    }

    n20_cbor_write_int(s, (uint64_t)request->certificate_format);
    n20_cbor_write_int(s, N20_MSG_LABEL_CERTIFICATE_FORMAT);

    if (request->parent_path_length > 0) {
        n20_msg_compressed_context_array_write(
            s, request->parent_path, request->parent_path_length);
        ++pairs;
    }

    n20_cbor_write_int(s, (uint64_t)request->subject_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_SUBJECT_KEY_TYPE);

    n20_cbor_write_int(s, (uint64_t)request->issuer_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_ISSUER_KEY_TYPE);

    n20_cbor_write_map_header(s, pairs);
}

void n20_msg_eca_ee_sign_request_write(n20_stream_t *s,
                                       n20_msg_eca_ee_sign_request_t const *request) {
    int pairs = 2;

    /* Write fields in reverse order */
    n20_cbor_write_byte_string(s, request->message);
    n20_cbor_write_int(s, N20_MSG_LABEL_MESSAGE);

    if (request->key_usage.size > 0) {
        n20_cbor_write_byte_string(s, request->key_usage);
        n20_cbor_write_int(s, N20_MSG_LABEL_KEY_USAGE);
        ++pairs;
    }

    if (request->name.size > 0) {
        n20_cbor_write_text_string(s, request->name);
        n20_cbor_write_int(s, N20_MSG_LABEL_NAME);
        ++pairs;
    }

    if (request->parent_path_length > 0) {
        n20_msg_compressed_context_array_write(
            s, request->parent_path, request->parent_path_length);
        ++pairs;
    }

    n20_cbor_write_int(s, (uint64_t)request->subject_key_type);
    n20_cbor_write_int(s, N20_MSG_LABEL_SUBJECT_KEY_TYPE);

    n20_cbor_write_map_header(s, pairs);
}

n20_error_t n20_msg_request_write(n20_msg_request_t const *request,
                                  uint8_t *buffer,
                                  size_t *buffer_size) {
    n20_stream_t stream;
    n20_stream_init(&stream, buffer, *buffer_size);

    switch (request->request_type) {
        case n20_msg_request_type_promote_e:
            n20_msg_promote_request_write(&stream, &request->payload.promote);
            break;
        case n20_msg_request_type_issue_cdi_cert_e:
            n20_msg_issue_cdi_cert_request_write(&stream, &request->payload.issue_cdi_cert);
            break;
        case n20_msg_request_type_issue_eca_cert_e:
            n20_msg_issue_eca_cert_request_write(&stream, &request->payload.issue_eca_cert);
            break;
        case n20_msg_request_type_issue_eca_ee_cert_e:
            n20_msg_issue_eca_ee_cert_request_write(&stream, &request->payload.issue_eca_ee_cert);
            break;
        case n20_msg_request_type_eca_ee_sign_e:
            n20_msg_eca_ee_sign_request_write(&stream, &request->payload.eca_ee_sign);
            break;
        default:
            return n20_error_request_type_unknown_e;
    }

    n20_cbor_write_uint(&stream, (uint64_t)request->request_type);
    n20_cbor_write_array_header(&stream, 2);

    if (n20_stream_has_write_position_overflow(&stream)) {
        return n20_error_write_position_overflow_e;
    }

    *buffer_size = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}

n20_error_t n20_msg_issue_cert_response_read_cb(n20_istream_t *istream,
                                                int64_t key,
                                                void *context) {
    n20_msg_issue_cert_response_t *response = (n20_msg_issue_cert_response_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case N20_MSG_LABEL_ERROR_CODE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The error code must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            response->error_code = (n20_error_t)cbor_value;
            break;
        case N20_MSG_LABEL_CERTIFICATE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The certificate must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &response->certificate, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_cert_response_read(n20_msg_issue_cert_response_t *response,
                                             n20_slice_t buffer) {
    if (response == NULL) {
        return n20_error_unexpected_null_response_e;
    }

    n20_istream_t istream;
    n20_istream_init(&istream, buffer.buffer, buffer.size);

    response->error_code = n20_error_ok_e;
    response->certificate.size = 0;
    response->certificate.buffer = NULL;

    return n20_msg_read_map_with_int_key(&istream, n20_msg_issue_cert_response_read_cb, response);
}

n20_error_t n20_msg_issue_cert_response_write(n20_msg_issue_cert_response_t const *response,
                                              uint8_t *buffer,
                                              size_t *const buffer_size_in_out) {
    if (response == NULL) {
        return n20_error_unexpected_null_response_e;
    }

    n20_stream_t stream;

    if (buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_stream_init(&stream, buffer, *buffer_size_in_out);

    /* If there was an error, only the error code is written, and the
     * certificate otherwise. */
    if (response->error_code != n20_error_ok_e) {
        n20_cbor_write_uint(&stream, (uint64_t)response->error_code);
        n20_cbor_write_uint(&stream, N20_MSG_LABEL_ERROR_CODE);
    } else {
        n20_cbor_write_byte_string(&stream, response->certificate);
        n20_cbor_write_uint(&stream, N20_MSG_LABEL_CERTIFICATE);
    }

    n20_cbor_write_map_header(&stream, 1);

    if (n20_stream_has_write_position_overflow(&stream)) {
        return n20_error_write_position_overflow_e;
    }

    *buffer_size_in_out = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}

n20_error_t n20_msg_error_response_read_cb(n20_istream_t *istream, int64_t key, void *context) {
    n20_msg_error_response_t *response = (n20_msg_error_response_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case N20_MSG_LABEL_ERROR_CODE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The error code must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            response->error_code = (n20_error_t)cbor_value;
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_error_response_read(n20_msg_error_response_t *response,
                                        n20_slice_t const buffer) {
    if (response == NULL) {
        return n20_error_unexpected_null_response_e;
    }

    n20_istream_t istream;
    n20_istream_init(&istream, buffer.buffer, buffer.size);

    response->error_code = n20_error_ok_e;

    return n20_msg_read_map_with_int_key(&istream, n20_msg_error_response_read_cb, response);
}

n20_error_t n20_msg_error_response_write(n20_msg_error_response_t const *response,
                                         uint8_t *buffer,
                                         size_t *const buffer_size_in_out) {
    if (response == NULL) {
        return n20_error_unexpected_null_response_e;
    }

    n20_stream_t stream;
    int pairs = 0;

    if (buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_stream_init(&stream, buffer, *buffer_size_in_out);

    /* The error code is written only if there was an error. */
    if (response->error_code != n20_error_ok_e) {
        n20_cbor_write_uint(&stream, (uint64_t)response->error_code);
        n20_cbor_write_uint(&stream, N20_MSG_LABEL_ERROR_CODE);
        pairs = 1;
    }

    n20_cbor_write_map_header(&stream, pairs);

    if (n20_stream_has_write_position_overflow(&stream)) {
        /* This is not reachable, because there are no variable sized elements
         * in the input. */
        return n20_error_write_position_overflow_e;
    }

    *buffer_size_in_out = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}

n20_error_t n20_msg_eca_ee_sign_response_read_cb(n20_istream_t *istream,
                                                 int64_t key,
                                                 void *context) {
    n20_msg_eca_ee_sign_response_t *response = (n20_msg_eca_ee_sign_response_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case N20_MSG_LABEL_ERROR_CODE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                /* The error code must be an unsigned integer. */
                return n20_error_unexpected_message_structure_e;
            }
            response->error_code = (n20_error_t)cbor_value;
            break;
        case N20_MSG_LABEL_SIGNATURE:
            if (!n20_cbor_read_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                /* The signature must be a byte string. */
                return n20_error_unexpected_message_structure_e;
            }
            if (!n20_istream_get_slice(istream, &response->signature, cbor_value)) {
                return n20_error_unexpected_message_structure_e;
            }
            break;
        default:
            /* Skip unknown keys. */
            return n20_cbor_read_skip_item(istream) ? n20_error_ok_e
                                                    : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_eca_ee_sign_response_read(n20_msg_eca_ee_sign_response_t *response,
                                              n20_slice_t buffer) {
    if (response == NULL) {
        return n20_error_unexpected_null_response_e;
    }

    n20_istream_t istream;
    n20_istream_init(&istream, buffer.buffer, buffer.size);

    response->error_code = n20_error_ok_e;
    response->signature.size = 0;
    response->signature.buffer = NULL;

    return n20_msg_read_map_with_int_key(&istream, n20_msg_eca_ee_sign_response_read_cb, response);
}

n20_error_t n20_msg_eca_ee_sign_response_write(n20_msg_eca_ee_sign_response_t const *response,
                                               uint8_t *buffer,
                                               size_t *const buffer_size_in_out) {
    if (response == NULL) {
        return n20_error_unexpected_null_response_e;
    }

    n20_stream_t stream;

    if (buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_stream_init(&stream, buffer, *buffer_size_in_out);

    /* If there was an error, only the error code is written, and
     * the signature otherwise. */
    if (response->error_code != n20_error_ok_e) {
        n20_cbor_write_uint(&stream, (uint64_t)response->error_code);
        n20_cbor_write_uint(&stream, N20_MSG_LABEL_ERROR_CODE);
    } else {
        n20_cbor_write_byte_string(&stream, response->signature);
        n20_cbor_write_uint(&stream, N20_MSG_LABEL_SIGNATURE);
    }

    n20_cbor_write_map_header(&stream, 1);

    if (n20_stream_has_write_position_overflow(&stream)) {
        return n20_error_write_position_overflow_e;
    }

    *buffer_size_in_out = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}
