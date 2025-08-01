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
#include <nat20/service/service.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <sys/types.h>

n20_error_t n20_msg_read_map_with_int_key(n20_istream_t *istream,
                                          n20_error_t (*cb)(n20_istream_t *istream,
                                                            int64_t key,
                                                            void *context),
                                          void *context) {
    n20_cbor_type_t cbor_type;
    uint64_t map_size;
    uint64_t cbor_value;

    if (!n20_read_cbor_header(istream, &cbor_type, &map_size) || cbor_type != n20_cbor_type_map_e) {
        // The map must be a CBOR map.
        return n20_error_unexpected_message_structure_e;
    }

    for (uint64_t i = 0; i < map_size; ++i) {
        if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
            (cbor_type != n20_cbor_type_uint_e && cbor_type != n20_cbor_type_nint_e)) {
            // The key must be an integer (either unsigned or negative).
            n20_cbor_skip_item(istream);
            continue;
        }
        int64_t key =
            cbor_type == n20_cbor_type_nint_e ? -1 - (int64_t)cbor_value : (int64_t)cbor_value;
        n20_error_t error = cb(istream, key, context);
        if (error != n20_error_ok_e) {
            // If the callback returns an error, propagate it.
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
        case 1:  // compressed_context
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The compressed context must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            request->compressed_context.size = cbor_value;
            request->compressed_context.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
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
        case 1:  // code_hash
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The code hash must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->code_hash.size = cbor_value;
            input->code_hash.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 2:  // code_descriptor
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The code descriptor must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->code_descriptor.size = cbor_value;
            input->code_descriptor.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 3:  // configuration_hash
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The configuration hash must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->configuration_hash.size = cbor_value;
            input->configuration_hash.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 4:  // configuration_descriptor
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The configuration descriptor must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->configuration_descriptor.size = cbor_value;
            input->configuration_descriptor.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 5:  // authority_hash
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The authority hash must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->authority_hash.size = cbor_value;
            input->authority_hash.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 6:  // authority_descriptor
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The authority descriptor must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->authority_descriptor.size = cbor_value;
            input->authority_descriptor.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 7:  // mode
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The mode must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            if (cbor_value >= n20_open_dice_mode_max_e) {
                // The mode value is out of range.
                return n20_error_unexpected_message_structure_e;
            }
            input->mode = (n20_open_dice_mode_t)cbor_value;
            break;
        case 8:  // hidden
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The hidden field must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            input->hidden.size = cbor_value;
            input->hidden.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 9:  // profile_name
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_string_e) {
                // The profile name must be a string.
                return n20_error_unexpected_message_structure_e;
            }
            input->profile_name.size = cbor_value;
            input->profile_name.buffer = (char const *)n20_istream_get_slice(istream, cbor_value);
            break;
        default:
            // Skip unknown keys.
            n20_cbor_skip_item(istream);
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

    n20_msg_read_map_with_int_key(istream, n20_msg_open_dice_input_read_cb, input);

    return n20_error_ok_e;
}

n20_error_t n20_msg_compressed_context_array_read(n20_istream_t *istream,
                                                  n20_slice_t *compressed_context,
                                                  size_t *path_length_in_out) {
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
        cbor_type != n20_cbor_type_array_e) {
        // The compressed context must be an array.
        return n20_error_unexpected_message_structure_e;
    }

    if (cbor_value > *path_length_in_out) {
        // The path length exceeds the maximum allowed.
        return n20_error_parent_path_size_exceeds_max_e;
    }

    *path_length_in_out = cbor_value;

    for (uint64_t i = 0; i < *path_length_in_out; ++i) {
        if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
            cbor_type != n20_cbor_type_bytes_e) {
            // Each item in the array must be a byte string.
            return n20_error_unexpected_message_structure_e;
        }

        compressed_context[i].size = cbor_value;
        compressed_context[i].buffer = n20_istream_get_slice(istream, cbor_value);
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
        case 1:  // parent_key_type
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The parent key type must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->parent_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case 2:  // key_type
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The key type must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case 3:  // context
            error = n20_msg_open_dice_input_read(istream, &request->next_context);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case 4:  // parent path
            request->parent_path_length = N20_STATELESS_MAX_PATH_LENGTH;
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case 5: // certificate format
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The certificate format must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->certificate_format = (n20_certificate_format_t)cbor_value;
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
                                               : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_cdi_cert_request_read(n20_istream_t *istream,
                                                n20_msg_issue_cdi_cert_request_t *request) {

    request->parent_path_length = 0;
    request->parent_key_type = n20_crypto_key_type_none_e;
    request->key_type = n20_crypto_key_type_none_e;
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
        case 1:  // parent_key_type
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The parent key type must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->parent_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case 2:  // key_type
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The key type must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case 3:  // parent path
            request->parent_path_length = N20_STATELESS_MAX_PATH_LENGTH;
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case 4: // certificate format
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The certificate format must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->certificate_format = (n20_certificate_format_t)cbor_value;
            break;
        case 5: // context
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_string_e) {
                // The context must be a text string.
                return n20_error_unexpected_message_structure_e;
            }
            request->context.size = cbor_value;
            request->context.buffer = (char const *)n20_istream_get_slice(istream, cbor_value);
            break;
        case 6: // key_usage
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The key usage must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            request->key_usage.size = cbor_value;
            request->key_usage.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 7: // challenge
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The challenge must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            request->challenge.size = cbor_value;
            request->challenge.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
                                               : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_eca_cert_request_read(n20_istream_t *istream,
                                                n20_msg_issue_eca_cert_request_t *request) {

    request->parent_path_length = 0;
    request->parent_key_type = n20_crypto_key_type_none_e;
    request->key_type = n20_crypto_key_type_none_e;
    request->certificate_format = n20_certificate_format_none_e;
    request->context = N20_STR_NULL;
    request->key_usage = N20_SLICE_NULL;
    request->challenge = N20_SLICE_NULL;

    return n20_msg_read_map_with_int_key(istream, n20_msg_issue_eca_cert_request_read_cb, request);
}

n20_error_t n20_msg_eca_sign_request_read_cb(n20_istream_t *istream,
                                             int64_t key,
                                             void *context) {
    n20_msg_eca_sign_request_t *request = (n20_msg_eca_sign_request_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;
    n20_error_t error;

    switch (key) {
        case 1:  // parent_key_type
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The parent key type must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->parent_key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case 2:  // key_type
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The key type must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            request->key_type = (n20_crypto_key_type_t)cbor_value;
            break;
        case 3:  // parent_path
            error = n20_msg_compressed_context_array_read(
                istream, request->parent_path, &request->parent_path_length);
            if (error != n20_error_ok_e) {
                return error;
            }
            break;
        case 5: // context
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_string_e) {
                // The context must be a text string.
                return n20_error_unexpected_message_structure_e;
            }
            request->context.size = cbor_value;
            request->context.buffer = (char const *)n20_istream_get_slice(istream, cbor_value);
            break;
        case 6: // key_usage
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The key usage must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            request->key_usage.size = cbor_value;
            request->key_usage.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 7: // challenge
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The challenge must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            request->challenge.size = cbor_value;
            request->challenge.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        case 8: // message
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The message must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            request->message.size = cbor_value;
            request->message.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
                                               : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_eca_sign_request_read(n20_istream_t *istream,
                                          n20_msg_eca_sign_request_t *request) {

    request->parent_path_length = 0;
    request->parent_key_type = n20_crypto_key_type_none_e;
    request->key_type = n20_crypto_key_type_none_e;
    request->context = N20_STR_NULL;
    request->key_usage = N20_SLICE_NULL;
    request->challenge = N20_SLICE_NULL;
    request->message = N20_SLICE_NULL;

    return n20_msg_read_map_with_int_key(istream, n20_msg_eca_sign_request_read_cb, request);
}

n20_error_t n20_msg_request_read(n20_msg_request_t *request, n20_slice_t const msg_buffer) {

    n20_istream_t istream;
    n20_istream_init(&istream, msg_buffer.buffer, msg_buffer.size);

    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    if (!n20_read_cbor_header(&istream, &cbor_type, &cbor_value)) {
        return n20_error_unexpected_message_structure_e;
    }

    if (cbor_type != n20_cbor_type_array_e || cbor_value != 2) {
        // The request must be an array of length 2.
        return n20_error_unexpected_message_structure_e;
    }

    // Read the first element, which is the request type.
    if (!n20_read_cbor_header(&istream, &cbor_type, &cbor_value) ||
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
        case n20_msg_request_type_eca_sign_e:
            return n20_msg_eca_sign_request_read(&istream, &request->payload.eca_sign);
        default:
            return n20_error_unrecognized_request_type_e;
    }
}

void n20_msg_promote_request_write(n20_stream_t *stream, n20_msg_promote_request_t const *request) {
    n20_cbor_write_byte_string(stream, request->compressed_context);
    n20_cbor_write_int(stream, 1);         // Key for compressed_context
    n20_cbor_write_map_header(stream, 1);  // The request is a map with one key-value pair.
}

void n20_msg_open_dice_input_write(n20_stream_t *stream, n20_open_dice_input_t const *input) {
    int pairs = 0;

    if (input->profile_name.size != 0) {
        n20_cbor_write_text_string(stream, input->profile_name);
        n20_cbor_write_int(stream, 9);  // Key for profile_name
        ++pairs;
    }

    if (input->hidden.size != 0) {
        n20_cbor_write_byte_string(stream, input->hidden);
        n20_cbor_write_int(stream, 8);  // Key for hidden
        ++pairs;
    }

    if (input->mode != n20_open_dice_mode_not_configured_e) {
        n20_cbor_write_int(stream, (uint64_t)input->mode);
        n20_cbor_write_int(stream, 7);  // Key for mode
        ++pairs;
    }

    if (input->authority_descriptor.size != 0) {
        n20_cbor_write_byte_string(stream, input->authority_descriptor);
        n20_cbor_write_int(stream, 6);  // Key for authority_descriptor
        ++pairs;
    }
    if (input->authority_hash.size != 0) {
        n20_cbor_write_byte_string(stream, input->authority_hash);
        n20_cbor_write_int(stream, 5);  // Key for authority_hash
        ++pairs;
    }
    if (input->configuration_descriptor.size != 0) {
        n20_cbor_write_byte_string(stream, input->configuration_descriptor);
        n20_cbor_write_int(stream, 4);  // Key for configuration_descriptor
        ++pairs;
    }
    if (input->configuration_hash.size != 0) {
        n20_cbor_write_byte_string(stream, input->configuration_hash);
        n20_cbor_write_int(stream, 3);  // Key for configuration_hash
        ++pairs;
    }
    if (input->code_descriptor.size != 0) {
        n20_cbor_write_byte_string(stream, input->code_descriptor);
        n20_cbor_write_int(stream, 2);  // Key for code_descriptor
        ++pairs;
    }

    if (input->code_hash.size != 0) {
        n20_cbor_write_byte_string(stream, input->code_hash);
        n20_cbor_write_int(stream, 1);  // Key for code_hash
        ++pairs;
    }
    n20_cbor_write_map_header(stream, pairs);  // The request is a map with nine key-value pairs.
}

void n20_msg_issue_cdi_cert_request_write(n20_stream_t *s,
                                          n20_msg_issue_cdi_cert_request_t const *request) {
    int pairs = 4;

    n20_cbor_write_int(s, (uint64_t)request->certificate_format);  // certificate format
    n20_cbor_write_int(s, 5);  // Key for certificate format

    if (request->parent_path_length > 0) {
        size_t i = request->parent_path_length;
        do {
            --i;
            n20_cbor_write_byte_string(s, request->parent_path[i]);
        } while (i != 0);
        n20_cbor_write_array_header(s, request->parent_path_length);
        n20_cbor_write_int(s, 4);  // Key for parent_path
        ++pairs;
    }

    n20_msg_open_dice_input_write(s, &request->next_context);
    n20_cbor_write_int(s, 3);  // Key for dice input

    n20_cbor_write_int(s, (uint64_t)request->key_type);  // key type
    n20_cbor_write_int(s, 2);                            // Key for key_type

    n20_cbor_write_int(s, (uint64_t)request->parent_key_type);  // parent key type
    n20_cbor_write_int(s, 1);                                   // Key for parent_key_type
    n20_cbor_write_map_header(s, pairs);  // The request is a map with four key-value pairs.
}

void n20_msg_issue_eca_cert_request_write(n20_stream_t *s,
                                          n20_msg_issue_eca_cert_request_t const *request) {
    int pairs = 3;

    // Count additional optional fields
    if (request->challenge.size > 0) ++pairs;
    if (request->key_usage.size > 0) ++pairs;
    if (request->context.size > 0) ++pairs;
    if (request->parent_path_length > 0) ++pairs;

    // Write fields in reverse order (because of reverse stream)
    if (request->challenge.size > 0) {
        n20_cbor_write_byte_string(s, request->challenge);
        n20_cbor_write_int(s, 7);  // Key for challenge
    }

    if (request->key_usage.size > 0) {
        n20_cbor_write_byte_string(s, request->key_usage);
        n20_cbor_write_int(s, 6);  // Key for key_usage
    }

    if (request->context.size > 0) {
        n20_cbor_write_text_string(s, request->context);
        n20_cbor_write_int(s, 5);  // Key for context
    }

    n20_cbor_write_int(s, (uint64_t)request->certificate_format);  // certificate format
    n20_cbor_write_int(s, 4);  // Key for certificate format

    if (request->parent_path_length > 0) {
        size_t i = request->parent_path_length;
        do {
            --i;
            n20_cbor_write_byte_string(s, request->parent_path[i]);
        } while (i != 0);
        n20_cbor_write_array_header(s, request->parent_path_length);
        n20_cbor_write_int(s, 3);  // Key for parent_path
    }

    n20_cbor_write_int(s, (uint64_t)request->key_type);  // key type
    n20_cbor_write_int(s, 2);                            // Key for key_type

    n20_cbor_write_int(s, (uint64_t)request->parent_key_type);  // parent key type
    n20_cbor_write_int(s, 1);                                   // Key for parent_key_type
    n20_cbor_write_map_header(s, pairs);  // The request is a map with pairs key-value pairs.
}

void n20_msg_eca_sign_request_write(n20_stream_t *s,
                                   n20_msg_eca_sign_request_t const *request) {
    int pairs = 3;  // parent_key_type, key_type, message

    // Count additional optional fields
    if (request->challenge.size > 0) ++pairs;
    if (request->key_usage.size > 0) ++pairs;
    if (request->context.size > 0) ++pairs;
    if (request->parent_path_length > 0) ++pairs;

    // Write fields in reverse order (because of reverse stream)
    n20_cbor_write_byte_string(s, request->message);
    n20_cbor_write_int(s, 8);  // Key for message
    
    if (request->challenge.size > 0) {
        n20_cbor_write_byte_string(s, request->challenge);
        n20_cbor_write_int(s, 7);  // Key for challenge
    }

    if (request->key_usage.size > 0) {
        n20_cbor_write_byte_string(s, request->key_usage);
        n20_cbor_write_int(s, 6);  // Key for key_usage
    }

    if (request->context.size > 0) {
        n20_cbor_write_text_string(s, request->context);
        n20_cbor_write_int(s, 5);  // Key for context
    }

    if (request->parent_path_length > 0) {
        size_t i = request->parent_path_length;
        do {
            --i;
            n20_cbor_write_byte_string(s, request->parent_path[i]);
        } while (i != 0);
        n20_cbor_write_array_header(s, request->parent_path_length);
        n20_cbor_write_int(s, 3);  // Key for parent_path
    }

    n20_cbor_write_int(s, (uint64_t)request->key_type);  // key type
    n20_cbor_write_int(s, 2);                            // Key for key_type

    n20_cbor_write_int(s, (uint64_t)request->parent_key_type);  // parent key type
    n20_cbor_write_int(s, 1);                                   // Key for parent_key_type
    n20_cbor_write_map_header(s, pairs);  // The request is a map with pairs key-value pairs.
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
        case n20_msg_request_type_eca_sign_e:
            n20_msg_eca_sign_request_write(&stream, &request->payload.eca_sign);
            break;
        default:
            return n20_error_unrecognized_request_type_e;
    }

    n20_cbor_write_uint(&stream, (uint64_t)request->request_type);
    n20_cbor_write_array_header(&stream, 2);  // The request is an array of two elements.

    if (n20_stream_has_write_position_overflow(&stream)) {
        return n20_error_write_position_overflow_e;
    }

    *buffer_size = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}

n20_error_t n20_msg_issue_cdi_cert_response_read_cb(n20_istream_t *istream,
                                                    int64_t key,
                                                    void *context) {
    n20_msg_issue_cdi_cert_response_t *response = (n20_msg_issue_cdi_cert_response_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case 1:  // error_code
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The error code must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            response->error_code = (n20_error_t)cbor_value;
            break;
        case 2:  // certificate
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The certificate must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            response->certificate.size = cbor_value;
            response->certificate.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
                                               : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_issue_cdi_cert_response_read(n20_msg_issue_cdi_cert_response_t *response,
                                                 n20_slice_t buffer) {
    n20_istream_t istream;
    n20_istream_init(&istream, buffer.buffer, buffer.size);

    response->error_code = n20_error_ok_e;
    response->certificate.size = 0;
    response->certificate.buffer = NULL;

    return n20_msg_read_map_with_int_key(
        &istream, n20_msg_issue_cdi_cert_response_read_cb, response);
}

n20_error_t n20_msg_issue_cdi_cert_response_write(n20_msg_issue_cdi_cert_response_t const *response,
                                                  uint8_t *buffer,
                                                  size_t *const buffer_size_in_out) {
    n20_stream_t stream;

    if (buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_stream_init(&stream, buffer, *buffer_size_in_out);

    if (response->error_code != n20_error_ok_e) {
        // If there is an error, we only write the error code and skip the certificate.
        n20_cbor_write_uint(&stream, (uint64_t)response->error_code);
        n20_cbor_write_uint(&stream, 1);  // Key for error_code
    } else {
        n20_cbor_write_byte_string(&stream, response->certificate);
        n20_cbor_write_uint(&stream, 2);  // Key for certificate
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
        case 1:  // error_code
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The error code must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            response->error_code = (n20_error_t)cbor_value;
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
                                               : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_error_response_read(n20_msg_error_response_t *response,
                                        n20_slice_t const buffer) {
    n20_istream_t istream;
    n20_istream_init(&istream, buffer.buffer, buffer.size);

    response->error_code = n20_error_ok_e;

    return n20_msg_read_map_with_int_key(&istream, n20_msg_error_response_read_cb, response);
}

n20_error_t n20_msg_error_response_write(n20_msg_error_response_t const *response,
                                         uint8_t *buffer,
                                         size_t *const buffer_size_in_out) {
    n20_stream_t stream;
    int pairs = 0;

    if (buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_stream_init(&stream, buffer, *buffer_size_in_out);

    if (response->error_code != n20_error_ok_e) {
        // If there is an error, we only write the error code and skip the certificate.
        n20_cbor_write_uint(&stream, (uint64_t)response->error_code);
        n20_cbor_write_uint(&stream, 1);  // Key for error_code
        pairs = 1;
    }

    n20_cbor_write_map_header(&stream, pairs);

    if (n20_stream_has_write_position_overflow(&stream)) {
        return n20_error_write_position_overflow_e;
    }

    *buffer_size_in_out = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}


n20_error_t n20_msg_eca_sign_response_read_cb(n20_istream_t *istream,
                                              int64_t key,
                                              void *context) {
    n20_msg_eca_sign_response_t *response = (n20_msg_eca_sign_response_t *)context;
    n20_cbor_type_t cbor_type;
    uint64_t cbor_value;

    switch (key) {
        case 1:  // error_code
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_uint_e) {
                // The error code must be an unsigned integer.
                return n20_error_unexpected_message_structure_e;
            }
            response->error_code = (n20_error_t)cbor_value;
            break;
        case 2:  // signature
            if (!n20_read_cbor_header(istream, &cbor_type, &cbor_value) ||
                cbor_type != n20_cbor_type_bytes_e) {
                // The signature must be a byte string.
                return n20_error_unexpected_message_structure_e;
            }
            response->signature.size = cbor_value;
            response->signature.buffer = n20_istream_get_slice(istream, cbor_value);
            break;
        default:
            // Skip unknown keys.
            return n20_cbor_skip_item(istream) ? n20_error_ok_e
                                               : n20_error_unexpected_message_structure_e;
    }

    return n20_error_ok_e;
}

n20_error_t n20_msg_eca_sign_response_read(n20_msg_eca_sign_response_t *response,
                                           n20_slice_t buffer) {
    n20_istream_t istream;
    n20_istream_init(&istream, buffer.buffer, buffer.size);

    response->error_code = n20_error_ok_e;
    response->signature.size = 0;
    response->signature.buffer = NULL;

    return n20_msg_read_map_with_int_key(
        &istream, n20_msg_eca_sign_response_read_cb, response);
}

n20_error_t n20_msg_eca_sign_response_write(n20_msg_eca_sign_response_t const *response,
                                            uint8_t *buffer,
                                            size_t *const buffer_size_in_out) {
    n20_stream_t stream;

    if (buffer_size_in_out == NULL) {
        return n20_error_unexpected_null_buffer_size_e;
    }

    n20_stream_init(&stream, buffer, *buffer_size_in_out);

    if (response->error_code != n20_error_ok_e) {
        // If there is an error, we only write the error code and skip the signature.
        n20_cbor_write_uint(&stream, (uint64_t)response->error_code);
        n20_cbor_write_uint(&stream, 1);  // Key for error_code
    } else {
        n20_cbor_write_byte_string(&stream, response->signature);
        n20_cbor_write_uint(&stream, 2);  // Key for signature
    }

    n20_cbor_write_map_header(&stream, 1);

    if (n20_stream_has_write_position_overflow(&stream)) {
        return n20_error_write_position_overflow_e;
    }

    *buffer_size_in_out = n20_stream_byte_count(&stream);

    return n20_stream_has_buffer_overflow(&stream) ? n20_error_insufficient_buffer_size_e
                                                   : n20_error_ok_e;
}
