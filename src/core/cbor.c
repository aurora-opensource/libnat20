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
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stddef.h>
#include <stdint.h>

void n20_cbor_write_header(n20_stream_t *const s, n20_cbor_type_t cbor_type, uint64_t n) {
    uint8_t header = (uint8_t)(cbor_type << 5);

    size_t value_size = 0;

    if (n < 24) {
        header |= (uint8_t)n;
        n20_stream_prepend(s, &header, /*src_len=*/1);
        return;
    } else if (n < 0x100) {
        header |= 24;
        value_size = 1;
    } else if (n < 0x10000) {
        header |= 25;
        value_size = 2;
    } else if (n < 0x100000000) {
        header |= 26;
        value_size = 4;
    } else {
        header |= 27;
        value_size = 8;
    }

    for (size_t i = 0; i < value_size; i++) {
        uint8_t byte = (uint8_t)(n >> (i * 8));
        n20_stream_prepend(s, &byte, /*src_len=*/1);
    }

    n20_stream_prepend(s, &header, /*src_len=*/1);
}

void n20_cbor_write_null(n20_stream_t *const s) {
    n20_cbor_write_header(s, n20_cbor_type_simple_float_e, 22);
}

void n20_cbor_write_bool(n20_stream_t *const s, bool const b) {
    n20_cbor_write_header(s, n20_cbor_type_simple_float_e, b ? 21 : 20);
}

void n20_cbor_write_tag(n20_stream_t *const s, uint64_t const tag) {
    n20_cbor_write_header(s, n20_cbor_type_tag_e, tag);
}

void n20_cbor_write_uint(n20_stream_t *const s, uint64_t const n) {
    n20_cbor_write_header(s, n20_cbor_type_uint_e, n);
}

void n20_cbor_write_int(n20_stream_t *const s, int64_t const n) {
    if (n >= 0) {
        n20_cbor_write_uint(s, (uint64_t)n);
    } else {
        n20_cbor_write_header(s, n20_cbor_type_nint_e, (uint64_t)(-n - 1));
    }
}

void n20_cbor_write_byte_string(n20_stream_t *const s, n20_slice_t const bytes) {
    if (bytes.size > 0 && bytes.buffer == NULL) {
        n20_cbor_write_null(s);
        return;
    }

    n20_stream_prepend(s, bytes.buffer, bytes.size);
    n20_cbor_write_header(s, n20_cbor_type_bytes_e, bytes.size);
}

void n20_cbor_write_text_string(n20_stream_t *const s, n20_string_slice_t const text) {
    if (text.size > 0 && text.buffer == NULL) {
        n20_cbor_write_null(s);
        return;
    }

    n20_stream_prepend(s, (uint8_t const *)text.buffer, text.size);
    n20_cbor_write_header(s, n20_cbor_type_string_e, text.size);
}

void n20_cbor_write_array_header(n20_stream_t *const s, size_t const len) {
    n20_cbor_write_header(s, n20_cbor_type_array_e, len);
}

void n20_cbor_write_map_header(n20_stream_t *const s, size_t const len) {
    n20_cbor_write_header(s, n20_cbor_type_map_e, len);
}

bool n20_read_cbor_header(n20_istream_t *const s, n20_cbor_type_t *const type, uint64_t *const n) {
    uint8_t header = 0;
    if (!n20_istream_get(s, &header)) {
        return false;
    }

    *type = (n20_cbor_type_t)(header >> 5);
    uint8_t additional_info = header & 0x1f;

    if (additional_info < 24 || additional_info > 27) {
        *n = additional_info;
        return true;
    }

    *n = 0;

    uint8_t additional_bytes = 1 << (additional_info - 24);
    for (int i = 0; i < additional_bytes; i++) {
        uint8_t byte = 0;
        if (!n20_istream_get(s, &byte)) {
            return false;
        }
        *n = (*n << 8) | byte;
    }

    return true;
}

bool n20_iterate_cbor_item(n20_istream_t *const s) {
    n20_cbor_type_t type = n20_cbor_type_none_e;
    uint64_t n = 0;
    if (!n20_read_cbor_header(s, &type, &n)) {
        return false;
    }

    switch (type) {
        case n20_cbor_type_array_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_iterate_cbor_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_map_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_iterate_cbor_item(s)) {
                    return false;
                }
                if (!n20_iterate_cbor_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_bytes_e:
        case n20_cbor_type_string_e: {
            uint8_t const *slice = n20_istream_get_slice(s, n);
            if (slice == NULL) {
                return false;
            }
            break;
        }
        default:
            break;
    }

    return true;
}

bool n20_cbor_skip_item(n20_istream_t *const s) {
    n20_cbor_type_t type = n20_cbor_type_none_e;
    uint64_t n = 0;
    if (!n20_read_cbor_header(s, &type, &n)) {
        return false;
    }

    switch (type) {
        case n20_cbor_type_array_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_cbor_skip_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_map_e:
            for (size_t i = 0; i < n; i++) {
                if (!n20_cbor_skip_item(s)) {
                    return false;
                }
                if (!n20_cbor_skip_item(s)) {
                    return false;
                }
            }
            break;
        case n20_cbor_type_bytes_e:
        case n20_cbor_type_string_e: {
            uint8_t const *slice = n20_istream_get_slice(s, n);
            if (slice == NULL) {
                return false;
            }
            break;
        }
        case n20_cbor_type_tag_e:
            return n20_cbor_skip_item(s);  // Skip the tag and the item it refers to.
        default:
            break;
    }

    return true;
}

