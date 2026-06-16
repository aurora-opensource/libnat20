/*
 * Copyright 2025 Aurora Operations, Inc.
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

#include <nat20/cbor.h>
#include <nat20/limits.h>
#include <nat20/stream.h>
#include <nat20/types.h>

void n20_cbor_write_header(n20_stream_t *const s, n20_cbor_type_t cbor_type, uint64_t n) {
    switch (cbor_type) {
        case n20_cbor_type_uint_e:
        case n20_cbor_type_nint_e:
        case n20_cbor_type_bytes_e:
        case n20_cbor_type_string_e:
        case n20_cbor_type_array_e:
        case n20_cbor_type_map_e:
        case n20_cbor_type_tag_e:
        case n20_cbor_type_simple_float_e:
            break;
        case n20_cbor_type_indefinite_bytes_e:
        case n20_cbor_type_indefinite_string_e:
        case n20_cbor_type_indefinite_array_e:
        case n20_cbor_type_indefinite_map_e:
        case n20_cbor_type_indefinite_break_e: {
            cbor_type = (n20_cbor_type_t)(cbor_type - 0x100);
            uint8_t header = (uint8_t)(cbor_type << 5) | 31;
            n20_stream_prepend(s, &header, /*src_len=*/1);
            return;
        }
        default:
            /* Invalid types are encoded as "undefined". */
            cbor_type = n20_cbor_type_simple_float_e;
            n = N20_SIMPLE_UNDEFINED;
            break;
    }

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
    n20_cbor_write_header(s, n20_cbor_type_simple_float_e, N20_SIMPLE_NULL);
}

void n20_cbor_write_bool(n20_stream_t *const s, bool const b) {
    n20_cbor_write_header(s, n20_cbor_type_simple_float_e, b ? N20_SIMPLE_TRUE : N20_SIMPLE_FALSE);
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

bool n20_cbor_read_header(n20_istream_t *const s, n20_cbor_type_t *const type, uint64_t *const n) {
    uint8_t header = 0;
    if (!n20_istream_get(s, &header)) {
        return false;
    }

    *type = (n20_cbor_type_t)(header >> 5);
    uint8_t additional_info = header & 0x1f;

    if (additional_info == 31) {
        switch (*type) {
            case n20_cbor_type_array_e:
            case n20_cbor_type_map_e:
            case n20_cbor_type_bytes_e:
            case n20_cbor_type_string_e:
            case n20_cbor_type_simple_float_e:
                /* Indefinite length encoding is encoded in the ninth bit of the type. */
                *type = (n20_cbor_type_t)(*type + 0x100);
                *n = 0;
                return true;
            default:
                /* Additional info 31 is only valid for arrays, maps, byte strings, and text
                 * strings. and in the simple/float type denoting the end of indefinite length
                 * items. */
                return false;
        }
    }

    if (additional_info > 27) {
        /* Reserved additional info values (28-30). Indefinite length
         * encoding (31) is handled above. */
        return false;
    }

    if (additional_info < 24) {
        /* 0-23 are the "simple" values. */
        *n = additional_info;
        return true;
    }

    *n = 0;

    uint8_t additional_bytes = 1 << (additional_info - 24);
    for (uint8_t i = 0; i < additional_bytes; i++) {
        uint8_t byte = 0;
        if (!n20_istream_get(s, &byte)) {
            return false;
        }
        *n = (*n << 8) | byte;
    }

    return true;
}

typedef enum n20_cbor_read_skip_item_result_s {
    n20_cbor_read_skip_item_ok_e,
    n20_cbor_read_skip_item_error_e,
    n20_cbor_read_skip_item_break_e,
} n20_cbor_read_skip_item_result_t;

static n20_cbor_read_skip_item_result_t n20_cbor_read_skip_item_internal(n20_istream_t *const s);

static n20_cbor_read_skip_item_result_t n20_cbor_read_skip_item_map_element_internal(
    n20_istream_t *const s) {
    n20_cbor_read_skip_item_result_t result = n20_cbor_read_skip_item_internal(s);
    if (result != n20_cbor_read_skip_item_ok_e) {
        return result;
    }
    if (n20_cbor_read_skip_item_internal(s) != n20_cbor_read_skip_item_ok_e) {
        /* If the second item is a terminator or if we ran out of buffer
         * we consider it an error. */
        return n20_cbor_read_skip_item_error_e;
    }
    return n20_cbor_read_skip_item_ok_e;
}

static n20_cbor_read_skip_item_result_t n20_cbor_read_skip_item_stringish_chunk_internal(
    n20_istream_t *const s, bool string) {
    n20_cbor_type_t type;
    uint64_t n;
    if (!n20_cbor_read_header(s, &type, &n)) {
        return n20_cbor_read_skip_item_error_e;
    }
    if (type == n20_cbor_type_indefinite_break_e) {
        return n20_cbor_read_skip_item_break_e;
    }
    if ((string && type != n20_cbor_type_string_e) || (!string && type != n20_cbor_type_bytes_e)) {
        return n20_cbor_read_skip_item_error_e; /* Not a valid expected stringish chunk. */
    }
    if (n > SIZE_MAX) {
        /* Prevent uncaught truncation. */
        return n20_cbor_read_skip_item_error_e;
    }
    if (!n20_istream_get_slice(s, NULL, n)) {
        return n20_cbor_read_skip_item_error_e;
    }
    return n20_cbor_read_skip_item_ok_e;
}

static n20_cbor_read_skip_item_result_t n20_cbor_read_skip_item_internal(n20_istream_t *const s) {
    n20_cbor_type_t type = n20_cbor_type_none_e;
    uint64_t n = 0;
    if (!n20_cbor_read_header(s, &type, &n)) {
        return n20_cbor_read_skip_item_error_e;
    }

    switch (type) {
        case n20_cbor_type_array_e:
            if (n > SIZE_MAX) {
                /* Prevent overflow in the loop counter. */
                return n20_cbor_read_skip_item_error_e;
            }
            for (size_t i = 0; i < n; i++) {
                if (n20_cbor_read_skip_item_internal(s) != n20_cbor_read_skip_item_ok_e) {
                    return n20_cbor_read_skip_item_error_e;
                }
            }
            break;
        case n20_cbor_type_map_e:
            if (n > SIZE_MAX) {
                /* Prevent overflow in the loop counter. */
                return n20_cbor_read_skip_item_error_e;
            }
            for (size_t i = 0; i < n; i++) {
                if (n20_cbor_read_skip_item_internal(s) != n20_cbor_read_skip_item_ok_e) {
                    return n20_cbor_read_skip_item_error_e;
                }
                if (n20_cbor_read_skip_item_internal(s) != n20_cbor_read_skip_item_ok_e) {
                    return n20_cbor_read_skip_item_error_e;
                }
            }
            break;
        case n20_cbor_type_bytes_e:
        case n20_cbor_type_string_e: {
            if (n > SIZE_MAX) {
                /* Prevent uncaught truncation. */
                return n20_cbor_read_skip_item_error_e;
            }
            if (!n20_istream_get_slice(s, NULL, n)) {
                return n20_cbor_read_skip_item_error_e;
            }
            break;
        }
        case n20_cbor_type_tag_e:
            /* Skip the tag and the item it refers to. */
            return n20_cbor_read_skip_item_internal(s);
        case n20_cbor_type_indefinite_bytes_e:
        case n20_cbor_type_indefinite_string_e: {
            n20_cbor_read_skip_item_result_t result;
            do {
                result = n20_cbor_read_skip_item_stringish_chunk_internal(
                    s, type == n20_cbor_type_indefinite_string_e);
                if (result == n20_cbor_read_skip_item_error_e) {
                    return n20_cbor_read_skip_item_error_e;
                }
            } while (result != n20_cbor_read_skip_item_break_e);
            break;
        }
        case n20_cbor_type_indefinite_array_e: {
            n20_cbor_read_skip_item_result_t result;
            do {
                result = n20_cbor_read_skip_item_internal(s);
                if (result == n20_cbor_read_skip_item_error_e) {
                    return n20_cbor_read_skip_item_error_e;
                }
            } while (result != n20_cbor_read_skip_item_break_e);
            break;
        }
        case n20_cbor_type_indefinite_map_e: {
            n20_cbor_read_skip_item_result_t result;
            do {
                result = n20_cbor_read_skip_item_map_element_internal(s);
                if (result == n20_cbor_read_skip_item_error_e) {
                    return n20_cbor_read_skip_item_error_e;
                }
            } while (result != n20_cbor_read_skip_item_break_e);
            break;
        }
        case n20_cbor_type_indefinite_break_e:
            return n20_cbor_read_skip_item_break_e;
        default:
            /* Simple values and integers have no additional data to skip. */
            break;
    }

    return n20_cbor_read_skip_item_ok_e;
}

bool n20_cbor_read_skip_item(n20_istream_t *const s) {
    return n20_cbor_read_skip_item_internal(s) == n20_cbor_read_skip_item_ok_e;
}
