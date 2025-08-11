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
    if ((unsigned int)cbor_type > 7) {
        /* 0xf7 is the encoding of the special value "undefined". */
        cbor_type = n20_cbor_type_simple_float_e;
        n = N20_SIMPLE_UNDEFINED;
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
