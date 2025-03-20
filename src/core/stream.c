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

#include <nat20/stream.h>
#include <nat20/types.h>
#include <string.h>

void n20_stream_init(n20_stream_t *s, uint8_t *const buffer, size_t buffer_size) {
    if (s == NULL) return;
    // If the buffer is NULL, the stream is marked bad.
    // This will essentially ignore the buffer size, because
    // begin or any pointer derived from it will never be
    // dereferenced. See n20_stream_prepend.
    s->buffer_overflow = buffer == NULL;
    s->begin = buffer;
    s->size = buffer == NULL ? 0 : buffer_size;
    s->write_position = 0;
    s->write_position_overflow = false;
}

bool n20_stream_has_buffer_overflow(n20_stream_t const *const s) {
    return (s == NULL) || s->buffer_overflow;
}

bool n20_stream_has_write_position_overflow(n20_stream_t const *const s) {
    return (s == NULL) || s->write_position_overflow;
}

// This function always returns the correct amount of data
// that was written to the stream even if the stream is bad.
// If the stream was bad it means that the stream ran out
// of buffer. In this case the return value of this function
// can be used to allocate a new buffer and initialize a new
// stream that will fit the data.
size_t n20_stream_byte_count(n20_stream_t const *const s) {
    return s != NULL ? s->write_position : 0;
}

// Returns a pointer to the beginning of the written region of the buffer.
// IMPORTANT it is only safe to dereference the returned pointer if
// n20_stream_has_buffer_overflow returns false. Also the access must be
// within the range [p, p + n20_stream_bytes_count) where p is the
// return value of this function.
uint8_t const *n20_stream_data(n20_stream_t const *const s) {
    return (s != NULL) ? (s->begin + (s->size - s->write_position)) : NULL;
}

// This function never fails. It might not write to the stream
// because it ran out of buffer, however, the stream position will
// be updated so that the required space can be read from the
// stream state later.
void n20_stream_prepend(n20_stream_t *const s, uint8_t const *const src, size_t const src_len) {
    if (s == NULL) return;
    // The write position shall be moved unconditionally,
    // because we use this to calculate the required size later.
    size_t old_pos = s->write_position;
    s->write_position += src_len;
    s->write_position_overflow = s->write_position_overflow || s->write_position < old_pos;
    // Mark the stream as bad if it was bad or if the next write.
    // will overflow the buffer.
    s->buffer_overflow =
        s->write_position_overflow || s->buffer_overflow || s->write_position > s->size;
    // If the stream is good we can write at the new position.
    if (!s->buffer_overflow) {
        memcpy(s->begin + (s->size - s->write_position), src, src_len);
    }
}

void n20_stream_put(n20_stream_t *const s, uint8_t const c) {
    n20_stream_prepend(s, &c, /*src_len=*/1);
}

void n20_istream_init(n20_istream_t *s, uint8_t const *buffer, size_t buffer_size) {
    if (s == NULL) return;
    s->begin = buffer;
    s->size = buffer_size;
    s->read_position = 0;
    s->buffer_underrun = false;
}

bool n20_istream_read(n20_istream_t *s, uint8_t *buffer, size_t buffer_size) {
    if (s == NULL || s->buffer_underrun) return false;
    size_t new_position = s->read_position + buffer_size;
    if (new_position > s->size || new_position < s->read_position) {
        s->read_position = s->size;
        s->buffer_underrun = true;
        return false;
    }
    memcpy(buffer, s->begin + s->read_position, buffer_size);
    s->read_position = new_position;
    return true;
}

bool n20_istream_get(n20_istream_t *s, uint8_t *c) {
    return n20_istream_read(s, c, /*buffer_size=*/1);
}

uint8_t const *n20_istream_get_slice(n20_istream_t *s, size_t size) {
    if (s == NULL || s->buffer_underrun) return NULL;
    size_t new_position = s->read_position + size;
    if (new_position > s->size || new_position < s->read_position) {
        s->read_position = s->size;
        s->buffer_underrun = true;
        return NULL;
    }
    uint8_t const *slice = s->begin + s->read_position;
    s->read_position = new_position;
    return slice;
}

bool n20_istream_has_buffer_underrun(n20_istream_t const *s) {
    return (s == NULL) || s->buffer_underrun;
}

size_t n20_istream_read_position(n20_istream_t const *s) {
    return (s == NULL) ? 0 : s->read_position;
}
