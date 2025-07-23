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

#pragma once

#include <nat20/stream.h>
#include <nat20/types.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file */

/**
 * @brief Represents the CBOR data types.
 *
 * This enumeration defines the major types of CBOR (Concise Binary Object Representation)
 * data items as specified in RFC 8949. Each type corresponds to a specific kind of data
 * that can be encoded in CBOR.
 *
 * @sa https://tools.ietf.org/html/rfc8949
 */
typedef enum n20_cbor_type_s {
    /**
     * @brief No value type.
     *
     * This is not a valid CBOR type. It is used to indicate that
     * no value is present.
     */
    n20_cbor_type_none_e = 0xFF,
    /**
     * @brief Unsigned integer type.
     *
     * Represents non-negative integer values.
     */
    n20_cbor_type_uint_e = 0,
    /**
     * @brief Negative integer type.
     *
     * Represents negative integer values. The value is encoded as the
     * absolute value minus one. E.g. -1 is encoded as 0, -2 as 1, etc.
     */
    n20_cbor_type_nint_e = 1,
    /**
     * @brief Byte string type.
     *
     * Represents a sequence of raw binary data.
     */
    n20_cbor_type_bytes_e = 2,
    /**
     * @brief Text string type.
     *
     * Represents a sequence of UTF-8 encoded characters.
     */
    n20_cbor_type_string_e = 3,
    /**
     * @brief Array type.
     *
     * Represents an ordered collection of CBOR data items.
     */
    n20_cbor_type_array_e = 4,
    /**
     * @brief Map type.
     *
     * Represents a collection of key-value pairs, where keys are unique.
     */
    n20_cbor_type_map_e = 5,
    /**
     * @brief Tag type.
     *
     * Represents a tagged data item, used to indicate semantic meaning.
     */
    n20_cbor_type_tag_e = 6,
    /**
     * @brief Simple value or floating-point type.
     *
     * Represents simple values (e.g., true, false, null) or floating-point numbers.
     */
    n20_cbor_type_simple_float_e = 7,
} n20_cbor_type_t;

/**
 * @brief Write a CBOR header to the given stream.
 *
 * This function writes the CBOR header for a given type and value to the stream.
 *
 * @param s The stream to write to.
 * @param type The CBOR type (see @ref n20_cbor_type_t).
 * @param value The value associated with the CBOR type.
 */
extern void n20_cbor_write_header(n20_stream_t *s, n20_cbor_type_t type, uint64_t value);

/** @brief Write a NULL to the stream in CBOR format.
 *
 * This function encodes the NULL value using the CBOR encoding rules.
 */
extern void n20_cbor_write_null(n20_stream_t *const s);

/** @brief Write a boolean to the stream in CBOR format.
 *
 *
 * This function encodes the boolean value using the CBOR encoding rules.
 * The value `true` is encoded as 21 and `false` as 20 with a major type of 7.
 *
 * @param s The stream to write to.
 * @param b The boolean value to write.
 */
extern void n20_cbor_write_bool(n20_stream_t *const s, bool const b);

/** @brief Write a CBOR tag to the stream.
 *
 * This function encodes a CBOR tag using the CBOR encoding rules.
 *
 * @param s The stream to write to.
 * @param tag The tag to write.
 */
extern void n20_cbor_write_tag(n20_stream_t *const s, uint64_t const tag);

/**
 * @brief Write an unsigned integer to the stream in CBOR format.
 *
 * This function encodes the unsigned integer using the CBOR encoding rules.
 * The result is a CBOR header with major type 0 (unsigned integer) and the
 * value of the integer.
 *
 * @param s The stream to write to.
 * @param value The unsigned integer to write.
 */
extern void n20_cbor_write_uint(n20_stream_t *s, uint64_t value);

/**
 * @brief Writes a signed integer to the stream in CBOR format.
 *
 * This function uses both major types 0 (unsigned integer) and 1 (negative integer)
 * depending on the sign of the integer. Positive integers are written using the
 * unsigned integer type, while negative integers are written using the negative
 * integer type.
 *
 * @param s The stream to write to.
 * @param value The signed integer to write.
 */
extern void n20_cbor_write_int(n20_stream_t *s, int64_t value);

/**
 * @brief Write a CBOR byte string to the given stream.
 *
 * This function encodes a byte string in CBOR format and writes it to the stream.
 * if @p data.size is not 0 but @p data.buffer is NULL, it writes a NULL value
 * instead.
 *
 * @param s The stream to write to.
 * @param data The byte string to encode.
 */
extern void n20_cbor_write_byte_string(n20_stream_t *s, n20_slice_t const data);

/**
 * @brief Write a CBOR text string to the given stream.
 *
 * This function encodes a text string in CBOR format and writes it to the stream.
 * if @p text.size is not 0 but @p text.buffer is NULL, it writes a NULL value
 * instead.
 *
 * @param s The stream to write to.
 * @param text The text string to encode.
 */
extern void n20_cbor_write_text_string(n20_stream_t *s, n20_string_slice_t const text);

/**
 * @brief Write a CBOR array header to the given stream.
 *
 * This function writes the CBOR header for an array to the stream.
 *
 * @param s The stream to write to.
 * @param size The number of elements in the array.
 */
extern void n20_cbor_write_array_header(n20_stream_t *s, size_t size);

/**
 * @brief Write a CBOR map header to the given stream.
 *
 * This function writes the CBOR header for a map to the stream.
 *
 * @param s The stream to write to.
 * @param size The number of key-value pairs in the map.
 */
extern void n20_cbor_write_map_header(n20_stream_t *s, size_t size);

#ifdef __cplusplus
}
#endif
