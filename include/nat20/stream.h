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

/** @file */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Represents an stream buffer for rendering ASN.1 artifacts.
 *
 * A `n20_stream` is used to render ASN.1 artifacts by writing
 * ASN.1 structures to it in reverse order. It can also be used to
 * compute the size of a rendered artifact without actually
 * writing it to a buffer by initializing the buffer with NULL.
 *
 * Writing ASN.1 in reverse has the benefit, that the sizes of
 * each field is known when rendering the corresponding header
 * with no further adjustment required to adhere to DER.
 */
struct n20_stream_s {
    /**
     * @brief Points to the beginning of the underlying buffer.
     *
     * This may be NULL.
     */
    uint8_t *begin;
    /**
     * @brief The size of the underlying buffer.
     *
     * This is effectively ignored if @ref begin is NULL.
     */
    size_t size;
    /**
     * @brief Indicates the write position in bytes.
     *
     * This is initialized with `0` and incremented with
     * each byte written. The actual write position within
     * the buffer is computed as @ref begin + @ref size - @ref write_position.
     */
    size_t write_position;
    /**
     * @brief Indicates if the stream data is inconsistent.
     *
     * If @ref begin is NULL or if @ref write_position became greater
     * than @ref size or if an overflow occurred while
     * incrementing @ref write_position, @ref buffer_overflow will be `true`.
     *
     * If @ref buffer_overflow is `true`, @ref begin will not be
     * dereferenced but subsequent writes will still update
     * @ref write_position.
     *
     * Note: NOT @ref buffer_overflow implies NOT @ref write_position_overflow.
     *
     * @sa n20_stream_has_buffer_overflow
     */
    bool buffer_overflow;
    /**
     * @brief Indicates that an overflow occurred while incrementing
     * @ref write_position.
     *
     * If an overflow occurred while incrementing @ref write_position,
     * @ref write_position_overflow is set to `true`.
     *
     * Note: @ref write_position_overflow implies @ref buffer_overflow.
     *
     * @sa n20_stream_has_write_postion_overflow
     */
    bool write_position_overflow;
};

/**
 * @brief Alias for @ref n20_stream_s
 */
typedef struct n20_stream_s n20_stream_t;

/**
 * @brief Initialize an @ref n20_stream_t structure.
 *
 * Initializes a structure of @ref n20_stream_t.
 * It is safe to call this function with `buffer == NULL`.
 * In this case the `buffer_size` parameter is effectively ignored
 * and the stream will merely count the bytes written
 * to it, which can be used for calculating a buffer size hint.
 * If `buffer` is given it must point to a buffer of at least
 * `buffer_size` bytes, or an out of bounds write will occur.
 *
 * ## Ownership and life time
 *
 * The initialized stream does not take ownership of the provided
 * buffer and the buffer must outlive the stream object.
 *
 * Calling this function with `s == NULL` is safe but a noop.
 *
 * @param s A pointer to the to be initialized @ref n20_stream_t structure.
 * @param buffer A pointer to the target stream buffer or NULL.
 * @param buffer_size Size of `buffer` in bytes.
 */
extern void n20_stream_init(n20_stream_t *s, uint8_t *buffer, size_t buffer_size);

/**
 * @brief Check if the stream has a buffer overflow.
 *
 * The stream is considered to have a buffer overflow if it received
 * more bytes than could be accommodated by the underlying stream
 * buffer. If `false` is returned, it implies that
 * @ref n20_stream_data returns a pointer that can
 * be safely dereferenced.
 * If `false` is returned it implies @ref n20_stream_has_write_position_overflow
 * must return `false`.
 *
 * @param s the pointer to the stream that is to be queried.
 * @return true if the stream ran out of buffer.
 */
extern bool n20_stream_has_buffer_overflow(n20_stream_t const *s);

/**
 * @brief Check if the stream write counter overflowed.
 *
 * The stream failed to count all the bytes written to it.
 * If `false` is returned @ref n20_stream_byte_count returns
 * a reliable result even if not all bytes were stored in
 * the underlying buffer. If `true` is returned, no inference
 * can be made about the stream data.
 * If `true` is returned it implies that
 * @ref n20_stream_has_buffer_overflow must also return `true`.
 *
 * @param s the pointer to the stream that is to be queried.
 * @return bool true if the stream write position did overflow.
 */
extern bool n20_stream_has_write_position_overflow(n20_stream_t const *s);

/**
 * @brief Query the number of bytes written to the stream.
 *
 * This function always returns the correct amount of data
 * unless @ref n20_stream_has_write_position_overflow is `true`
 * even if @ref n20_stream_has_buffer_overflow is `true`.
 * The latter indicates that the stream ran out of buffer,
 * however, this function can still be used to gauge the
 * buffer size required for the data rendering operation.
 *
 * @param s the pointer to the stream that is to be queried.
 * @return size_t number of bytes written to the stream.
 */
extern size_t n20_stream_byte_count(n20_stream_t const *s);

/**
 * @brief Points to the current stream position in the underlying buffer.
 *
 * The stream is always written from the end of the buffer.
 * This means that the returned pointer points always to the
 * beginning of the written section. If no data has been written
 * this points past the end of the buffer.
 *
 * IMPORTANT it is only safe to dereference the returned pointer if
 * @ref n20_stream_has_buffer_overflow returns `false`. Also the
 * access must be within the range [p, p + @ref n20_stream_byte_count)
 * where p is the return value of this function.
 *
 * @param s the pointer to the stream that is to be queried.
 * @return pointer to the beginning of the written buffer.
 */
extern uint8_t const *n20_stream_data(n20_stream_t const *s);

/**
 * @brief Write a buffer to the front of the stream buffer.
 *
 * The asn1 stream is always written in reverse. This means that
 * prepending is the only way to write to the stream buffer.
 * The buffer's write position is moved by `-src_len`
 * unconditionally. If the stream is good and the new position
 * points inside of the underlying buffer, the entire source
 * buffer @p src is copied into the stream buffer. Otherwise,
 * nothing is copied and the stream is marked as bad.
 * A bad stream can still be written to, but it will only record
 * the number of bytes written without storing any data.
 *
 * If @p src_len is exceedingly large such that the the write position
 * would wrapp and point within the writable buffer region, the
 * stream will remain bad but in addition the overflow flag will be
 * raised on the stream indicating that even @ref n20_stream_byte_count
 * is no longer reliable. This condition can be queried using
 * @ref n20_stream_has_write_position_overflow.
 *
 * @param s The stream that is to be updated.
 * @param src The source buffer that is to be written to the stream.
 * @param src_len The size of the source buffer in bytes.
 * @sa n20_stream_byte_count
 * @sa n20_stream_has_write_position_overflow
 */
extern void n20_stream_prepend(n20_stream_t *s, uint8_t const *src, size_t src_len);

/**
 * @brief Convenience function to write a single byte to the stream.
 *
 * This convenience function prepends a single byte to the stream.
 * It is useful for writing literals that are not already stored in
 * a memory address that can be referred to with a pointer.
 *
 * The function call
 * @code{.c}
 * n20_stream_put(s, 3)
 * @endcode
 * is equivalent to
 * @code{.c}
 * uint8_t c = 3
 * n20_stream_prepend(s, &c, 1)
 * @endcode
 *
 * @param s The stream that is to be updated.
 * @param c The byte that is to be written.
 * @sa n20_stream_prepend
 */
extern void n20_stream_put(n20_stream_t *s, uint8_t c);

/**
 * @brief Represents an input stream buffer.
 *
 * A `n20_istream` is used to safely extract data from a
 * buffer of a given size.
 */
typedef struct n20_istream_s {
    /**
     * @brief Points to the beginning of the underlying buffer.
     *
     * This may be NULL.
     */
    uint8_t const *begin;
    /**
     * @brief The size of the underlying buffer.
     *
     * This is effectively ignored if @ref begin is NULL.
     */
    size_t size;
    /**
     * @brief Indicates the read position in bytes.
     *
     * This is initialized with `0` and incremented with
     * each byte extracted.
     */
    size_t read_position;
    /**
     * @brief Indicates that the data requested from the stream exceeded the buffer size.
     *
     */
    bool buffer_underrun;
} n20_istream_t;

/**
 * @brief Initialize an @ref n20_istream_t structure.
 *
 * Initializes a structure of @ref n20_istream_t.
 * It is safe to call this function with `buffer == NULL`.
 * In this case the `buffer_size` parameter is effectively ignored
 * and the stream will merely count the bytes written
 * to it, which can be used for calculating a buffer size hint.
 * If `buffer` is given it must point to a buffer of at least
 * `buffer_size` bytes, or an out of bounds write will occur.
 *
 * ## Ownership and life time
 *
 * The initialized stream does not take ownership of the provided
 * buffer and the buffer must outlive the stream object.
 *
 * Calling this function with `s == NULL` is safe but a noop.
 *
 * @param s A pointer to the to be initialized @ref n20_istream_t structure.
 * @param buffer A pointer to the target stream buffer or NULL.
 * @param buffer_size Size of `buffer` in bytes.
 */
extern void n20_istream_init(n20_istream_t *s, uint8_t const *buffer, size_t buffer_size);

/**
 * @brief Reads data from the input stream into a buffer.
 *
 * This function reads a specified number of bytes from the input stream
 * into the provided buffer. If the read operation exceeds the available
 * data in the stream, the `buffer_underrun` flag is set and the provided
 * buffer remains unmodified. In this case, the function returns `false`.
 *
 * @note The function does not check for buffer overflows in the provided
 * buffer. It is the caller's responsibility to ensure that the buffer is
 * dereferenceable and that it is at least `buffer_size` bytes long.
 *
 * @param s The input stream to read from.
 * @param buffer The buffer to store the read data.
 * @param buffer_size The number of bytes to read.
 * @return `true` if the read operation was successful, `false` otherwise.
 */
extern bool n20_istream_read(n20_istream_t *s, uint8_t *buffer, size_t buffer_size);

/**
 * @brief Reads a single byte from the input stream.
 *
 * This function reads a single byte from the input stream and stores it
 * in the provided variable. If the read operation exceeds the available
 * data in the stream, the `buffer_underrun` flag is set and the provided
 * buffer remains unmodified. In this case, the function returns `false`.
 *
 * @note The function does not check for buffer overflows in the provided
 * uint_t variable. It is the caller's responsibility to ensure that the
 * variable is dereferenceable.
 *
 * @param s The input stream to read from.
 * @param c Pointer to a variable where the read byte will be stored.
 * @return `true` if the read operation was successful, `false` otherwise.
 */
extern bool n20_istream_get(n20_istream_t *s, uint8_t *c);

/** @brief Gets a buffer slice from the input stream.
 *
 * This function advances the read position of the input stream by the
 * specified size and returns a slice of the input stream buffer.
 *
 * @param s The input stream to read from.
 * @param size The size of the slice to read.
 * @return A pointer to the slice of the input stream buffer or NULL if
 * the read operation exceeds the available data in the stream.
 */
extern uint8_t const *n20_istream_get_slice(n20_istream_t *s, size_t size);

/**
 * @brief Checks if the input stream has encountered a buffer underrun.
 *
 * This function returns whether the input stream has encountered a buffer
 * underrun, which occurs when a read operation exceeds the available data
 * in the stream.
 *
 * @param s The input stream to check.
 * @return `true` if a buffer underrun has occurred, `false` otherwise.
 */
extern bool n20_istream_has_buffer_underrun(n20_istream_t const *s);

/**
 * @brief Gets the current read position of the input stream.
 *
 * This function returns the current read position in the input stream.
 * If the stream is `NULL`, it returns 0.
 *
 * @param s The input stream to query.
 * @return The current read position, or 0 if the stream is `NULL`.
 */
extern size_t n20_istream_read_position(n20_istream_t const *s);

#ifdef __cplusplus
}
#endif
