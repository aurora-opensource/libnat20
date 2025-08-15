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

/** @file */

#pragma once

#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Refers to a constant buffer of the specified size.
 *
 * This is used to refer to foreign non-mutable buffers
 * of a given size. The user has to assure buffer outlives
 * the instance of the slice and that the buffer is
 * sufficiently large to accommodate @ref size bytes of data.
 *
 * No ownership is implied.
 *
 * Implementations must handle the cases where @ref buffer
 * is NULL gracefully, and must not dereference the pointer
 * even if @ref size is not 0.
 *
 * If @ref size is 0, implementation may use the value of buffer
 * to distinguish between an empty buffer and an optional
 * field that is not present.
 */
struct n20_slice_s {
    /**
     * @brief The guaranteed capacity of the buffer.
     */
    size_t size;
    /**
     * @brief Pointer to the buffer.
     *
     * A buffer with a capacity of at least @ref size bytes or NULL.
     */
    uint8_t const *buffer;
};

/**
 * @brief Alias for @ref n20_slice_s
 */
typedef struct n20_slice_s n20_slice_t;

/**
 * @brief Convenience macro for defining a null slice.
 *
 * This macro defines a slice with a size of 0 and a NULL buffer.
 *
 * The following code snippets are equivalent:
 * @code
 * n20_slice_t slice = N20_SLICE_NULL;
 * @endcode
 *
 * @code
 * n20_slice_t slice = {.size = 0, .buffer = NULL};
 * @endcode
 */
#define N20_SLICE_NULL ((n20_slice_t){.size = 0, .buffer = NULL})

/**
 * @brief Refers to a constant buffer holding a string.
 *
 * No ownership is implied.
 *
 * This is used to refer to foreign non-mutable buffers
 * holding utf-8 encoded strings.
 * The user has to assure that the buffer outlives the string slice
 * object and that the buffer is sufficiently large to accommodate
 * @ref size bytes of data.
 *
 * @note The string cannot be assumed to be null terminated.
 *       While it is safe to initialize a string slice with a null terminated
 *       string, it is not safe to use a @ref buffer where a null terminated
 *       string is expected.
 */
struct n20_string_slice_s {
    /**
     * @brief The guaranteed capacity of the buffer.
     */
    size_t size;
    /**
     * @brief Pointer to the buffer.
     *
     * A buffer with a capacity of at least @ref size bytes or NULL.
     */
    char const *buffer;
};

/**
 * @brief Alias for @ref n20_string_slice_s
 */
typedef struct n20_string_slice_s n20_string_slice_t;

/**
 * @brief Convenience macro to create a string slice from a string literal.
 *
 * This is equivalent to:
 * @code{.c}
 * (n20_string_slice_t) { .size = sizeof(str__) - 1, .buffer = str__ }
 * @endcode
 *
 * @note This macro is only safe to use with string literals.
 *       An effort is made to make this macro fail to compile if not used with
 *       a string literal by concatenating the argument with the empty string `""`.
 *
 * @param str__ The string literal to be converted.
 */
#define N20_STR_C(str__) \
    (n20_string_slice_t) { .size = sizeof(str__) - 1, .buffer = str__ "" }

/**
 * @brief Convenience macro to create an empty string slice.
 *
 * This is equivalent to:
 * @code{.c}
 * (n20_string_slice_t) { .size = 0, .buffer = NULL }
 * @endcode
 */
#define N20_STR_NULL \
    (n20_string_slice_t) { .size = 0, .buffer = NULL }

#ifdef __cplusplus
}
#endif
