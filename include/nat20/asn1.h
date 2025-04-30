/*
 * Copyright 2024 Aurora Operations, Inc.
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

#include <nat20/oid.h>
#include <nat20/stream.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

/** @file */

/**
 * @defgroup n20_asn1_classes ASN.1 Classes
 *
 * ASN1 class definitions.
 * @{
 */

/**
 * @brief The universal class.
 *
 * Indicates that the tag in the corresponding ASN.1 header
 * has a global meaning as defined in X.208.
 * @sa n20_asn1_universal_tags
 */
#define N20_ASN1_CLASS_UNIVERSAL 0
/**
 * @brief The application class.
 *
 * Indicates that the tag in the corresponding ASN.1 header
 * is application specific.
 */
#define N20_ASN1_CLASS_APPLICATION 1
/**
 * @brief The context specific class.
 *
 * Indicates that the tag in the corresponding ASN.1 header
 * is context specific.
 * @sa n20_asn1_universal_tags
 */
#define N20_ASN1_CLASS_CONTEXT_SPECIFIC 2
/**
 * @brief The private class.
 *
 * Indicates that the tag in the corresponding ASN.1 header
 * is private.
 * @sa n20_asn1_universal_tags
 */
#define N20_ASN1_CLASS_PRIVATE 3

/** @} */

/**
 * @defgroup n20_asn1_universal_tags ASN.1 Universal Tags
 *
 * A subset of the universal type tags as defined in X.208
 * @{
 */

/**
 * @brief The boolean type.
 *
 * X.690 specifies that booleans are encoded as single
 * byte that represents FALSE if 0 and TRUE otherwise.
 *
 * However, DER requires TRUE to be encoded as 0xFF.
 */
#define N20_ASN1_TAG_BOOLEAN 0x1
/**
 * @brief The integer type.
 *
 * Integers are signed and encoded using two's complement
 * representation, and DER requires that the least number of
 * bytes is used to express all significant bits.
 * Care must be taken that the most significant bit correctly
 * expresses the sign. E.g. `128` must be expressed as `0x00 0x80`
 * because without the leading zeroes `0x80` would be interpreted as
 * `-128`.
 */
#define N20_ASN1_TAG_INTEGER 0x2
/**
 * @brief The bitstring type.
 *
 * A bit string encodes a sequence of bits. The first byte in a
 * bitstring indicates the number of unused bits in the last byte
 * in the bit string. The remaining bytes hold the bit string.
 * The bit with the index `n` can be accessed as
 *
 * @code{.c}
 * (bits[n / 8] >> (7 - (n % 8))) & 0x1
 * @endcode
 */
#define N20_ASN1_TAG_BIT_STRING 0x3
/**
 * @brief The octet string type.
 *
 * The OctetString is a string of octets. Which may be
 * constructed of multiple substrings.
 *
 * DER does not allow substring, only primitive
 * encoding is allowed.
 */
#define N20_ASN1_TAG_OCTET_STRING 0x4
/**
 * @brief The NULL type.
 *
 * The NULL type has no content. It only consists of the ASN.1
 * header with a length fields: of zero: `0x05 0x00`.
 */
#define N20_ASN1_TAG_NULL 0x5
/**
 * @brief The object identifier type.
 *
 * An object identifier is a sequence of integers.
 * The first two integers i0 and i1 are encoded in a single
 * byte as such: `40 * i0 + i1`. Each subsequent integer
 * is encoded using base 128 encoding.
 * @sa @ref n20_asn1_base128_int
 */
#define N20_ASN1_TAG_OBJECT_IDENTIFIER 0x6
/**
 * @brief The UTF-8 string type.
 *
 * A UTF8String is a string of unicode characters.
 */
#define N20_ASN1_TAG_UTF8_STRING 0xC
/**
 * @brief The sequence type.
 *
 * A sequence is an ordered collection of zero or more
 * elements.
 *
 * The ASN.1 definition language
 * distinguishes between `SEQUENCE` and `SEQUENCE OF`
 * The former can hold one or more elements of differing
 * types. The latter may hold zero or more elements of
 * a specific type. This distinction is lost in the
 * encoded format though.
 */
#define N20_ASN1_TAG_SEQUENCE 0x10
/**
 * @brief The set type.
 *
 * A set is an unordered collection of zero or more
 * elements.
 *
 * The ASN.1 definition language
 * distinguishes between `SET` and `SET OF`
 * The former can hold one or more elements of differing
 * types. The latter may hold zero or more elements of
 * a specific type. This distinction is lost in the
 * encoded format though.
 */
#define N20_ASN1_TAG_SET 0x11
/**
 * @brief The printable string type.
 *
 * A PrintableString is a string of printable characters
 * from a limited set of characters.
 */
#define N20_ASN1_TAG_PRINTABLE_STRING 0x13
/**
 * @brief The UTC time type.
 *
 * The content of a UTCTime object is encoded as a string of
 * the form `YYMMDDhhmm[ss]<TZ>` where
 * - YY is the lowest two digits of the calendar year,
 * - MM is the calendar month in the inclusive range [1 .. 12],
 * - DD is the calendar day starting with 1,
 * - hh is the hour of the day [0 .. 23],
 * - mm is the minute of the hour [0 .. 60],
 * - ss is optional and denotes the second of the minute [0 .. 60],
 * - <TZ> is the timezone specifier, where a literal `Z` denotes UTC
 *   and `[+-]hhmm` indicates the offset form UTC in hours (`hh`) and
 *   minutes (`mm`) such that the time denoted by the string can be
 *   converted to UTC by subtracting the given offset.
 *
 * The fact that only two digits of the year are expressed leads
 * ambiguity. RFC5280 Section 4.1.2.5.1 disambiguates this by defining
 * all values greater or equal than 50 to be interpreted as 19YY and
 * all values less than 50 as 20YY when used in the validity date of
 * an X509 certificate.
 */
#define N20_ASN1_TAG_UTC_TIME 0x17
/**
 * @brief The GeneralizeTime type.
 *
 * The GeneralizedTime type is similar to the UTCTime
 * (see @ref N20_ASN1_TAG_UTC_TIME). However, it removes the ambiguity
 * by using 4 digits for the year field. And adds more
 * precision by adding optional fractional seconds.
 *
 * RFC 5280 4.1.2.5.2 restricts the use of GeneralizedTime
 * in X509 certificates using the following rules:
 * - The time is always UTC so the time zone specifier is
 *   always a literal `Z`.
 * - fractional seconds are not allowed.
 * - minutes and seconds are not optional.
 *
 * Thus GeneralizedTime string in the context of X509
 * is always of the form `YYYYMMDDhhmmssZ`.
 */
#define N20_ASN1_TAG_GENERALIZED_TIME 0x18

/** @} */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Represents the ASN.1 class of an object.
 *
 * This type shall take one of values in @ref n20_asn1_classes.
 */
typedef uint8_t n20_asn1_class_t;

/**
 * @brief Write a base 128 integer to the given stream.
 *
 * A base 128 integer is always positive. The encoding
 * uses the msb of every byte to indicate whether more bytes
 * follow. The final byte has the msb cleared; it holds
 * the 7 least significant bits of the integer.
 * This function follows distinguished encoding rules (DER)
 * in that it uses the least number of bytes to encode
 * the given integer.
 *
 * This integer encoding is used for encoding long form
 * tags in the ASN1.1 header and also in the encoding of
 * object identifiers.
 *
 * @param s The stream that is to be updated.
 * @param n The integer to be written.
 */
extern void n20_asn1_base128_int(n20_stream_t *s, uint64_t n);

/**
 * @brief Write an ASN.1 header to the given stream.
 *
 * The first byte of the ASN.1 header consists of the following
 * bits form most to least significant
 *
 * `ccCttttt`
 *
 * Where:
 * - `c` denotes the ASN.1 class (see @ref n20_asn1_classes)
 * - `C` denotes whether the type is constructed (`1`) or primitive (`0`)
 * - `t` holds the tag (see @ref n20_asn1_universal_tags). If the tag is greater than
 *       30, all `t` bits are set to `1` and the tag is encoded in
 *       subsequent bytes using base 128 encoding (see @ref n20_asn1_base128_int).
 *
 * The header and conditional tag bytes are followed by the length field.
 * If the length of the structure is less than or equal to 127, the length
 * is encoded in a single byte as a positive integer with the msb set to
 * `0`. If the length is grater than 127, the first byte of the length
 * field indicates the size of the length field in bytes in the lower
 * seven bits with the msb set to `1`. Subsequent bytes hold the length
 * in big endian order. DER requires that the least number of bytes is
 * used to represent the length.
 *
 * ## Example
 *
 * Remember that the stream is written in reverse. This means that a header
 * is written after the content of the structure. This makes it very easy
 * to determine the length of the structure and the length of the length
 * field. A typical usage pattern of this function is as follows:
 *
 * @code{.c}
 * size_t mark = n20_stream_byte_count(s);
 * // Write structure content here.
 * n20_asn1_header(s,
 *             N20_ASN1_CLASS_UNIVERSAL,
 *             1, // constructed
 *             N20_ASN1_TAG_SEQUENCE,
 *             n20_stream_byte_count(s) - mark);
 * @endcode
 *
 * @param s The stream that is to be updated.
 * @param class_ One of @ref n20_asn1_classes.
 * @param constructed `true` if the structure is constructed, `false` for
 *                    primitive.
 * @param tag The tag.
 * @param len The length of the content of the structure started by this
 *            header.
 */
extern void n20_asn1_header(
    n20_stream_t *s, n20_asn1_class_t class_, bool constructed, uint32_t tag, size_t len);

/**
 * @brief Qualifies the tag info override type.
 */
enum n20_asn1_tag_info_type_s {
    /**
     * @brief No override.
     *
     * The tag info override is ignored.
     */
    n20_asn1_tag_info_no_override_e = 0,
    /**
     * @brief Context specific tagging with implicit typing.
     */
    n20_asn1_tag_info_implicit_e = 1,
    /**
     * @brief Context specific tagging with explicit typing.
     */
    n20_asn1_tag_info_explicit_e = 2,
};

/**
 * @brief Alias for @ref n20_asn1_tag_info_type_s
 */
typedef enum n20_asn1_tag_info_type_s n20_asn1_tag_info_type_t;

/**
 * @brief The tag info override.
 *
 * The asn1 module implements a set of convenience
 * functions to render various universal ASN.1 data types.
 * In some specifications the same format used for these types
 * is used with context specific tags expressing an implicit data
 * type. Other specification require context specific tagging with
 * explicit data type.
 *
 * To accommodate this need, the functions in this library accept
 * an optional tag info override parameter.
 * These functions must adhere to the following behavior depending
 * on the value of @ref type (Except when the default fallback value
 * is rendered).
 *
 * - @ref n20_asn1_tag_info_no_override_e : The override is ignored.
 * - @ref n20_asn1_tag_info_implicit_e : The class of the ASN.1 item
 *   is set to @ref N20_ASN1_CLASS_CONTEXT_SPECIFIC, and the tag is
 *   replaced with the value of @ref tag.
 * - @ref n20_asn1_tag_info_explicit_e : The header of the ASN.1 item
 *   is unchanged, but a second header is rendered with a class of
 *   @ref N20_ASN1_CLASS_CONTEXT_SPECIFIC, and a value of @ref tag.
 */
struct n20_asn1_tag_info_s {
    /**
     * @brief Indicates the type of the tag info override.
     *
     * @sa n20_asn1_tag_info_type_t
     */
    n20_asn1_tag_info_type_t type;
    /**
     * @brief The override tag value.
     *
     * This value is used as replacement tag value if
     * implicit typing is requested, and as tag value in
     * an additional tag header if explicit typing is
     * requested.
     */
    uint32_t tag;
};

/**
 * @brief Alias for @ref n20_asn1_tag_info_s
 */
typedef struct n20_asn1_tag_info_s n20_asn1_tag_info_t;

/**
 * @brief Convenience function for initializing @ref n20_asn1_tag_info_t.
 *
 * Create a tag info structure indicating no deviance from the default
 * behavior.
 *
 * The two following code snippets are semantically equivalent.
 * @code{.c}
 * n20_asn1_tag_info_t tag_info = n20_asn1_tag_info_no_override();
 * @endcode
 *
 * @code{.c}
 * n20_asn1_tag_info_t tag_info = { .type = n20_asn1_tag_info_no_override_e };
 * @endcode
 *
 * @return n20_asn1_tag_info_t
 */
extern n20_asn1_tag_info_t n20_asn1_tag_info_no_override(void);
/**
 * @brief Convenience function for initializing @ref n20_asn1_tag_info_t.
 *
 * Create a tag info structure indicating context specific
 * tagging with explicit typing is desired.
 *
 * The two following code snippets are semantically equivalent.
 * @code{.c}
 * n20_asn1_tag_info_t tag_info = n20_asn1_tag_info_explicit(7);
 * @endcode
 *
 * @code{.c}
 * n20_asn1_tag_info_t tag_info = { .type = n20_asn1_tag_info_explicit_e, tag = 7 };
 * @endcode
 *
 * @param tag The desired tag number.
 * @return n20_asn1_tag_info_t
 */
extern n20_asn1_tag_info_t n20_asn1_tag_info_explicit(int tag);
/**
 * @brief Convenience function for initializing @ref n20_asn1_tag_info_t.
 *
 * Create a tag info structure indicating that
 * context specific taging with implicit typing is desired.
 *
 * The two following code snippets are semantically equivalent.
 * @code{.c}
 * n20_asn1_tag_info_t tag_info = n20_asn1_tag_info_implicit(7);
 * @endcode
 *
 * @code{.c}
 * n20_asn1_tag_info_t tag_info = { .type = n20_asn1_tag_info_implicit_e, tag = 7 };
 * @endcode
 *
 * @param tag The desired tag number.
 * @return n20_asn1_tag_info_t
 */
extern n20_asn1_tag_info_t n20_asn1_tag_info_implicit(int tag);

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
struct n20_asn1_slice_s {
    /**
     * @brief Pointer to the buffer.
     *
     * A buffer with a capacity of at least @ref size bytes or NULL.
     */
    uint8_t const *buffer;
    /**
     * @brief The guaranteed capacity of the buffer.
     */
    size_t size;
};

/**
 * @brief Alias for @ref n20_asn1_slice_s
 */
typedef struct n20_asn1_slice_s n20_asn1_slice_t;

/**
 * @brief Write an ASN1 NULL to the given stream.
 *
 * @param s The stream that is to be updated.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_NULL
 */
extern void n20_asn1_null(n20_stream_t *const s, n20_asn1_tag_info_t tag_info);

/**
 * @brief Write an object identifier complete with ASN.1 header to the given stream.
 *
 * If the @p oid parameter is NULL this function behaves like
 * @ref n20_asn1_null.
 *
 * If `oid->element_count` is initialized to avalue greater than
 * @ref N20_ASN1_MAX_OID_ELEMENTS this function behaves like
 * @ref n20_asn1_null.
 *
 * @param s The stream that is to be updated.
 * @param oid The object identifier to be written to the stream.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_OBJECT_IDENTIFIER
 */
extern void n20_asn1_object_identifier(n20_stream_t *s,
                                       n20_asn1_object_identifier_t const *oid,
                                       n20_asn1_tag_info_t tag_info);

/**
 * @brief Write an integer complete with ASN.1 header to the given stream.
 *
 * The function expects a buffer `n` of length `len` bytes which
 * it will interpret as integer according to the parameters `little_endian`
 * and `two_complement`. It will format an ASN1 INTEGER into the stream using
 * DER, i.e., leading zero bytes (unsigned) or bytes that have all bits set
 * according to the sign byte (2-complement) are stripped or padded as appropriate.
 *
 * If `n` is NULL this function behaves like @ref n20_asn1_null.
 *
 * @param s The stream that is to be updated.
 * @param n The buffer holding the integer.
 * @param len The size of the buffer in bytes.
 * @param little_endian Indicates if the byteorder of the integer in the given buffer.
 * @param two_complement If `true` the buffer is interpreted as signed 2-complement integer.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_INTEGER
 */
extern void n20_asn1_integer(n20_stream_t *s,
                             uint8_t const *n,
                             size_t len,
                             bool little_endian,
                             bool two_complement,
                             n20_asn1_tag_info_t tag_info);

/**
 * @brief Convenience function to write an unsigned C integer as ASN.1 INTEGER.
 *
 * This function uses @ref n20_asn1_integer to write the given
 * integer to the stream. The endianess is determined to be the
 * host endianess and the `two_complement` parameter is set to false.
 * It is generally okay to promote shorter types as the
 * DER will cause the final formatting result to be as short as
 * possible.
 *
 * @param s The stream that is to be updated.
 * @param n An unsigned integer.
 * @param tag_info Tag info override.
 */
extern void n20_asn1_uint64(n20_stream_t *s, uint64_t n, n20_asn1_tag_info_t tag_info);

/**
 * @brief Convenience function to write a signed C integer as ASN.1 INTEGER.
 *
 * This function uses @ref n20_asn1_integer to write the given
 * integer to the stream. The endianess is determined to be the
 * host endianess and the `two_complement` parameter is set to true.
 * It is generally okay to promote shorter types as the
 * DER will cause the final formatting result to be as short as
 * possible.
 *
 * @param s The stream that is to be updated.
 * @param n A signed integer.
 * @param tag_info Tag info override.
 */
extern void n20_asn1_int64(n20_stream_t *s, int64_t n, n20_asn1_tag_info_t tag_info);

/**
 * @brief Write a bit string complete with ASN.1 header to the given stream.
 *
 * The length of the bitstring is given in bits where `bits` may not
 * be a multiple of 8. This means that buffer must be at least `ceil(bits/8)`
 * octets in size. The layout is such that the first bit in the string
 * can be found at the most significant bit of the byte at offset 0 in
 * the buffer. The last bit in the string can be found in the least
 * significant used bit in the byte at offset `bits/8`. The remaining
 * bits are to be set to zero as for DER.
 *
 * If @p b is NULL an empty bitstring is written.
 *
 * @param s The stream that is to be updated.
 * @param b Buffer holding the bitstring.
 * @param bits Number of bits represented by the bitstring.
 * @param tag_info Tag info override.
 */
extern void n20_asn1_bitstring(n20_stream_t *s,
                               uint8_t const *b,
                               size_t bits,
                               n20_asn1_tag_info_t tag_info);

/**
 * @brief Write an octet string complete with ASN.1 header to the given stream.
 *
 * Writes the `len` octets from `str` to the stream.
 *
 * If @p str is NULL an empty octetstring is written.
 *
 * @param s The stream that is to be updated.
 * @param slice Buffer holding the octet string.
 * @param tag_info Tag info override.
 */
extern void n20_asn1_octetstring(n20_stream_t *s,
                                 n20_asn1_slice_t const *slice,
                                 n20_asn1_tag_info_t tag_info);

/**
 * @brief Write an UTF-8 string complete with ASN.1 header to the given stream.
 *
 * This function assumes that `str` is `'\0'` terminated and uses
 * `strlen` to determine the size of the string.
 * It writes the string without the terminating character to the
 * stream. This function assumes the string pointed to by @p str is
 * a valid UTF-8 encoding.
 * It is up to the caller to uphold this invariant. This function does
 * not perform any compliance checks.
 *
 * If @p str is NULL, an empty string is written.
 *
 * @param s The stream that is to be updated.
 * @param str Buffer holding the string.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_UTF8_STRING
 */
extern void n20_asn1_utf8_string(n20_stream_t *s, char const *str, n20_asn1_tag_info_t tag_info);

/**
 * @brief Write an printable string complete with ASN.1 header to the given stream.
 *
 * This function assumes that `str` is `'\0'` terminated and uses
 * `strlen` to determine the size of the string.
 * It writes the string without the terminating character to the
 * stream. Printable according to ITU X.680 printable strings
 * may contain the following characters: `[A..Z][a..z][0..9][ '()+,-./:=?]`.
 * It is up to the caller to uphold this invariant. This function does
 * not perform any compliance checks.
 *
 * If @p str is NULL, an empty printable string is written.
 *
 * @param s The stream that is to be updated.
 * @param str Buffer holding the string.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_PRINTABLE_STRING
 */
extern void n20_asn1_printablestring(n20_stream_t *s,
                                     char const *str,
                                     n20_asn1_tag_info_t tag_info);

/**
 * @brief Write a generalized time string complete with ASN.1 header to the given stream.
 *
 * This function assumes that `str` is `'\0'` terminated and uses
 * `strlen` to determine the size of the string.
 * It writes the string without the terminating character to the
 * stream.
 * It is up to the caller to format the time string, and no checks are
 * performed on the string.
 *
 * If @p time_str is `NULL`, this function behaves like @ref n20_asn1_null.
 *
 * @param s The stream that is to be updated.
 * @param time_str Buffer holding the string.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_GENERALIZED_TIME
 */
extern void n20_asn1_generalized_time(n20_stream_t *s,
                                      char const *time_str,
                                      n20_asn1_tag_info_t tag_info);

/**
 * @brief The callback function prototype formating constructed content.
 *
 * This callback function type is used by functions like
 * @ref n20_asn1_header_with_content and @ref n20_asn1_sequence.
 * for client code to implement the formatting of the structured content.
 *
 * @sa n20_asn1_header_with_content
 * @sa n20_asn1_sequence
 */
typedef void(n20_asn1_content_cb_t)(n20_stream_t *, void *);

/**
 * @brief Format an ASN.1 header while inferring the length field from the content.
 *
 * This function provides full control over the ASN.1 header fields while inferring the length
 * field from the content of the ASN.1 structure. The function stores the current write position on
 * the stack, runs the content call back function to render the content, computes the written
 * content length, and renders the header.
 *
 * @param s The stream that is to be updated.
 * @param class_ One of @ref n20_asn1_classes.
 * @param constructed `true` if the structure is constructed, `false` for primitive.
 * @param tag The tag.
 * @param content_cb The callback function rendering the content. A null function pointer will be
 * treated as a no-op function.
 * @param cb_context This opaque pointer is passed to the content callback as-is.
 * @param tag_info Tag info override.
 * @sa n20_asn1_header
 * @sa n20_asn1_content_cb_t
 */
extern void n20_asn1_header_with_content(n20_stream_t *s,
                                         n20_asn1_class_t class_,
                                         bool constructed,
                                         uint32_t tag,
                                         n20_asn1_content_cb_t content_cb,
                                         void *cb_context,
                                         n20_asn1_tag_info_t tag_info);

/**
 * @brief Convenience function to write an ASN.1 sequence complete with header to the given stream.
 *
 * This function is equivalent to:
 *
 * @code{.c}
 * n20_asn1_header_with_content(
 *     s,
 *     N20_ASN1_CLASS_UNIVERSAL,
 *     true,
 *     N20_ASN1_TAG_SEQUENCE,
 *     content_cb,
 *     cb_context);
 * @endcode
 *
 * @param s The stream that is to be updated.
 * @param content_cb The callback function rendering the content. A null function pointer will be
 * treated as a no-op function.
 * @param cb_context This opaque pointer is passed to the content callback as-is.
 * @param tag_info Tag info override.
 * @sa n20_asn1_header
 * @sa n20_asn1_content_cb_t
 * @sa n20_asn1_header_with_content
 * @sa N20_ASN1_TAG_SEQUENCE
 * @sa N20_ASN1_CLASS_UNIVERSAL
 */
extern void n20_asn1_sequence(n20_stream_t *s,
                              n20_asn1_content_cb_t content_cb,
                              void *cb_context,
                              n20_asn1_tag_info_t tag_info);

/**
 * @brief Write an ASN.1 (DER) boolean to the given stream.
 *
 * Renders an ASN.1 boolean using DER, i.e., `false` is represented
 * as `0x00` bytes and `true` is represented as `0xff` byte.
 * With header, this amounts to `0x01 0x01 0x00` for false and
 * `0x01 0x01 0xff` for true.
 *
 * @param s The stream that is to be updated.
 * @param v The boolean value that is to be written.
 * @param tag_info Tag info override.
 * @sa N20_ASN1_TAG_BOOLEAN
 */
extern void n20_asn1_boolean(n20_stream_t *s, bool v, n20_asn1_tag_info_t tag_info);

#ifdef __cplusplus
}
#endif
