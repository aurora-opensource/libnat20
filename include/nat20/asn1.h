#pragma once

#include <stdint.h>
#include <unistd.h>

/** @file */

/**
 * @defgroup asn1_classes ASN.1 Classes
 *
 * ASN1 class definitions.
 * @{
 */

/**
 * @brief The universal class.
 *
 * Indicates that the tag in the corresponding ASN.1 header
 * has a global meaning as defined in X.208.
 * @sa asn1_universal_tags
 */
#define ASN1_CLASS_UNIVERSAL 0
#define ASN1_CLASS_APPLICATION 1
#define ASN1_CLASS_CONTEXT_SPECIFIC 2
#define ASN1_CLASS_PRIVATE 3

/** @} */

/**
 * @defgroup asn1_universal_tags ASN.1 Universal Tags
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
#define ASN1_TAG_BOOLEAN 0x1
/**
 * @brief The integer type.
 *
 * Integers are signed and encoded using two complement
 * representation, and DER requires that the least number of
 * bytes is used to express all significant bits.
 * Care must be taken that the most significant bit correctly
 * expresses the sign. E.g. `128` must be expressed as `0x00 0x80`
 * because `0x80` would be interpreted as `-128`.
 */
#define ASN1_TAG_INTEGER 0x2
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
#define ASN1_TAG_BIT_STRING 0x3
/**
 * @brief The octet string type.
 *
 * The OctetString is a string of octets. Which may be
 * constructed of multiple substrings.
 *
 * DER does not allow substring, only primitive
 * encoding is allowed.
 */
#define ASN1_TAG_OCTET_STRING 0x4
/**
 * @brief The NULL type.
 *
 * The NULL type has no content. It only consists of the ASN.1
 * header with a zero length fields: `0x05 0x00`.
 */
#define ASN1_TAG_NULL 0x5
/**
 * @brief The object identifier type.
 *
 * An object identifier is a sequence of integers.
 * The first two integers i0 and i1 are encoded in a single
 * byte as such: `40 * i0 + i1`. Each subsequent integer
 * is encoded using base 128 encoding.
 * @sa @ref asn1_base128_int
 */
#define ASN1_TAG_OBJECT_IDENTIFIER 0x6
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
#define ASN1_TAG_SEQUENCE 0x10
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
#define ASN1_TAG_SET 0x11
/**
 * @brief The printable string type.
 *
 * A PrintableString is an string of printable characters
 * from a limited set of characters.
 */
#define ASN1_TAG_PRINTABLE_STRING 0x13
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
#define ASN1_TAG_UTC_TIME 0x17
/**
 * @brief The GeneralizeTime type.
 *
 * The GeneralizedTime type is similar to the UTCTime
 * (see @ref ASN1_TAG_UTC_TIME). However, it removes the ambiguity
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
#define ASN1_TAG_GENERALIZED_TIME 0x18

/** @} */

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t asn1_class_t;
typedef int asn1_bool_t;

typedef struct asn1_stream {
    uint8_t *begin;
    uint8_t *end;
    uint8_t *pos;
    int bad;
} asn1_stream_t;

extern void asn1_stream_init(struct asn1_stream *s, uint8_t *buffer, size_t buffer_size);

/**
 * @brief Check if the stream is good.
 *
 * The stream is considered good if all bytes
 * written to it where stored in the underlying stream
 * buffer.
 *
 * @param s the pointer to the stream that is to be queried.
 * @return asn1_bool_t non zero if the stream is good.
 */
extern asn1_bool_t asn1_stream_is_good(struct asn1_stream const *s);

/**
 * @brief Query the number of bytes written to the stream.
 *
 * This function always returns the correct amount of data
 * that was written to the stream even if the stream is bad.
 * If the stream was bad it means that the stream ran out
 * of buffer. In this case the return value of this function
 * can be used as a hint to allocate a new buffer and
 * initialize a new stream that will fit the data.
 *
 * @param s the pointer to the stream that is to be queried.
 * @return size_t number of bytes written to the stream.
 */
extern size_t asn1_stream_data_written(struct asn1_stream const *s);

/**
 * @brief Points to the current stream position.
 *
 * The stream is always written from the end of the buffer.
 * This means that the returned pointer points always to the
 * beginning of the written section. If no data has been written
 * this points past the end of the buffer.
 *
 * IMPORTANT it is only safe to dereference the returned pointer if
 * @ref asn1_stream_is_good returns a non zero value. Also the access must be
 * within the range [p, p + @ref asn1_stream_data_written) where p is the
 * @param s the pointer to the stream that is to be queried.
 * @return pointer to the beginning of the written buffer.
 */
extern uint8_t const *asn1_stream_data(struct asn1_stream const *s);

/**
 * @brief Write a buffer to the front of the stream buffer.
 *
 * The asn1 stream is always written in revers. This means that
 * prepending is the only way to write to the stream buffer.
 * The buffer's write position is moved by `-src_len`
 * unconditionally. If the stream is good and the new position
 * points inside of the underlying buffer, the entire source
 * buffer @ref src is copied into the stream buffer. Otherwise,
 * nothing is copied and the stream is marked as bad.
 * A bad stream can still be written to, but it will only record
 * the number of bytes written without storing any data.
 *
 * @param s The stream that is to be updated.
 * @param src The source buffer that is to be written to the stream.
 * @param src_len The size of the source buffer in bytes.
 */
extern void asn1_stream_prepend(asn1_stream_t *s, uint8_t const *src, size_t src_len);

/**
 * @brief Convenience function to write a single byte to the stream.
 *
 * This convenience function prepends a single byte to the stream.
 * It is useful for writing literals that are not already stored in
 * a memory address that can be referred to with a pointer.
 *
 * The function call
 * @code{.c}
 * asn1_stream_put(s, 3)
 * @endcode
 * is equivalent to
 * @code{.c}
 * uint8_t c = 3
 * asn1_stream_prepend(s, &c, 1)
 * @endcode
 *
 * @param s The stream that is to be updated.
 * @param c The byte that is to be written.
 * @sa asn1_stream_prepend
 */
extern void asn1_stream_put(asn1_stream_t *s, uint8_t c);

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
extern void asn1_base128_int(asn1_stream_t *s, uint64_t n);

/**
 * @brief Write an ASN.1 header to the given stream.
 *
 * The first byte of the ASN.1 header consists of the following
 * bits form most to least significant
 *
 * `ccCttttt`
 *
 * Where:
 * - `c` denotes the ASN.1 class (see @ref asn1_classes)
 * - `C` denotes whether the type is constructed (`1`) or primitive (`0`)
 * - `t` holds the tag (see @ref asn1_universal_tags). If the tag is is greater
 *       30, all `t` bits are set to `1` and the tag is encoded in
 *       subsequent bytes using base 128 encoding (see @ref asn1_base128_int).
 *
 * The header and conditional tag bytes is followed by the length field.
 * If the length of the structure is less then or equal to 127, the length
 * is encoded in a single byte as a positive integer with the msb set to
 * `0`. If the lengths is grater than 127, the first byte of the length
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
 * size_t mark = asn1_stream_data_written(s);
 * // Write structure content here.
 * asn1_header(s,
 *             ASN1_CLASS_UNIVERSAL,
 *             1, // constructed
 *             ASN1_TAG_SEQUENCE,
 *             asn1_stream_data_written(s) - mark);
 * @endcode
 *
 * @param s The stream that is to be updated.
 * @param class_ One of @ref asn1_classes.
 * @param constructed Non zero if the structure is constructed, zero for
 *                    primitive.
 * @param tag The tag.
 * @param len The length of the content of the structure started by this
 *            header.
 */
extern void asn1_header(
    asn1_stream_t *s, asn1_class_t class_, asn1_bool_t constructed, uint32_t tag, size_t len);

#define ASN1_MAX_OID_ELEMENTS 7

typedef struct asn1_object_identifier {
    size_t elem_count;
    uint32_t elements[ASN1_MAX_OID_ELEMENTS];
} asn1_object_identifier_t;

#define OBJECT_ID(...)                                                      \
    {                                                                       \
        .elem_count = sizeof((uint32_t[]){__VA_ARGS__}) / sizeof(uint32_t), \
        .elements = {__VA_ARGS__},                                          \
    }

#define DEFINE_OID(name, ...) struct asn1_object_identifier name = OBJECT_ID(__VA_ARGS__)

#define DECLARE_OID(name) extern struct asn1_object_identifier name

DECLARE_OID(OID_RSA_ENCRYPTION);
DECLARE_OID(OID_SHA256_WITH_RSA_ENC);

DECLARE_OID(OID_LOCALITY_NAME);
DECLARE_OID(OID_COUNTRY_NAME);
DECLARE_OID(OID_STATE_OR_PROVINCE_NAME);
DECLARE_OID(OID_ORGANIZATION_NAME);
DECLARE_OID(OID_ORGANIZATION_UNIT_NAME);
DECLARE_OID(OID_COMMON_NAME);

DECLARE_OID(OID_BASIC_CONSTRAINTS);
DECLARE_OID(OID_KEY_USAGE);

extern void asn1_null(asn1_stream_t *const s);

extern void asn1_object_identifier(asn1_stream_t *s, struct asn1_object_identifier const *oid);
extern void asn1_integer_internal(asn1_stream_t *s,
                                  uint8_t const *n,
                                  size_t len,
                                  asn1_bool_t little_endian,
                                  asn1_bool_t unsigned_);

extern void asn1_integer(asn1_stream_t *s,
                         uint8_t const *n,
                         size_t len,
                         asn1_bool_t little_endian,
                         asn1_bool_t unsigned_);

extern void asn1_uint64(asn1_stream_t *s, uint64_t n);

extern void asn1_int64(asn1_stream_t *s, int64_t n);

extern void asn1_bitstring(asn1_stream_t *s, uint8_t const *b, size_t bits);

extern void asn1_octetstring(asn1_stream_t *s, uint8_t const *str, size_t len);

extern void asn1_printablestring(asn1_stream_t *s, char const *str);

extern void asn1_generalized_time(asn1_stream_t *s, char const *time_str);

typedef void(asn1_content_cb_t)(asn1_stream_t *, void *);

extern void asn1_header_with_content(asn1_stream_t *s,
                                     asn1_class_t class_,
                                     asn1_bool_t constructed,
                                     uint32_t tag,
                                     asn1_content_cb_t content_cb,
                                     void *cb_context);

extern void asn1_sequence(asn1_stream_t *s, asn1_content_cb_t content_cb, void *cb_context);

extern void asn1_boolean(asn1_stream_t *s, asn1_bool_t v);

#ifdef __cplusplus
}
#endif
