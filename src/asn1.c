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

#include <endian.h>
#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <string.h>

void n20_asn1_stream_init(n20_asn1_stream_t *s, uint8_t *const buffer, size_t buffer_size) {
    if (s == NULL) return;
    // If the buffer is NULL, the stream is marked bad.
    // This will essentially ignore the buffer size, because
    // begin or any pointer derived from it will never be
    // dereferenced. See n20_asn1_stream_prepend.
    s->bad = buffer == NULL;
    s->begin = buffer;
    s->size = buffer_size;
    s->pos = 0;
    s->overflow = false;
}

bool n20_asn1_stream_is_data_good(n20_asn1_stream_t const *const s) {
    return (s != NULL) && !s->bad;
}

bool n20_asn1_stream_is_data_written_good(n20_asn1_stream_t const *const s) {
    return (s != NULL) && !s->overflow;
}

// This function always returns the correct amount of data
// that was written to the stream even if the stream is bad.
// If the stream was bad it means that the stream ran out
// of buffer. In this case the return value of this function
// can be used to allocate a new buffer and initialize a new
// stream that will fit the data.
size_t n20_asn1_stream_data_written(n20_asn1_stream_t const *const s) {
    return s != NULL ? s->pos : 0;
}

// Returns a pointer to the beginning of the written region of the buffer.
// IMPORTANT it is only safe to dereference the returned pointer if
// n20_asn1_stream_is_data_good returns a non zero value. Also the access must be
// within the range [p, p + n20_asn1_stream_data_written) where p is the
// return value of this function.
uint8_t const *n20_asn1_stream_data(n20_asn1_stream_t const *const s) {
    return (s != NULL) ? (s->begin + (s->size - s->pos)) : NULL;
}

// This function never fails. It might not write to the stream
// because it ran out of buffer, however, the stream position will
// be updated so that the required space can be read from the
// stream state later.
void n20_asn1_stream_prepend(n20_asn1_stream_t *const s,
                             uint8_t const *const src,
                             size_t const src_len) {
    if (s == NULL) return;
    // The write position shall be moved unconditionally,
    // because we use this to calculate the required size later.
    size_t old_pos = s->pos;
    s->pos += src_len;
    s->overflow = s->overflow || s->pos < old_pos;
    // Mark the stream as bad if it was bad or if the next write.
    // will overflow the buffer.
    s->bad = s->overflow || s->bad || s->pos > s->size;
    // If the stream is good we can write at the new position.
    if (!s->bad) {
        memcpy(s->begin + (s->size - s->pos), src, src_len);
    }
}

void n20_asn1_stream_put(n20_asn1_stream_t *const s, uint8_t const c) {
    n20_asn1_stream_prepend(s, &c, /*src_len=*/1);
}

void n20_asn1_base128_int(n20_asn1_stream_t *const s, uint64_t n) {
    // The integer n is written 7 bits at a time starting with the least
    // significant bits (because we are writing in reverse!). This
    // byte has the msb unset, because it terminates the sequence.
    uint8_t t = n & 0x7f;
    do {
        n20_asn1_stream_prepend(s, &t, /*src_len=*/1);
        n >>= 7;
        // All following bytes now have have the msb set indicating that
        // more bytes follow.
        t = 0x80 | (n & 0x7f);
    } while (n);
}

void n20_asn1_header(n20_asn1_stream_t *const s,
                     n20_asn1_class_t const class_,
                     bool const constructed,
                     uint32_t const tag,
                     size_t len) {
    uint8_t header = 0;
    // The header is written backwards, so the first thing written
    // is the length.
    if (len <= 127) {
        // If the length is is less than 128, it is encoded
        // in a single byte with the msb cleared.
        uint8_t l = len;
        n20_asn1_stream_prepend(s, &l, /*src_len=*/1);
    } else {
        // Otherwise, the length is is written in big endian
        // order with the least number of bytes necessary as per DER.
        // But because it is written in reverse, start with the least
        // significant byte.
        uint8_t l = len & 0xff;
        size_t bytes = 0;
        do {
            // Count the bytes written for the the length header.
            ++bytes;
            n20_asn1_stream_prepend(s, &l, /*src_len=*/1);
            len >>= 8;
            l = len & 0xff;
        } while (len);

        // Finally, write the length header.
        // The length header has the msb set and the lower 7 bits hold
        // the number of additional length bytes.
        l = (bytes & 0x7f) | 0x80;
        n20_asn1_stream_prepend(s, &l, /*src_len=*/1);
    }

    // Now for the tag.
    if (tag > 30) {
        // Long tags are written as base 128 integers
        // because one can never have enough different ways to
        // encode an integer... oh well.
        n20_asn1_base128_int(s, tag);
        // The low 5 bits of the header shall be set indicating
        // a long tag.
        header = 0x1f;
    } else {
        // Short tags are encoded into the low 5 bits of the header.
        header = tag & 0x1f;
    }

    // The class is encoded in the two most significant bits of the header.
    header |= class_ << 6;
    // The sixth bit indicates whether or not the content of the
    // structure is constructed.
    if (constructed) {
        header |= 0x20;
    }

    n20_asn1_stream_prepend(s, &header, /*src_len=*/1);
}

void n20_asn1_null(n20_asn1_stream_t *const s) {
    n20_asn1_header(s, N20_ASN1_CLASS_UNIVERSAL, /*constructed=*/false, N20_ASN1_TAG_NULL, 0);
}

void n20_asn1_null_implicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag) {
    n20_asn1_header(s, N20_ASN1_CLASS_CONTEXT_SPECIFIC, /*constructed=*/false, tag, 0);
}

static void n20_asn1_object_identifier_content(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_object_identifier_t const *const oid =
        (n20_asn1_object_identifier_t const *const)context;

    // oid is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.
    size_t e = oid->elem_count;
    while (e > 2) {
        --e;
        n20_asn1_base128_int(s, oid->elements[e]);
    }

    uint8_t h = 0;
    if (e == 2) {
        h = oid->elements[1];
    }
    if (e > 0) {
        h += oid->elements[0] * 40;
    }
    n20_asn1_stream_prepend(s, &h, /*src_len=*/1);
}

void n20_asn1_object_identifier(n20_asn1_stream_t *const s,
                                n20_asn1_object_identifier_t const *const oid) {
    // If oid is a null pointer, or
    // if the element count was initialized to an out of bounds
    // value write a ASN1 NULL instead of the OID and return.
    if (NULL == oid || oid->elem_count > N20_ASN1_MAX_OID_ELEMENTS) {
        n20_asn1_null(s);
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_OBJECT_IDENTIFIER,
                                 n20_asn1_object_identifier_content,
                                 (void *)oid);
}

void n20_asn1_object_identifier_implicitly_tagged(n20_asn1_stream_t *const s,
                                                  uint32_t tag,
                                                  n20_asn1_object_identifier_t const *const oid) {
    // If oid is a null pointer, or
    // if the element count was initialized to an out of bounds
    // value write a ASN1 NULL instead of the OID and return.
    if (NULL == oid || oid->elem_count > N20_ASN1_MAX_OID_ELEMENTS) {
        n20_asn1_null_implicitly_tagged(s, tag);
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_object_identifier_content,
                                 (void *)oid);
}

static void n20_asn1_object_identifier_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_object_identifier_t const *const oid =
        (n20_asn1_object_identifier_t const *const)context;
    n20_asn1_object_identifier(s, oid);
}

void n20_asn1_object_identifier_explicitly_tagged(n20_asn1_stream_t *const s,
                                                  uint32_t tag,
                                                  n20_asn1_object_identifier_t const *const oid) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_object_identifier_explicit_wrapper,
                                 (void *)oid);
}

static void n20_asn1_integer_content(n20_asn1_stream_t *s, void *context) {
    n20_asn1_interger_t const *const integer = (n20_asn1_interger_t const *const)context;

    // integer is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.
    uint8_t const *msb = integer->n;
    uint8_t const *end = integer->n + integer->length;
    ssize_t inc = 1;
    int add_extra = 0;
    uint8_t extra = 0;

    if (integer->little_endian) {
        // If the buffer is in little endian order:
        // - flip the direction
        inc = -1;
        // - point the most significant pointer to the last byte.
        msb = end - 1;
        // - point the end pointer one position before the first byte.
        end = integer->n - 1;
        // Now the rest of the algorithm traverses the buffer in reverse order.
    }

    // DER encoding requires that we strip leading insignificant bytes.
    if (integer->two_complement && (*msb & 0x80)) {
        // Strip leading 0xff bytes if negative.
        while (*msb == 0xff && msb != end) {
            msb += inc;
        }
        // An extra 0xff byte needs to be added if the remaining
        // msb is 0 or no bytes remain (in case of -1).
        add_extra = msb == end || !(*msb & 0x80);
        extra = 0xff;
    } else {
        // Strip leading 0 bytes.
        while (*msb == 0 && msb != end) {
            msb += inc;
        }
        // An extra 0 byte needs to be added if the remaining msb
        // is 1 or no bytes remain (in case of 0).
        add_extra = msb == end || (*msb & 0x80);
    }

    while (msb != end) {
        end -= inc;
        n20_asn1_stream_prepend(s, end, /*src_len=*/1);
    }

    if (add_extra) {
        n20_asn1_stream_prepend(s, &extra, /*src_len=*/1);
    }
}

void n20_asn1_integer(n20_asn1_stream_t *s, n20_asn1_interger_t const *const integer) {
    // If the integer n is NULL, write an ASN1 NULL and return.
    if (NULL == integer || NULL == integer->n) {
        n20_asn1_null(s);
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_INTEGER,
                                 n20_asn1_integer_content,
                                 (void *)integer);
}

void n20_asn1_integer_implicitly_tagged(n20_asn1_stream_t *s,
                                        uint32_t tag,
                                        n20_asn1_interger_t const *const integer) {
    // If the integer n is NULL, write an ASN1 NULL and return.
    if (NULL == integer || NULL == integer->n) {
        n20_asn1_null_implicitly_tagged(s, tag);
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_integer_content,
                                 (void *)integer);
}

static void n20_asn1_integer_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_interger_t const *const integer = (n20_asn1_interger_t const *const)context;
    n20_asn1_integer(s, integer);
}

void n20_asn1_integer_explicitly_tagged(n20_asn1_stream_t *s,
                                        uint32_t tag,
                                        n20_asn1_interger_t const *const integer) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_integer_explicit_wrapper,
                                 (void *)integer);
}

void n20_asn1_uint64(n20_asn1_stream_t *const s, uint64_t const n) {
    n20_asn1_interger_t integer = {
        .n = (uint8_t *)&n,
        .length = sizeof(n),
        .little_endian = LITTLE_ENDIAN == BYTE_ORDER,
        .two_complement = false,
    };
    n20_asn1_integer(s, &integer);
}

void n20_asn1_uint64_implicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag, uint64_t const n) {
    n20_asn1_interger_t integer = {
        .n = (uint8_t *)&n,
        .length = sizeof(n),
        .little_endian = LITTLE_ENDIAN == BYTE_ORDER,
        .two_complement = false,
    };
    n20_asn1_integer_implicitly_tagged(s, tag, &integer);
}

void n20_asn1_uint64_explicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag, uint64_t const n) {
    n20_asn1_interger_t integer = {
        .n = (uint8_t *)&n,
        .length = sizeof(n),
        .little_endian = LITTLE_ENDIAN == BYTE_ORDER,
        .two_complement = false,
    };
    n20_asn1_integer_explicitly_tagged(s, tag, &integer);
}

void n20_asn1_int64(n20_asn1_stream_t *const s, int64_t const n) {
    n20_asn1_interger_t integer = {
        .n = (uint8_t *)&n,
        .length = sizeof(n),
        .little_endian = LITTLE_ENDIAN == BYTE_ORDER,
        .two_complement = true,
    };
    n20_asn1_integer(s, &integer);
}

void n20_asn1_int64_implicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag, int64_t const n) {
    n20_asn1_interger_t integer = {
        .n = (uint8_t *)&n,
        .length = sizeof(n),
        .little_endian = LITTLE_ENDIAN == BYTE_ORDER,
        .two_complement = true,
    };
    n20_asn1_integer_implicitly_tagged(s, tag, &integer);
}

void n20_asn1_int64_explicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag, int64_t const n) {
    n20_asn1_interger_t integer = {
        .n = (uint8_t *)&n,
        .length = sizeof(n),
        .little_endian = LITTLE_ENDIAN == BYTE_ORDER,
        .two_complement = true,
    };
    n20_asn1_integer_explicitly_tagged(s, tag, &integer);
}

static void n20_asn1_bitstring_content(n20_asn1_stream_t *s, void *context) {
    n20_asn1_bitstring_t *const bitstring = (n20_asn1_bitstring_t *const)context;

    // bitstring is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.
    // If the b is NULL, write empty bitstring;
    if (NULL == bitstring->b) {
        bitstring->bits = 0;
    }

    size_t bytes = (bitstring->bits + 7) >> 3;
    uint8_t unused = (8 - (bitstring->bits & 7)) & 7;
    if (bytes) {
        --bytes;
        uint8_t c = bitstring->b[bytes] & ~((1 << unused) - 1);
        n20_asn1_stream_prepend(s, &c, /*src_len=*/1);
        while (bytes) {
            --bytes;
            n20_asn1_stream_prepend(s, &bitstring->b[bytes], /*src_len=*/1);
        }
    }

    n20_asn1_stream_prepend(s, &unused, /*src_len=*/1);
}

void n20_asn1_bitstring(n20_asn1_stream_t *const s, n20_asn1_bitstring_t *const bitstring) {
    if (NULL == bitstring) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_BIT_STRING,
                                 n20_asn1_bitstring_content,
                                 bitstring);
}

void n20_asn1_bitstring_implicitly_tagged(n20_asn1_stream_t *const s,
                                          uint32_t tag,
                                          n20_asn1_bitstring_t *const bitstring) {
    if (NULL == bitstring) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_bitstring_content,
                                 bitstring);
}

static void n20_asn1_bitstring_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_bitstring_t *const bitstring = (n20_asn1_bitstring_t *const)context;
    n20_asn1_bitstring(s, bitstring);
}

void n20_asn1_bitstring_explicitly_tagged(n20_asn1_stream_t *const s,
                                          uint32_t tag,
                                          n20_asn1_bitstring_t *const bitstring) {
    if (NULL == bitstring) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_bitstring_explicit_wrapper,
                                 bitstring);
}

static void n20_asn1_string_content(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_string_t *const string = (n20_asn1_string_t *const)context;

    // string is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.

    // If str is null force len to be zero. And write an empty string.
    if (NULL == string->str) {
        string->length = 0;
    }
    n20_asn1_stream_prepend(s, string->str, string->length);
}

void n20_asn1_octetstring(n20_asn1_stream_t *const s, n20_asn1_string_t *const string_) {
    if (NULL == string_) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_OCTET_STRING,
                                 n20_asn1_string_content,
                                 string_);
}

void n20_asn1_octetstring_implicitly_tagged(n20_asn1_stream_t *const s,
                                            uint32_t tag,
                                            n20_asn1_string_t *const string_) {
    if (NULL == string_) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_string_content,
                                 string_);
}

static void n20_asn1_octetstring_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_string_t *const string_ = (n20_asn1_string_t *const)context;
    n20_asn1_octetstring(s, string_);
}

void n20_asn1_octetstring_explicitly_tagged(n20_asn1_stream_t *const s,
                                            uint32_t tag,
                                            n20_asn1_string_t *const string_) {
    if (NULL == string_) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_octetstring_explicit_wrapper,
                                 string_);
}

void n20_asn1_printablestring(n20_asn1_stream_t *const s, char const *const str) {
    n20_asn1_string_t string_ = {
        .str = (uint8_t const *)str,
        .length = NULL == str ? 0 : strlen(str),
    };
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_PRINTABLE_STRING,
                                 n20_asn1_string_content,
                                 &string_);
}

void n20_asn1_printablestring_implicitly_tagged(n20_asn1_stream_t *const s,
                                                uint32_t tag,
                                                char const *const str) {
    n20_asn1_string_t string_ = {
        .str = (uint8_t const *)str,
        .length = NULL == str ? 0 : strlen(str),
    };
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_string_content,
                                 &string_);
}

static void n20_asn1_printablestring_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    char const *const str = (char *const)context;
    n20_asn1_printablestring(s, str);
}

void n20_asn1_printablestring_explicitly_tagged(n20_asn1_stream_t *const s,
                                                uint32_t tag,
                                                char const *const str) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_printablestring_explicit_wrapper,
                                 (void *)str);
}

void n20_asn1_generalized_time(n20_asn1_stream_t *const s, char const *const time_str) {
    if (time_str == NULL) {
        n20_asn1_null(s);
        return;
    }

    n20_asn1_string_t string_ = {
        .str = (uint8_t const *)time_str,
        .length = strlen(time_str),
    };
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_GENERALIZED_TIME,
                                 n20_asn1_string_content,
                                 &string_);
}

void n20_asn1_generalized_time_implicitly_tagged(n20_asn1_stream_t *const s,
                                                 uint32_t tag,
                                                 char const *const time_str) {
    if (time_str == NULL) {
        n20_asn1_null_implicitly_tagged(s, tag);
        return;
    }

    n20_asn1_string_t string_ = {
        .str = (uint8_t const *)time_str,
        .length = strlen(time_str),
    };
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_string_content,
                                 &string_);
}

static void n20_asn1_generalized_time_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    char *const str = (char *const)context;
    n20_asn1_generalized_time(s, str);
}

void n20_asn1_generalized_time_explicitly_tagged(n20_asn1_stream_t *const s,
                                                 uint32_t tag,
                                                 char const *const str) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_generalized_time_explicit_wrapper,
                                 (void *)str);
}

void n20_asn1_header_with_content(n20_asn1_stream_t *const s,
                                  n20_asn1_class_t const class_,
                                  bool const constructed,
                                  uint32_t const tag,
                                  n20_asn1_content_cb_t content_cb,
                                  void *cb_context) {
    size_t content_size = n20_asn1_stream_data_written(s);
    if (content_cb != NULL) {
        content_cb(s, cb_context);
    }
    content_size = n20_asn1_stream_data_written(s) - content_size;
    n20_asn1_header(s, class_, constructed, tag, content_size);
}

void n20_asn1_sequence(n20_asn1_stream_t *const s, n20_asn1_sequence_t *const sequence) {
    if (NULL == sequence) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/true,
                                 N20_ASN1_TAG_SEQUENCE,
                                 sequence->content_cb,
                                 sequence->cb_context);
}

void n20_asn1_sequence_implicitly_tagged(n20_asn1_stream_t *const s,
                                         uint32_t tag,
                                         n20_asn1_sequence_t *const sequence) {
    if (NULL == sequence) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 sequence->content_cb,
                                 sequence->cb_context);
}

static void n20_asn1_sequence_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    n20_asn1_sequence_t *const sequence = (n20_asn1_sequence_t *const)context;
    n20_asn1_sequence(s, sequence);
}

void n20_asn1_sequence_explicitly_tagged(n20_asn1_stream_t *const s,
                                         uint32_t tag,
                                         n20_asn1_sequence_t *const sequence) {
    if (NULL == sequence) {
        return;
    }
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_sequence_explicit_wrapper,
                                 sequence);
}

static void n20_asn1_boolean_content(n20_asn1_stream_t *const s, void *context) {
    // context is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.
    bool v = *(bool *)context;

    uint8_t buffer[1] = {v ? 0xff : 0x00};
    n20_asn1_stream_prepend(s, &buffer[0], /*src_len=*/1);
}

void n20_asn1_boolean(n20_asn1_stream_t *const s, bool v) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_BOOLEAN,
                                 n20_asn1_boolean_content,
                                 &v);
}

void n20_asn1_boolean_implicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag, bool v) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_boolean_content,
                                 &v);
}

static void n20_asn1_boolean_explicit_wrapper(n20_asn1_stream_t *const s, void *context) {
    // context is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.
    bool v = *(bool *)context;
    n20_asn1_boolean(s, v);
}

void n20_asn1_boolean_explicitly_tagged(n20_asn1_stream_t *const s, uint32_t tag, bool v) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                                 /*constructed=*/true,
                                 tag,
                                 n20_asn1_boolean_explicit_wrapper,
                                 &v);
}
