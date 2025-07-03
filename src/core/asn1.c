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

#ifdef __AVR__
#define BYTE_ORDER 0xaa55
#define LITTLE_ENDIAN 0xaa55
#define BIG_ENDIAN 0x55aa
#else
#include <endian.h>
#endif
#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <stdbool.h>
#include <string.h>

void n20_asn1_base128_int(n20_stream_t *const s, uint64_t n) {
    // The integer n is written 7 bits at a time starting with the least
    // significant bits (because we are writing in reverse!). This
    // byte has the msb unset, because it terminates the sequence.
    uint8_t t = n & 0x7f;
    do {
        n20_stream_prepend(s, &t, /*src_len=*/1);
        n >>= 7;
        // All following bytes now have have the msb set indicating that
        // more bytes follow.
        t = 0x80 | (n & 0x7f);
    } while (n);
}

n20_asn1_tag_info_t n20_asn1_tag_info_no_override(void) {
    n20_asn1_tag_info_t ret = {.type = n20_asn1_tag_info_no_override_e, .tag = 0};
    return ret;
}

n20_asn1_tag_info_t n20_asn1_tag_info_explicit(int tag) {
    n20_asn1_tag_info_t ret = {.type = n20_asn1_tag_info_explicit_e, .tag = tag};
    return ret;
}

n20_asn1_tag_info_t n20_asn1_tag_info_implicit(int tag) {
    n20_asn1_tag_info_t ret = {.type = n20_asn1_tag_info_implicit_e, .tag = tag};
    return ret;
}

void n20_asn1_header(n20_stream_t *const s,
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
        n20_stream_prepend(s, &l, /*src_len=*/1);
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
            n20_stream_prepend(s, &l, /*src_len=*/1);
            len >>= 8;
            l = len & 0xff;
        } while (len);

        // Finally, write the length header.
        // The length header has the msb set and the lower 7 bits hold
        // the number of additional length bytes.
        l = (bytes & 0x7f) | 0x80;
        n20_stream_prepend(s, &l, /*src_len=*/1);
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

    n20_stream_prepend(s, &header, /*src_len=*/1);
}

void n20_asn1_null(n20_stream_t *const s, n20_asn1_tag_info_t const tag_info) {
    uint32_t tag = N20_ASN1_TAG_NULL;
    uint32_t class_ = N20_ASN1_CLASS_UNIVERSAL;
    if (tag_info.type == n20_asn1_tag_info_implicit_e) {
        tag = tag_info.tag;
        class_ = N20_ASN1_CLASS_CONTEXT_SPECIFIC;
    }
    size_t mark = n20_stream_byte_count(s);
    n20_asn1_header(s, class_, /*constructed=*/false, tag, /*len=*/0);

    if (tag_info.type == n20_asn1_tag_info_explicit_e) {
        n20_asn1_header(s,
                        N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                        /*constructed=*/true,
                        tag_info.tag,
                        n20_stream_byte_count(s) - mark);
    }
}

static void n20_asn1_object_identifier_content(n20_stream_t *const s, void *ctx) {
    /* ctx must not be NULL. Since this function is static
       all call sites are in this compilation unit and must
       not call this function with a NULL argument. */
    n20_asn1_object_identifier_t const *oid = ctx;

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
    n20_stream_prepend(s, &h, /*src_len=*/1);
}

void n20_asn1_object_identifier(n20_stream_t *const s,
                                n20_asn1_object_identifier_t const *const oid,
                                n20_asn1_tag_info_t const tag_info) {
    // If oid is a null pointer, or
    // if the element count was initialized to an out of bounds
    // value write a ASN1 NULL instead of the OID and return.
    if (oid == NULL || oid->elem_count > N20_ASN1_MAX_OID_ELEMENTS) {
        n20_asn1_null(s, n20_asn1_tag_info_no_override());
        return;
    }

    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_OBJECT_IDENTIFIER,
                                 n20_asn1_object_identifier_content,
                                 (void *)oid,
                                 tag_info);
}

struct n20_asn1_number_s {
    n20_slice_t n;
    bool little_endian;
    bool two_complement;
};

static void n20_asn1_integer_internal_content(n20_stream_t *const s, void *ctx) {
    struct n20_asn1_number_s const *number = ctx;

    // n is never NULL because all of the call sites are in this
    // compilation unit and assure that it is never NULL.
    uint8_t const *msb = number->n.buffer;
    uint8_t const *end = number->n.buffer + number->n.size;
    int inc = 1;
    int add_extra = 0;
    uint8_t extra = 0;

    if (number->little_endian) {
        // If the buffer is in little endian order:
        // - flip the direction
        inc = -1;
        // - point the most significant pointer to the last byte.
        msb = end - 1;
        // - point the end pointer one position before the first byte.
        end = number->n.buffer - 1;
        // Now the rest of the algorithm traverses the buffer in reverse order.
    }

    // DER encoding requires that we strip leading insignificant bytes.
    if (number->two_complement && (*msb & 0x80)) {
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
        n20_stream_prepend(s, end, /*src_len=*/1);
    }

    if (add_extra) {
        n20_stream_prepend(s, &extra, /*src_len=*/1);
    }
}

void n20_asn1_integer(n20_stream_t *const s,
                      n20_slice_t const n,
                      bool const little_endian,
                      bool const two_complement,
                      n20_asn1_tag_info_t const tag_info) {
    // If the integer n is NULL, write an ASN1 NULL and return.
    if (n.buffer == NULL) {
        n20_asn1_null(s, n20_asn1_tag_info_no_override());
        return;
    }

    struct n20_asn1_number_s number = {
        .n = n,
        .little_endian = little_endian,
        .two_complement = two_complement,
    };

    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_INTEGER,
                                 n20_asn1_integer_internal_content,
                                 &number,
                                 tag_info);
}

void n20_asn1_uint64(n20_stream_t *const s, uint64_t const n, n20_asn1_tag_info_t const tag_info) {
    n20_asn1_integer(s,
                     (n20_slice_t){sizeof(n), (uint8_t const *)&n},
                     LITTLE_ENDIAN == BYTE_ORDER,
                     /*two_complement=*/false,
                     tag_info);
}

void n20_asn1_int64(n20_stream_t *const s, int64_t const n, n20_asn1_tag_info_t const tag_info) {
    n20_asn1_integer(s,
                     (n20_slice_t){sizeof(n), (uint8_t const *)&n},
                     LITTLE_ENDIAN == BYTE_ORDER,
                     /*two_complement=*/true,
                     tag_info);
}

struct n20_asn1_bitstring_slice_s {
    uint8_t const *buffer;
    size_t bits;
};

static void n20_asn1_bitstring_content(n20_stream_t *const s, void *ctx) {
    struct n20_asn1_bitstring_slice_s *bit_slice = ctx;
    size_t bits = 0;
    uint8_t const *b = NULL;

    // If the bitstring is NULL, write empty bitstring;
    if (bit_slice != NULL && bit_slice->buffer != NULL) {
        bits = bit_slice->bits;
        b = bit_slice->buffer;
    }

    size_t bytes = (bits + 7) >> 3;
    uint8_t unused = (8 - (bits & 7)) & 7;

    if (bytes) {
        --bytes;
        uint8_t c = b[bytes] & ~((1 << unused) - 1);
        n20_stream_prepend(s, &c, /*src_len=*/1);
        while (bytes) {
            --bytes;
            n20_stream_prepend(s, &b[bytes], /*src_len=*/1);
        }
    }

    n20_stream_prepend(s, &unused, /*src_len=*/1);
}

void n20_asn1_bitstring(n20_stream_t *const s,
                        uint8_t const *const b,
                        size_t bits,
                        n20_asn1_tag_info_t const tag_info) {

    struct n20_asn1_bitstring_slice_s bit_slice = {
        .bits = bits,
        .buffer = b,
    };

    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_BIT_STRING,
                                 n20_asn1_bitstring_content,
                                 &bit_slice,
                                 tag_info);
}

static void n20_asn1_stringish_content(n20_stream_t *const s, void *ctx) {
    n20_slice_t const *slice = (n20_slice_t const *)ctx;
    if (slice != NULL && slice->buffer != NULL) {
        n20_stream_prepend(s, slice->buffer, slice->size);
    }
}

static void n20_asn1_stringish(n20_stream_t *const s,
                               uint32_t tag,
                               n20_slice_t const *const slice,
                               n20_asn1_tag_info_t const tag_info) {

    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 tag,
                                 n20_asn1_stringish_content,
                                 (void *)slice,
                                 tag_info);
}

void n20_asn1_octetstring(n20_stream_t *const s,
                          n20_slice_t const *const slice,
                          n20_asn1_tag_info_t const tag_info) {
    n20_asn1_stringish(s, N20_ASN1_TAG_OCTET_STRING, slice, tag_info);
}

void n20_asn1_printablestring(n20_stream_t *const s,
                              n20_string_slice_t const *const str,
                              n20_asn1_tag_info_t const tag_info) {
    n20_slice_t slice = N20_SLICE_NULL;
    if (str != NULL) {
        slice.buffer = (uint8_t *)str->buffer;
        slice.size = str->size;
    }
    n20_asn1_stringish(s, N20_ASN1_TAG_PRINTABLE_STRING, &slice, tag_info);
}

void n20_asn1_utf8_string(n20_stream_t *const s,
                          n20_string_slice_t const *const str,
                          n20_asn1_tag_info_t const tag_info) {
    n20_slice_t slice = N20_SLICE_NULL;
    if (str != NULL) {
        slice.buffer = (uint8_t *)str->buffer;
        slice.size = str->size;
    }
    n20_asn1_stringish(s, N20_ASN1_TAG_UTF8_STRING, &slice, tag_info);
}

void n20_asn1_generalized_time(n20_stream_t *const s,
                               n20_string_slice_t const *const time_str,
                               n20_asn1_tag_info_t const tag_info) {
    if (time_str == NULL) {
        n20_asn1_null(s, n20_asn1_tag_info_no_override());
        return;
    }
    n20_slice_t const slice = {
        .buffer = (uint8_t *)time_str->buffer,
        .size = time_str->size,
    };
    n20_asn1_stringish(s, N20_ASN1_TAG_GENERALIZED_TIME, &slice, tag_info);
}

void n20_asn1_header_with_content(n20_stream_t *const s,
                                  n20_asn1_class_t class_,
                                  bool const constructed,
                                  uint32_t tag,
                                  n20_asn1_content_cb_t content_cb,
                                  void *cb_context,
                                  n20_asn1_tag_info_t const tag_info) {
    size_t mark = n20_stream_byte_count(s);
    if (content_cb != NULL) {
        content_cb(s, cb_context);
    }

    if (tag_info.type == n20_asn1_tag_info_implicit_e) {
        // If there is an implicit tag override, ignore
        // the class and tag and replace it with the override.
        class_ = N20_ASN1_CLASS_CONTEXT_SPECIFIC;
        tag = tag_info.tag;
    }

    n20_asn1_header(s, class_, constructed, tag, n20_stream_byte_count(s) - mark);

    if (tag_info.type == n20_asn1_tag_info_explicit_e) {
        // If there is an explicit tag info, add another
        // context specific tag header to the previously finalized structure.
        n20_asn1_header(s,
                        N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                        /*constructed=*/true,
                        tag_info.tag,
                        n20_stream_byte_count(s) - mark);
    }
}

void n20_asn1_sequence(n20_stream_t *const s,
                       n20_asn1_content_cb_t content_cb,
                       void *cb_context,
                       n20_asn1_tag_info_t const tag_info) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/true,
                                 N20_ASN1_TAG_SEQUENCE,
                                 content_cb,
                                 cb_context,
                                 tag_info);
}

static void n20_asn1_boolean_content(n20_stream_t *const s, void *ctx) {
    bool *v = ctx;
    uint8_t c = (v != NULL && *v) ? 0xff : 0x00;

    n20_stream_prepend(s, &c, 1);
}

void n20_asn1_boolean(n20_stream_t *const s, bool const v, n20_asn1_tag_info_t const tag_info) {
    n20_asn1_header_with_content(s,
                                 N20_ASN1_CLASS_UNIVERSAL,
                                 /*constructed=*/false,
                                 N20_ASN1_TAG_BOOLEAN,
                                 n20_asn1_boolean_content,
                                 (void *)&v,
                                 tag_info);
}
