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
#include <string.h>

void n20_asn1_stream_init(struct n20_asn1_stream *s,
                          uint8_t *const buffer,
                          size_t const buffer_size) {
    s->begin = buffer;
    s->end = buffer + buffer_size;
    s->pos = s->end;
    s->bad = 0;
}

n20_asn1_bool_t n20_asn1_stream_is_good(struct n20_asn1_stream const *const s) { return !s->bad; }

// This function always returns the correct amount of data
// that was written to the stream even if the stream is bad.
// If the stream was bad it means that the stream ran out
// of buffer. In this case the return value of this function
// can be used to allocate a new buffer and initialize a new
// stream that will fit the data.
size_t n20_asn1_stream_data_written(struct n20_asn1_stream const *const s) {
    return s->end - s->pos;
}

// Returns a pointer to the begging of the written region of the buffer.
// IMPORTANT it is only safe to dereference the returned pointer if
// n20_asn1_stream_is_good returns a non zero value. Also the access must be
// within the range [p, p + n20_asn1_stream_data_written) where p is the
// return value of this function.
uint8_t const *n20_asn1_stream_data(struct n20_asn1_stream const *const s) { return s->pos; }

// This function never fails. It might not write to the stream
// because it ran out of buffer, however, the stream position will
// be updated so that the required space can be read from the
// stream state later.
void n20_asn1_stream_prepend(n20_asn1_stream_t *const s,
                             uint8_t const *const src,
                             size_t const src_len) {
    // Mark the stream as bad if it was bad or if the next write.
    // will overflow the buffer.
    s->bad = s->bad || ((size_t)(s->pos - s->begin) < src_len);
    // The write position shall be moved unconditionally,
    // because we use this to calculate the required size later.
    s->pos -= src_len;
    // If the stream is good we can write at the new position.
    if (!s->bad) {
        memcpy(s->pos, src, src_len);
    }
}

void n20_asn1_stream_put(n20_asn1_stream_t *const s, uint8_t const c) {
    n20_asn1_stream_prepend(s, &c, 1);
}

void n20_asn1_base128_int(n20_asn1_stream_t *const s, uint64_t n) {
    // The integer n is written 7 bits at a time starting with the least
    // significant bits (because we are writing in reverse!). This
    // byte has the msb unset, because it terminates the sequence.
    uint8_t t = n & 0x7f;
    do {
        n20_asn1_stream_prepend(s, &t, 1);
        n >>= 7;
        // All following bytes have have the msb set indicating that
        // more bytes follow.
        t = 0x80 | (n & 0x7f);
    } while (n);
}

void n20_asn1_header(n20_asn1_stream_t *const s,
                     n20_asn1_class_t const class_,
                     n20_asn1_bool_t const constructed,
                     uint32_t const tag,
                     size_t len) {
    uint8_t header = 0;
    // The header is written backwards, so the first thing written
    // is the length.
    if (len <= 127) {
        // If the length is is less than 128, it is encoded
        // in a single byte with the msb cleared.
        uint8_t l = len;
        n20_asn1_stream_prepend(s, &l, 1);
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
            n20_asn1_stream_prepend(s, &l, 1);
            len >>= 8;
            l = len & 0xff;
        } while (len);

        // Finally, write the length header.
        // The length header has the msb set and the lower 7 bits hold
        // the number of additional length bytes.
        l = (bytes & 0x7f) | 0x80;
        n20_asn1_stream_prepend(s, &l, 1);
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

    n20_asn1_stream_prepend(s, &header, 1);
}

N20_ASN1_DEFINE_OID(OID_RSA_ENCRYPTION, 1, 2, 840, 113549, 1, 1, 1);
N20_ASN1_DEFINE_OID(OID_SHA256_WITH_RSA_ENC, 1, 2, 840, 113549, 1, 1, 11);

N20_ASN1_DEFINE_OID(OID_LOCALITY_NAME, 2, 5, 4, 7);
N20_ASN1_DEFINE_OID(OID_COUNTRY_NAME, 2, 5, 4, 6);
N20_ASN1_DEFINE_OID(OID_STATE_OR_PROVINCE_NAME, 2, 5, 4, 8);
N20_ASN1_DEFINE_OID(OID_ORGANIZATION_NAME, 2, 5, 4, 10);
N20_ASN1_DEFINE_OID(OID_ORGANIZATION_UNIT_NAME, 2, 5, 4, 11);
N20_ASN1_DEFINE_OID(OID_COMMON_NAME, 2, 5, 4, 3);

N20_ASN1_DEFINE_OID(OID_BASIC_CONSTRAINTS, 2, 5, 29, 19);
N20_ASN1_DEFINE_OID(OID_KEY_USAGE, 2, 5, 29, 15);

struct n20_asn1_object_identifier test_oid = N20_ASN1_OBJECT_ID(1, 2, 840, 113549);

void n20_asn1_null(n20_asn1_stream_t *const s) {
    n20_asn1_header(s, N20_ASN1_CLASS_UNIVERSAL, 0, N20_ASN1_TAG_NULL, 0);
}

void n20_asn1_object_identifier(n20_asn1_stream_t *const s,
                                struct n20_asn1_object_identifier const *const oid) {
    size_t e = oid->elem_count;
    size_t content_size = n20_asn1_stream_data_written(s);
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
    n20_asn1_stream_prepend(s, &h, 1);

    content_size = n20_asn1_stream_data_written(s) - content_size;

    n20_asn1_header(
        s, N20_ASN1_CLASS_UNIVERSAL, 0, N20_ASN1_TAG_N20_ASN1_OBJECT_IDENTIFIER, content_size);
}

void n20_asn1_integer_internal(n20_asn1_stream_t *const s,
                               uint8_t const *const n,
                               size_t const len,
                               n20_asn1_bool_t const little_endian,
                               n20_asn1_bool_t const unsigned_) {
    uint8_t const *msb = n;
    uint8_t const *end = n + len;
    ssize_t inc = 1;
    int add_extra = 0;
    uint8_t extra = 0;

    if (little_endian) {
        // If the buffer is in little endian order:
        // - flip the direction
        inc = -1;
        // - point the most significant pointer to the last byte.
        msb = end - 1;
        // - point the end pointer one position before the first byte.
        end = n - 1;
        // Now the rest of the algorithm traverses the buffer in reverse order.
    }

    // DER encoding requires that we strip leading insignificant bytes.
    if (!unsigned_ && (*msb & 0x80)) {
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
        add_extra = msb == end || !!(*msb & 0x80);
    }

    while (msb != end) {
        end -= inc;
        n20_asn1_stream_prepend(s, end, 1);
    }

    if (add_extra) {
        n20_asn1_stream_prepend(s, &extra, 1);
    }
}

void n20_asn1_integer(n20_asn1_stream_t *const s,
                      uint8_t const *const n,
                      size_t const len,
                      n20_asn1_bool_t const little_endian,
                      n20_asn1_bool_t const unsigned_) {
    size_t content_size = n20_asn1_stream_data_written(s);
    n20_asn1_integer_internal(s, n, len, little_endian, unsigned_);
    content_size = n20_asn1_stream_data_written(s) - content_size;
    n20_asn1_header(s, N20_ASN1_CLASS_UNIVERSAL, 0, N20_ASN1_TAG_INTEGER, content_size);
}

void n20_asn1_uint64(n20_asn1_stream_t *const s, uint64_t const n) {
    n20_asn1_integer(s, (uint8_t *)&n, sizeof(n), LITTLE_ENDIAN == BYTE_ORDER, 1 /* unsigned */);
}

void n20_asn1_int64(n20_asn1_stream_t *const s, int64_t const n) {
    n20_asn1_integer(s, (uint8_t *)&n, sizeof(n), LITTLE_ENDIAN == BYTE_ORDER, 0 /* unsigned */);
}

void n20_asn1_bitstring(n20_asn1_stream_t *const s, uint8_t const *const b, size_t const bits) {
    size_t bytes = (bits + 7) >> 3;
    uint8_t unused = (8 - (8 + (bits & 7))) & 7;

    size_t content_size = n20_asn1_stream_data_written(s);

    if (bytes) {
        --bytes;
        uint8_t c = b[bytes] & ~((1 << unused) - 1);
        n20_asn1_stream_prepend(s, &c, 1);
        while (bytes) {
            --bytes;
            n20_asn1_stream_prepend(s, &b[bytes], 1);
        }
    }

    n20_asn1_stream_prepend(s, &unused, 1);

    content_size = n20_asn1_stream_data_written(s) - content_size;

    n20_asn1_header(s, N20_ASN1_CLASS_UNIVERSAL, 0, N20_ASN1_TAG_BIT_STRING, content_size);
}

void n20_asn1_stringish(n20_asn1_stream_t *const s,
                        uint32_t tag,
                        uint8_t const *const str,
                        size_t const len) {
    size_t content_size = n20_asn1_stream_data_written(s);
    n20_asn1_stream_prepend(s, str, len);
    content_size = n20_asn1_stream_data_written(s) - content_size;
    n20_asn1_header(s, N20_ASN1_CLASS_UNIVERSAL, 0, tag, content_size);
}

void n20_asn1_octetstring(n20_asn1_stream_t *const s, uint8_t const *const str, size_t const len) {
    n20_asn1_stringish(s, N20_ASN1_TAG_OCTET_STRING, str, len);
}

void n20_asn1_printablestring(n20_asn1_stream_t *const s, char const *const str) {
    n20_asn1_stringish(s, N20_ASN1_TAG_PRINTABLE_STRING, (uint8_t const *const)str, strlen(str));
}

void n20_asn1_generalized_time(n20_asn1_stream_t *const s, char const *const time_str) {
    n20_asn1_stringish(
        s, N20_ASN1_TAG_GENERALIZED_TIME, (uint8_t const *)time_str, strlen(time_str));
}

typedef void(n20_asn1_content_cb_t)(n20_asn1_stream_t *const, void *);

void n20_asn1_header_with_content(n20_asn1_stream_t *const s,
                                  n20_asn1_class_t const class_,
                                  n20_asn1_bool_t const constructed,
                                  uint32_t const tag,
                                  n20_asn1_content_cb_t content_cb,
                                  void *cb_context) {
    size_t content_size = n20_asn1_stream_data_written(s);
    content_cb(s, cb_context);
    content_size = n20_asn1_stream_data_written(s) - content_size;
    n20_asn1_header(s, class_, constructed, tag, content_size);
}

void n20_asn1_sequence(n20_asn1_stream_t *const s,
                       n20_asn1_content_cb_t content_cb,
                       void *cb_context) {
    n20_asn1_header_with_content(
        s, N20_ASN1_CLASS_UNIVERSAL, 1, N20_ASN1_TAG_SEQUENCE, content_cb, cb_context);
}

void n20_asn1_boolean(n20_asn1_stream_t *const s, n20_asn1_bool_t const v) {
    uint8_t buffer[3] = {0x01, 0x01, 0};
    buffer[2] = v ? 0xff : 0x00;
    n20_asn1_stream_prepend(s, &buffer[0], 3);
}
