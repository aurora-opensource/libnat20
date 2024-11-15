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

#include <nat20/asn1.h>
#include <nat20/x509.h>

void n20_x509_rdn_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_rdn_t const *rdn = (n20_x509_rdn_t const *)context;

    n20_asn1_printablestring(s, rdn->value);
    n20_asn1_object_identifier(s, rdn->type);
}

void n20_x509_rdn(n20_asn1_stream_t *const s, n20_x509_rdn_t const *rdn) {
    size_t mark = n20_asn1_stream_data_written(s);
    n20_asn1_sequence(s, n20_x509_rdn_content, (void *)rdn);
    n20_asn1_header(
        s, N20_ASN1_CLASS_UNIVERSAL, 1, N20_ASN1_TAG_SET, n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_name_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_name_t const *name = context;

    for (size_t i = 0; i < name->element_count; ++i) {
        n20_x509_rdn(s, &name->elements[name->element_count - (i + 1)]);
    }
}

void n20_x509_name(n20_asn1_stream_t *const s, n20_x509_name_t const *name) {
    n20_asn1_sequence(s, n20_x509_name_content, (void *)name);
}

const uint8_t public_key_info[] = {
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbf, 0xf8, 0x2d, 0x06, 0xf7, 0xa1, 0xc8,
    0x0c, 0xf6, 0x72, 0xf5, 0xbe, 0x3e, 0x67, 0xa8, 0x24, 0xbd, 0x4b, 0x41, 0x4a, 0xf9, 0xa6, 0x11,
    0xf1, 0xfd, 0x1b, 0xc4, 0x6f, 0xca, 0xcc, 0x2f, 0x08, 0xe7, 0xe3, 0xd7, 0x4a, 0xf4, 0x61, 0xa0,
    0x66, 0x9b, 0x77, 0xdc, 0x0b, 0xc2, 0x85, 0xa6, 0x77, 0xfd, 0x3b, 0x4c, 0x8f, 0x77, 0x97, 0x6e,
    0x74, 0xf3, 0xc9, 0x39, 0x5f, 0xb5, 0xda, 0xd5, 0xb3, 0xa4, 0x19, 0x45, 0x37, 0xea, 0x4f, 0x74,
    0x7f, 0x11, 0x11, 0x96, 0x88, 0xdd, 0x6a, 0x72, 0xe7, 0x84, 0x97, 0x24, 0x67, 0x83, 0x52, 0xb8,
    0xc2, 0xf2, 0xfc, 0x2d, 0xc1, 0x87, 0x3f, 0x5a, 0x5c, 0xdb, 0x6a, 0x6c, 0x75, 0x4e, 0x74, 0x14,
    0x7b, 0xfa, 0xef, 0xd1, 0xed, 0x24, 0x62, 0x37, 0x96, 0x34, 0x2c, 0xdb, 0x2d, 0x2e, 0xa9, 0x04,
    0x44, 0xb2, 0x04, 0x5a, 0xff, 0x05, 0xe3, 0x6d, 0x2d, 0xe8, 0x36, 0x61, 0x61, 0x76, 0xbc, 0xee,
    0xbe, 0xa3, 0x30, 0x26, 0x38, 0x3c, 0x7f, 0x79, 0xd0, 0x52, 0xb3, 0xe0, 0xf4, 0x64, 0x84, 0x7c,
    0x97, 0x0b, 0x80, 0x8c, 0x42, 0x60, 0xdf, 0x4f, 0x15, 0xf9, 0x6d, 0xa7, 0xb1, 0xff, 0xc6, 0x53,
    0x92, 0x1c, 0x94, 0x3a, 0x64, 0xfe, 0x74, 0xf3, 0x80, 0x41, 0x0a, 0x13, 0x66, 0xbb, 0x3d, 0x4f,
    0x0a, 0xd6, 0x8d, 0x63, 0xd2, 0x77, 0x3a, 0x64, 0xf8, 0xd6, 0x29, 0x18, 0x31, 0x88, 0xe9, 0x34,
    0xd3, 0x00, 0x6a, 0xf1, 0x89, 0xc7, 0xb4, 0x41, 0x85, 0x3f, 0x77, 0x0a, 0x77, 0xc7, 0xa8, 0x5a,
    0xdb, 0x38, 0x3f, 0x4d, 0xe6, 0xa3, 0x8d, 0x5e, 0x90, 0x25, 0xbe, 0x22, 0x1f, 0xb1, 0x0f, 0x7a,
    0x13, 0x60, 0xaf, 0x0f, 0xb9, 0x2a, 0xfe, 0x5c, 0x52, 0xc8, 0x9d, 0xc1, 0xd3, 0x4c, 0xf3, 0xb0,
    0xbc, 0xd7, 0x12, 0x77, 0x15, 0x79, 0xb0, 0xc8, 0xf1, 0x02, 0x03, 0x01, 0x00, 0x01};

const uint8_t signature[] = {
    0x82, 0x00, 0x47, 0x34, 0xf1, 0x67, 0x75, 0x84, 0x34, 0x48, 0xbe, 0x11, 0x9f, 0x04, 0xdc, 0x2e,
    0xd9, 0xa2, 0x82, 0xd7, 0x4d, 0xf7, 0xf0, 0xc8, 0x93, 0x01, 0x20, 0xea, 0x1e, 0xa8, 0x03, 0x50,
    0x57, 0x67, 0x82, 0x39, 0xdc, 0xda, 0x5e, 0x44, 0x03, 0xb3, 0xf2, 0x2b, 0xee, 0xa8, 0x8b, 0x00,
    0xda, 0x37, 0x57, 0x60, 0x61, 0xbc, 0x8f, 0x38, 0xf8, 0xb5, 0x3f, 0x03, 0x5d, 0x1a, 0x85, 0x9d,
    0xd2, 0x9b, 0x34, 0xdf, 0xcf, 0x09, 0x22, 0xa5, 0x62, 0x24, 0x59, 0x4f, 0xc2, 0xd4, 0x47, 0x56,
    0xe5, 0x7a, 0xa3, 0xf6, 0xa4, 0x1c, 0x3e, 0x93, 0x05, 0x9c, 0xe2, 0x12, 0xc6, 0x00, 0xa1, 0xd4,
    0xeb, 0x98, 0xa6, 0x60, 0x76, 0xb9, 0x40, 0x91, 0x2f, 0x90, 0x5e, 0x1d, 0x47, 0xf3, 0xc8, 0xcc,
    0x5a, 0xb1, 0x15, 0xad, 0xf5, 0x80, 0xab, 0xc9, 0x4b, 0x61, 0xa4, 0x38, 0x5a, 0x86, 0x40, 0x5c,
    0x0c, 0xe4, 0x88, 0x93, 0xaa, 0xcf, 0xb2, 0x5c, 0xda, 0xc1, 0xea, 0xf4, 0xef, 0xf4, 0x3e, 0xc5,
    0x34, 0x80, 0xd6, 0x62, 0xd0, 0x54, 0x83, 0x24, 0x8e, 0x10, 0x42, 0x02, 0x9a, 0x42, 0x61, 0x0b,
    0x23, 0x90, 0x56, 0x89, 0x8d, 0xb7, 0x3f, 0x89, 0x6b, 0xb5, 0xc4, 0x07, 0x08, 0x1b, 0xd7, 0x12,
    0x92, 0x73, 0xb5, 0x0e, 0x1b, 0x93, 0x36, 0x36, 0x6e, 0x69, 0x49, 0xb2, 0x4f, 0x71, 0x15, 0x5c,
    0xb3, 0x0b, 0x9f, 0x35, 0x79, 0x73, 0x57, 0x90, 0x82, 0xe6, 0x88, 0x4b, 0xf7, 0xc2, 0x2a, 0xd7,
    0x57, 0x1c, 0x06, 0x46, 0x53, 0x4a, 0x57, 0x59, 0x71, 0x99, 0xf8, 0xd7, 0x31, 0x1b, 0x06, 0xb1,
    0xd3, 0xad, 0xd0, 0x8a, 0x14, 0xe2, 0xd7, 0x8d, 0xe5, 0xa0, 0x0b, 0x46, 0xcc, 0x5f, 0x4b, 0xf9,
    0x70, 0xb7, 0xd2, 0x0b, 0xf2, 0x3b, 0x65, 0x3c, 0xaa, 0x88, 0x61, 0xb8, 0x3a, 0xc3, 0xa2, 0x79};

n20_x509_name_t subject_name =
    N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                  N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"),
                  N20_X509_RDN(&OID_ORGANIZATION_NAME, "Aurora Innovation Inc"),
                  N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Aurora Information Security"),
                  N20_X509_RDN(&OID_COMMON_NAME, "Aurora DICE Authority"), );

void n20_x509_extension_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_extensions_t const *exts = context;

    if (!exts || !exts->extensions || exts->extensions_count == 0) {
        return;
    }

    size_t mark = 0;

    for (size_t i = 0; i < exts->extensions_count; ++i) {
        n20_x509_extension_t const *ext = &exts->extensions[exts->extensions_count - (i + 1)];

        mark = n20_asn1_stream_data_written(s);

        ext->content_cb(s, ext->context);

        n20_asn1_header(s,
                        N20_ASN1_CLASS_UNIVERSAL,
                        0,
                        N20_ASN1_TAG_OCTET_STRING,
                        n20_asn1_stream_data_written(s) - mark);
        if (ext->critical) {
            n20_asn1_boolean(s, 1);
        }

        n20_asn1_object_identifier(s, ext->oid);

        n20_asn1_header(s,
                        N20_ASN1_CLASS_UNIVERSAL,
                        1,
                        N20_ASN1_TAG_SEQUENCE,
                        n20_asn1_stream_data_written(s) - mark);
    }
}

void n20_x509_extension(n20_asn1_stream_t *const s, n20_x509_extensions_t const *exts) {
    size_t mark = n20_asn1_stream_data_written(s);

    n20_asn1_sequence(s, n20_x509_extension_content, (void *)exts);

    // Extensions have an explicit tag 3.
    n20_asn1_header(
        s, N20_ASN1_CLASS_CONTEXT_SPECIFIC, 1, 3, n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_ext_basic_constraints_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_ext_basic_constraints_t const *basic_constraints = context;

    size_t mark = n20_asn1_stream_data_written(s);
    n20_asn1_uint64(s, basic_constraints->path_length);
    if (basic_constraints->is_ca) {
        n20_asn1_boolean(s, 1);
    }
    n20_asn1_header(s,
                    N20_ASN1_CLASS_UNIVERSAL,
                    1,
                    N20_ASN1_TAG_SEQUENCE,
                    n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_ext_key_usage_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_ext_key_usage_t const *key_usage = context;
    uint8_t bits = 0;

    // Compute the minimal number of bits in the bit string.
    if (key_usage->key_usage_mask[1]) {
        bits = 9;
    } else if (key_usage->key_usage_mask[0]) {
        bits = 8;
        uint8_t c = key_usage->key_usage_mask[0];
        if ((c & 0xf) == 0) {
            bits -= 4;
            c >>= 4;
        }
        if ((c & 3) == 0) {
            bits -= 2;
            c >>= 2;
        }
        if ((c & 1) == 0) {
            bits -= 1;
        }
    }

    n20_asn1_bitstring(s, key_usage->key_usage_mask, bits);
}

void n20_x509_algorithm_identifier_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_algorithm_identifier_t const *alg_id = context;
    n20_asn1_null(s);
    n20_asn1_object_identifier(s, &alg_id->oid);
}

void n20_x509_algorithm_identifier(
    n20_asn1_stream_t *const s, n20_x509_algorithm_identifier_t const *const algorithm_identifier) {
    n20_asn1_sequence(s, n20_x509_algorithm_identifier_content, (void *)algorithm_identifier);
}

void n20_x509_public_key_info_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_public_key_info_t const *pub_key_info = context;
    n20_asn1_bitstring(s, pub_key_info->public_key, pub_key_info->public_key_bits);
    n20_x509_algorithm_identifier(s, &pub_key_info->algorithm_identifier);
}

void n20_x509_public_key_info(n20_asn1_stream_t *const s,
                              n20_x509_public_key_info_t const *const public_key_info) {
    n20_asn1_sequence(s, n20_x509_public_key_info_content, (void *)public_key_info);
}

void n20_x509_validity_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_validity_t const* const validity = context;
    // not after
    n20_asn1_generalized_time(s, validity->not_after != NULL ? validity->not_after : n20_x509_no_expiration);
    // not before
    n20_asn1_generalized_time(s, validity->not_before != NULL ? validity->not_before : n20_x509_unix_epoch);

}

void n20_x509_validity(n20_asn1_stream_t *const s, n20_x509_validity_t const *const validity) {
    n20_asn1_sequence(s, n20_x509_validity_content, (void*)validity);
}

void n20_x509_version_3(n20_asn1_stream_t *const s) {
    // Version 3 (value 2) with explicit tag 0.
    size_t mark = n20_asn1_stream_data_written(s);
    n20_asn1_uint64(s, 2);
    n20_asn1_header(
        s, N20_ASN1_CLASS_CONTEXT_SPECIFIC, 1, 0, n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_cert_tbs_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_tbs_t const *tbs = context;

    // n20_x509_ext_key_usage_t key_usage = {0};
    // N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    // N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    // n20_x509_ext_basic_constraints_t basic_constraints = {
    //     .is_ca = 1,
    //     .path_length = 1,
    // };

    // n20_x509_extension_t exts[] = {
    //     {
    //         .oid = &OID_KEY_USAGE,
    //         .critical = 1,
    //         .content_cb = n20_x509_ext_key_usage_content,
    //         .context = &key_usage,
    //     },
    //     {
    //         .oid = &OID_BASIC_CONSTRAINTS,
    //         .critical = 1,
    //         .content_cb = n20_x509_ext_basic_constraints_content,
    //         .context = &basic_constraints,
    //     },
    // };

    // n20_x509_extensions_t extensions = {
    //     .extensions_count = 2,
    //     .extensions = exts,
    // };

    n20_x509_extension(s, &tbs->extensions);

    // subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL

    // issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL

    // subjectPublicKeyInfo SubjectPublicKeyInfo,
    n20_x509_public_key_info(s, &tbs->subject_public_key_info);
    // mark = n20_asn1_stream_data_written(s);
    // n20_asn1_bitstring(s, public_key_info, sizeof(public_key_info) * 8);
    // imark = n20_asn1_stream_data_written(s);
    // n20_asn1_null(s);
    // n20_asn1_object_identifier(s, &OID_RSA_ENCRYPTION);

    // n20_asn1_header(s,
    //                 N20_ASN1_CLASS_UNIVERSAL,
    //                 1,
    //                 N20_ASN1_TAG_SEQUENCE,
    //                 n20_asn1_stream_data_written(s) - imark);
    // n20_asn1_header(s,
    //                 N20_ASN1_CLASS_UNIVERSAL,
    //                 1,
    //                 N20_ASN1_TAG_SEQUENCE,
    //                 n20_asn1_stream_data_written(s) - mark);

    // subject Name,
    n20_x509_name(s, &tbs->subject_name);

    // validity Validity,
    n20_x509_validity(s, &tbs->validity);
    // mark = n20_asn1_stream_data_written(s);
    // // not after
    // n20_asn1_generalized_time(s, tbs->not_after != NULL ? tbs->not_after : n20_x509_no_expiration);
    // // not before
    // n20_asn1_generalized_time(s, tbs->not_before != NULL ? tbs->not_before : n20_x509_unix_epoch);
    // n20_asn1_header(s,
    //                 N20_ASN1_CLASS_UNIVERSAL,
    //                 1,
    //                 N20_ASN1_TAG_SEQUENCE,
    //                 n20_asn1_stream_data_written(s) - mark);

    // issuer Name
    n20_x509_name(s, &tbs->issuer_name);

    // signature AlgorithmIdentifier
    n20_x509_algorithm_identifier(s, &tbs->signature_algorithm);
    // mark = n20_asn1_stream_data_written(s);
    // n20_asn1_null(s);
    // n20_asn1_object_identifier(s, &OID_SHA256_WITH_RSA_ENC);
    // n20_asn1_header(s,
    //                 N20_ASN1_CLASS_UNIVERSAL,
    //                 1,
    //                 N20_ASN1_TAG_SEQUENCE,
    //                 n20_asn1_stream_data_written(s) - mark);

    // Serial number.
    n20_asn1_uint64(s, tbs->serial_number);

    // Version 3 (value 2) with explicit tag 0.
    n20_x509_version_3(s);
    // mark = n20_asn1_stream_data_written(s);
    // n20_asn1_uint64(s, 2);
    // n20_asn1_header(
    //     s, N20_ASN1_CLASS_CONTEXT_SPECIFIC, 1, 0, n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_cert_tbs(n20_asn1_stream_t *const s, n20_x509_tbs_t const *const tbs) {
    n20_asn1_sequence(s, n20_x509_cert_tbs_content, (void *)tbs);
}

void n20_x509_cert_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_t const* x509 = context;
    n20_asn1_bitstring(s, x509->signature, x509->signature_bits);
    n20_x509_algorithm_identifier(s, &x509->signature_algorithm);
    // size_t mark = n20_asn1_stream_data_written(s);
    // n20_asn1_null(s);
    // n20_asn1_object_identifier(s, &OID_RSA_ENCRYPTION);
    // n20_asn1_header(s,
    //                 N20_ASN1_CLASS_UNIVERSAL,
    //                 1,
    //                 N20_ASN1_TAG_SEQUENCE,
    //                 n20_asn1_stream_data_written(s) - mark);
    n20_x509_cert_tbs(s, x509->tbs);
}

void n20_x509_cert(n20_asn1_stream_t *const s, n20_x509_t const *const x509) {
    n20_asn1_sequence(s, n20_x509_cert_content, (void *)x509);
}
