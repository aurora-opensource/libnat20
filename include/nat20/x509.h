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

#include "asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define N20_X509_NAME_MAX_NAME_ELEMENTS 8

/**
 * @brief No expiration.
 *
 * The special value `99991231235959Z` used a s not after date in an
 * x509 certificate indicates that the certificate does not expire.
 * (See RFC5280 Section 4.1.2.5.)
 */
static char const *const n20_x509_no_expiration = "99991231235959Z";
/**
 * @brief Generalized string representing Jan 1st 1970 00:00:00 UTC.
 *
 * This is the beginning of the UNIX epoch and is used as the default.
 * not before date for certificates.
 */
static char const *const n20_x509_unix_epoch = "19700101000000Z";

struct n20_x509_rdn {
    struct n20_asn1_object_identifier *type;
    char const *value;
};
typedef struct n20_x509_rdn n20_x509_rdn_t;

#define N20_X509_RDN(type__, value__) \
    { .type = type__, .value = value__, }

#define N20_X509_NAME(...)                                                                 \
    {                                                                                      \
        .element_count = sizeof((n20_x509_rdn_t[]){__VA_ARGS__}) / sizeof(n20_x509_rdn_t), \
        .elements = {                                                                      \
            __VA_ARGS__                                                                    \
        }                                                                                  \
    }

extern void n20_x509_rdn(n20_asn1_stream_t *const s, n20_x509_rdn_t const *rdn);

struct n20_x509_name {
    size_t element_count;
    n20_x509_rdn_t elements[N20_X509_NAME_MAX_NAME_ELEMENTS];
};

typedef struct n20_x509_name n20_x509_name_t;

extern void n20_x509_name(n20_asn1_stream_t *const s, n20_x509_name_t const *name);

typedef struct n20_x509_extension {
    n20_asn1_object_identifier_t *oid;
    n20_asn1_bool_t critical;
    n20_asn1_content_cb_t *content_cb;
    void *context;
} n20_x509_extension_t;

typedef struct n20_x509_extensions {
    size_t extensions_count;
    n20_x509_extension_t const *extensions;
} n20_x509_extensions_t;

extern void n20_x509_extension(n20_asn1_stream_t *const s, n20_x509_extensions_t const *exts);

typedef struct n20_x509_ext_basic_constraints {
    n20_asn1_bool_t is_ca;
    uint32_t path_length;
} n20_x509_ext_basic_constraints_t;

extern void n20_x509_ext_basic_constraints_content(n20_asn1_stream_t *const s, void *context);
extern void n20_x509_ext_key_usage_content(n20_asn1_stream_t *const s, void *context);

typedef struct n20_x509_ext_key_usage {
    uint8_t key_usage_mask[2];
} n20_x509_ext_key_usage_t;

typedef struct n20_x509_algorithm_identifier {
    n20_asn1_object_identifier_t oid;
    // params
} n20_x509_algorithm_identifier_t;

typedef struct n20_x509_public_key_info {
    n20_x509_algorithm_identifier_t algorithm_identifier;
    size_t public_key_bits;
    uint8_t const* public_key;
} n20_x509_public_key_info_t;

typedef struct n20_x509_validity {
    /**
     * @brief The certificate shall not be valid before.
     *
     * Must be initialize to a generalized time string of the form as
     * described in @ref N20_ASN1_TAG_UTC_TIME, or NULL.
     * If NULL, the not before field of the certificate will be set to
     * @ref n20_x509_unix_epoch.
     */
    char const *not_before;

    /**
     * @brief The certificate shall not be valid after.
     *
     * Must be initialize to a generalized time string of the form as
     * described in @ref N20_ASN1_TAG_UTC_TIME, or NULL.
     * If NULL, the not after field of the certificate will be set to
     * @ref n20_x509_no_expiration.
     */
    char const *not_after;

} n20_x509_validity_t;

typedef struct n20_x509_tbs {
    /**
     * @brief The certificate's serial number.
     */
    uint64_t serial_number;

    n20_x509_algorithm_identifier_t signature_algorithm;

    n20_x509_name_t issuer_name;

    n20_x509_validity_t validity;

    n20_x509_name_t subject_name;

    n20_x509_public_key_info_t subject_public_key_info;

    // Extensions
    n20_x509_extensions_t extensions;

} n20_x509_tbs_t;

typedef struct n20_x509 {
    n20_x509_tbs_t const *tbs;
    n20_x509_algorithm_identifier_t signature_algorithm;
    size_t signature_bits;
    uint8_t const* signature;
} n20_x509_t;

#define N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(key_usage) (key_usage)->key_usage_mask[0] |= 0x80
#define N20_X509_KEY_USAGE_SET_CONTENT_COMMITMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x40
#define N20_X509_KEY_USAGE_SET_KEY_ENCIPHERMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x20
#define N20_X509_KEY_USAGE_SET_DATA_ENCIPHERMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x10
#define N20_X509_KEY_USAGE_SET_KEY_AGREEMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x08
#define N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(key_usage) (key_usage)->key_usage_mask[0] |= 0x04
#define N20_X509_KEY_USAGE_SET_CRL_SIGN(key_usage) (key_usage)->key_usage_mask[0] |= 0x02
#define N20_X509_KEY_USAGE_SET_ENCIPHER_ONLY(key_usage) (key_usage)->key_usage_mask[0] |= 0x01
#define N20_X509_KEY_USAGE_SET_DECIPHER_ONLY(key_usage) (key_usage)->key_usage_mask[1] |= 0x80

extern void n20_x509_cert_tbs(n20_asn1_stream_t *const s, n20_x509_tbs_t const *tbs);

extern void n20_x509_cert(n20_asn1_stream_t *const s, n20_x509_t const *x509);

#ifdef __cplusplus
}
#endif
