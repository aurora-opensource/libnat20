#pragma once

#include "asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define X509_NAME_MAX_NAME_ELEMENTS 8

static char const *const x509_no_expiration = "99991231235959Z";

struct x509_RDN {
    struct asn1_object_identifier *type;
    char const *value;
};
typedef struct x509_RDN x509_RDN_t;

#define X509_RDN(type__, value__) \
    { .type = type__, .value = value__, }

#define X509_NAME(...)                                                                           \
    {                                                                                            \
        .element_count = sizeof((x509_RDN_t[]){__VA_ARGS__}) / sizeof(x509_RDN_t), .elements = { \
            __VA_ARGS__                                                                          \
        }                                                                                        \
    }

extern void x509_RDN(asn1_stream_t *const s, x509_RDN_t const *rdn);

struct x509_name {
    size_t element_count;
    x509_RDN_t elements[X509_NAME_MAX_NAME_ELEMENTS];
};

typedef struct x509_name x509_name_t;

extern void x509_name(asn1_stream_t *const s, x509_name_t const *name);

typedef struct x509_extension {
    asn1_object_identifier_t *oid;
    asn1_bool_t critical;
    asn1_content_cb_t *content_cb;
    void *context;
} x509_extension_t;

typedef struct x509_extensions {
    size_t extensions_count;
    x509_extension_t const *extensions;
} x509_extensions_t;

extern void x509_extension(asn1_stream_t *const s, x509_extensions_t const *exts);

typedef struct x509_ext_basic_constraints {
    asn1_bool_t is_ca;
    uint32_t path_length;
} x509_ext_basic_constraints_t;

extern void x509_ext_basic_constraints_content(asn1_stream_t *const s, void *context);

typedef struct x509_ext_key_usage {
    uint8_t key_usage_mask[2];
} x509_ext_key_usage_t;

#define X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(key_usage) (key_usage)->key_usage_mask[0] |= 0x80
#define X509_KEY_USAGE_SET_CONTENT_COMMITMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x40
#define X509_KEY_USAGE_SET_KEY_ENCIPHERMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x20
#define X509_KEY_USAGE_SET_DATA_ENCIPHERMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x10
#define X509_KEY_USAGE_SET_KEY_AGREEMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x08
#define X509_KEY_USAGE_SET_KEY_CERT_SIGN(key_usage) (key_usage)->key_usage_mask[0] |= 0x04
#define X509_KEY_USAGE_SET_CRL_SIGN(key_usage) (key_usage)->key_usage_mask[0] |= 0x02
#define X509_KEY_USAGE_SET_ENCIPHER_ONLY(key_usage) (key_usage)->key_usage_mask[0] |= 0x01
#define X509_KEY_USAGE_SET_DECIPHER_ONLY(key_usage) (key_usage)->key_usage_mask[1] |= 0x80

extern void x509_cert_tbs(asn1_stream_t *const s);

extern void x509_cert(asn1_stream_t *const s);

#ifdef __cplusplus
}
#endif
