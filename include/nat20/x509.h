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

/** @file */

#pragma once

#include "asn1.h"
#include "oid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Maximum number of elements of element in @ref n20_x509_name.
 *
 * @ref n20_x509_name contains an array of elements for storing
 * elements of the RDNSequence. This macro definition controls the size
 * of this array.
 */
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

/**
 * @brief Representing a RelativeDistinguishedName.
 *
 * This struct represents an element in a RDNSequence as used
 * in the issuerName and subjectName fields of an x509 certificate.
 *
 * As of this writing only elements that are presented as
 * PritableString are supported. This means that the provided
 * nul terminated string must only contain allows characters
 * as outlined in @ref n20_asn1_printablestring. No checking
 * is done on the provided string, this means that if the
 * caller provides a string containing invalid characters,
 * the resulting certificate will be malformed.
 *
 * No ownership is taken. The user is required to assure
 * that the pointer targets outlive instances of this structure.
 *
 * (See RFC5280 Section 4.1.2.4.)
 */
typedef struct n20_x509_rdn_s {
    /**
     * @brief The object identifier of the RDNSequence element.
     */
    struct n20_asn1_object_identifier *type;
    /**
     * @brief The value of the RDNSequence element.
     *
     * Must be a nul terminated string of characters of the
     * following set; `[A..Z][a..z][0..9][ '()+,-./:=?]`.
     *
     * @sa n20_asn1_printablestring
     */
    char const *value;
} n20_x509_rdn_t;

/**
 * @brief Convenience macro for initializing @ref n20_x509_rdn.
 *
 * # Example
 *
 * The following example is safe. Both pointers
 * are pointing to static objects that will remain valid
 * for the entire runtime of the program.
 * If either argument is created through heap allocation.
 * The user is responsible for making sure that the arguments.
 * outlive `rdn`.
 *
 * @code{.c}
 * n20_x509_rdn rdn = N20_X509_RDN(&OID_COMMON_NAME, "CommonName")
 * @endcode
 */
#define N20_X509_RDN(type__, value__) \
    { .type = type__, .value = value__, }

/**
 * @brief Represents an RDNSequence.
 *
 * This structure represents a sequence of
 * RelativeDistinguishedName elements. It can hold
 * of @ref N20_X509_NAME_MAX_NAME_ELEMENTS or less elements.
 * The number of actual elements in this sequence is
 * given by @ref element_count.
 *
 * It is recommended to initialize an instance of this
 * structure using the macros @ref N20_X509_RDN and @ref N20_X509_NAME
 * (See @ref N20_X509_NAME for an example).
 */
typedef struct n20_x509_name_s {
    /**
     * @brief Number of actual elements in the seqence.
     *
     * Must be in the range of [0 .. @ref N20_X509_NAME_MAX_NAME_ELEMENTS]
     */
    size_t element_count;
    /**
     * @brief Holds the elements of the RDNSequence.
     */
    n20_x509_rdn_t elements[N20_X509_NAME_MAX_NAME_ELEMENTS];
} n20_x509_name_t;

/**
 * @brief Convenience macro for initializing an instance of @ref n20_x509_name.
 *
 * # Example
 *
 * @code{.c}
 * n20_x509_name name =
 *     N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "Schlaraffenland"),
 *                   N20_X509_RDN(&OID_LOCALITY_NAME, "Wolperting"),
 *                   N20_X509_RDN(&OID_ORGANIZATION_NAME, "Traumfabrik"),
 *                   N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Pyramidenverleih"),
 *                   N20_X509_RDN(&OID_COMMON_NAME, "Schulze"), );
 *
 * @endcode
 */
#define N20_X509_NAME(...)                                                                 \
    {                                                                                      \
        .element_count = sizeof((n20_x509_rdn_t[]){__VA_ARGS__}) / sizeof(n20_x509_rdn_t), \
        .elements = {                                                                      \
            __VA_ARGS__                                                                    \
        }                                                                                  \
    }

/**
 * @brief Renders an RDNSequence into the given stream.
 *
 * The @ref name parameter should be initialized using the macros
 * @ref N20_X509_NAME and @ref N20_X509_RDN (See @ref N20_X509_NAME for
 * an example).
 *
 * It is the responsibility of the caller that all pointers
 * are valid until the function call returns.
 *
 * Passing NULL pointers is well defined, however, the
 * rendered output may be nonsensical.
 * E.g.: If @ref name is NULL, this function renders an
 * ASN1 NULL, i.e., `0x05 0x00`, which is not a valid
 * RDNSequence.
 *
 * If @ref name.element_count is greater than
 * @ref N20_X509_NAME_MAX_NAME_ELEMENTS `ASN1 NULL` is rendered.
 *
 * @param s The stream that is to be updated.
 * @param name Pointer to an initialized instance of @ref x20_x509_name_t
 */
extern void n20_x509_name(n20_asn1_stream_t *s, n20_x509_name_t const *name);

/**
 * @brief Represents an x509 v3 extension.
 *
 * The extension structure hold an object identifier
 * and the critical flag. The content of the value sequence
 * is given as a rendering callback of the form
 * @ref n20_asn1_content_cb_t.
 */
typedef struct n20_x509_extension_s {
    /**
     * @brief The object identifier indicating the type of the
     * extension.
     *
     * If this is NULL, ASN1 NULL will be rendered instead
     * of an object identifier. Which, while well defined, leads
     * to a malformed certificate.
     *
     * No ownership is taken. The user has to assure that
     * the pointer target outlives instances of this
     * structure.
     */
    n20_asn1_object_identifier_t *oid;
    /**
     * @brief The critical flag.
     */
    bool critical;
    /**
     * @brief Callback rendering the value of the extension.
     *
     * The callback function renders the value of the extension.
     * this content is consumed by n20_x509_extension and treated
     * as octet string.
     *
     * If the content_cb is NULL the extension value
     * will be an empty octet string.
     */
    n20_asn1_content_cb_t *content_cb;
    /**
     * @brief Callback context.
     *
     * This is an opaque pointer that is passed to the
     * @ref content_cb as is.
     */
    void *context;
} n20_x509_extension_t;

/**
 * @brief Represents a set of x509 v3 extensions.
 *
 * The extensions will appear in the output in the
 * same order that they appear in @ref extensions.
 *
 * @sa n20_x509_extension
 */
typedef struct n20_x509_extensions_s {
    /**
     * @brief The number of extensions in @ref extensions.
     *
     * If this field is zero, the entire optional extensions
     * field is skipped.
     */
    size_t extensions_count;
    /**
     * @brief An array of @ref extensions_count elements of
     * @ref n20_x509_extension_t
     *
     * It is undefined behavior if the buffer pointed to
     * by @ref extensions is smaller than
     * `sizeof(n20_x509_extension_t) * extensions_count`.
     *
     * If @ref extensions is NULL, the entire optional
     * extensions field is skipped.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    n20_x509_extension_t const *extensions;
} n20_x509_extensions_t;

/**
 * @brief Renders a the extensions field of an X509 certificate.
 *
 * This function renders the given set of extensions to the
 * given stream. The function also renders the enveloping sequence
 * header as well as the explicit tag `3`. The extensions will appear
 * inside of the sequence in the same order in which they appear in
 * @ref n20_x509_extensions_t.extensions.
 *
 * If @ref exts is NULL or `exts->extensions_count == 0` or `exts->extensions == NULL`
 * this function becomes a no-op, i.e., nothing is rendered to the stream.
 *
 * # Example
 *
 * The following example shows how to render the extensions field
 * of an X509 certificate comprising a key usage
 * extensions and a basic constraints extension.
 *
 * @code{.c}
 *    n20_x509_ext_key_usage_t key_usage = {0};
 *    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
 *    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);
 *
 *    n20_x509_ext_basic_constraints_t basic_constraints = {
 *        .is_ca = 1,
 *        .path_length = 1,
 *    };
 *
 *    n20_x509_extension_t extensions[] = {
 *        {
 *            .oid = &OID_KEY_USAGE,
 *            .critical = 1,
 *            .content_cb = n20_x509_ext_key_usage_content,
 *            .context = &key_usage,
 *        },
 *        {
 *            .oid = &OID_BASIC_CONSTRAINTS,
 *            .critical = 1,
 *            .content_cb = n20_x509_ext_basic_constraints_content,
 *            .context = &basic_constraints,
 *        },
 *    };
 *
 *    n20_x509_extensions_t exts = {
 *        .extensions_count = 2,
 *        .extensions = extensions,
 *    };
 *
 *    n20_x509_extensions(s, &exts);
 * @endcode
 *
 * @param s The stream that is to be updated.
 * @param exts Set of extensions.
 */
extern void n20_x509_extension(n20_asn1_stream_t *const s, n20_x509_extensions_t const *exts);

/**
 * @brief Basic constraints callback context.
 *
 * This is the context expected by
 * @ref n20_x509_ext_basic_constraints_content.
 * An instance of this object must be passed to the callback.
 * This is typically done using @ref n20_x509_extension by
 * initializing @ref n20_x509_extension_t.content_cb with
 * @ref n20_x509_ext_basic_constraints_content and setting
 * @ref n20_x509_extension_t.context to an instance of this
 * struct.
 *
 * (See RFC5280 Section 4.2.1.9.)
 * @sa OID_BASIC_CONSTRAINTS
 */
typedef struct n20_x509_ext_basic_constraints_s {
    /**
     * @brief Indicates that the certificate subject is a CA.
     */
    bool is_ca;
    /**
     * @brief Indicates whether a pathLenConstraint is present.
     */
    bool has_path_length;
    /**
     * @brief The value of the pathLenConstraint field.
     *
     * This indicates the number intermediate certificates
     * certificates that may follow this certificate,
     * not including any end entity certificates.
     *
     * (See RFC5280 Section 4.2.1.9.)
     */
    uint32_t path_length;
} n20_x509_ext_basic_constraints_t;

/**
 * @brief Renders the value of a basic constraints extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_basic_constraints_t
 * as @ref context argument.
 *
 * If @ref context is NULL, nothing is rendered, which would leave
 * the resulting basic constraints extension malformed.
 *
 * This function is typically not used directly but instead
 * passed to @ref n20_x509_extension by initializing an
 * instance of @ref n20_x509_extensions_t
 * (See @ref n20_x509_extension for an example).
 *
 * @param s The stream that is to be updated.
 * @param context A pointer to an instance of
 *        @ref n20_x509_ext_basic_constraints_t.
 */
extern void n20_x509_ext_basic_constraints_content(n20_asn1_stream_t *const s, void *context);

/**
 * @defgroup n20_x509_key_usage_macros Key Usage Macros
 *
 * These macros set the corresponding flags in the key
 * useage bit mask of @ref n20_x509_key_usage_t.
 * Each macro takes a pointer to an instance of
 * @ref n20_x509_key_usage_t as its argument.
 *
 * See RFC5280 Section 4.2.1.3.
 *
 * # Example
 *
 * @code{.c}
 * n20_x509_ext_key_usage_t key_usage = {0};
 * N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);
 * @endcode
 * @{
 */

/**
 * @brief The subject key can be used to issue digital signatures.
 */
#define N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(key_usage) (key_usage)->key_usage_mask[0] |= 0x80
/**
 * @brief The subject key can be used to sign statements of commitment.
 *
 * This field was formerly known as nonRepudiation flag.
 */
#define N20_X509_KEY_USAGE_SET_CONTENT_COMMITMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x40
/**
 * @brief The subject key can be used for encryption of key material.
 */
#define N20_X509_KEY_USAGE_SET_KEY_ENCIPHERMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x20
/**
 * @brief The subject key can be used for encryption of arbitrary messages.
 */
#define N20_X509_KEY_USAGE_SET_DATA_ENCIPHERMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x10
/**
 * @brief The subject key can be used for key agreement.
 */
#define N20_X509_KEY_USAGE_SET_KEY_AGREEMENT(key_usage) (key_usage)->key_usage_mask[0] |= 0x08
/**
 * @brief The subject key can be used for signing certificates.
 */
#define N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(key_usage) (key_usage)->key_usage_mask[0] |= 0x04
/**
 * @brief The subject key can be used for signing certificate revocation lists.
 */
#define N20_X509_KEY_USAGE_SET_CRL_SIGN(key_usage) (key_usage)->key_usage_mask[0] |= 0x02
/**
 * @brief The subject key can be used only for enciphering data during key agreement.
 *
 * The key agreement flag must also be set.
 */
#define N20_X509_KEY_USAGE_SET_ENCIPHER_ONLY(key_usage) (key_usage)->key_usage_mask[0] |= 0x01
/**
 * @brief the subject key can be used only for deciphering data during key agreement.
 *
 * The key agreement flag must also be set.
 */
#define N20_X509_KEY_USAGE_SET_DECIPHER_ONLY(key_usage) (key_usage)->key_usage_mask[1] |= 0x80

/**
 * @}
 */

/**
 * @brief Key usage content callback.
 *
 * This is the context expected by
 * @ref n20_x509_ext_key_usage_content.
 * An instance of this object must be passed to the callback.
 * This is typically done using @ref n20_x509_extension by
 * initializing @ref n20_x509_extension_t.content_cb with
 * @ref n20_x509_ext_key_usage_content and setting
 * @ref n20_x509_extension_t.context to an instance of this
 * struct.
 *
 * Always zero initialize instances of this structure as and
 * set the flags using the @ref n20_x509_key_usage_macros.
 *
 * # Example
 *
 * @code{.c}
 * n20_x509_ext_key_usage_t key_usage = {0};
 * N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);
 * @endcode
 *
 * (See RFC5280 Section 4.2.1.3.)
 * @sa OID_KEY_USAGE
 */
typedef struct n20_x509_ext_key_usage_s {
    /**
     * @brief The key usage mask.
     *
     * Use the @ref n20_x509_key_usage_macros to set the individual
     * of the key usage mask. As described at @ref n20_x509_ext_key_usage_t.
     * there no need accessing this field directly.
     */
    uint8_t key_usage_mask[2];
} n20_x509_ext_key_usage_t;

/**
 * @brief Renders the value of a key usage extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_key_usage_t as @ref context argument.
 *
 * If @ref context is NULL, nothing is rendered, which would leave
 * the resulting key usage extension malformed.
 *
 * This function is typically not used directly but instead
 * passed to @ref n20_x509_extension by initializing an
 * instance of @ref n20_x509_extensions_t
 * (See @ref n20_x509_extension for an example).
 */
extern void n20_x509_ext_key_usage_content(n20_asn1_stream_t *const s, void *context);

/**
 * @brief Indicates the type of the algorithm parameter.
 *
 * @ref n20_x509_algorithm_parameters_t is a tagged union
 * and this enum is the tag indicating which variant of the
 * union is populated.
 */
typedef enum n20_x509_algorithm_parameter_variants_s {
    /**
     * @brief Indicates that the parameter shall be omitted.
     *
     * This variant is used with edwards curve algorithms
     * like @ref OID_ED25519.
     */
    n20_x509_pv_none_e = 0,
    /**
     * @brief Indicates that the parameter shall be ASN.1 NULL.
     *
     * This variant is used with @ref OID_RSA_ENCRYPTION.
     */
    n20_x509_pv_null_e = 1,
    /**
     * @brief Indicates that the parameter variant
     * @ref n20_x509_algorithm_parameters_t.ec_curve shall be used.
     *
     * This is used with @ref OID_EC_PUBLIC_KEY. The value
     * is an object identifier that identifies the elliptic curve
     * parameters, E.g.: @ref OID_SECP256R1 or @ref OID_SECP384R1
     */
    n20_x509_pv_ec_curve_e = 2,
} n20_x509_algorithm_parameter_variants_t;

/**
 * @brief Tagged union that represents the algorithm parameters.
 *
 * This structure is used to represent algorithm parameters for
 * public key or signature algorithms.
 * It is a tagged union, where @ref variant serves as the tag.
 * See @ref n20_x509_algorithm_parameter_variants_t for options.
 */
typedef struct n20_x509_algorithm_parameters_s {
    /**
     * @brief Indicates the type of the parameter.
     *
     * @sa n20_x509_algorithm_parameter_variants_t
     */
    n20_x509_algorithm_parameter_variants_t variant;
    union {
        /**
         * @brief Indicates the elliptic curve parameters for public key
         * algorithm @ref OID_EC_PUBLIC_KEY.
         *
         * This variant is selected by setting @ref variant to
         * @ref n20_x509_pv_ec_curve_e.
         */
        n20_asn1_object_identifier_t *ec_curve;
    };
} n20_x509_algorithm_parameters_t;

/**
 * @brief Represents an algorithm identifier.
 *
 * The algorithm identifier is used to express the public key
 * and signature algorithms in an X509 certificate.
 */
typedef struct n20_x509_algorithm_identifier_s {
    /**
     * @brief The algorithm type.
     */
    n20_asn1_object_identifier_t *oid;
    /**
     * @brief Optional parameters to the selected algorithm.
     *
     * See @ref n20_x509_algorithm_parameters_t for more details.
     */
    n20_x509_algorithm_parameters_t params;
} n20_x509_algorithm_identifier_t;

/**
 * @brief Represents the public key info of an X509 certificate.
 *
 * The public key consists of an algorithm identifier and the actual
 * public key rendered as a bit string.
 *
 * The public key format is algorithms specific, and the caller has
 * to provide the key in the correct format.
 *
 * - ED25519: See RFC8709 and RFC8032
 * - NIST curves: See RFC5490
 * - RSA: See RFC8017
 */
typedef struct n20_x509_public_key_info_s {
    /**
     * @brief Describes the key algorithm for the associated public key material.
     */
    n20_x509_algorithm_identifier_t algorithm_identifier;
    /**
     * @brief The number of bits (not bytes or octets) provided.
     *
     * The buffer provided in @ref public_key must be at least
     * `ceil(public_key_bits / 8)` bytes long. Or the behavior is undefined.
     */
    size_t public_key_bits;
    /**
     * @brief The buffer holding the public key material.
     *
     * If provided, must point to a buffer of at least
     * `ceil(public_key_bits / 8)` bytes. Or the behaviour
     * undefined.
     *
     * If NULL the resulting bitstring will be empty.
     *
     * No ownership is taken. The user must ensure that
     * the target outlives instances of this structure.
     */
    uint8_t const *public_key;
} n20_x509_public_key_info_t;

/**
 * @brief Represents the validity field of an X509 certificate.
 */
typedef struct n20_x509_validity_s {
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

/**
 * @brief Represents the to-be-signed section of an X509 certificate.
 *
 * This structure holds all of the information for the to-be-signed
 * section of an X509 v3 certificate as outlined in RFC5280.
 *
 * The version is fixed to 3.
 *
 * As of this writing the optional fields issuerUniqueID and subjectUniqueID
 * are not yet implemented.
 *
 */
typedef struct n20_x509_tbs_s {
    /**
     * @brief The certificate's serial number.
     *
     * See RFC5280 Section 4.1.2.2.
     */
    uint64_t serial_number;

    /**
     * @brief The signature algorithm identifier.
     *
     * See RFC5280 Section 4.1.2.3.
     */
    n20_x509_algorithm_identifier_t signature_algorithm;

    /**
     * @brief The certificate issue name.
     *
     * See RFC5280 Section 4.1.2.4.
     * @sa n20_x509_name_t
     */
    n20_x509_name_t issuer_name;

    /**
     * @brief The certificate validity.
     *
     * See RFC5280 Section 4.1.2.5.
     * @sa n20_x509_validity_t
     */
    n20_x509_validity_t validity;

    /**
     * @brief The certificate subject name.
     *
     * See RFC5280 Section 4.1.2.6.
     * @sa n20_x509_name_t
     */
    n20_x509_name_t subject_name;

    /**
     * @brief The subject public key info.
     *
     * See RFC 5280 Section 4.1.2.7.
     * @sa n20_x509_public_key_info_t
     */
    n20_x509_public_key_info_t subject_public_key_info;

    /**
     * @brief The X509 v3 extensions.
     *
     * See RFC 5280 Section 4.1.2.8.
     * @sa n20_x509_extensions_t
     */
    n20_x509_extensions_t extensions;
} n20_x509_tbs_t;

/**
 * @brief Represents a full X509 certificate.
 *
 * This structure contain a pointer to an instance of
 * @ref n20_x509_tbs_t as well as the signature algorithm identifier
 * and the signature.
 */
typedef struct n20_x509_s {
    /**
     * @brief A representation of the to-be-signed section of the certificate.
     *
     * This must be identical to the representation that was used
     * to render that tbs section that was signed by @ref signature.
     * Otherwise the resulting certificate cannot be verified.
     *
     * No ownership is taken. The user must make sure that the target
     * outlives the instance of this structure.
     */
    n20_x509_tbs_t const *tbs;
    /**
     * @brief The signature algorithm identifier.
     *
     * This must correctly describe the algorithm used to generate
     * the @ref signature, and it must be identical to the
     * @ref n20_x509_tbs_t.signature_algorithm field in @ref tbs.
     */
    n20_x509_algorithm_identifier_t signature_algorithm;
    /**
     * @brief The number of used bits in the signature buffer.
     *
     * The signature is represented as an ASN.1 bitstring. So the
     * size must be given in bits (not bytes or octets).
     *
     * The buffer pointed to by @ref signature must be at least
     * `ceil(signature_bits / 8)` bytes in size or the behavior
     * is undefined.
     */
    size_t signature_bits;
    /**
     * @brief The signature.
     *
     * This buffer holds the signature material. The signature
     * format depends on the signature algorithm used. Refer to the
     * following references for the different kinds of supported
     * algorithms.
     *
     * - ED25519: See RFC8709 and RFC8032
     * - NIST curves: See RFC5490
     * - RSA: See RFC8017
     *
     * The pointer target must be at least `ceil(signature_bits / 8)`
     * bytes in size or the behavior is undefined.
     *
     * If @ref signature is NULL, it results in an empty octet string
     * in the output certificate.
     *
     * Now ownership is assumed. The user has to assure that
     * the target buffer outlives the instance of this structure.
     */
    uint8_t const *signature;
} n20_x509_t;

/**
 * @brief Render the TBSCertificate of an X509 certificate.
 *
 * Renders the given TBSCertificate to the given stream.
 *
 * @ref tbs must be valid for the duration of the function call.
 * And no ownership is assumed.
 *
 * If @ref tbs is NULL and empty sequence is rendered.
 *
 * @param s The stream that is to be updated.
 * @param tbs Pointer to @ref n20_x509_tbs_t holding the certificate content
 * that is to be rendered.
 *
 * @sa n20_x509_tbs_t
 */
extern void n20_x509_cert_tbs(n20_asn1_stream_t *const s, n20_x509_tbs_t const *tbs);

/**
 * @brief Render an X509 certificate.
 *
 * Renders the given x509 certificate to the given stream.
 *
 * @ref x509 must be valid for the duration of the function call.
 * And no ownership is assumed.
 *
 * If @ref x509 is NULL an empty sequence is rendered.
 *
 * @param s The stream that is to be updated.
 * @param x509 Pointer to an instance of @ref n20_x509_t holding the
 * certificate content that is to be rendered.
 */
extern void n20_x509_cert(n20_asn1_stream_t *const s, n20_x509_t const *x509);

#ifdef __cplusplus
}
#endif
