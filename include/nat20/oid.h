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

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

/** @file
 *
 * This file defines usefull macros for defining and declaring
 * object identifiers.
 */

/**
 * @brief The maximum number of elements supported in an object identifier.
 *
 * Object identifiers are represented as an array of integers.
 * This macro controls the size of the data structure used for
 * representing an object identifier. It needs to be increased
 * if longer OID needs to be supported by the library.
 *
 * @sa n20_asn1_object_identifier_t
 * @sa N20_ASN1_DEFINE_OID
 * @sa N20_ASN1_DECLARE_OID
 */
#define N20_ASN1_MAX_OID_ELEMENTS 10

/**
 * @brief Structure representing an object identifier.
 */
struct n20_asn1_object_identifier_s {
    /**
     * @brief Indicates the number of elements used.
     */
    uint32_t elem_count;
    /**
     * @brief The integer elements of the object identifier.
     */
    uint32_t elements[N20_ASN1_MAX_OID_ELEMENTS];
};

/**
 * @brief Alias for @ref n20_asn1_object_identifier_s
 */
typedef struct n20_asn1_object_identifier_s n20_asn1_object_identifier_t;

/**
 * @brief Helper for @ref N20_ASN1_DEFINE_OID.
 *
 * This macro is used by @ref N20_ASN1_DEFINE_OID to expand
 * the value of the object identifier.
 */
#define N20_ASN1_OBJECT_ID(...)                                             \
    {                                                                       \
        .elem_count = sizeof((uint32_t[]){__VA_ARGS__}) / sizeof(uint32_t), \
        .elements = {__VA_ARGS__},                                          \
    }

/**
 * @brief Defines an object identifier.
 *
 * Defines an object identifier with the given name. This is typically
 * used in the implementation part of a compilation unit, and it should
 * be complemented with corresponding invocation of @ref N20_ASN1_DECLARE_OID
 * in the header part to publish the symbol.
 *
 * ## Example
 *
 * @code{.c}
 * N20_ASN1_DEFINE_OID(OID_LOCALITY_NAME, 2, 5, 4, 7);
 * @endcode
 *
 * Expands to:
 *
 * @code{.c}
 * n20_asn1_object_identifier_t OID_LOCALITY_NAME = {
 *     .elem_count = 4,
 *     .elements = {2, 5, 4, 7},
 * };
 * @endcode
 *
 * @sa N20_ASN1_DECLARE_OID
 */
#define N20_ASN1_DEFINE_OID(name, ...) \
    n20_asn1_object_identifier_t name = N20_ASN1_OBJECT_ID(__VA_ARGS__)

/**
 * @brief Declares an objet identifier.
 *
 * ## Example
 *
 * @code{.c}
 * N20_ASN1_DECLARE_OID(OID_LOCALITY_NAME);
 * @endcode
 *
 * Expands to:
 *
 * @code{.c}
 * extern n20_asn1_object_identifier_t OID_LOCALITY_NAME;
 * @endcode
 *
 * @sa N20_ASN1_DEFINE_OID
 */
#define N20_ASN1_DECLARE_OID(name) extern n20_asn1_object_identifier_t name

/**
 * @defgroup n20_asn1_oids Object Identifiers
 * @brief Object identifiers known to libnat20.
 *
 * This group contains the object identifiers (OIDs) used in libnat20 for various cryptographic
 * algorithms, key types, and X.509 certificate extensions. These OIDs are defined according to
 * relevant standards and specifications.
 *
 * @{
 */

/**
 * @brief OID for RSA encryption.
 *
 * Represents the object identifier for RSA encryption as defined in PKCS #1.
 */
N20_ASN1_DECLARE_OID(OID_RSA_ENCRYPTION);

/**
 * @brief OID for SHA-256 with RSA encryption.
 *
 * Represents the object identifier for the SHA-256 hash algorithm combined with RSA encryption.
 */
N20_ASN1_DECLARE_OID(OID_SHA256_WITH_RSA_ENC);

/**
 * @brief OID for Ed25519.
 *
 * Represents the object identifier for the Ed25519 digital signature algorithm.
 */
N20_ASN1_DECLARE_OID(OID_ED25519);

/**
 * @brief OID for EC public key.
 *
 * Represents the object identifier for elliptic curve public keys.
 */
N20_ASN1_DECLARE_OID(OID_EC_PUBLIC_KEY);

/**
 * @brief OID for the SECP256R1 curve.
 *
 * Represents the object identifier for the SECP256R1 elliptic curve, also known as P-256.
 */
N20_ASN1_DECLARE_OID(OID_SECP256R1);

/**
 * @brief OID for the SECP384R1 curve.
 *
 * Represents the object identifier for the SECP384R1 elliptic curve, also known as P-384.
 */
N20_ASN1_DECLARE_OID(OID_SECP384R1);

/**
 * @brief OID for the SHA-224 hash algorithm.
 *
 * Represents the object identifier for the SHA-224 cryptographic hash function.
 */
N20_ASN1_DECLARE_OID(OID_SHA224);

/**
 * @brief OID for the SHA-256 hash algorithm.
 *
 * Represents the object identifier for the SHA-256 cryptographic hash function.
 */
N20_ASN1_DECLARE_OID(OID_SHA256);

/**
 * @brief OID for the SHA-384 hash algorithm.
 *
 * Represents the object identifier for the SHA-384 cryptographic hash function.
 */
N20_ASN1_DECLARE_OID(OID_SHA384);

/**
 * @brief OID for the SHA-512 hash algorithm.
 *
 * Represents the object identifier for the SHA-512 cryptographic hash function.
 */
N20_ASN1_DECLARE_OID(OID_SHA512);

/**
 * @brief OID for ECDSA with SHA-224.
 *
 * Represents the object identifier for the ECDSA digital signature algorithm using SHA-224.
 */
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA224);

/**
 * @brief OID for ECDSA with SHA-256.
 *
 * Represents the object identifier for the ECDSA digital signature algorithm using SHA-256.
 */
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA256);

/**
 * @brief OID for ECDSA with SHA-384.
 *
 * Represents the object identifier for the ECDSA digital signature algorithm using SHA-384.
 */
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA384);

/**
 * @brief OID for ECDSA with SHA-512.
 *
 * Represents the object identifier for the ECDSA digital signature algorithm using SHA-512.
 */
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA512);

/**
 * @brief OID for the locality name attribute.
 *
 * Represents the object identifier for the locality name attribute in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_LOCALITY_NAME);

/**
 * @brief OID for the country name attribute.
 *
 * Represents the object identifier for the country name attribute in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_COUNTRY_NAME);

/**
 * @brief OID for the state or province name attribute.
 *
 * Represents the object identifier for the state or province name attribute in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_STATE_OR_PROVINCE_NAME);

/**
 * @brief OID for the organization name attribute.
 *
 * Represents the object identifier for the organization name attribute in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_ORGANIZATION_NAME);

/**
 * @brief OID for the organizational unit name attribute.
 *
 * Represents the object identifier for the organizational unit name attribute in X.509
 * certificates.
 */
N20_ASN1_DECLARE_OID(OID_ORGANIZATION_UNIT_NAME);

/**
 * @brief OID for the common name attribute.
 *
 * Represents the object identifier for the common name attribute in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_COMMON_NAME);

/**
 * @brief OID for the serial number attribute.
 *
 * Represents the object identifier for the serial number attribute in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_SERIAL_NUMBER);

/**
 * @brief OID for the basic constraints extension.
 *
 * Represents the object identifier for the basic constraints extension in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_BASIC_CONSTRAINTS);

/**
 * @brief OID for the key usage extension.
 *
 * Represents the object identifier for the key usage extension in X.509 certificates.
 */
N20_ASN1_DECLARE_OID(OID_KEY_USAGE);

/**
 * @brief OID for the Open DICE input extension.
 *
 * Represents the object identifier for the Open DICE input extension.
 */
N20_ASN1_DECLARE_OID(OID_OPEN_DICE_INPUT);

/**
 * @brief OID for the TCG DICE TCB info extension.
 *
 * Represents the object identifier for the Trusted Computing Group (TCG) DICE TCB info extension.
 */
N20_ASN1_DECLARE_OID(OID_TCG_DICE_TCB_INFO);

/**
 * @brief OID for the TCG DICE multi-TCB info extension.
 *
 * Represents the object identifier for the Trusted Computing Group (TCG) DICE multi-TCB info
 * extension.
 */
N20_ASN1_DECLARE_OID(OID_TCG_DICE_MULTI_TCB_INFO);

/**
 * @brief OID for the TCG DICE UEID extension.
 *
 * Represents the object identifier for the Trusted Computing Group (TCG) DICE Unique Endpoint
 * Identifier (UEID) extension.
 */
N20_ASN1_DECLARE_OID(OID_TCG_DICE_UEID);

/**
 * @brief OID for the TCG DICE TCB freshness extension.
 *
 * Represents the object identifier for the Trusted Computing Group (TCG) DICE TCB freshness
 * extension.
 */
N20_ASN1_DECLARE_OID(OID_TCG_DICE_TCB_FRESHNESS);

/** @} */ /* End of n20_asn1_oids group */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compare two object identifiers for equality.
 *
 * This function compares two object identifiers for equality.
 * It returns true if the object identifiers are equal, false otherwise.
 *
 * If both object identifiers are NULL, the function returns true.
 * If one is NULL and the other is not, it returns false.
 * If the element counts differ, it returns false.
 * If any of the first count elements differ, it returns false.
 *
 * @param oid1 The first object identifier to compare.
 * @param oid2 The second object identifier to compare.
 * @return true if the object identifiers are equal, false otherwise.
 */
bool n20_asn1_oid_equals(n20_asn1_object_identifier_t const *oid1,
                         n20_asn1_object_identifier_t const *oid2);

#ifdef __cplusplus
}
#endif
