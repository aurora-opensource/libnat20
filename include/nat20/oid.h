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
#define N20_ASN1_MAX_OID_ELEMENTS 20

/**
 * @brief Structure representing an object identifier.
 */
typedef struct n20_asn1_object_identifier_s {
    /**
     * @brief Indicates the number of elements used.
     */
    uint32_t elem_count;
    /**
     * @brief The integer elements of the object identifier.
     */
    uint32_t elements[N20_ASN1_MAX_OID_ELEMENTS];
} n20_asn1_object_identifier_t;

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
 * @defgroup n20_asn1_oids Object identifiers
 *
 * Object identifiers known to libnat20.
 * @{
 */

N20_ASN1_DECLARE_OID(OID_RSA_ENCRYPTION);
N20_ASN1_DECLARE_OID(OID_SHA256_WITH_RSA_ENC);

N20_ASN1_DECLARE_OID(OID_ED25519);

N20_ASN1_DECLARE_OID(OID_EC_PUBLIC_KEY);

N20_ASN1_DECLARE_OID(OID_SECP256R1);
N20_ASN1_DECLARE_OID(OID_SECP384R1);

N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA224);
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA256);
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA384);
N20_ASN1_DECLARE_OID(OID_ECDSA_WITH_SHA512);

N20_ASN1_DECLARE_OID(OID_LOCALITY_NAME);
N20_ASN1_DECLARE_OID(OID_COUNTRY_NAME);
N20_ASN1_DECLARE_OID(OID_STATE_OR_PROVINCE_NAME);
N20_ASN1_DECLARE_OID(OID_ORGANIZATION_NAME);
N20_ASN1_DECLARE_OID(OID_ORGANIZATION_UNIT_NAME);
N20_ASN1_DECLARE_OID(OID_COMMON_NAME);

N20_ASN1_DECLARE_OID(OID_BASIC_CONSTRAINTS);
N20_ASN1_DECLARE_OID(OID_KEY_USAGE);

N20_ASN1_DECLARE_OID(OID_OPEN_DICE_INPUT);

/** @} */
