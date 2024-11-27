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

/** @file */

#define N20_ASN1_MAX_OID_ELEMENTS 7

typedef struct n20_asn1_object_identifier {
    size_t elem_count;
    uint32_t elements[N20_ASN1_MAX_OID_ELEMENTS];
} n20_asn1_object_identifier_t;

#define N20_ASN1_OBJECT_ID(...)                                             \
    {                                                                       \
        .elem_count = sizeof((uint32_t[]){__VA_ARGS__}) / sizeof(uint32_t), \
        .elements = {__VA_ARGS__},                                          \
    }

#define N20_ASN1_DEFINE_OID(name, ...) \
    n20_asn1_object_identifier_t name = N20_ASN1_OBJECT_ID(__VA_ARGS__)

#define N20_ASN1_DECLARE_OID(name) extern n20_asn1_object_identifier_t name

N20_ASN1_DECLARE_OID(OID_RSA_ENCRYPTION);
N20_ASN1_DECLARE_OID(OID_SHA256_WITH_RSA_ENC);

N20_ASN1_DECLARE_OID(OID_LOCALITY_NAME);
N20_ASN1_DECLARE_OID(OID_COUNTRY_NAME);
N20_ASN1_DECLARE_OID(OID_STATE_OR_PROVINCE_NAME);
N20_ASN1_DECLARE_OID(OID_ORGANIZATION_NAME);
N20_ASN1_DECLARE_OID(OID_ORGANIZATION_UNIT_NAME);
N20_ASN1_DECLARE_OID(OID_COMMON_NAME);

N20_ASN1_DECLARE_OID(OID_BASIC_CONSTRAINTS);
N20_ASN1_DECLARE_OID(OID_KEY_USAGE);
