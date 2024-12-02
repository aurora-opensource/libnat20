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

#include <nat20/oid.h>

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
