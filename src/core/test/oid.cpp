/*
 * Copyright 2025 Aurora Operations, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
 *
 * This work is dual licensed.
 * You may use it under Apache-2.0 or GPL-2.0 at your option.
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
 *
 * OR
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#include <gtest/gtest.h>
#include <nat20/oid.h>

TEST(N20OidEqualsTest, BothNull) { EXPECT_TRUE(n20_asn1_oid_equals(nullptr, nullptr)); }

TEST(N20OidEqualsTest, OneNull) {
    n20_asn1_object_identifier_t oid = {2, {1, 2}};
    EXPECT_FALSE(n20_asn1_oid_equals(&oid, nullptr));
    EXPECT_FALSE(n20_asn1_oid_equals(nullptr, &oid));
}

TEST(N20OidEqualsTest, EqualOids) {
    n20_asn1_object_identifier_t oid1 = {3, {1, 2, 3}};
    n20_asn1_object_identifier_t oid2 = {3, {1, 2, 3}};
    EXPECT_TRUE(n20_asn1_oid_equals(&oid1, &oid2));
}

TEST(N20OidEqualsTest, DifferentElementCount) {
    n20_asn1_object_identifier_t oid1 = {2, {1, 2}};
    n20_asn1_object_identifier_t oid2 = {3, {1, 2, 3}};
    EXPECT_FALSE(n20_asn1_oid_equals(&oid1, &oid2));
}

TEST(N20OidEqualsTest, DifferentElements) {
    n20_asn1_object_identifier_t oid1 = {3, {1, 2, 3}};
    n20_asn1_object_identifier_t oid2 = {3, {1, 2, 4}};
    EXPECT_FALSE(n20_asn1_oid_equals(&oid1, &oid2));
}

TEST(N20OidEqualsTest, LibraryDefinedOidsEqual) {
    // OID_RSA_ENCRYPTION is defined in the library and should equal itself
    EXPECT_TRUE(n20_asn1_oid_equals(&OID_RSA_ENCRYPTION, &OID_RSA_ENCRYPTION));
}

TEST(N20OidEqualsTest, LibraryDefinedOidsNotEqual) {
    // OID_RSA_ENCRYPTION and OID_SHA256_WITH_RSA_ENC are different
    EXPECT_FALSE(n20_asn1_oid_equals(&OID_RSA_ENCRYPTION, &OID_SHA256_WITH_RSA_ENC));
}
