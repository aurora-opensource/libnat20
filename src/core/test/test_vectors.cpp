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

#include "test_vectors.h"

#include <gtest/gtest.h>
#include <nat20/crypto.h>
#include <nat20/testing/test_vector_reader.h>

#include <vector>

#include "nat20/functionality.h"

struct key_type_parser {
    static std::optional<n20_crypto_key_type_t> parse(std::string const& str) {
        if (str == "ed25519") {
            return n20_crypto_key_type_ed25519_e;
        } else if (str == "secp256r1") {
            return n20_crypto_key_type_secp256r1_e;
        } else if (str == "secp384r1") {
            return n20_crypto_key_type_secp384r1_e;
        }
        return std::nullopt;  // Invalid key type
    }
};

struct certificate_type_parser {
    static std::optional<n20_cert_type_t> parse(std::string const& str) {
        if (str == "self-signed") {
            return n20_cert_type_self_signed_e;
        } else if (str == "cdi") {
            return n20_cert_type_cdi_e;
        } else if (str == "eca") {
            return n20_cert_type_eca_e;
        } else if (str == "eca-ee") {
            return n20_cert_type_eca_ee_e;
        }
        return std::nullopt;  // Invalid certificate type
    }
};

DEFINE_FIELD(Name, std::string, string_parser, "Name")
DEFINE_FIELD(IssKeyType, n20_crypto_key_type_t, key_type_parser, "IssKeyType")
DEFINE_FIELD(SubjKeyType, n20_crypto_key_type_t, key_type_parser, "SubjKeyType")
DEFINE_FIELD(CertificateType, n20_cert_type_t, certificate_type_parser, "CertType")
DEFINE_FIELD(WantCert, std::vector<uint8_t>, hex_string_parser, "WantCert");

using AttestationCertificateVectorReader =
    TestVectorReader<Name, IssKeyType, SubjKeyType, CertificateType, WantCert>;

std::vector<AttestationCertificateVectorReader::tuple_type> x509_test_vectors =
    AttestationCertificateVectorReader::read_all_vectors_from_file(
        "test_data/core/functionality_x509_test_vectors.txt");
