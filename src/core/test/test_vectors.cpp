/*
 * Copyright 2025 Aurora Operations, Inc.
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

struct certificate_format_parser {
    static std::optional<n20_certificate_format_t> parse(std::string const& str) {
        if (str == "X509") {
            return n20_certificate_format_x509_e;
        } else if (str == "COSE") {
            return n20_certificate_format_cose_e;
        }
        return std::nullopt;  // Invalid certificate format
    }
};

DEFINE_FIELD(Name, std::string, string_parser, "Name")
DEFINE_FIELD(ParentKey, n20_crypto_key_type_t, key_type_parser, "pKeyType")
DEFINE_FIELD(Key, n20_crypto_key_type_t, key_type_parser, "keyType")
DEFINE_FIELD(CertificateFormat, n20_certificate_format_t, certificate_format_parser, "certFormat")
DEFINE_FIELD(WantCert, std::vector<uint8_t>, hex_string_parser, "wantCert");

using AttestationCertificateVectorReader =
    TestVectorReader<Name, ParentKey, Key, CertificateFormat, WantCert>;

std::vector<AttestationCertificateVectorReader::tuple_type> attestationCertificateTestVectors =
    AttestationCertificateVectorReader::read_all_vectors_from_file(
        "test_data/core/opendice_attestation_test_vectors.txt");
