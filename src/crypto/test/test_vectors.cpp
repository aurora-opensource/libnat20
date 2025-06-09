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

struct algorithm_parser {
    static std::optional<n20_crypto_digest_algorithm_t> parse(std::string const& str) {
        if (str == "sha224") {
            return n20_crypto_digest_algorithm_sha2_224_e;
        } else if (str == "sha256") {
            return n20_crypto_digest_algorithm_sha2_256_e;
        } else if (str == "sha384") {
            return n20_crypto_digest_algorithm_sha2_384_e;
        } else if (str == "sha512") {
            return n20_crypto_digest_algorithm_sha2_512_e;
        }
        return std::nullopt;  // Invalid algorithm
    }
};

DEFINE_FIELD(Name, std::string, string_parser, "Name")
DEFINE_FIELD(Algorithm, n20_crypto_digest_algorithm_t, algorithm_parser, "Alg")
DEFINE_FIELD(Message, std::vector<uint8_t>, hex_string_parser, "Msg")
DEFINE_FIELD(MessageDigest, std::vector<uint8_t>, hex_string_parser, "MD")

using SHA2TestVectorReader = TestVectorReader<Name, Algorithm, Message, MessageDigest>;

std::vector<SHA2TestVectorReader::tuple_type> sha2TestVectors =
    SHA2TestVectorReader::read_all_vectors_from_file("test_data/crypto/sha2_test_vectors.txt");

DEFINE_FIELD(Key, std::vector<uint8_t>, hex_string_parser, "Key")
DEFINE_FIELD(Mac, std::vector<uint8_t>, hex_string_parser, "Mac")

using HmacTestVectorReader = TestVectorReader<Name, Algorithm, Key, Message, Mac>;

std::vector<HmacTestVectorReader::tuple_type> hmacTestVectors =
    HmacTestVectorReader::read_all_vectors_from_file("test_data/crypto/hmac_test_vectors.txt");
