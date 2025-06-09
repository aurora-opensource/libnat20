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

#include <gtest/gtest.h>
#include <nat20/crypto.h>

#include <tuple>
#include <vector>

extern std::vector<std::tuple<std::string,
                              n20_crypto_digest_algorithm_t,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>>>
    sha2TestVectors;

/*
 * The following test vectors are from the cryptographic algorithm validation program:
 * FIPS 198-1 Keyed-Hash message authentication code (HMAC).
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/message-authentication
 */
extern std::vector<std::tuple<std::string,
                              n20_crypto_digest_algorithm_t,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>>>
    hmacTestVectors;

extern std::vector<std::tuple<std::string,
                              n20_crypto_digest_algorithm_t,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>,
                              std::vector<uint8_t>>>
    hkdfTestVectors;
