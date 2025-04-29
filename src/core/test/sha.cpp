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
#include <nat20/sha.h>

#include <string>
#include <tuple>

#include "sha256_test_vectors.hpp"
#include "sha224_test_vectors.hpp"
#include "sha512_test_vectors.hpp"
#include "sha384_test_vectors.hpp"

static std::string hexdump(std::vector<uint8_t> const& data) {
    std::stringstream s;
    int i;
    for (i = 0; i < data.size(); ++i) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

template <size_t N>
static std::string hexdump(uint8_t const (&data)[N]) {
    return hexdump(std::vector<uint8_t>(data, data + N));
}

class Sha256TestFixture : public testing::TestWithParam<
                              std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>> {
};

INSTANTIATE_TEST_CASE_P(
    ShaSha256Test,
    Sha256TestFixture,
    sha256TestVectors,
    [](testing::TestParamInfo<Sha256TestFixture::ParamType> const& info) -> std::string {
        return std::get<0>(info.param);
    });

TEST_P(Sha256TestFixture, Sha256DigestTest) {
    auto [_, msg, want_digest] = GetParam();

    n20_sha224_sha256_state_t state = n20_sha256_init();
    n20_sha256_update(&state, msg.data(), msg.size());
    std::vector<uint8_t> got_digest(32);
    n20_sha256_finalize(&state, got_digest.data());
    EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hexdump(want_digest) << std::endl
                                       << "Actual digest: " << hexdump(got_digest) << std::endl;
}


class Sha224TestFixture : public testing::TestWithParam<
                              std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>> {
};

INSTANTIATE_TEST_CASE_P(
    ShaSha224Test,
    Sha224TestFixture,
    sha224TestVectors,
    [](testing::TestParamInfo<Sha256TestFixture::ParamType> const& info) -> std::string {
        return std::get<0>(info.param);
    });

TEST_P(Sha224TestFixture, Sha224DigestTest) {
    auto [_, msg, want_digest] = GetParam();

    n20_sha224_sha256_state_t state = n20_sha224_init();
    n20_sha224_update(&state, msg.data(), msg.size());
    std::vector<uint8_t> got_digest(28);
    n20_sha224_finalize(&state, got_digest.data());
    EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hexdump(want_digest) << std::endl
                                       << "Actual digest: " << hexdump(got_digest) << std::endl;
}

class Sha512TestFixture : public testing::TestWithParam<
                              std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>> {
};

INSTANTIATE_TEST_CASE_P(
    ShaSha512Test,
    Sha512TestFixture,
    sha512TestVectors,
    [](testing::TestParamInfo<Sha256TestFixture::ParamType> const& info) -> std::string {
        return std::get<0>(info.param);
    });

TEST_P(Sha512TestFixture, Sha512DigestTest) {
    auto [_, msg, want_digest] = GetParam();

    n20_sha384_sha512_state_t state = n20_sha512_init();
    n20_sha512_update(&state, msg.data(), msg.size());
    std::vector<uint8_t> got_digest(64);
    n20_sha512_finalize(&state, got_digest.data());
    EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hexdump(want_digest) << std::endl
                                       << "Actual digest: " << hexdump(got_digest) << std::endl;
}

class Sha384TestFixture : public testing::TestWithParam<
                              std::tuple<std::string, std::vector<uint8_t>, std::vector<uint8_t>>> {
};
INSTANTIATE_TEST_CASE_P(
    ShaSha384Test,
    Sha384TestFixture,
    sha384TestVectors,
    [](testing::TestParamInfo<Sha256TestFixture::ParamType> const& info) -> std::string {
        return std::get<0>(info.param);
    });
TEST_P(Sha384TestFixture, Sha384DigestTest) {
    auto [_, msg, want_digest] = GetParam();

    n20_sha384_sha512_state_t state = n20_sha384_init();
    n20_sha384_update(&state, msg.data(), msg.size());
    std::vector<uint8_t> got_digest(48);
    n20_sha384_finalize(&state, got_digest.data());
    EXPECT_EQ(got_digest, want_digest) << "Expected digest: " << hexdump(want_digest) << std::endl
                                       << "Actual digest: " << hexdump(got_digest) << std::endl;
}
