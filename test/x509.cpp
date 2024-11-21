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

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <vector>

#include "openssl/base.h"
#include "openssl/digest.h"

#define MAKE_PTR(name)                                     \
    template <>                                            \
    struct std::default_delete<name> {                     \
        void operator()(name* p) const { name##_free(p); } \
    };                                                     \
                                                           \
    using name##_PTR_t = std::unique_ptr<name>

MAKE_PTR(EVP_PKEY);
MAKE_PTR(EVP_PKEY_CTX);
MAKE_PTR(EVP_MD_CTX);

EVP_PKEY_PTR_t generate_rsa_key(uint32_t key_bits) {
    auto evp_ctx = EVP_PKEY_CTX_PTR_t(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    if (!evp_ctx) {
        ADD_FAILURE();
        return nullptr;
    }

    if (!EVP_PKEY_keygen_init(evp_ctx.get())) {
        ADD_FAILURE();
        return nullptr;
    }

    if (!EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx.get(), key_bits)) {
        ADD_FAILURE();
        return nullptr;
    }

    EVP_PKEY* key;
    if (!EVP_PKEY_keygen(evp_ctx.get(), &key)) {
        ADD_FAILURE();
        return nullptr;
    }
    return EVP_PKEY_PTR_t(key);
}

std::optional<std::vector<uint8_t>> sign(EVP_PKEY_PTR_t const& key, std::vector<uint8_t> message) {

    auto md_ctx = EVP_MD_CTX_PTR_t(EVP_MD_CTX_new());
    if (!md_ctx) {
        ADD_FAILURE();
        return std::nullopt;
    }

    if (1 != EVP_DigestSignInit(md_ctx.get(), NULL, EVP_sha256(), NULL, key.get())) {
        ADD_FAILURE();
        return std::nullopt;
    }

    if (1 != EVP_DigestSignUpdate(md_ctx.get(), message.data(), message.size())) {
        ADD_FAILURE();
        return std::nullopt;
    }

    size_t sig_size;
    if (1 != EVP_DigestSignFinal(md_ctx.get(), NULL, &sig_size)) {
        ADD_FAILURE();
        return std::nullopt;
    }

    std::vector<uint8_t> result(sig_size);

    if (1 != EVP_DigestSignFinal(md_ctx.get(), result.data(), &sig_size)) {
        ADD_FAILURE();
        return std::nullopt;
    }

    EXPECT_EQ(sig_size, result.size());
    return result;
}

class CryptoTest : public testing::Test {};

TEST_F(CryptoTest, KeyGenSign) {

    std::string message("the message");
    auto message_v =
        std::vector<uint8_t>(reinterpret_cast<uint8_t const*>(message.c_str()),
                             reinterpret_cast<uint8_t const*>(message.c_str() + message.size()));

    auto key = generate_rsa_key(2048);
    ASSERT_TRUE(!!key);

    auto signature = sign(key, message_v);
    ASSERT_TRUE(!!signature);
}
