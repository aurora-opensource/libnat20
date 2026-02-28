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
#include <nat20/testing/test_bssl_utils.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>

EVP_PKEY_PTR_t n20_crypto_key_to_evp_pkey_ptr(n20_crypto_key_type_s key_type,
                                              uint8_t* public_key,
                                              size_t public_key_size) {
    switch (key_type) {
        case n20_crypto_key_type_ed25519_e: {
            auto key = EVP_PKEY_PTR_t(
                EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, public_key_size));
            if (!key) {
                ADD_FAILURE();
                return nullptr;
            }

            return key;
        }
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            auto ec_key = EC_KEY_PTR_t(EC_KEY_new_by_curve_name(
                key_type == n20_crypto_key_type_secp256r1_e ? NID_X9_62_prime256v1
                                                            : NID_secp384r1));
            if (!ec_key) {
                ADD_FAILURE();
                return nullptr;
            }

            auto ec_key_p = ec_key.get();
            uint8_t const* p = public_key;
            if (!o2i_ECPublicKey(&ec_key_p, &p, public_key_size)) {
                ADD_FAILURE();
                return nullptr;
            }

            auto key = EVP_PKEY_PTR_t(EVP_PKEY_new());
            if (!key || !EVP_PKEY_assign_EC_KEY(key.get(), ec_key.release())) {
                ADD_FAILURE();
                return nullptr;
            }

            return key;
        }
        default: {
            ADD_FAILURE();
            return nullptr;
        }
    }
}

std::string BsslError() {
    constexpr size_t BSSL_ERROR_BUFFER_SIZE = 2000;
    char buffer[BSSL_ERROR_BUFFER_SIZE];
    auto error = ERR_get_error();
    ERR_error_string_n(error, buffer, BSSL_ERROR_BUFFER_SIZE);
    return std::string(buffer);
}
