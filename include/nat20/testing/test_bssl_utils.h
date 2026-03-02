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

#pragma once

#include <nat20/crypto.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include <string>

/**
 * @file test_bssl_utils.h
 * @brief BoringSSL utility functions and types for NAT20 testing.
 *
 * This header provides utility functions and type definitions for working
 * with BoringSSL in NAT20 unit tests. It includes smart pointer wrappers
 * for BoringSSL types and conversion functions between NAT20 and BoringSSL
 * cryptographic objects.
 *
 * These utilities are intended for testing purposes only and should not
 * be used in production code.
 */

/**
 * @brief Macro to create BoringSSL unique pointer type aliases.
 *
 * This macro creates a type alias for bssl::UniquePtr<name> with the
 * suffix _PTR_t. It simplifies the declaration of smart pointers for
 * BoringSSL types, providing automatic memory management.
 *
 * @param name The base type name (e.g., EVP_PKEY becomes EVP_PKEY_PTR_t)
 *
 * Example usage:
 * @code
 * MAKE_PTR(EVP_PKEY);  // Creates EVP_PKEY_PTR_t type alias
 * EVP_PKEY_PTR_t key = ...;  // Automatic cleanup when out of scope
 * @endcode
 */
#define MAKE_PTR(name) using name##_PTR_t = bssl::UniquePtr<name>

/**
 * @brief Smart pointer type for EVP_PKEY objects.
 *
 * Provides automatic memory management for EVP_PKEY structures.
 * The pointer automatically calls the appropriate cleanup function
 * when it goes out of scope.
 */
MAKE_PTR(EVP_PKEY);

/**
 * @brief Smart pointer type for EVP_PKEY_CTX objects.
 *
 * Provides automatic memory management for EVP_PKEY_CTX structures
 * used in key operations like signing, verification, and key derivation.
 */
MAKE_PTR(EVP_PKEY_CTX);

/**
 * @brief Smart pointer type for EVP_MD_CTX objects.
 *
 * Provides automatic memory management for EVP_MD_CTX structures
 * used in message digest operations.
 */
MAKE_PTR(EVP_MD_CTX);

/**
 * @brief Smart pointer type for BIO objects.
 *
 * Provides automatic memory management for BIO (Basic Input/Output)
 * structures used for data serialization and deserialization.
 */
MAKE_PTR(BIO);

/**
 * @brief Smart pointer type for X509 objects.
 *
 * Provides automatic memory management for X509 certificate structures.
 */
MAKE_PTR(X509);

/**
 * @brief Smart pointer type for EC_KEY objects.
 *
 * Provides automatic memory management for EC_KEY structures
 * used for elliptic curve cryptographic operations.
 */
MAKE_PTR(EC_KEY);

/**
 * @brief Convert a NAT20 crypto key to a BoringSSL EVP_PKEY.
 *
 * This function creates a BoringSSL EVP_PKEY object from NAT20 key type
 * and public key data. The resulting EVP_PKEY can be used with BoringSSL
 * APIs for cryptographic operations and verification.
 *
 * This is primarily used in testing to verify that NAT20-generated keys
 * are compatible with standard cryptographic libraries and to perform
 * independent verification of cryptographic operations.
 *
 * @param key_type The NAT20 cryptographic key type (Ed25519, P-256, P-384)
 * @param public_key Pointer to the public key data buffer
 * @param public_key_size Size of the public key data in bytes
 *
 * @return Smart pointer to EVP_PKEY object on success, nullptr on failure
 *
 * @note The public key data format must match the expectations for the
 *       specified key type (e.g., 32 bytes for Ed25519, uncompressed
 *       point format for ECDSA curves).
 *
 * @warning This function is for testing purposes only and should not be
 *          used in production code.
 *
 * Example usage:
 * @code
 * uint8_t ed25519_pubkey[32] = {...};
 * auto evp_key = n20_crypto_key_to_evp_pkey_ptr(
 *     n20_crypto_key_type_ed25519_e,
 *     ed25519_pubkey,
 *     sizeof(ed25519_pubkey)
 * );
 * if (evp_key) {
 *     // Use evp_key for verification
 * }
 * @endcode
 */
EVP_PKEY_PTR_t n20_crypto_key_to_evp_pkey_ptr(n20_crypto_key_type_s key_type,
                                              uint8_t* public_key,
                                              size_t public_key_size);

/**
 * @brief Get the last BoringSSL error as a formatted string.
 *
 * This function retrieves and formats the most recent error from the
 * BoringSSL error queue. It's useful for debugging and test diagnostics
 * when BoringSSL operations fail.
 *
 * The function clears the error from the error queue as a side effect.
 * If multiple errors are present, only the most recent one is returned.
 *
 * @return String containing the formatted error message, or empty string
 *         if no error is present in the queue
 *
 * @warning This function is for testing and debugging purposes only.
 *
 * Example usage:
 * @code
 * EVP_PKEY* key = EVP_PKEY_new();
 * if (!key) {
 *     std::string error = BsslError();
 *     FAIL() << "Failed to create key: " << error;
 * }
 * @endcode
 */
std::string BsslError();
