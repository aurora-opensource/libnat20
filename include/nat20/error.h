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

/**
 * @file error.h
 *
 * @brief Error code definitions for libnat20.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes that may be returned by a libnat20 service function.
 *
 * This includes errors related to crypto operations, service context issues,
 * and other service-related errors.
 *
 * The error codes permitted by the crypto backend implementation are n20_error_ok_e
 * and n20_error_crypto_*_e. Crypto errors are in the range 0x1000 to 0x1FFF.
 */
enum n20_error_s {
    /**
     * @brief No error occurred.
     */
    n20_error_ok_e = 0,

    /**
     * @brief The function requires a crypto context to be passed, but none was provided.
     */
    n20_error_missing_crypto_context_e = 1,
    /**
     * @brief Insufficient buffer size.
     */
    n20_error_insufficient_buffer_size_e = 3,
    /**
     * @brief Unexpected NULL pointer in buffer size argument.
     */
    n20_error_unexpected_null_buffer_size_e = 4,
    /**
     * @brief Unexpected NULL pointer key_handle argument.
     */
    n20_error_unexpected_null_key_handle_e = 5,

    n20_error_missing_node_state_e = 6,
    n20_error_client_slot_index_out_of_range_e = 7,
    n20_error_client_slot_empty_e = 8,
    n20_error_missing_callback_function_or_context_e = 9,
    n20_error_parent_path_size_exceeds_max_e = 10,
    n20_error_missing_parent_service_e = 11,
    n20_error_unexpected_message_structure_e = 12,
    n20_error_unrecognized_request_type_e = 13,
    n20_error_write_position_overflow_e = 14,
    /**
     * @brief The crypto context given to an interface was invalid.
     *
     * Implementations must return this error if the context given is
     * NULL.
     * Implementation may deploy additional techniques to determine
     * if the context given is valid.
     */
    n20_error_crypto_invalid_context_e = 0x1001,
    /**
     * @brief Indicates that an input key argument was NULL.
     *
     * Interface function implementations that expect a `key_in`
     * parameter return this error said parameter receives a NULL
     * argument.
     *
     * @sa n20_crypto_context_t.kdf
     * @sa n20_crypto_context_t.sign
     */
    n20_error_crypto_unexpected_null_key_in_e = 0x1002,
    /**
     * @brief Indicates that an output key argument was NULL.
     *
     * Interface function implementations that expect a `key_out`
     * parameter return this error said parameter receives a NULL
     * argument.
     *
     * @sa n20_crypto_context_t.kdf
     */
    n20_error_crypto_unexpected_null_key_out_e = 0x1003,
    /**
     * @brief Indicates that a size output argument was NULL.
     *
     * Interface function implementations that expect a `*_size_in_out`
     * parameter return this error said parameter receives a NULL
     * argument.
     *
     * @sa n20_crypto_digest_context_t.digest
     * @sa n20_crypto_context_t.sign
     * @sa n20_crypto_context_t.key_public_key
     */
    n20_error_crypto_unexpected_null_size_e = 0x1004,
    /**
     * @brief Indicates that the user data input argument was NULL.
     *
     * Functions that receive unformatted user data, like
     * the message for `sign` and `digest` or the
     * the key derivation context of `kdf` return this
     * error if the data parameter receives a NULL argument.
     *
     * @sa n20_crypto_digest_context_t.digest
     * @sa n20_crypto_context_t.sign
     * @sa n20_crypto_context_t.kdf
     */
    n20_error_crypto_unexpected_null_data_e = 0x1005,
    /**
     * @brief Indicates that the user data input argument was NULL.
     *
     * Functions that receive unformatted user data, like
     * the message for `sign` and `digest` or the
     * the key derivation context of `kdf` return this
     * error if @ref n20_crypto_gather_list_t.count is
     * non zero but @ref n20_crypto_gather_list_t.list is NULL.
     *
     * @sa n20_crypto_digest_context_t.digest
     * @sa n20_crypto_context_t.sign
     * @sa n20_crypto_context_t.kdf
     */
    n20_error_crypto_unexpected_null_list_e = 0x1006,
    /**
     * @brief Indicates that the user data input argument was NULL.
     *
     * Functions that receive unformatted user data, like
     * the message for `sign` and `digest` or the
     * the key derivation context of `kdf` return this
     * error the gather list contains a slice
     * with @ref n20_slice_t.size non zero but
     * @ref n20_slice_t.buffer is NULL.
     *
     * @sa n20_crypto_digest_context_t.digest
     * @sa n20_crypto_context_t.kdf
     * @sa n20_crypto_context_t.sign
     */
    n20_error_crypto_unexpected_null_slice_e = 0x1007,
    /**
     * @brief This should not be used outside of development.
     *
     * During development of a new crypto interface implementation
     * this error can be returned by yet unimplemented functions.
     * It may never be returned in complete implementations.
     *
     * It may be used in the future to toggle tests depending on
     * unimplemented functions in debug builds. Release builds
     * must never tolerate unimplemented errors however.
     */
    n20_error_crypto_not_implemented_e = 0x1008,
    /**
     * @brief Indicates that an unknown algorithm was selected.
     *
     * Interface functions that expect an algorithm selector
     * return this error if the selected algorithm is
     * outside of the selected range.
     *
     * @sa n20_crypto_digest_context_t.digest
     */
    n20_error_crypto_unknown_algorithm_e = 0x1009,
    /**
     * @brief Indicates that the key input argument is unsuitable for the requested operation.
     *
     * Interface functions that expect a `key_in` argument
     * must check if the given key is suitable for the requested
     * operation and return this error if it is not.
     *
     * @sa n20_crypto_context_t.kdf
     * @sa n20_crypto_context_t.sign
     * @sa n20_crypto_context_t.key_public_key
     */
    n20_error_crypto_invalid_key_e = 0x100a,
    /**
     * @brief Indicates that the requested key type is out of range.
     *
     * Interface functions that expect a `key_type_in` argument
     * return this error if the selected key type is outside of
     * defined range.
     *
     * @sa n20_crypto_context_t.kdf
     */
    n20_error_crypto_invalid_key_type_e = 0x100b,
    /**
     * @brief Indicates that the user supplied buffer is insufficient.
     *
     * Interface functions that require the user to allocate an output buffer
     * return this error if the supplied buffer size is too small or
     * if the output buffer argument was NULL.
     *
     * Important: If this error is returned, and the function has a corresponding
     * `*_size_in_out` parameter, it must be set to the maximal required buffer
     * size required by the implementation to successfully complete the function call.
     * This must always be possible because if the `*_size_in_out` argument was
     * NULL, the function must have returned
     * @ref n20_error_crypto_unexpected_null_size_e.
     *
     * @sa n20_crypto_digest_context_t.digest
     * @sa n20_crypto_digest_context_t.hmac
     * @sa n20_crypto_digest_context_t.hkdf
     * @sa n20_crypto_digest_context_t.hkdf_extract
     * @sa n20_crypto_digest_context_t.hkdf_expand
     * @sa n20_crypto_context_t.sign
     * @sa n20_crypto_context_t.key_public_key
     */
    n20_error_crypto_insufficient_buffer_size_e = 0x100c,
    /**
     * @brief Indicates that an unexpected null pointer was received as argument.
     *
     * This generic variant of the error should not be used by
     * implementations of any of the interface functions, rather it is returned
     * by implementation specific factory functions indicating that
     * one of their implementation specific arguments was unexpectedly
     * NULL.
     */
    n20_error_crypto_unexpected_null_e = 0x100d,
    /**
     * @brief Indicates that the implementation ran out of a critical resource.
     *
     * Interface functions may return this error if they failed to
     * perform an operation due to a lack of physical resources.
     * This includes memory allocation errors.
     */
    n20_error_crypto_no_resources_e = 0x100e,
    /**
     * @brief Indicates that an implementation specific error has occurred.
     *
     * This is a catch all for unexpected errors that can be encountered
     * by an implementation.
     */
    n20_error_crypto_implementation_specific_e = 0x100f,
    /**
     * @brief Indicates that the key slice was NULL.
     *
     * This error is returned by HKDF implementations if the key slice
     * passed to the HKDF function is NULL but the size is non-zero.
     *
     * @sa n20_crypto_digest_context_t.hkdf
     */
    n20_error_crypto_unexpected_null_slice_key_e = 0x1010,
    /**
     * @brief Indicates that the salt slice was NULL.
     *
     * This error is returned by HKDF implementations if the salt slice
     * passed to the HKDF function is NULL but the size is non-zero.
     *
     * @sa n20_crypto_digest_context_t.hkdf
     * @sa n20_crypto_digest_context_t.hkdf_extract
     */
    n20_error_crypto_unexpected_null_slice_salt_e = 0x1011,
    /**
     * @brief Indicates that the info slice was NULL.
     *
     * This error is returned by HKDF implementations if the info slice
     * passed to the HKDF function is NULL but the size is non-zero.
     *
     * @sa n20_crypto_digest_context_t.hkdf
     * @sa n20_crypto_digest_context_t.hkdf_extract
     */
    n20_error_crypto_unexpected_null_slice_info_e = 0x1012,
    /**
     * @brief Indicates that the IKM slice was NULL.
     *
     * This error is returned by HKDF implementations if the IKM slice
     * passed to the HKDF function is NULL but the size is non-zero.
     *
     * @sa n20_crypto_digest_context_t.hkdf_extract
     */
    n20_error_crypto_unexpected_null_slice_ikm_e = 0x1013,
    /**
     * @brief Indicates that the PRK slice was NULL.
     *
     * This error is returned by HKDF implementations if the PRK slice
     * passed to the HKDF function is NULL but the size is non-zero.
     *
     * @sa n20_crypto_digest_context_t.hkdf_extract
     */
    n20_error_crypto_unexpected_null_slice_prk_e = 0x1014,

};

/**
 * @brief Alias for @ref n20_error_s
 */
typedef enum n20_error_s n20_error_t;

#ifdef __cplusplus
}
#endif
