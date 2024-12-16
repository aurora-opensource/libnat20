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

/** @file */

#pragma once

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define N20_OPEN_DICE_HASH_LENGTH 64
#define N20_OPEN_DICE_CONFIGURATION_INLINE_LENGTH 64
#define N20_OPEN_DICE_HIDDEN_LENGTH 64

/**
 * @brief Mode inputs to the DICE.
 */
typedef enum n20_open_dice_modes_s {
    /**
     * @brief No security features (e.g. verified boot) have been configured on the device.
     */
    n20_open_dice_not_configured_e = 0,
    /**
     * @brief Device is operating normally with security features enabled.
     */
    n20_open_dice_normal_e = 1,
    /**
     * @brief Device is in debug mode, which is a non-secure state.
     */
    n20_open_dice_debug_e = 2,
    /**
     * @brief Device is in a debug or maintenance mode.
     */
    n20_open_dice_recovery_e = 3,
} n20_open_dice_modes_t;

/**
 * @brief Format of the configuration data used as input to the DICE.
 */
typedef enum n20_open_dice_configuration_format_s {
    /**
     * @brief Format of the configuration data is an implementation defined inline value (not a
     * hash).
     */
    n20_open_dice_configuration_format_inline_e = 0,
    /**
     * @brief Format of the configuration data is a hash over an implementation defined
     * configuration descriptor.
     */
    n20_open_dice_configuration_format_descriptor_e = 1,
} n20_open_dice_configuration_format_t;

/**
 * @brief Inputs to the DICE.
 *
 * This structure represents all the security-revelvant properties to calculate the CDI values
 * for the next layer.
 */
typedef struct n20_open_dice_inputs_s {
    /**
     * @brief Digest of the code used as input to the DICE.
     */
    uint8_t code_hash[N20_OPEN_DICE_HASH_LENGTH];
    /**
     * @brief Additional data used in the code input to the DICE.
     *
     * Implementation specific data about the code used to compute the CDI values.
     * If the data pointed to by @ref code_descriptor changes, this implies a change in the value
     * of @ref code_hash.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    uint8_t const *code_descriptor;
    /**
     * @brief Length of the buffer pointed to by @ref code_descriptor, in bytes.
     */
    size_t code_descriptor_length;
    /**
     * @brief Configuration type (inline or descriptor).
     *
     * If @ref configuration_format is set to @ref n20_open_dice_configuration_format_inline_e, @ref
     * configuration_inline is used as the configuation input to the DICE. @ref
     * configuration_descriptor and
     * @ref configuration_hash are ignored.
     *
     * If @ref configuration_format is set to @ref n20_open_dice_configuration_format_decriptor_e,
     * @ref configuration_descriptor and @ref configuration_hash are used.
     * @ref configuration_inline is ignored.
     *
     * @sa n20_open_dice_configuration_t
     */
    n20_open_dice_configuration_format_t configuration_format;
    /**
     * @brief Implementation defined inline configuration input to the DICE.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_open_dice_configuration_format_inline_e.
     *
     * (TODO): This will be defind in detail in a later PR. Per the OpenDICE profile,
     * it is @ref N20_OPEN_DICE_CONFIGURATION_INLINE_LENGTH bytes in length.
     */
    uint8_t configuration_inline[N20_OPEN_DICE_CONFIGURATION_INLINE_LENGTH];
    /**
     * @brief Digest of the configuration descriptor used as input to the DICE.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_open_dice_configuration_format_decriptor_e.
     */
    uint8_t configuration_hash[N20_OPEN_DICE_HASH_LENGTH];
    /**
     * @brief The configuration data used to calculate the digest used for the configuration input
     * to the DICE.
     *
     * H( @ref configuration_descriptor ) must equal the value stored in @ref configuration_hash.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_open_dice_configuration_format_decriptor_e.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    uint8_t const *configuration_descriptor;
    /**
     * @brief Length of the buffer pointed to by @ref configuration_descriptor, in bytes.
     *
     * Only valid if @ref configuration_format is set to @ref
     * n20_open_dice_configuration_format_decriptor_e.
     */
    size_t configuration_descriptor_length;
    /**
     * @brief Digest of the authority used as input to the DICE.
     */
    uint8_t authority_hash[N20_OPEN_DICE_HASH_LENGTH];
    /**
     * @brief Additional data used in the authority input to the DICE.
     *
     * Implementation specific data about the authority used to compute the CDI values.
     * If the data pointed to by @ref authority_descriptor changes, this implies a change in the
     * value of @ref authority_hash.
     *
     * No ownerships is taken. The user has to
     * assure that the buffer outlives the instance
     * of this structure.
     */
    uint8_t const *authority_descriptor;
    /**
     * @brief Length of the buffer pointed to by @ref authority_descriptor, in bytes.
     */
    size_t authority_descriptor_length;
    /**
     * @brief The DICE mode input.
     *
     * @sa n20_open_dice_modes_t
     */
    n20_open_dice_modes_t mode;
    /**
     * @brief The hidden input to the DICE.
     *
     * This value does not appear in certificates.
     */
    uint8_t hidden[N20_OPEN_DICE_HIDDEN_LENGTH];
} n20_open_dice_inputs_t;

#ifdef __cplusplus
}
#endif
