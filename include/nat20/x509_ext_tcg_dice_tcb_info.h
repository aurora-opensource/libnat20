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

/** @file */

#pragma once

#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup n20_x509_ext_tcg_dice_tcb_info_operational_flags_macros TCG DICE TCB Info Operational
 * Flags Macros.
 *
 * These macros set the corresponding flags in the operational flags (and mask)
 * bit mask of @ref n20_x509_ext_tcg_dice_tcb_info_operational_flags_t.
 * Each macro takes a pointer to an instance of
 * @ref n20_x509_ext_tcg_dice_tcb_info_operational_flags_t as its argument.
 *
 * See TCG DICE Attestation Architecture Version 1.1, Section 6.1.1.1.
 *
 * # Example
 *
 * @code{.c}
 * n20_x509_ext_tcg_dice_tcb_info_operational_flags_t operational_flags = {0};
 * N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_SECURE(&operational_flags);
 * @endcode
 * @{
 */

/**
 * @brief The target environment is not configured for normal operation.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_CONFIGURED(operational_flags) \
    (operational_flags)->operational_flags_mask[0] |= 0x80
/**
 * @brief The target environment is not secure.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_SECURE(operational_flags) \
    (operational_flags)->operational_flags_mask[0] |= 0x40
/**
 * @brief The target environment is recovering (e.g. from a failure).
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_RECOVERY(operational_flags) \
    (operational_flags)->operational_flags_mask[0] |= 0x20
/**
 * @brief The target environment can be debuged.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_DEBUG(operational_flags) \
    (operational_flags)->operational_flags_mask[0] |= 0x10
/**
 * @brief The target environment is vulnerable to replay attack.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_REPLAY_PROTECTED( \
    operational_flags)                                                             \
    (operational_flags)->operational_flags_mask[0] |= 0x08
/**
 * @brief The target environment is vulneerable to modification by unauthorized updates.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_INTEGRITY_PROTECTED( \
    operational_flags)                                                                \
    (operational_flags)->operational_flags_mask[0] |= 0x04
/**
 * @brief The target environment is not measured after being loaded into memory.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_RUNTIME_MEASURED( \
    operational_flags)                                                             \
    (operational_flags)->operational_flags_mask[0] |= 0x02
/**
 * @brief The target environment is mutable.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_IMMUTABLE(operational_flags) \
    (operational_flags)->operational_flags_mask[0] |= 0x01
/**
 * @brief – The Target Environment measurements are not measurements of a Trusted Computing Base
 * (TCB).
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_TCB(operational_flags) \
    (operational_flags)->operational_flags_mask[1] |= 0x80
/**
 * @brief Used to force a fixed width of for the OperationalFlags (and OperationalFlagsMask) bit
 * string.
 */
#define N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_FIXED_WIDTH(operational_flags) \
    (operational_flags)->operational_flags_mask[3] |= 0x01
/**
 * @}
 */

/**
 * @brief TCG DICE TCB Info Operational Flags.
 *
 * This type is used to populate the TCB Info Operational Flags and Operational Flags Mask
 * ASN.1 bitstrings.
 *
 * Always zero initialize instances of this structure and
 * set the flags using the @ref n20_x509_ext_tcg_dice_tcb_info_operational_flags_macros.
 *
 * # Example
 *
 * @code{.c}
 * n20_x509_ext_tcg_dice_tcb_info_operational_flags_t operational_flags = {0};
 * N20_X509_EXT_TCG_DICE_TCB_INFO_OPERATIONAL_FLAGS_SET_NOT_SECURE(&operational_flags);
 * @endcode
 *
 * (See TCG DICE Attestation Architecture Version 1.1, Section 6.1.1.1.)
 */
struct n20_x509_ext_tcg_dice_tcb_info_operational_flags_s {
    /**
     * @brief The operational flags mask.
     *
     * Use the @ref n20_x509_ext_tcg_dice_tcb_info_operational_flags_macros to set the individual
     * bits of the operation flags mask. As described in
     * @ref n20_x509_ext_tcg_dice_tcb_info_operational_flags_t, there is no need to access this
     * field directly.
     */
    uint8_t operational_flags_mask[4];
};

/**
 * @brief Alias for @ref n20_x509_ext_tcg_dice_tcb_info_operational_flags_s
 */
typedef struct n20_x509_ext_tcg_dice_tcb_info_operational_flags_s n20_x509_ext_tcg_dice_tcb_info_operational_flags_t;

/**
 * @brief TCG DICE TCB FW ID.
 *
 * (See TCG DICE Attestation Architecture Version 1.1, Section 6.1.1.)
 */
struct n20_x509_ext_tcg_dice_tcb_info_fwid_s {
    /**
     * @brief Hash algorithm OID of the algorithm used to generate the digest.
     */
    n20_asn1_object_identifier_t hash_algo;
    /**
     * @brief Digest of firmware, initialization values, or other settings of the Target
     * Environment.
     *
     * If the digest buffer is NULL, no digest is added to the extension.
     */
    n20_asn1_slice_t digest;
};

/**
 * @brief Alias for @ref n20_x509_ext_tcg_dice_tcb_info_fwid_s
 */
typedef struct n20_x509_ext_tcg_dice_tcb_info_fwid_s n20_x509_ext_tcg_dice_tcb_info_fwid_t;

/**
 * @brief List of TCG DICE FWIDs.
 *
 * If the list is NULL, no FWIDs are inserted into the TCG DICE TCB Info extension.
 */
struct n20_x509_ext_tcg_dice_tcb_info_fwid_list_s {
    /**
     * @brief List of FWIDs to include in the TCG DICE TCB Info extension.
     */
    n20_x509_ext_tcg_dice_tcb_info_fwid_t const *list;
    /**
     * @brief Number of FWIDs in the list.
     */
    size_t count;
};

/**
 * @brief Alias for @ref n20_x509_ext_tcg_dice_tcb_info_fwid_list_s
 */
typedef struct n20_x509_ext_tcg_dice_tcb_info_fwid_list_s n20_x509_ext_tcg_dice_tcb_info_fwid_list_t;

/**
 * @brief TCG DICE TCB Info X509 extension context.
 *
 * This is the context expected by
 * @ref n20_x509_ext_tcg_dice_tcb_info_content.
 * An instance of this object must be passed to the callback.
 * This is typically done using @ref n20_x509_extension by
 * initializing @ref n20_x509_extension_t.content_cb with
 * @ref n20_x509_ext_tcg_dice_tcb_info_content and setting
 * @ref n20_x509_extension_t.context to an instance of this
 * struct.
 *
 * (See TCG DICE Attestation Architecture Version 1.1, Section 6.1.1.)
 * @sa OID_TCG_DICE_TCB_INFO
 */
struct n20_x509_ext_tcg_dice_tcb_info_s {
    /**
     * @brief The entity that created the measurement of the Target Environment.
     *
     * Must be a nul terminated UTF-8 encoded string.
     *
     * If NULL, vendor is not included in the generated extension.
     */
    char const *vendor;
    /**
     * @brief The product name associated with the measurement of the Target Environment.
     *
     * Must be a nul terminated UTF-8 encoded string.
     *
     * If NULL, model is not included in the generated extension.
     */
    char const *model;
    /**
     * @brief The revision string associated with the Target Environment.
     *
     * Must be a nul terminated UTF-8 encoded string.
     *
     * If NULL, version is not included in the generated extension.
     */
    char const *version;
    /**
     * @brief The security version number associated with the Target Environment.
     */
    int64_t svn;
    /**
     * @brief The DICE layer associated with this measurement of the Target Environment.
     */
    int64_t layer;
    /**
     * @brief A value that distinguishes different instances of the same type of Target Environment.
     */
    int64_t index;
    /**
     * @brief List of FWIDs to include in the extension.
     *
     * @sa n20_x509_ext_tcg_dice_tcb_info_fwid_list_t
     */
    n20_x509_ext_tcg_dice_tcb_info_fwid_list_t fwids;
    /**
     * @brief A list of flags that enumerate potentially simultaneous operational states of the
     * Target Environment.
     *
     * @sa n20_x509_ext_tcg_dice_tcb_info_operational_flags_t
     */
    n20_x509_ext_tcg_dice_tcb_info_operational_flags_t flags;
    /**
     * @brief Used to commumicate which bits in @ref flags are meaningful.
     *
     * When a bit is set here, the bit at the corresponding position in @ref flags is meaninful to
     * the verifier.
     *
     * @sa n20_x509_ext_tcg_dice_tcb_info_operational_flags_t
     */
    n20_x509_ext_tcg_dice_tcb_info_operational_flags_t flags_mask;
    /**
     * @brief Vendor supplied values that encode vendor, model, or device specific state.
     *
     * If vender_info.buffer is NULL vendor info is not included in the generated extension.
     */
    n20_asn1_slice_t vendor_info;
    /**
     * @brief A machine readable description of the measurement.
     *
     * If type.buffer is NULL, type is not included in the generated extension.
     */
    n20_asn1_slice_t type;
};

/**
 * @brief Alias for @ref n20_x509_ext_tcg_dice_tcb_info_s
 */
typedef struct n20_x509_ext_tcg_dice_tcb_info_s n20_x509_ext_tcg_dice_tcb_info_t;

/**
 * @brief Renders the value of a TCG DICE TCB Info X509 extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_tcg_dice_tcb_info_t as @p context argument.
 *
 * If @p context is NULL, nothing is rendered, which would leave
 * the resulting TCG DICE TCB Info extension malformed.
 *
 * This function is typically not used directly but instead
 * passed to @ref n20_x509_extension by initializing an
 * instance of @ref n20_x509_extensions_t
 * (See @ref n20_x509_extension for an example).
 */
extern void n20_x509_ext_tcg_dice_tcb_info_content(n20_stream_t *const s, void *context);

/**
 * @brief TCG DICE Multi TCB Info X509 extension context.
 *
 * This is the context expected by
 * @ref n20_x509_ext_tcg_dice_multi_tcb_info_content.
 * An instance of this object must be passed to the callback.
 * This is typically done using @ref n20_x509_extension by
 * initializing @ref n20_x509_extension_t.content_cb with
 * @ref n20_x509_ext_tcg_dice_multi_tcb_info_content and setting
 * @ref n20_x509_extension_t.context to an instance of this
 * struct.
 *
 * (See TCG DICE Attestation Architecture Version 1.1, Section 6.1.2.)
 * @sa OID_TCG_DICE_MULTI_TCB_INFO
 */
struct n20_x509_ext_tcg_dice_multi_tcb_info_s {
    /**
     * @brief List of TCB Info to include in the extension.
     *
     * If NULL, no list is rendered in the extension.
     *
     * @sa n20_x509_ext_tcg_dice_tcb_info_t
     */
    n20_x509_ext_tcg_dice_tcb_info_t const *list;
    /**
     * @brief Number of elements in the list.
     */
    size_t count;
};

/**
 * @brief Alias for @ref n20_x509_ext_tcg_dice_multi_tcb_info_s
 */
typedef struct n20_x509_ext_tcg_dice_multi_tcb_info_s n20_x509_ext_tcg_dice_multi_tcb_info_t;

/**
 * @brief Renders the value of a TCG DICE Multi TCB Info X509 extension.
 *
 * The function expects a pointer to an instance of
 * @ref n20_x509_ext_tcg_dice_multi_tcb_info_t as @p context argument.
 *
 * If @p context is NULL, or the list is NULL or number of elements in the list is 0, nothing is
 * rendered, which would leave the resulting TCG DICE Multi TCB Info extension malformed.
 *
 * This function is typically not used directly but instead
 * passed to @ref n20_x509_extension by initializing an
 * instance of @ref n20_x509_extensions_t
 * (See @ref n20_x509_extension for an example).
 */
extern void n20_x509_ext_tcg_dice_multi_tcb_info_content(n20_stream_t *const s, void *context);

#ifdef __cplusplus
}
#endif
