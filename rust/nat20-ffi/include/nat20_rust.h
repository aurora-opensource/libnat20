/*
 * Copyright 2026 Aurora Operations, Inc.
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

/**
 * @file nat20_rust.h
 * @brief C interface of the Rust nat20 library (libnat20_rust.a).
 *
 * Deterministic DICE key derivation and CWT (COSE_Sign1, Ed25519)
 * certificate issuance for boot firmware. Derivation- and wire-compatible
 * with C libnat20 (BoringSSL backend): the same CDI yields the same keys,
 * identifiers, and certificate bytes.
 *
 * Certificates are not returned in a caller buffer: the issue functions
 * append them to a DICE handover (the certificate chain passed from stage to
 * stage; format in HANDOVER.md) as entries, sizing each entry to the
 * certificate before writing it. There is therefore no size-negotiation
 * call; a handover too small to hold another entry is reported as
 * N20R_ERR_INSUFFICIENT_BUFFER. n20r_issue_next_stage_cwt() leaves the
 * handover unchanged on that and every other error; for
 * n20r_issue_device_id_cwt(), which starts a new handover, see there.
 *
 * A NULL pointer with a size is an empty buffer, whatever the size.
 *
 * A handover region must be 4-byte aligned.
 */

#ifndef NAT20_RUST_H
#define NAT20_RUST_H

#ifdef N20R_TYPES_HEADER
/* For environments compiled with -nostdinc that provide size_t and the
 * uintN_t types themselves, where the compiler's stdint.h would conflict:
 * define N20R_TYPES_HEADER to their header. U-Boot, for example, needs
 * -DN20R_TYPES_HEADER='"linux/types.h"': quoted, because GNU C predefines
 * `linux`, which would be expanded inside angle brackets. */
#include N20R_TYPES_HEADER
#else
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum n20r_error {
    N20R_OK = 0,
    /** The handover cannot fit another entry of the required size.
     *  Same numeric value as n20_error_insufficient_buffer_size_e. */
    N20R_ERR_INSUFFICIENT_BUFFER = 3,
    /** An argument violates the documented contract, or the DICE context
     *  was never initialised with n20r_ctx_init(). */
    N20R_ERR_INVALID_ARGUMENT = 4,
    N20R_ERR_CRYPTO = 5,
    /** A certificate came out a different size than predicted (a library
     *  bug); nothing was appended. */
    N20R_ERR_CERTIFICATE_SIZE_MISMATCH = 6,
} n20r_error_t;

/**
 * The DICE context
 * ================
 *
 * Open-DICE measurements become available at different points in a boot, so
 * they are accumulated in a context before a certificate commits them. The
 * library keeps no global state: the caller provides the storage, stamps it
 * with n20r_ctx_init(), and passes it back to every setter and to
 * n20r_issue_next_stage_cwt(). Each access verifies the stamp, so using an
 * uninitialised context returns N20R_ERR_INVALID_ARGUMENT rather than acting
 * on garbage. Zero-filled memory is deliberately not a valid context.
 *
 * Declare the storage with this size and an alignment suitable for a
 * pointer:
 *
 *     static uint8_t dice_ctx[N20R_DICE_CTX_SIZE] __aligned(8);
 *
 * The constant is deliberately larger than the structure needs so that this
 * header stays stable if the layout changes; a compile-time assertion in the
 * library keeps the two in step.
 *
 * Each setter takes a (pointer, size) pair and an optional destructor. With
 * a destructor the buffer is adopted and released when the field is replaced
 * or the context is cleaned up; without one it is borrowed and must stay
 * valid, and must not be mutated, until that same point. Ownership
 * transfers only when the setter returns N20R_OK; on an error the
 * destructor is not called and the buffer stays the caller's. A NULL
 * pointer clears the field. Fields never set are empty.
 *
 * Notes on the fields:
 *  - If configuration_hash is empty, configuration_descriptor is used as
 *    the inline configuration value. Its size is not checked: the Open
 *    Profile for DICE requires exactly 64 bytes, other profiles relax that.
 *  - profile_name should be UTF-8 (not NUL-terminated; size gives the
 *    length). It is written verbatim as a CBOR text string and not
 *    validated, as in C libnat20.
 *  - hidden feeds the CDI derivation but never appears in the certificate.
 */
#define N20R_DICE_CTX_SIZE 256

/** Prepares a caller-provided buffer for use as a DICE context. Rejects a
 *  NULL, misaligned or undersized buffer. */
n20r_error_t n20r_ctx_init(uint8_t *ctx, size_t size);

/** Releases every buffer the context adopted and invalidates the stamp, so a
 *  later use without re-initialising is rejected. */
n20r_error_t n20r_ctx_cleanup(uint8_t *ctx);

n20r_error_t n20r_set_code_hash(uint8_t *ctx,
                                uint8_t const *code_hash,
                                size_t code_hash_size,
                                void (*drop)(void *));
n20r_error_t n20r_set_code_descriptor(uint8_t *ctx,
                                      uint8_t const *code_descriptor,
                                      size_t code_descriptor_size,
                                      void (*drop)(void *));
n20r_error_t n20r_set_configuration_hash(uint8_t *ctx,
                                         uint8_t const *configuration_hash,
                                         size_t configuration_hash_size,
                                         void (*drop)(void *));
n20r_error_t n20r_set_configuration_descriptor(uint8_t *ctx,
                                               uint8_t const *configuration_descriptor,
                                               size_t configuration_descriptor_size,
                                               void (*drop)(void *));
n20r_error_t n20r_set_authority_hash(uint8_t *ctx,
                                     uint8_t const *authority_hash,
                                     size_t authority_hash_size,
                                     void (*drop)(void *));
n20r_error_t n20r_set_authority_descriptor(uint8_t *ctx,
                                           uint8_t const *authority_descriptor,
                                           size_t authority_descriptor_size,
                                           void (*drop)(void *));
n20r_error_t n20r_set_profile_name(uint8_t *ctx,
                                   uint8_t const *profile_name,
                                   size_t profile_name_size,
                                   void (*drop)(void *));
n20r_error_t n20r_set_hidden(uint8_t *ctx,
                             uint8_t const *hidden,
                             size_t hidden_size,
                             void (*drop)(void *));

/** 0 not-configured, 1 normal, 2 debug, 3 recovery. Any other value is
 *  rejected and leaves the previous mode in place. */
n20r_error_t n20r_set_mode(uint8_t *ctx, uint8_t mode);

/**
 * Issues the self-signed device-identity CWT from the 32-byte root CDI and
 * starts a new handover with it.
 *
 * The certificate certifies the device-identity Ed25519 public key (derived
 * deterministically from the CDI) and is signed with that same key. Issuer
 * and subject are both the key's CDI_ID.
 *
 * This initialises the handover, discarding anything it held, so call it
 * first. All arguments are checked before the region is touched; once they
 * pass, the region is initialised even if issuing then fails, which leaves
 * an empty handover.
 *
 * @param cdi 32-byte root CDI secret.
 * @param profile_name Optional profile-name claim (UTF-8, not validated);
 *        NULL or size 0 to omit.
 * @param handover The handover region, 4-byte aligned.
 * @param handover_size Size of the handover region in bytes.
 */
n20r_error_t n20r_issue_device_id_cwt(uint8_t const cdi[32],
                                      uint8_t const *profile_name,
                                      size_t profile_name_size,
                                      uint8_t *handover,
                                      size_t handover_size);

/**
 * Derives the next-stage CDI from the root CDI and the open-DICE input, and
 * issues the next-stage CWT: it contains the open-DICE claims and the
 * next-stage public key, and is signed by the device-identity key. The
 * certificate is appended to the handover, which must already hold the
 * chain up to this stage (see n20r_issue_device_id_cwt()).
 *
 * @param ctx DICE context holding the open-DICE input, prepared by
 *        n20r_ctx_init(). Fields never set are empty.
 * @param cdi 32-byte root CDI secret.
 * @param next_cdi_out Receives the 32-byte next-stage CDI (hand this to the
 *        next boot stage); written only on success. Must be non-NULL.
 *        Treat as secret.
 * @param handover The handover region, 4-byte aligned.
 * @param handover_size Size of the handover region in bytes.
 */
n20r_error_t n20r_issue_next_stage_cwt(uint8_t *ctx,
                                       uint8_t const cdi[32],
                                       uint8_t next_cdi_out[32],
                                       uint8_t *handover,
                                       size_t handover_size);

/**
 * Validates a DICE handover left by an earlier stage, as a stage taking it
 * over must before relying on or extending it.
 *
 * Checks the header and that the content is a CBOR indefinite-length array
 * closed at the terminator offset (HANDOVER.md, "Rules"); entries are not
 * parsed. The region is not modified.
 *
 * @param handover The handover region, 4-byte aligned.
 * @param handover_size Size of the region in bytes.
 * @param used On success, the number of bytes in use (header, entries and
 *        terminator); unchanged on error.
 * @return N20R_ERR_INVALID_ARGUMENT for any malformed structure.
 */
n20r_error_t n20r_handover_validate(uint8_t const *handover, size_t handover_size, size_t *used);

/**
 * Writes the 32-byte device-identity Ed25519 public key for the given root
 * CDI (e.g. for provisioning or out-of-band trust establishment).
 */
n20r_error_t n20r_device_id_public_key(uint8_t const cdi[32], uint8_t public_key_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* NAT20_RUST_H */
