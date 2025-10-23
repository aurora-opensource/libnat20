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

#include <nat20/constants.h>
#include <nat20/crypto.h>
#include <nat20/error.h>
#include <nat20/oid.h>
#include <nat20/stream.h>
#include <nat20/types.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup n20_input_compression_macros Input Compression Macros
 *
 * Macros for configuring input compression settings.
 * By default SHA2-512 is used for OpenDICE input compression.
 * Set `N20_INPUT_COMPRESSION_SHA256=1` to use SHA2-256 instead.
 * @{
 */

#if defined(N20_INPUT_COMPRESSION_SHA256)
#define N20_FUNC_COMPRESSED_INPUT_SIZE 32
#define N20_FUNC_COMPRESSED_INPUT_ALGORITHM n20_crypto_digest_algorithm_sha2_256_e
#else
/**
 * @brief Size of the compressed input.
 *
 * This controls the size of @ref n20_compressed_input_t.
 */
#define N20_FUNC_COMPRESSED_INPUT_SIZE 64
/**
 * @brief Algorithm used for compressing the input.
 *
 * This controls the algorithm used for compressing @ref n20_compressed_input_t.
 *
 * @sa n20_compress_input
 */
#define N20_FUNC_COMPRESSED_INPUT_ALGORITHM n20_crypto_digest_algorithm_sha2_512_e
#endif

/** @} */

/**
 * @brief Compressed input type.
 *
 * This type is used to represent the compressed input data
 * for the OpenDICE protocol.
 *
 * The type is defined as a fixed-size array of 64 bytes by default.
 * It can be changed to 32 bytes by defining `N20_INPUT_COMPRESSION_SHA256=1`
 * at compile time.
 */
typedef uint8_t n20_compressed_input_t[N20_FUNC_COMPRESSED_INPUT_SIZE];

/**
 * @brief Alias for @ref n20_certificate_format_s.
 */
typedef enum n20_certificate_format_s n20_certificate_format_t;

/**
 * @brief Compresses the input data.
 *
 * This function is used to generate the salt for key derivation.
 *
 * During CDI generation ( @p cert_info->cert_type == @ref n20_cert_type_cdi_e ),
 * this function compresses the OpenDICE input using a cryptographic hash function.
 *
 * In this context "compression" refers to digesting the required fields
 * of the OpenDICE input and producing the fixed-sized output that is
 * used as salt in the key derivation of the CDI_Attest (See [1]).
 *
 * H(code hash, configuration hash (or descriptor), authority hash, mode, hidden)
 *
 * If @p cert_info->configuration_hash is not set (size 0),
 * the configuration descriptor is used instead.
 *
 * H is SHA2-512 by default but can be changed to SHA2-256 at
 * compile time. By defining `N20_INPUT_COMPRESSION_SHA256=1`.
 *
 * During end-entity ( @p cert_info->cert_type == @ref n20_cert_type_eca_ee_e )
 * key generation this function compresses the name and key usage information.
 * The result is used as the salt for the key derivation.
 *
 * [1]
 * https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md#asymmetric-key-pair-derivation
 *
 * @param crypto_ctx The crypto context.
 * @param cert_info The Nat20 certificate information.
 * @param digest The compressed input digest.
 * @return n20_error_t
 */
extern n20_error_t n20_compress_input(n20_crypto_digest_context_t *crypto_ctx,
                                      n20_open_dice_cert_info_t const *cert_info,
                                      n20_compressed_input_t digest);

/**
 * @brief The CDI Identifier unique for a CDI (or UDS) public key.
 *
 * The identifier is derived from the public key using a cryptographic hash function.
 * It is always truncated to 20 bytes with the msb in the first byte
 * unset so that it can be used as a positive integer serial number in
 * an X509 certificate without exceeding the maximum allowed length.
 */
typedef uint8_t n20_cdi_id_t[20];

/**
 * @brief Derives the CDI Identifier from the public key.
 *
 * This function derives the CDI Identifier from the public key using
 * SHA2-512. The result is truncated to 20 bytes and the msb in the first byte
 * is unset so that it can be used as a positive integer serial number in
 * an X509 certificate without exceeding the maximum allowed length.
 *
 * For reproducibility, the raw public key bits should be used.
 * For NIST curves, the uncompressed format without the 0x04 prefix
 * should be used. For ED25519, the canonical 32 bytes compressed
 * format should be used.
 *
 * @param crypto_ctx The crypto digest context that must implement SHA2-512.
 * @param public_key The public key to derive the CDI Identifier from.
 * @param cdi_id The derived CDI Identifier.
 * @return n20_error_t
 */
extern n20_error_t n20_open_dice_cdi_id(n20_crypto_digest_context_t *crypto_ctx,
                                        n20_slice_t const public_key,
                                        n20_cdi_id_t cdi_id);

/**
 * @brief Derives a key from the given CDI secret.
 *
 * This function derives a key from the given CDI secret using
 * the given salt and tag. The derived key is returned in the
 * given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret_in The CDI secret to derive the key from.
 * @param derived_out The derived key.
 * @param key_type_in The type of the derived key.
 * @param salt_in The salt to use for the derivation.
 * @param tag_in The tag to use for the derivation.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_derive_key(n20_crypto_context_t *crypto_ctx,
                                  n20_crypto_key_t cdi_secret_in,
                                  n20_crypto_key_t *derived_out,
                                  n20_crypto_key_type_t key_type_in,
                                  n20_slice_t const salt_in,
                                  n20_slice_t const tag_in);

/**
 * @brief Derives the next level CDI secret from the given CDI secret.
 *
 * This function derives the next level CDI secret from the given
 * CDI secret using the given salt and tag. The derived key is
 * returned in the given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param current_cdi The current CDI secret to derive the key from.
 * @param next The derived key.
 * @param info The information to use for the derivation.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_next_level_cdi_attest(n20_crypto_context_t *crypto_ctx,
                                             n20_crypto_key_t current_cdi,
                                             n20_crypto_key_t *next,
                                             n20_compressed_input_t info);

/**
 * @brief Derives an attestation key from the given CDI secret.
 *
 * This function derives an attestation key from the given CDI
 * secret using the given salt and tag. The derived key is returned
 * in the given buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret The CDI secret to derive the key from.
 * @param derived The derived key.
 * @param key_type The type of the derived key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_derive_cdi_attestation_key(n20_crypto_context_t *crypto_ctx,
                                                  n20_crypto_key_t cdi_secret,
                                                  n20_crypto_key_t *derived,
                                                  n20_crypto_key_type_t key_type);

/**
 * @brief Derives an ECA key from the given CDI secret.
 *
 * This function derives an ECA key from the given CDI secret using the
 * provided parameters. The derived key is returned in the given buffer.
 *
 * It works similar to @ref n20_derive_cdi_attestation_key, but it uses
 * a different tag to make the key space disjoint from the cdi attestation
 * key space.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret The CDI secret to derive the key from.
 * @param derived The derived key.
 * @param key_type The type of the derived key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_derive_eca_key(n20_crypto_context_t *crypto_ctx,
                                      n20_crypto_key_t cdi_secret,
                                      n20_crypto_key_t *derived,
                                      n20_crypto_key_type_t key_type);

/**
 * @brief Derives an ECA end-entity key from the given CDI secret.
 *
 * This function derives an ECA end-entity (EE) key from the given CDI
 * secret using the provided parameters. The derived key is returned in
 * the given buffer.
 *
 * It works similar to @ref n20_derive_cdi_attestation_key, but it uses
 * a different tag to make the key space disjoint from the cdi attestation
 * and ECA CA key space. And it uses the provided salt to allow for
 * additional disambiguation of the derived keys.
 *
 * @param crypto_ctx The crypto context.
 * @param cdi_secret The CDI secret to derive the key from.
 * @param salt The salt to use for the derivation.
 * @param derived The derived key.
 * @param key_type The type of the derived key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */

extern n20_error_t n20_derive_eca_ee_key(n20_crypto_context_t *crypto_ctx,
                                         n20_crypto_key_t cdi_secret,
                                         n20_slice_t const salt,
                                         n20_crypto_key_t *derived,
                                         n20_crypto_key_type_t key_type);

/**
 * @brief Initializes the algorithm identifier structure.
 *
 * This function initializes the algorithm identifier structure
 * with the given key type.
 *
 * @param algorithm_identifier The algorithm identifier structure to initialize.
 * @param key_type The type of the key.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_init_algorithm_identifier(
    n20_x509_algorithm_identifier_t *algorithm_identifier, n20_crypto_key_type_t key_type);

/**
 * @brief Initializes the key info structure.
 *
 * This function initializes the key info structure with the
 * given key type and public key.
 *
 * @param key_info The key info structure to initialize.
 * @param key_type The type of the key.
 * @param public_key The public key to use.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_init_key_info(n20_x509_public_key_info_t *key_info,
                                     n20_crypto_key_type_t key_type,
                                     n20_slice_t const *public_key);

/**
 * @brief Callback function type for signing operations.
 *
 * This function type is used for signing operations within the
 * n20_signer_t structure.
 *
 * @param signer The signer context.
 * @param tbs The data to be signed (to be signed).
 * @param signature The buffer to write the signature to.
 * @param signature_size In/out parameter for the size of the signature.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
typedef n20_error_t (*n20_signer_callback_t)(void *signer,
                                             n20_slice_t tbs,
                                             uint8_t *signature,
                                             size_t *signature_size);

/**
 * @brief Signer context structure.
 *
 * This structure holds the context for signing operations,
 * including the crypto context, signing key, and callback function.
 */
struct n20_signer_s {
    /**
     * @brief Crypto context for signing operations.
     *
     * The @ref n20_crypto_context_t.
     */
    n20_crypto_context_t *crypto_ctx;
    /**
     * @brief Signing key for the signer context.
     *
     * The @ref n20_crypto_key_t.
     */
    n20_crypto_key_t signing_key;
    /**
     * @brief Callback function for signing operations.
     *
     * The @ref n20_signer_callback_t.
     */
    n20_signer_callback_t cb;
};

/**
 * @brief Alias for @ref n20_signer_s.
 *
 */
typedef struct n20_signer_s n20_signer_t;

/**
 * @brief Prepares an X.509 certificate.
 *
 * This function uses the n20_x509 library to render an x509
 * certificate and sign it.
 *
 * The main purpose of this function is to use the generic
 * n20_open_dice_cert_info_t structure populated by the caller
 * to populate the @ref n20_x509_tbs_t structure and render the
 * X.509 certificate.
 *
 * It then signs it with the provided signer callback.
 *
 * @param cert_info The Nat20 certificate information.
 * @param signer The signer callback to use for signing the certificate.
 * @param issuer_key_type The type of the issuer's key.
 * @param attestation_certificate The buffer to write the certificate to.
 * @param attestation_certificate_size In/out parameter for buffer size.
 *
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_issue_x509_cert(n20_open_dice_cert_info_t const *cert_info,
                                       n20_signer_t *signer,
                                       n20_crypto_key_type_t issuer_key_type,
                                       uint8_t *attestation_certificate,
                                       size_t *attestation_certificate_size);

/**
 * @brief Sign a message with an ECA key.
 *
 * This function derives an embedded CA (ECA) key using the provided
 * parameters and signs the given message with it.
 *
 * The derived key is not returned to the caller. The corresponding
 * key handle is freed before the function returns.
 *
 * The signature format depends on the signing key algorithm.
 * See @ref n20_crypto_context_s.sign for details.
 *
 * In keeping with the other functions, the signature is written
 * to the end of the provided buffer.
 *
 * @param crypto_ctx The crypto context.
 * @param parent_secret The parent CDI secret.
 * @param key_type The type of the ECA key to generate.
 * @param name The key name. This is part of the derivation context.
 * @param key_usage Key usage as intended by the client. Also part of the derivation context.
 * @param message The message to sign.
 * @param signature Buffer to write the signature.
 * @param signature_size In/out parameter for buffer size.
 * @return n20_error_ok_e on success, or an error code on failure.
 */
extern n20_error_t n20_eca_ee_sign_message(n20_crypto_context_t *crypto_ctx,
                                           n20_crypto_key_t parent_secret,
                                           n20_crypto_key_type_t key_type,
                                           n20_string_slice_t name,
                                           n20_slice_t key_usage,
                                           n20_slice_t message,
                                           uint8_t *signature,
                                           size_t *signature_size);

/**
 * @brief Computes cryptographic artifacts for a certificate.
 *
 * This function derives all necessary secrets and keys for a certificate.
 *
 * - The issuer's key pair is derived from the issuer's CDI.
 * - In the case that the subject key belongs to the next level
 *   CDI, it derives the next CDI from the open dice input
 *   in the @p cert_info.
 * - If @p issuer_serial_number_out is not NULL, the issuer's
 *   public key is loaded and the CDI_ID is computed and stored
 *   into @p issuer_serial_number_out. Note that to minimize
 *   stack usage the provided subject public key buffer is used
 *   as a scratch pad for the issuer public key. This
 *   means that the buffer must be large enough for the issuer
 *   public key type even if a smaller subject key type is used.
 *   As of this writing 96 bytes is sufficient for the largest
 *   supported key type, i.e, P-384.
 * - The subject's key pair is derived from subject's CDI.
 *   This is the next CDI if the @p cert_info.cert_type is
 *   @ref n20_cert_type_cdi_e and @p issuer_cdi otherwise.
 * - The subject's public key is loaded and stored in
 *   @p subject_public_key_buffer_out. The size of the buffer
 *   must be given in @p subject_public_key_buffer_size_in_out
 *   and on return the actual size is stored there.
 *   If the buffer is too small, the function returns
 *   @ref n20_error_crypto_insufficient_buffer_size_e and
 *   sets @p subject_public_key_buffer_size_in_out to the
 *   required size.
 * - If @p subject_serial_number_out is not NULL, the
 *   subject's public key is used to compute the subject's CDI_ID
 *   which is stored in @p subject_serial_number_out.
 * - If @p issuer_key_out is not NULL, the issuer's key handle
 *   is returned in @p issuer_key_out. The caller is responsible
 *   for freeing the key handle when it is no longer needed.
 *
 * Not counting @p issuer_cdi, the function may use no more than
 * 2 additional key handles at any time. If the function returns an
 * error, those additional key handles are guaranteed to be freed.
 * If the function returns @ref n20_error_ok_e, the function
 * guarantees that no more than 1 additional key handle is
 * used, and only if @p issuer_key_out is not NULL. In this case
 * the caller is responsible for freeing the additional key handle
 * returned in @p issuer_key_out.
 *
 * @param crypto_ctx
 * @param issuer_cdi
 * @param cert_info
 * @param issuer_key_type
 * @param subject_key_type
 * @param issuer_key_out
 * @param issuer_serial_number_out
 * @param subject_serial_number_out
 * @param subject_public_key_buffer_out
 * @param subject_public_key_buffer_size_in_out
 * @return n20_error_t
 */
extern n20_error_t n20_compute_certificate_context(n20_crypto_context_t *crypto_ctx,
                                                   n20_crypto_key_t issuer_cdi,
                                                   n20_open_dice_cert_info_t const *cert_info,
                                                   n20_crypto_key_type_t const issuer_key_type,
                                                   n20_crypto_key_type_t const subject_key_type,
                                                   n20_crypto_key_t *issuer_key_out,
                                                   n20_cdi_id_t issuer_serial_number_out,
                                                   n20_cdi_id_t subject_serial_number_out,
                                                   uint8_t *subject_public_key_buffer_out,
                                                   size_t *subject_public_key_buffer_size_in_out);

/**
 * @brief This function issues all currently supported types of certificates.
 *
 * This includes CDI attestation certificates, ECA certificates, ECA end-entity
 * certificates and self signed certificates.
 *
 * The @p cert_info_in structure must be initialized with minimal information
 * to provide context for the certificate being issued.
 *
 * The function uses the given pointer as a scratchpad and populates
 * it with the necessary cryptographic artifacts computed using
 * @ref n20_compute_certificate_context.
 *
 * @p cert_info_in.cert_type must always be given. In addition the following
 * fields may be initialized depending on the certificate type.
 * - @ref n20_cert_type_cdi_e requires @p cert_info_in.open_dice_input to be set.
 * - @ref n20_cert_type_eca_e takes an optional challenge in @p cert_info_in.eca.nonce.
 * - @ref n20_cert_type_eca_ee_e requires @p cert_info_in.eca_ee.name and
 *   @p cert_info_in.key_usage to be set, however, as of this writing only
 *   the key usage for digital signatures is supported. An optional challenge
 *   may be set in @p cert_info_in.eca_ee.nonce.
 * - @ref n20_cert_type_self_signed_e does not require any additional fields.
 *
 * @param crypto_ctx
 * @param issuer_secret_in
 * @param issuer_key_type_in
 * @param subject_key_type_in
 * @param cert_info_in
 * @param certificate_format_in
 * @param certificate_out
 * @param certificate_size_in_out
 * @return n20_error_t
 */
extern n20_error_t n20_issue_certificate(n20_crypto_context_t *crypto_ctx,
                                         n20_crypto_key_t issuer_secret_in,
                                         n20_crypto_key_type_t issuer_key_type_in,
                                         n20_crypto_key_type_t subject_key_type_in,
                                         n20_open_dice_cert_info_t *cert_info_in,
                                         n20_certificate_format_t certificate_format_in,
                                         uint8_t *certificate_out,
                                         size_t *certificate_size_in_out);

#ifdef __cplusplus
}
#endif
