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

#include <nat20/crypto.h>
#include <nat20/crypto_bssl/crypto.h>
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pki/verify.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <variant>
#include <vector>

#define MAKE_PTR(name) using name##_PTR_t = bssl::UniquePtr<name>

MAKE_PTR(EVP_PKEY);
MAKE_PTR(EVP_PKEY_CTX);
MAKE_PTR(EVP_MD_CTX);
MAKE_PTR(BIO);
MAKE_PTR(X509);
MAKE_PTR(EC_KEY);

#define N2_BSSL_SHA2_224_OCTETS 28
#define N2_BSSL_SHA2_256_OCTETS 32
#define N2_BSSL_SHA2_384_OCTETS 48
#define N2_BSSL_SHA2_512_OCTETS 64

struct n20_bssl_key_base {
    n20_crypto_key_type_t type;
    virtual ~n20_bssl_key_base() {}
};

struct n20_bssl_cdi_key : n20_bssl_key_base {
    std::vector<uint8_t> bits;
    virtual ~n20_bssl_cdi_key() {}
};

struct n20_bssl_evp_pkey : n20_bssl_key_base {
    EVP_PKEY_PTR_t key;
    virtual ~n20_bssl_evp_pkey() {}
};

struct n20_bssl_context : public n20_crypto_context_t {
    n20_bssl_cdi_key cdi;
};

static n20_bssl_context* context_cast(n20_crypto_context_t* ctx) {
    return static_cast<n20_bssl_context*>(ctx);
}

static n20_crypto_error_t n20_crypto_boringssl_digest(struct n20_crypto_context_s* ctx,
                                                      n20_crypto_digest_algorithm_t alg_in,
                                                      n20_crypto_gather_list_t const* msg_in,
                                                      uint8_t* digest_out,
                                                      size_t* digest_size_in_out) {
    if (ctx == nullptr) {
        return n20_crypto_error_invalid_context_e;
    }

    if (digest_size_in_out == NULL) {
        return n20_crypto_error_unexpected_null_size_e;
    }

    EVP_MD const* md = NULL;
    size_t digest_size = 0;
    switch (alg_in) {
        case n20_crypto_digest_algorithm_sha2_224_e:
            digest_size = N2_BSSL_SHA2_224_OCTETS;
            md = EVP_sha224();
            break;
        case n20_crypto_digest_algorithm_sha2_256_e:
            digest_size = N2_BSSL_SHA2_256_OCTETS;
            md = EVP_sha256();
            break;
        case n20_crypto_digest_algorithm_sha2_384_e:
            digest_size = N2_BSSL_SHA2_384_OCTETS;
            md = EVP_sha384();
            break;
        case n20_crypto_digest_algorithm_sha2_512_e:
            digest_size = N2_BSSL_SHA2_512_OCTETS;
            md = EVP_sha512();
            break;
        default:
            return n20_crypto_error_unkown_algorithm_e;
    }

    // If the provided buffer size is too small or no buffer was provided
    // set the required buffer size and return
    // n20_crypto_error_insufficient_buffer_size_e.
    if (digest_size > *digest_size_in_out || digest_out == nullptr) {
        *digest_size_in_out = digest_size;
        return n20_crypto_error_insufficient_buffer_size_e;
    }

    // It can be tolerated above if no message was given.
    // The caller might just query the required buffer size.
    // But from here a message must be provided.
    if (msg_in == nullptr) {
        return n20_crypto_error_unexpected_null_data_e;
    }

    if (msg_in->count != 0 && msg_in->list == nullptr) {
        return n20_crypto_error_unexpected_null_list_e;
    }

    auto md_ctx = EVP_MD_CTX_PTR_t(EVP_MD_CTX_new());

    if (!EVP_DigestInit(md_ctx.get(), md)) {
        return n20_crypto_error_no_memory_e;
    }

    for (size_t i = 0; i < msg_in->count; ++i) {
        if (msg_in->list[i].size == 0) continue;
        if (msg_in->list[i].buffer == nullptr) {
            return n20_crypto_error_unexpected_null_slice_e;
        }
        EVP_DigestUpdate(md_ctx.get(), msg_in->list[i].buffer, msg_in->list[i].size);
    }

    unsigned int out_size = *digest_size_in_out;

    EVP_DigestFinal(md_ctx.get(), digest_out, &out_size);

    *digest_size_in_out = out_size;

    return n20_crypto_error_ok_e;
}

static std::variant<n20_crypto_error_t, std::vector<uint8_t> const> gather_list_to_vector(
    n20_crypto_gather_list_t const* list) {
    std::vector<uint8_t> result;
    if (list == nullptr) {
        return n20_crypto_error_unexpected_null_data_e;
    }

    if (list->count != 0 && list->list == nullptr) {
        return n20_crypto_error_unexpected_null_list_e;
    }

    for (size_t i = 0; i < list->count; ++i) {
        if (list->list[i].size == 0) continue;
        if (list->list[i].buffer == NULL) {
            return n20_crypto_error_unexpected_null_slice_e;
        }
        result.insert(
            result.end(), list->list[i].buffer, list->list[i].buffer + list->list[i].size);
    }

    return result;
}

static n20_crypto_error_t n20_crypto_boringssl_kdf(struct n20_crypto_context_s* ctx,
                                                   n20_crypto_key_t key_in,
                                                   n20_crypto_key_type_t key_type_in,
                                                   n20_crypto_gather_list_t const* context_in,
                                                   n20_crypto_key_t* key_out) {
    if (ctx == nullptr) {
        return n20_crypto_error_invalid_context_e;
    }

    if (key_in == NULL) {
        return n20_crypto_error_unexpected_null_key_in_e;
    }

    auto bssl_base_key = reinterpret_cast<n20_bssl_key_base*>(key_in);
    if (bssl_base_key->type != n20_crypto_key_type_cdi_e) {
        return n20_crypto_error_invalid_key_e;
    }

    auto bssl_cdi_key = static_cast<n20_bssl_cdi_key*>(bssl_base_key);

    if (key_out == NULL) {
        return n20_crypto_error_unexpected_null_key_out_e;
    }

    auto const context_error = gather_list_to_vector(context_in);
    if (auto error = std::get_if<n20_crypto_error_t>(&context_error)) {
        return *error;
    }

    auto context = std::get<std::vector<uint8_t> const>(std::move(context_error));

    std::vector<uint8_t> derived(32);

    int rc = HKDF_expand(derived.data(),
                         derived.size(),
                         EVP_sha256(),
                         bssl_cdi_key->bits.data(),
                         bssl_cdi_key->bits.size(),
                         context.data(),
                         context.size());
    if (!rc) {
        return n20_crypto_error_implementation_specific_e;
    }

    switch (key_type_in) {
        case n20_crypto_key_type_ed25519_e: {
            auto key = EVP_PKEY_PTR_t(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_ED25519, NULL, derived.data(), derived.size()));
            if (!key) {
                return n20_crypto_error_implementation_specific_e;
            }
            auto bssl_out = new n20_bssl_evp_pkey();
            if (bssl_out == NULL) {
                return n20_crypto_error_no_memory_e;
            }
            bssl_out->type = key_type_in;
            bssl_out->key = std::move(key);
            *key_out = bssl_out;
            return n20_crypto_error_ok_e;
        }
        case n20_crypto_key_type_cdi_e: {
            auto bssl_out = new n20_bssl_cdi_key();
            bssl_out->type = key_type_in;
            bssl_out->bits = std::move(derived);
            *key_out = bssl_out;
            return n20_crypto_error_ok_e;
        }
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {

            EC_GROUP const* ec_group = nullptr;
            if (key_type_in == n20_crypto_key_type_secp256r1_e) {
                ec_group = EC_group_p256();
            } else {
                ec_group = EC_group_p384();
            }

            auto ec_key =
                EC_KEY_PTR_t(EC_KEY_derive_from_secret(ec_group, derived.data(), derived.size()));
            if (!ec_key) {
                return n20_crypto_error_implementation_specific_e;
            }

            auto key = EVP_PKEY_PTR_t(EVP_PKEY_new());
            if (!key) {
                return n20_crypto_error_no_memory_e;
            }

            EVP_PKEY_assign_EC_KEY(key.get(), ec_key.release());

            auto bssl_out = new n20_bssl_evp_pkey();
            bssl_out->type = key_type_in;
            bssl_out->key = std::move(key);
            *key_out = bssl_out;
            return n20_crypto_error_ok_e;
        }
    }

    return n20_crypto_error_invalid_key_type_e;
}

static n20_crypto_error_t n20_crypto_boringssl_sign(struct n20_crypto_context_s* ctx,
                                                    n20_crypto_key_t key_in,
                                                    n20_crypto_gather_list_t const* msg_in,
                                                    uint8_t* signature_out,
                                                    size_t* signature_size_in_out) {

    if (ctx == nullptr) {
        return n20_crypto_error_invalid_context_e;
    }

    if (key_in == nullptr) {
        return n20_crypto_error_unexpected_null_key_in_e;
    }

    if (signature_size_in_out == nullptr) {
        return n20_crypto_error_unexpected_null_size_e;
    }

    auto bssl_base_key = reinterpret_cast<n20_bssl_key_base*>(key_in);
    if (bssl_base_key->type == n20_crypto_key_type_cdi_e) {
        return n20_crypto_error_invalid_key_e;
    }

    auto bssl_evp_key = static_cast<n20_bssl_evp_pkey*>(bssl_base_key);

    auto md_ctx = EVP_MD_CTX_PTR_t(EVP_MD_CTX_new());
    if (!md_ctx) {
        return n20_crypto_error_no_memory_e;
    }

    constexpr size_t ed25519_signature_size = 64;
    constexpr size_t secp256r1_signature_size = 64;
    constexpr size_t secp384r1_signature_size = 96;
    size_t signature_size = 0;
    switch (bssl_base_key->type) {
        case n20_crypto_key_type_ed25519_e:
            signature_size = ed25519_signature_size;
            break;
        case n20_crypto_key_type_secp256r1_e:
            signature_size = secp256r1_signature_size;
            break;
        case n20_crypto_key_type_secp384r1_e:
            signature_size = secp384r1_signature_size;
            break;
        case n20_crypto_key_type_cdi_e:
        default:
            return n20_crypto_error_invalid_key_e;
    }

    if (*signature_size_in_out < signature_size || signature_out == nullptr) {
        *signature_size_in_out = signature_size;
        return n20_crypto_error_insufficient_buffer_size_e;
    }

    switch (bssl_base_key->type) {
        case n20_crypto_key_type_ed25519_e: {
            EVP_MD const* md = nullptr;
            if (1 != EVP_DigestSignInit(md_ctx.get(), NULL, md, NULL, bssl_evp_key->key.get())) {
                return n20_crypto_error_implementation_specific_e;
            }

            auto const msg_error = gather_list_to_vector(msg_in);
            if (auto error = std::get_if<n20_crypto_error_t>(&msg_error)) {
                return *error;
            }

            auto msg = std::get<std::vector<uint8_t> const>(std::move(msg_error));

            if (1 !=
                EVP_DigestSign(
                    md_ctx.get(), signature_out, signature_size_in_out, msg.data(), msg.size())) {
                return n20_crypto_error_implementation_specific_e;
            }

            return n20_crypto_error_ok_e;
        }
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            if (msg_in == NULL) {
                return n20_crypto_error_unexpected_null_data_e;
            }
            if (msg_in->count != 0 && msg_in->list == nullptr) {
                return n20_crypto_error_unexpected_null_list_e;
            }

            EVP_MD const* md = EVP_sha256();
            if (1 != EVP_DigestSignInit(md_ctx.get(), NULL, md, NULL, bssl_evp_key->key.get())) {
                return n20_crypto_error_implementation_specific_e;
            }

            for (size_t i = 0; i < msg_in->count; ++i) {
                // Skip empty segments.
                if (msg_in->list[i].size == 0) continue;
                // But non empty segments cannot have nullptr buffers.
                if (msg_in->list[i].buffer == nullptr) {
                    return n20_crypto_error_unexpected_null_slice_e;
                }

                if (1 != EVP_DigestSignUpdate(
                             md_ctx.get(), msg_in->list[i].buffer, msg_in->list[i].size)) {
                    return n20_crypto_error_implementation_specific_e;
                }
            }

            // 104 is the maximum size for an ASN.1 encoded signature
            // using ECDSA with P-384.
            uint8_t signature_buffer[104];
            *signature_size_in_out = sizeof(signature_buffer);
            if (1 != EVP_DigestSignFinal(md_ctx.get(), signature_buffer, signature_size_in_out)) {
                return n20_crypto_error_implementation_specific_e;
            }

            // EVP_DigestSignFinal returned the signature as ASN.1 sequence
            // containing two integers.
            // The following code unwraps the integers and stores them
            // in the format as specified by the n20 crypto interface.

            // The size of a single integer is halve of the signature
            // size, i.e, 32 for P-256 and 48 for P-384.
            size_t const integer_size = signature_size / 2;
            // The first two bytes are the sequence header.
            // No need to look at those.
            // The size of R is at index 3.
            size_t r_size = signature_buffer[3];
            // To get the size of S skip the the sequence header (2 octets),
            // skip the integer header of R (2 octets) skip R (r_size octets),
            // skip the integer header but not the size (1 octet).
            // So the resulting offset is 2 + 2 + rsize + 1 = 5 + r_size.
            size_t s_size = signature_buffer[5 + r_size];
            // R starts at offset 4, i.e., skip the sequence header and the
            // integer header.
            size_t r_offset = 4;
            // S starts at offset 6 + r_size, i.e., skip the sequence header
            // both integer headers and the content of R.
            size_t s_offset = 6 + r_size;
            // Due to ASN.1 encoding the integers may be padded with a leading
            // zero octet if the msb of the following octet is 1.
            // This can bring the total size of the integer to integer_size + 1
            // without adding significant bits. The following line cuts this
            // leading zero octet off by moving the offset by one and reducing
            // the respective size by one.
            if (r_size == integer_size + 1) {
                r_offset += 1;
                r_size -= 1;
            }
            if (s_size == integer_size + 1) {
                s_offset += 1;
                s_size -= 1;
            }
            // However unlikely, r_size and s_size can be smaller than integer_size.
            // In that case the write position must be adjusted by the difference
            // integer_size - r_size. To assure that leading octets will be zero
            // the output buffer is be zeroed.
            memset(signature_out, 0, signature_size);
            memcpy(signature_out + integer_size - r_size, &signature_buffer[r_offset], r_size);
            memcpy(signature_out + integer_size + integer_size - s_size,
                   &signature_buffer[s_offset],
                   s_size);
            *signature_size_in_out = signature_size;

            return n20_crypto_error_ok_e;
        }
        case n20_crypto_key_type_cdi_e:
        default:
            return n20_crypto_error_invalid_key_e;
    }
}

static n20_crypto_error_t n20_crypto_boringssl_get_cdi(struct n20_crypto_context_s* ctx,
                                                       n20_crypto_key_t* key_out) {
    if (ctx == nullptr) {
        return n20_crypto_error_invalid_context_e;
    }

    if (key_out == nullptr) {
        return n20_crypto_error_unexpected_null_key_out_e;
    }

    auto bssl_ctx = context_cast(ctx);
    *key_out = reinterpret_cast<n20_crypto_key_t*>(static_cast<n20_bssl_key_base*>(&bssl_ctx->cdi));

    return n20_crypto_error_ok_e;
}

struct BoringsslDeleter {
    void operator()(void* p) { OPENSSL_free(p); }
};

static n20_crypto_error_t n20_crypto_boringssl_key_get_public_key(struct n20_crypto_context_s* ctx,
                                                                  n20_crypto_key_t key_in,
                                                                  uint8_t* public_key_out,
                                                                  size_t* public_key_size_in_out) {
    if (ctx == nullptr) {
        return n20_crypto_error_invalid_context_e;
    }

    if (public_key_size_in_out == nullptr) {
        return n20_crypto_error_unexpected_null_size_e;
    }

    if (key_in == nullptr) {
        return n20_crypto_error_unexpected_null_key_in_e;
    }

    auto bssl_base_key = reinterpret_cast<n20_bssl_key_base*>(key_in);
    switch (bssl_base_key->type) {
        case n20_crypto_key_type_ed25519_e:
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e:
            break;
        case n20_crypto_key_type_cdi_e:
        default:
            return n20_crypto_error_invalid_key_e;
    }

    auto bssl_evp_key = static_cast<n20_bssl_evp_pkey*>(bssl_base_key);

    auto evp_key_type = EVP_PKEY_id(bssl_evp_key->key.get());
    auto const& key = bssl_evp_key->key;

    switch (evp_key_type) {
        case EVP_PKEY_EC: {
            if (bssl_evp_key->type != n20_crypto_key_type_secp256r1_e &&
                bssl_evp_key->type != n20_crypto_key_type_secp384r1_e) {
                // If this happened this implementation handed out
                // inconsistent data or the user did something undefined.
                return n20_crypto_error_implementation_specific_e;
            }

            uint8_t* der_key_info = NULL;
            int rc_der_len = i2d_PublicKey(key.get(), &der_key_info);
            if (rc_der_len <= 0) {
                return n20_crypto_error_no_memory_e;
            }
            auto der_key_info_guard = std::unique_ptr<uint8_t, BoringsslDeleter>(der_key_info);

            if (*public_key_size_in_out < (size_t)rc_der_len || public_key_out == nullptr) {
                *public_key_size_in_out = (size_t)rc_der_len;
                return n20_crypto_error_insufficient_buffer_size_e;
            }

            *public_key_size_in_out = (size_t)rc_der_len;
            memcpy(public_key_out, der_key_info_guard.get(), *public_key_size_in_out);

            return n20_crypto_error_ok_e;
        }
        case EVP_PKEY_ED25519: {
            if (bssl_base_key->type != n20_crypto_key_type_ed25519_e) {
                // If this happened this implementation handed out
                // inconsistent data or the user did something undefined.
                return n20_crypto_error_implementation_specific_e;
            }

            if (*public_key_size_in_out < 32 || public_key_out == nullptr) {
                *public_key_size_in_out = 32;
                return n20_crypto_error_insufficient_buffer_size_e;
            }

            auto rc =
                EVP_PKEY_get_raw_public_key(key.get(), public_key_out, public_key_size_in_out);
            if (!rc || *public_key_size_in_out != 32) {
                return n20_crypto_error_implementation_specific_e;
            }
            return n20_crypto_error_ok_e;
        }
        default:
            return n20_crypto_error_invalid_key_e;
    }
}

static n20_crypto_error_t n20_crypto_boringssl_key_free(struct n20_crypto_context_s* ctx,
                                                        n20_crypto_key_t key_in) {
    if (ctx == nullptr) {
        return n20_crypto_error_invalid_context_e;
    }

    if (key_in == NULL) {
        return n20_crypto_error_ok_e;
    }

    auto bssl_key = reinterpret_cast<n20_bssl_key_base*>(key_in);

    // Every key handle given out by the library must be freed eventually.
    // But the key handle for the root secret is owned by the context
    // there is nothing to do here in this case.
    auto bssl_ctx = context_cast(ctx);
    if (bssl_key == static_cast<n20_bssl_key_base*>(&bssl_ctx->cdi)) {
        return n20_crypto_error_ok_e;
    }

    delete bssl_key;

    return n20_crypto_error_ok_e;
}

static n20_crypto_context_t bssl_ctx{n20_crypto_boringssl_digest,
                                     n20_crypto_boringssl_kdf,
                                     n20_crypto_boringssl_sign,
                                     n20_crypto_boringssl_get_cdi,
                                     n20_crypto_boringssl_key_get_public_key,
                                     n20_crypto_boringssl_key_free};

extern "C" n20_crypto_error_t n20_crypto_open_boringssl(n20_crypto_context_t** ctx,
                                                        n20_crypto_slice_t const* cdi) {
    if (ctx == NULL || cdi == NULL || cdi->buffer == NULL || cdi->size == 0) {
        return n20_crypto_error_unexpected_null_e;
    }

    auto new_ctx = std::make_unique<n20_bssl_context>();
    if (!new_ctx) {
        return n20_crypto_error_no_memory_e;
    }

    new_ctx->cdi.type = n20_crypto_key_type_cdi_e;
    new_ctx->cdi.bits = std::vector<uint8_t>(cdi->buffer, cdi->buffer + cdi->size);

    *ctx = static_cast<n20_crypto_context_t*>(new_ctx.release());
    **ctx = bssl_ctx;

    return n20_crypto_error_ok_e;
}

extern "C" n20_crypto_error_t n20_crypto_close_boringssl(n20_crypto_context_t* ctx) {
    if (ctx == NULL) {
        return n20_crypto_error_unexpected_null_e;
    }

    auto tbd_context = std::unique_ptr<n20_bssl_context>(context_cast(ctx));
    return n20_crypto_error_ok_e;
}
