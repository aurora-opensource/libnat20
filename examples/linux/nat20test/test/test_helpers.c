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

#include "test_helpers.h"

#include <nat20/cbor.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <nat20/stream.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

n20_error_t test_compress_cdi_input(uint8_t const* code_hash,
                                    size_t code_hash_size,
                                    uint8_t const* config_hash,
                                    size_t config_hash_size,
                                    uint8_t const* authority_hash,
                                    size_t authority_hash_size,
                                    uint8_t mode,
                                    uint8_t const* hidden,
                                    size_t hidden_size,
                                    uint8_t* compressed_out,
                                    size_t compressed_out_size) {
    n20_crypto_digest_context_t* digest_ctx = NULL;
    n20_error_t err = n20_crypto_nat20_open(&digest_ctx);
    if (err != n20_error_ok_e) {
        return err;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_cdi_e;
    cert_info.open_dice_input.code_hash =
        (n20_slice_t){.size = code_hash_size, .buffer = code_hash};
    cert_info.open_dice_input.configuration_hash =
        (n20_slice_t){.size = config_hash_size, .buffer = config_hash};
    cert_info.open_dice_input.authority_hash =
        (n20_slice_t){.size = authority_hash_size, .buffer = authority_hash};
    cert_info.open_dice_input.mode = (n20_open_dice_modes_t)mode;
    cert_info.open_dice_input.hidden = (n20_slice_t){.size = hidden_size, .buffer = hidden};

    if (compressed_out_size < N20_FUNC_COMPRESSED_INPUT_SIZE) {
        n20_crypto_nat20_close(digest_ctx);
        return n20_error_insufficient_buffer_size_e;
    }

    err = n20_compress_input(digest_ctx, &cert_info, compressed_out);
    n20_crypto_nat20_close(digest_ctx);
    return err;
}

static EVP_PKEY* evp_pkey_from_ec_pubkey(uint8_t const* pubkey,
                                         size_t pubkey_size,
                                         n20_crypto_key_type_t key_type) {
    char const* group_name =
        (key_type == n20_crypto_key_type_secp256r1_e) ? SN_X9_62_prime256v1 : SN_secp384r1;

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        return NULL;
    }

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_size);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (params == NULL) {
        return NULL;
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (pctx == NULL) {
        OSSL_PARAM_free(params);
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_fromdata_init(pctx) != 1 ||
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        pkey = NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    return pkey;
}

static EVP_PKEY* evp_pkey_from_pubkey(uint8_t const* pubkey,
                                      size_t pubkey_size,
                                      n20_crypto_key_type_t key_type) {
    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, pubkey_size);
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e:
            return evp_pkey_from_ec_pubkey(pubkey, pubkey_size, key_type);
        default:
            return NULL;
    }
}

bool test_verify_x509_signature(uint8_t const* cert_der,
                                size_t cert_der_size,
                                uint8_t const* issuer_pubkey,
                                size_t issuer_pubkey_size,
                                n20_crypto_key_type_t key_type) {
    uint8_t const* p = cert_der;
    X509* cert = d2i_X509(NULL, &p, (long)cert_der_size);
    if (cert == NULL) {
        fprintf(stderr, "    d2i_X509 failed\n");
        return false;
    }

    EVP_PKEY* pkey = evp_pkey_from_pubkey(issuer_pubkey, issuer_pubkey_size, key_type);
    if (pkey == NULL) {
        fprintf(stderr, "    Failed to construct EVP_PKEY\n");
        X509_free(cert);
        return false;
    }

    bool result = X509_verify(cert, pkey) == 1;
    if (!result) {
        fprintf(stderr, "    X509_verify failed\n");
    }

    EVP_PKEY_free(pkey);
    X509_free(cert);
    return result;
}

bool test_extract_x509_pubkey(uint8_t const* cert_der,
                              size_t cert_der_size,
                              uint8_t* pubkey_out,
                              size_t* pubkey_size_in_out) {
    uint8_t const* p = cert_der;
    X509* cert = d2i_X509(NULL, &p, (long)cert_der_size);
    if (cert == NULL) {
        fprintf(stderr, "    d2i_X509 failed\n");
        return false;
    }

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "    X509_get_pubkey failed\n");
        X509_free(cert);
        return false;
    }

    bool result = false;
    int key_id = EVP_PKEY_id(pkey);

    if (key_id == EVP_PKEY_ED25519) {
        size_t len = *pubkey_size_in_out;
        if (EVP_PKEY_get_raw_public_key(pkey, pubkey_out, &len) == 1) {
            *pubkey_size_in_out = len;
            result = true;
        }
    } else if (key_id == EVP_PKEY_EC) {
        size_t len = 0;
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len) == 1 &&
            len <= *pubkey_size_in_out) {
            if (EVP_PKEY_get_octet_string_param(
                    pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey_out, *pubkey_size_in_out, &len) == 1) {
                *pubkey_size_in_out = len;
                result = true;
            }
        }
    }

    EVP_PKEY_free(pkey);
    X509_free(cert);
    return result;
}

bool test_parse_cose_sign1(uint8_t const* data, size_t size, test_cose_sign1_t* out) {
    n20_istream_t stream;
    n20_istream_init(&stream, data, size);

    n20_cbor_type_t type;
    uint64_t value;

    if (!n20_cbor_read_header(&stream, &type, &value)) return false;
    if (type != n20_cbor_type_array_e || value != 4) return false;

    /* Element 1: protected header (bstr) */
    if (!n20_cbor_read_header(&stream, &type, &value)) return false;
    if (type != n20_cbor_type_bytes_e) return false;
    if (!n20_istream_get_slice(&stream, &out->protected_header, value)) return false;

    /* Element 2: unprotected header (map) — skip */
    if (!n20_cbor_read_skip_item(&stream)) return false;

    /* Element 3: payload (bstr or nil) */
    if (!n20_cbor_read_header(&stream, &type, &value)) return false;
    if (type == n20_cbor_type_bytes_e) {
        if (!n20_istream_get_slice(&stream, &out->payload, value)) return false;
    } else if (type == n20_cbor_type_simple_float_e && value == 22) {
        /* nil payload */
        out->payload = (n20_slice_t){.size = 0, .buffer = NULL};
    } else {
        return false;
    }

    /* Element 4: signature (bstr) */
    if (!n20_cbor_read_header(&stream, &type, &value)) return false;
    if (type != n20_cbor_type_bytes_e) return false;
    if (!n20_istream_get_slice(&stream, &out->signature, value)) return false;

    return true;
}

bool test_verify_raw_signature(uint8_t const* pubkey,
                               size_t pubkey_size,
                               uint8_t const* message,
                               size_t message_size,
                               uint8_t const* sig,
                               size_t sig_size,
                               n20_crypto_key_type_t key_type) {
    EVP_PKEY* pkey = NULL;

    switch (key_type) {
        case n20_crypto_key_type_ed25519_e:
            pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, pubkey_size);
            break;
        case n20_crypto_key_type_secp256r1_e:
        case n20_crypto_key_type_secp384r1_e: {
            /* The pubkey is raw x||y — wrap with 0x04 uncompressed prefix */
            uint8_t uncompressed[1 + 96];
            uncompressed[0] = 0x04;
            memcpy(uncompressed + 1, pubkey, pubkey_size);
            pkey = evp_pkey_from_ec_pubkey(uncompressed, 1 + pubkey_size, key_type);
            break;
        }
        default:
            return false;
    }

    if (pkey == NULL) return false;

    bool result = false;

    if (key_type == n20_crypto_key_type_ed25519_e) {
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (md_ctx != NULL) {
            if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1 &&
                EVP_DigestVerify(md_ctx, sig, sig_size, message, message_size) == 1) {
                result = true;
            }
            EVP_MD_CTX_free(md_ctx);
        }
    } else {
        /* ECDSA: convert raw r||s to DER ECDSA_SIG for OpenSSL */
        size_t coord_size = sig_size / 2;
        BIGNUM* r_bn = BN_bin2bn(sig, (int)coord_size, NULL);
        BIGNUM* s_bn = BN_bin2bn(sig + coord_size, (int)coord_size, NULL);
        ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
        if (r_bn && s_bn && ecdsa_sig && ECDSA_SIG_set0(ecdsa_sig, r_bn, s_bn)) {
            /* DER-encode the signature */
            uint8_t* der_sig = NULL;
            int der_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
            if (der_sig_len > 0 && der_sig != NULL) {
                EVP_MD const* md =
                    (key_type == n20_crypto_key_type_secp256r1_e) ? EVP_sha256() : EVP_sha384();
                EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
                if (md_ctx != NULL) {
                    if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pkey) == 1 &&
                        EVP_DigestVerifyUpdate(md_ctx, message, message_size) == 1 &&
                        EVP_DigestVerifyFinal(md_ctx, der_sig, (size_t)der_sig_len) == 1) {
                        result = true;
                    }
                    EVP_MD_CTX_free(md_ctx);
                }
                OPENSSL_free(der_sig);
            }
            /* r_bn and s_bn are owned by ecdsa_sig after ECDSA_SIG_set0 */
        } else {
            BN_free(r_bn);
            BN_free(s_bn);
        }
        ECDSA_SIG_free(ecdsa_sig);
    }

    EVP_PKEY_free(pkey);
    return result;
}

bool test_verify_cose_sign1(test_cose_sign1_t const* sign1,
                            uint8_t const* issuer_pubkey,
                            size_t issuer_pubkey_size,
                            n20_crypto_key_type_t key_type) {
    /* Reconstruct the Sig_structure1:
     * ["Signature1", protected, external_aad, payload]
     * Encoded as: 84 6a "Signature1" <protected_bstr> 40 <payload_bstr>
     *
     * The to-be-signed data is the concatenation of:
     *   [0] = array(4) header + "Signature1" text string
     *   [1] = protected header as bstr (with its CBOR bstr wrapper)
     *   [2] = empty bstr (0x40)
     *   [3] = payload as bstr (with its CBOR bstr wrapper)
     */
    uint8_t sig_struct_buf[2048];
    n20_stream_t s;
    n20_stream_init(&s, sig_struct_buf, sizeof(sig_struct_buf));

    /* Write in reverse (right-to-left stream) */
    /* [3] payload as bstr */
    n20_cbor_write_byte_string(&s, sign1->payload);
    /* [2] empty external_aad */
    n20_cbor_write_byte_string(&s, (n20_slice_t){.size = 0, .buffer = NULL});
    /* [1] protected header as bstr */
    n20_cbor_write_byte_string(&s, sign1->protected_header);
    /* [0] context string "Signature1" */
    n20_stream_prepend(&s, (uint8_t const*)"\x6aSignature1", 11);
    /* Array header for 4 elements */
    n20_cbor_write_array_header(&s, 4);

    if (n20_stream_has_buffer_overflow(&s)) {
        fprintf(stderr, "    Sig_structure1 buffer overflow\n");
        return false;
    }

    size_t tbs_size = n20_stream_byte_count(&s);
    uint8_t const* tbs_data = sig_struct_buf + (sizeof(sig_struct_buf) - tbs_size);

    return test_verify_raw_signature(issuer_pubkey,
                                     issuer_pubkey_size,
                                     tbs_data,
                                     tbs_size,
                                     sign1->signature.buffer,
                                     sign1->signature.size,
                                     key_type);
}

/* COSE_Key label constants (matching cose.c) */
#define COSE_KEY_LABEL_KEY_TYPE (1)
#define COSE_KEY_LABEL_ALGORITHM_ID (3)
#define COSE_KEY_LABEL_CURVE (-1)
#define COSE_KEY_LABEL_X_COORDINATE (-2)
#define COSE_KEY_LABEL_Y_COORDINATE (-3)

#define COSE_KEY_TYPE_OKP (1)
#define COSE_KEY_TYPE_EC2 (2)

#define COSE_CURVE_P256 (1)
#define COSE_CURVE_P384 (2)
#define COSE_CURVE_ED25519 (6)

/* CWT claim label for the subject public key */
#define CWT_LABEL_SUBJECT_PUBLIC_KEY (-4670552)

static int64_t cbor_read_int(n20_istream_t* s) {
    n20_cbor_type_t type;
    uint64_t value;
    if (!n20_cbor_read_header(s, &type, &value)) return 0;
    if (type == n20_cbor_type_uint_e) return (int64_t)value;
    if (type == n20_cbor_type_nint_e) return -1 - (int64_t)value;
    return 0;
}

bool test_extract_cose_pubkey(uint8_t const* cose_sign1,
                              size_t cose_sign1_size,
                              uint8_t* pubkey_out,
                              size_t* pubkey_size_in_out,
                              n20_crypto_key_type_t* key_type_out) {
    /* Parse the COSE_Sign1 to get the payload */
    test_cose_sign1_t sign1;
    if (!test_parse_cose_sign1(cose_sign1, cose_sign1_size, &sign1)) {
        fprintf(stderr, "    Failed to parse COSE_Sign1\n");
        return false;
    }

    if (sign1.payload.buffer == NULL || sign1.payload.size == 0) {
        fprintf(stderr, "    COSE_Sign1 has no payload\n");
        return false;
    }

    /* The payload is a CWT (CBOR map). Find the subject public key claim. */
    n20_istream_t cwt;
    n20_istream_init(&cwt, sign1.payload.buffer, sign1.payload.size);

    n20_cbor_type_t type;
    uint64_t value;
    if (!n20_cbor_read_header(&cwt, &type, &value) || type != n20_cbor_type_map_e) {
        fprintf(stderr, "    CWT payload is not a map\n");
        return false;
    }
    uint64_t map_count = value;

    /* Iterate through the CWT map to find the subject public key */
    bool found_pubkey = false;
    for (uint64_t i = 0; i < map_count; i++) {
        int64_t label = cbor_read_int(&cwt);
        if (label == CWT_LABEL_SUBJECT_PUBLIC_KEY) {
            found_pubkey = true;
            break;
        } else {
            if (!n20_cbor_read_skip_item(&cwt)) {
                fprintf(stderr, "    Failed to skip CWT claim value\n");
                return false;
            }
        }
    }

    if (!found_pubkey) {
        fprintf(stderr, "    Subject public key claim not found in CWT\n");
        return false;
    }

    if (!n20_cbor_read_header(&cwt, &type, &value) || type != n20_cbor_type_bytes_e) {
        fprintf(stderr, "    COSE_Key is not a byte string\n");
        return false;
    }

    if (!n20_cbor_read_header(&cwt, &type, &value) || type != n20_cbor_type_map_e) {
        fprintf(stderr, "    COSE_Key is not a map\n");
        return false;
    }
    uint64_t key_pairs = value;

    n20_slice_t x = {0};
    n20_slice_t y = {0};
    int64_t key_type_val = 0;
    int64_t crv = 0;

    for (uint64_t i = 0; i < key_pairs; i++) {
        int64_t key_label = cbor_read_int(&cwt);
        switch (key_label) {
            case COSE_KEY_LABEL_KEY_TYPE:
                key_type_val = cbor_read_int(&cwt);
                break;
            case COSE_KEY_LABEL_CURVE:
                crv = cbor_read_int(&cwt);
                break;
            case COSE_KEY_LABEL_X_COORDINATE:
                if (!n20_cbor_read_header(&cwt, &type, &value) || type != n20_cbor_type_bytes_e) {
                    return false;
                }
                if (!n20_istream_get_slice(&cwt, &x, value)) return false;
                break;
            case COSE_KEY_LABEL_Y_COORDINATE:
                if (!n20_cbor_read_header(&cwt, &type, &value) || type != n20_cbor_type_bytes_e) {
                    return false;
                }
                if (!n20_istream_get_slice(&cwt, &y, value)) return false;
                break;
            default:
                if (!n20_cbor_read_skip_item(&cwt)) return false;
                break;
        }
    }

    /* Reconstruct the raw public key based on key type */
    if (key_type_val == COSE_KEY_TYPE_EC2) {
        /* EC2: output is x || y */
        if (x.size == 0 || y.size == 0) {
            fprintf(stderr, "    EC2 key missing x or y coordinate\n");
            return false;
        }
        size_t total = x.size + y.size + 1;
        if (total > *pubkey_size_in_out) return false;
        pubkey_out[0] = 0x04; /* Uncompressed point prefix */
        memcpy(pubkey_out + 1, x.buffer, x.size);
        memcpy(pubkey_out + 1 + x.size, y.buffer, y.size);
        *pubkey_size_in_out = total;

        if (crv == COSE_CURVE_P256) {
            *key_type_out = n20_crypto_key_type_secp256r1_e;
        } else if (crv == COSE_CURVE_P384) {
            *key_type_out = n20_crypto_key_type_secp384r1_e;
        } else {
            fprintf(stderr, "    Unknown EC2 curve: %lld\n", (long long)crv);
            return false;
        }
    } else if (key_type_val == COSE_KEY_TYPE_OKP) {
        /* OKP (Ed25519): output is x only */
        if (x.size == 0) {
            fprintf(stderr, "    OKP key missing x coordinate\n");
            return false;
        }
        if (x.size > *pubkey_size_in_out) return false;
        memcpy(pubkey_out, x.buffer, x.size);
        *pubkey_size_in_out = x.size;
        *key_type_out = n20_crypto_key_type_ed25519_e;
    } else {
        fprintf(stderr, "    Unknown COSE key type: %lld\n", (long long)key_type_val);
        return false;
    }

    return true;
}
