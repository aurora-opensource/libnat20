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

#include "nat20/x509.h"

#include <gtest/gtest.h>
#include <openssl/base.h>
#include <openssl/digest.h>
#include <openssl/evp.h>

#include <iomanip>
#include <memory>
#include <optional>
#include <vector>
#include <sstream>

#include "nat20/asn1.h"
#include "openssl/hkdf.h"
#include "openssl/mem.h"
#include "openssl/pki/verify.h"
#include "openssl/x509.h"

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
MAKE_PTR(BIO);
MAKE_PTR(X509);

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

    EVP_PKEY* key = NULL;
    if (!EVP_PKEY_keygen(evp_ctx.get(), &key)) {
        ADD_FAILURE();
        return nullptr;
    }
    return EVP_PKEY_PTR_t(key);
}

std::optional<std::vector<uint8_t>> sign(EVP_PKEY_PTR_t const& key,
                                         std::vector<uint8_t> const& message) {

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

bool verify(EVP_PKEY_PTR_t const& key,
            std::vector<uint8_t> const& message,
            std::vector<uint8_t> const& signature) {

    auto md_ctx = EVP_MD_CTX_PTR_t(EVP_MD_CTX_new());
    if (!md_ctx) {
        ADD_FAILURE();
        return false;
    }

    if (1 != EVP_DigestVerifyInit(md_ctx.get(), NULL, EVP_sha256(), NULL, key.get())) {
        ADD_FAILURE();
        return false;
    }

    if (1 != EVP_DigestVerifyUpdate(md_ctx.get(), message.data(), message.size())) {
        ADD_FAILURE();
        return false;
    }

    size_t sig_size;
    if (1 != EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size())) {
        ADD_FAILURE();
        return false;
    }

    return true;
}

class CryptoTest : public testing::Test {};

TEST_F(CryptoTest, KeyGenSignVerify) {

    std::string message("the message");
    auto message_v =
        std::vector<uint8_t>(reinterpret_cast<uint8_t const*>(message.c_str()),
                             reinterpret_cast<uint8_t const*>(message.c_str() + message.size()));

    auto key = generate_rsa_key(2048);
    ASSERT_TRUE(!!key);

    auto signature = sign(key, message_v);
    ASSERT_TRUE(!!signature);

    ASSERT_TRUE(verify(key, message_v, *signature));
}

class X509Test : public testing::Test {};

struct BoringsslDeleter {
    void operator()(void* p) { OPENSSL_free(p); }
};

TEST_F(X509Test, Inittest) {

    n20_x509_tbs_t tbs = {0};

    ASSERT_EQ(tbs.serial_number, 0);
    ASSERT_EQ(tbs.signature_algorithm.oid.elem_count, 0);
    ASSERT_EQ(tbs.signature_algorithm.oid.elements[0], 0);
    ASSERT_EQ(tbs.validity.not_after, nullptr);
    ASSERT_EQ(tbs.validity.not_before, nullptr);
    ASSERT_EQ(tbs.issuer_name.element_count, 0);
    ASSERT_EQ(tbs.subject_name.element_count, 0);
    ASSERT_EQ(tbs.extensions.extensions_count, 0);
    ASSERT_EQ(tbs.subject_public_key_info.public_key_bits, 0);
    ASSERT_EQ(tbs.subject_public_key_info.algorithm_identifier.oid.elem_count, 0);
}

TEST_F(X509Test, Test1) {

    // Generate an RSA key and get the DER encoded key info.
    auto key = generate_rsa_key(2048);
    ASSERT_TRUE(!!key);
    uint8_t* der_key_info = NULL;
    int rc_der_len = i2d_PublicKey(key.get(), &der_key_info);
    ASSERT_GE(rc_der_len, 0);
    auto der_key_info_guard = std::unique_ptr<uint8_t, BoringsslDeleter>(der_key_info);

    // Assemble the to-be-signed information of the certificate.
    n20_x509_tbs_t tbs = {};
    tbs.serial_number = 1;
    tbs.signature_algorithm.oid = OID_SHA256_WITH_RSA_ENC;
    tbs.issuer_name =
        N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                      N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"),
                      N20_X509_RDN(&OID_ORGANIZATION_NAME, "Aurora Innovation Inc"),
                      N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Aurora Information Security"),
                      N20_X509_RDN(&OID_COMMON_NAME, "Aurora DICE Authority"), );
    tbs.validity = {.not_before = NULL, .not_after = NULL};
    tbs.subject_name =
        N20_X509_NAME(N20_X509_RDN(&OID_COUNTRY_NAME, "US"),
                      N20_X509_RDN(&OID_LOCALITY_NAME, "Pittsburgh"),
                      N20_X509_RDN(&OID_ORGANIZATION_NAME, "Aurora Innovation Inc"),
                      N20_X509_RDN(&OID_ORGANIZATION_UNIT_NAME, "Aurora Information Security"),
                      N20_X509_RDN(&OID_COMMON_NAME, "Aurora DICE Authority"), );
    tbs.subject_public_key_info = {
        .algorithm_identifier = {.oid = OID_RSA_ENCRYPTION},
        .public_key_bits = (size_t)rc_der_len * 8,
        .public_key = der_key_info,
    };

    n20_x509_ext_key_usage_t key_usage = {0};
    N20_X509_KEY_USAGE_SET_DIGITAL_SIGNATURE(&key_usage);
    N20_X509_KEY_USAGE_SET_KEY_CERT_SIGN(&key_usage);

    n20_x509_ext_basic_constraints_t basic_constraints = {
        .is_ca = 1,
        .path_length = 1,
    };

    n20_x509_extension_t exts[] = {
        {
            .oid = &OID_KEY_USAGE,
            .critical = 1,
            .content_cb = n20_x509_ext_key_usage_content,
            .context = &key_usage,
        },
        {
            .oid = &OID_BASIC_CONSTRAINTS,
            .critical = 1,
            .content_cb = n20_x509_ext_basic_constraints_content,
            .context = &basic_constraints,
        },
    };

    tbs.extensions = {
        .extensions_count = 2,
        .extensions = exts,
    };

    // DER encode the to-be-signed part of the certificate.
    // First run the formatting function with NULL stream buffer
    // to compute the length of the tbs part.
    n20_asn1_stream_t s;
    n20_asn1_stream_init(&s, nullptr, 0);
    n20_x509_cert_tbs(&s, &tbs);
    auto tbs_size = n20_asn1_stream_data_written(&s);
    ASSERT_FALSE(n20_asn1_stream_is_good(&s));
    ASSERT_EQ(675, tbs_size);

    // Now allocate a buffer large enough to hold the tbs part,
    // reinitialize the asn1_stream and write the tbs part again.
    uint8_t buffer[2000] = {};
    n20_asn1_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_cert_tbs(&s, &tbs);
    tbs_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_good(&s));
    ASSERT_EQ(675, tbs_size);

    // Sign the TBS part.
    auto sig = sign(
        key, std::vector<uint8_t>(n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + tbs_size));
    ASSERT_TRUE(!!sig);

    // Combine the tbs info with the signature algorithm,
    // reinitialize the asn1 stream and write out the entire
    // certificate.
    n20_x509_t x509 = {
        .tbs = &tbs,
        .signature_algorithm = {.oid = OID_SHA256_WITH_RSA_ENC},
        .signature_bits = sig->size() * 8,
        .signature = sig->data(),
    };
    n20_asn1_stream_init(&s, &buffer[0], sizeof(buffer));
    n20_x509_cert(&s, &x509);
    auto x509_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_good(&s));

    // Now verify the signature on the Certificate.
    uint8_t const* p = n20_asn1_stream_data(&s);
    std::cout << "Ptr: " << p << std::endl;
    auto x509i = X509_PTR_t(d2i_X509(nullptr, &p, (long)x509_size));
    ASSERT_TRUE(!!x509i);
    X509_print_ex_fp(stdout, x509i.get(), 0, X509V3_EXT_DUMP_UNKNOWN);
    auto rc = X509_verify(x509i.get(), key.get());
    ASSERT_EQ(rc, 1);

    // Validate the self signed certificate.
    std::string diag;
    auto cert_string_view =
        std::string_view(reinterpret_cast<char const*>(n20_asn1_stream_data(&s)), x509_size);
    auto trust_store = bssl::VerifyTrustStore::FromDER(cert_string_view, &diag);
    ASSERT_TRUE(!!trust_store) << "Diag: " << diag;
    bssl::CertificateVerifyOptions cert_opts{};
    cert_opts.leaf_cert = cert_string_view;
    cert_opts.trust_store = trust_store.get();
    bssl::VerifyError v_error{};
    bssl::CertificateVerifyStatus v_status{};
    auto verify_result = bssl::CertificateVerify(cert_opts, &v_error, &v_status);
    ASSERT_TRUE(!!verify_result);
    ASSERT_EQ(v_error.Code(), bssl::VerifyError::StatusCode::PATH_VERIFIED)
        << "Diag: " << v_error.DiagnosticString();

    // Now create a certificate signed with a different key.
    // It is expected to fail the verification.

    // Now allocate a buffer large enough to hold the tbs part,
    // reinitialize the asn1_stream and write the tbs part again.
    uint8_t buffer2[2000] = {};
    n20_asn1_stream_init(&s, &buffer2[0], sizeof(buffer2));
    n20_x509_cert_tbs(&s, &tbs);
    tbs_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_good(&s));
    ASSERT_EQ(675, tbs_size);

    auto key2 = generate_rsa_key(2048);

    // Sign the TBS part.
    auto sig2 = sign(
        key2, std::vector<uint8_t>(n20_asn1_stream_data(&s), n20_asn1_stream_data(&s) + tbs_size));
    ASSERT_TRUE(!!sig);

    // Combine the tbs info with the signature algorithm,
    // reinitialize the asn1 stream and write out the entire
    // certificate.
    n20_x509_t x5092 = {
        .tbs = &tbs,
        .signature_algorithm = {.oid = OID_SHA256_WITH_RSA_ENC},
        .signature_bits = sig2->size() * 8,
        .signature = sig2->data(),
    };
    n20_asn1_stream_init(&s, &buffer2[0], sizeof(buffer2));
    n20_x509_cert(&s, &x5092);
    auto x5092_size = n20_asn1_stream_data_written(&s);
    ASSERT_TRUE(n20_asn1_stream_is_good(&s));

    auto cert2_string_view =
        std::string_view(reinterpret_cast<char const*>(n20_asn1_stream_data(&s)), x509_size);

    cert_opts.leaf_cert = cert2_string_view;
    verify_result = bssl::CertificateVerify(cert_opts, &v_error, &v_status);
    ASSERT_FALSE(!!verify_result);
    ASSERT_EQ(v_error.Code(), bssl::VerifyError::StatusCode::CERTIFICATE_INVALID_SIGNATURE)
        << "Diag: " << v_error.DiagnosticString();
}

uint8_t const test_uds[] = {
    0xa4, 0x32, 0xb4, 0x34, 0x94, 0x4f, 0x59, 0xcf, 0xdb, 0xf7, 0x04, 0x46, 0x95, 0x9c, 0xee, 0x08,
    0x7f, 0x6b, 0x87, 0x60, 0xd8, 0xef, 0xb4, 0xcf, 0xed, 0xf2, 0xf6, 0x29, 0x33, 0x88, 0xf0, 0x64,
    0xbb, 0xe0, 0x21, 0xf5, 0x87, 0x1c, 0x6c, 0x0c, 0x30, 0x2b, 0x32, 0x4f, 0x4c, 0x44, 0xd1, 0x26,
    0xca, 0x35, 0x6b, 0xc3, 0xc5, 0x0e, 0x17, 0xc6, 0x21, 0xad, 0x1d, 0x32, 0xbd, 0x6e, 0x35, 0x08};


std::string hexdump(std::vector<uint8_t> const & data) {
    std::stringstream s;
    int i;
    for (i = 0; i < data.size() - 1; ++i) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i % 16 == 15) {
            s << "\n";
        } else if (i % 16 == 7) {
            s << "  ";
        } else {
            s << " ";
        }
    }
    if (i < data.size()) {
        s << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return s.str();
}

TEST_F(X509Test, KeyDerivation) {
    std::vector<uint8_t> out_key(64);
    char const *info = "the info";
    int rc = HKDF_expand(out_key.data(),
                out_key.size(),
                EVP_sha256(),
                test_uds,
                sizeof(test_uds),
                reinterpret_cast<uint8_t const*>(info),
                strlen(info));

    ASSERT_EQ(rc, 1);

    std::cout << "Key:\n" << hexdump(out_key) << std::endl;
}
