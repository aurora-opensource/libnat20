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

#include <nat20/asn1.h>
#include <nat20/oid.h>
#include <nat20/x509.h>

void n20_x509_rdn_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_rdn_t const *rdn = (n20_x509_rdn_t const *)context;

    n20_asn1_printablestring(s, rdn->value);
    n20_asn1_object_identifier(s, rdn->type);
}

void n20_x509_rdn(n20_asn1_stream_t *const s, n20_x509_rdn_t const *rdn) {
    size_t mark = n20_asn1_stream_data_written(s);
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_rdn_content,
        .cb_context = (void *)rdn,
    };
    n20_asn1_sequence(s, &sequence);
    n20_asn1_header(s,
                    N20_ASN1_CLASS_UNIVERSAL,
                    /*constructed=*/true,
                    N20_ASN1_TAG_SET,
                    n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_name_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_name_t const *name = context;
    if (name == NULL || name->element_count > N20_X509_NAME_MAX_NAME_ELEMENTS) {
        n20_asn1_null(s);
        return;
    }

    for (size_t i = 0; i < name->element_count; ++i) {
        n20_x509_rdn(s, &name->elements[name->element_count - (i + 1)]);
    }
}

void n20_x509_name(n20_asn1_stream_t *const s, n20_x509_name_t const *name) {
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_name_content,
        .cb_context = (void *)name,
    };
    n20_asn1_sequence(s, &sequence);
}

static void n20_x509_extension_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_extensions_t const *exts = context;

    size_t mark = 0;

    for (size_t i = 0; i < exts->extensions_count; ++i) {
        n20_x509_extension_t const *ext = &exts->extensions[exts->extensions_count - (i + 1)];

        mark = n20_asn1_stream_data_written(s);

        // If no content_cb was given, no data is written.
        // The value octet string will be empty.
        if (ext->content_cb != NULL) {
            ext->content_cb(s, ext->context);
        }

        n20_asn1_header(s,
                        N20_ASN1_CLASS_UNIVERSAL,
                        /*constructed=*/false,
                        N20_ASN1_TAG_OCTET_STRING,
                        n20_asn1_stream_data_written(s) - mark);

        if (ext->critical) {
            n20_asn1_boolean(s, 1);
        }

        // ext->oid does not need to be checked for NULL.
        // n20_asn1_object_identifier will render an
        // ASN1 NULL which is nonsensical at this point
        // but safe.
        n20_asn1_object_identifier(s, ext->oid);

        n20_asn1_header(s,
                        N20_ASN1_CLASS_UNIVERSAL,
                        /*constructed=*/true,
                        N20_ASN1_TAG_SEQUENCE,
                        n20_asn1_stream_data_written(s) - mark);
    }
}

void n20_x509_extension(n20_asn1_stream_t *const s, n20_x509_extensions_t const *exts) {
    if (exts == NULL || exts->extensions == NULL || exts->extensions_count == 0) {
        return;
    }

    // Extensions have a context specific explicit tag of 3.
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_extension_content,
        .cb_context = (void *)exts,
    };
    n20_asn1_sequence_explicitly_tagged(s, /*tag=*/3, &sequence);
}

void n20_x509_ext_basic_constraints_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_ext_basic_constraints_t const *basic_constraints = context;
    if (basic_constraints == NULL) {
        return;
    }

    size_t mark = n20_asn1_stream_data_written(s);
    if (basic_constraints->is_ca) {
        if (basic_constraints->has_path_length) {
            n20_asn1_uint64(s, basic_constraints->path_length);
        }
        n20_asn1_boolean(s, true);
    }
    n20_asn1_header(s,
                    N20_ASN1_CLASS_UNIVERSAL,
                    /*constructed=*/true,
                    N20_ASN1_TAG_SEQUENCE,
                    n20_asn1_stream_data_written(s) - mark);
}

void n20_x509_ext_key_usage_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_ext_key_usage_t const *key_usage = context;
    uint8_t bits = 0;

    if (key_usage == NULL) {
        return;
    }

    // Compute the minimal number of bits in the bit string.
    if (key_usage->key_usage_mask[1] != 0) {
        bits = 9;
    } else if (key_usage->key_usage_mask[0] != 0) {
        bits = 8;
        uint8_t c = key_usage->key_usage_mask[0];
        if ((c & 0xf) == 0) {
            bits -= 4;
            c >>= 4;
        }
        if ((c & 3) == 0) {
            bits -= 2;
            c >>= 2;
        }
        if ((c & 1) == 0) {
            bits -= 1;
        }
    }

    n20_asn1_bitstring_t bitstring = {
        .b = key_usage->key_usage_mask,
        .bits = bits,
    };
    n20_asn1_bitstring(s, &bitstring);
}

void n20_x509_algorithm_identifier_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_algorithm_identifier_t const *alg_id = context;
    if (alg_id == NULL) {
        return;
    }

    switch (alg_id->params.variant) {
        case n20_x509_pv_none_e:
            break;
        case n20_x509_pv_null_e:
            n20_asn1_null(s);
            break;
        case n20_x509_pv_ec_curve_e:
            n20_asn1_object_identifier(s, alg_id->params.ec_curve);
            break;
    }

    n20_asn1_object_identifier(s, alg_id->oid);
}

void n20_x509_algorithm_identifier(
    n20_asn1_stream_t *const s, n20_x509_algorithm_identifier_t const *const algorithm_identifier) {
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_algorithm_identifier_content,
        .cb_context = (void *)algorithm_identifier,
    };
    n20_asn1_sequence(s, &sequence);
}

void n20_x509_public_key_info_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_public_key_info_t const *pub_key_info = context;
    n20_asn1_bitstring_t bitstring = {
        .b = pub_key_info->public_key,
        .bits = pub_key_info->public_key_bits,
    };
    n20_asn1_bitstring(s, &bitstring);
    n20_x509_algorithm_identifier(s, &pub_key_info->algorithm_identifier);
}

void n20_x509_public_key_info(n20_asn1_stream_t *const s,
                              n20_x509_public_key_info_t const *const public_key_info) {
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_public_key_info_content,
        .cb_context = (void *)public_key_info,
    };
    n20_asn1_sequence(s, &sequence);
}

void n20_x509_validity_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_validity_t const *const validity = context;
    // not after
    n20_asn1_generalized_time(
        s, validity->not_after != NULL ? validity->not_after : n20_x509_no_expiration);
    // not before
    n20_asn1_generalized_time(
        s, validity->not_before != NULL ? validity->not_before : n20_x509_unix_epoch);
}

void n20_x509_validity(n20_asn1_stream_t *const s, n20_x509_validity_t const *const validity) {
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_validity_content,
        .cb_context = (void *)validity,
    };
    n20_asn1_sequence(s, &sequence);
}

void n20_x509_version_3(n20_asn1_stream_t *const s) {
    // Version 3 (value 2) with explicit tag 0.
    n20_asn1_uint64_explicitly_tagged(s, /*tag=*/0, /*n=*/2);
}

void n20_x509_cert_tbs_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_tbs_t const *tbs = context;
    if (tbs == NULL) {
        return;
    }

    // X509 V3 extensions
    n20_x509_extension(s, &tbs->extensions);

    // The following optional fields are not implemented yet.
    // subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL
    // issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL

    // subjectPublicKeyInfo SubjectPublicKeyInfo
    n20_x509_public_key_info(s, &tbs->subject_public_key_info);

    // subject Name
    n20_x509_name(s, &tbs->subject_name);

    // validity Validity
    n20_x509_validity(s, &tbs->validity);

    // issuer Name
    n20_x509_name(s, &tbs->issuer_name);

    // signature AlgorithmIdentifier
    n20_x509_algorithm_identifier(s, &tbs->signature_algorithm);

    // Serial number
    n20_asn1_uint64(s, tbs->serial_number);

    // Version 3 (value 2) with explicit tag 0
    n20_x509_version_3(s);
}

void n20_x509_cert_tbs(n20_asn1_stream_t *const s, n20_x509_tbs_t const *const tbs) {
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_cert_tbs_content,
        .cb_context = (void *)tbs,
    };
    n20_asn1_sequence(s, &sequence);
}

void n20_x509_cert_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_t const *x509 = context;
    if (x509 == NULL) {
        return;
    }
    n20_asn1_bitstring_t bitstring = {
        .b = x509->signature,
        .bits = x509->signature_bits,
    };
    n20_asn1_bitstring(s, &bitstring);
    n20_x509_algorithm_identifier(s, &x509->signature_algorithm);
    n20_x509_cert_tbs(s, x509->tbs);
}

void n20_x509_cert(n20_asn1_stream_t *const s, n20_x509_t const *const x509) {
    n20_asn1_sequence_t sequence = {
        .content_cb = n20_x509_cert_content,
        .cb_context = (void *)x509,
    };
    n20_asn1_sequence(s, &sequence);
}
