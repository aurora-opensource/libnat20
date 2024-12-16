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
#include <nat20/open_dice.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>

void n20_x509_ext_open_dice_input_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_ext_open_dice_input_t const *open_dice_input = context;
    if (open_dice_input == NULL) {
        return;
    }

    n20_open_dice_inputs_t const *inputs = open_dice_input->inputs;
    if (inputs == NULL) {
        return;
    }

    size_t sequence_mark = n20_asn1_stream_data_written(s);
    size_t mark = sequence_mark;

    // profileName [7] EXPLICIT UTF8String OPTIONAL
    // Don't include this if it's NULL.
    if (open_dice_input->profile_name != NULL) {
        n20_asn1_printablestring(s, open_dice_input->profile_name);
        n20_asn1_header(s,
                        N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                        /*constructed=*/true,
                        /*tag=*/7,
                        n20_asn1_stream_data_written(s) - mark);
        mark = n20_asn1_stream_data_written(s);
    }

    // Mode ::= INTEGER (0..3)
    // mode [6] EXPLICIT Mode OPTIONAL
    n20_asn1_uint64(s, inputs->mode);
    n20_asn1_header(s,
                    N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                    /*constructed=*/true,
                    /*tag=*/6,
                    n20_asn1_stream_data_written(s) - mark);
    mark = n20_asn1_stream_data_written(s);

    // authorityDescriptor [5] EXPLICIT OCTET STRING OPTIONAL
    // Don't include this if it's NULL.
    if (inputs->authority_descriptor != NULL) {
        n20_asn1_octetstring(s, inputs->authority_descriptor, inputs->authority_descriptor_length);
        n20_asn1_header(s,
                        N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                        /*constructed=*/true,
                        /*tag=*/5,
                        n20_asn1_stream_data_written(s) - mark);
        mark = n20_asn1_stream_data_written(s);
    }

    // authorityHash [4] EXPLICIT OCTET STRING OPTIONAL
    n20_asn1_octetstring(s, inputs->authority_hash, sizeof(inputs->authority_hash));
    n20_asn1_header(s,
                    N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                    /*constructed=*/true,
                    /*tag=*/4,
                    n20_asn1_stream_data_written(s) - mark);
    mark = n20_asn1_stream_data_written(s);

    switch (inputs->configuration_format) {
        case n20_open_dice_configuration_format_inline_e:
            // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(
                s, inputs->configuration_inline, sizeof(inputs->configuration_inline));
            n20_asn1_header(s,
                            N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                            /*constructed=*/true,
                            /*tag=*/3,
                            n20_asn1_stream_data_written(s) - mark);
            mark = n20_asn1_stream_data_written(s);
            break;
        case n20_open_dice_configuration_format_descriptor_e:
            // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(
                s, inputs->configuration_descriptor, inputs->configuration_descriptor_length);
            n20_asn1_header(s,
                            N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                            /*constructed=*/true,
                            /*tag=*/3,
                            n20_asn1_stream_data_written(s) - mark);
            mark = n20_asn1_stream_data_written(s);

            // configurationHash [2] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(s, inputs->configuration_hash, sizeof(inputs->configuration_hash));
            n20_asn1_header(s,
                            N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                            /*constructed=*/true,
                            /*tag=*/2,
                            n20_asn1_stream_data_written(s) - mark);
            mark = n20_asn1_stream_data_written(s);
            break;
    }

    // codeDescriptor [1] EXPLICIT OCTET STRING OPTIONAL
    // Don't include this if it's NULL.
    if (inputs->code_descriptor != NULL) {
        n20_asn1_octetstring(s, inputs->code_descriptor, inputs->code_descriptor_length);
        n20_asn1_header(s,
                        N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                        /*constructed=*/true,
                        /*tag=*/1,
                        n20_asn1_stream_data_written(s) - mark);
        mark = n20_asn1_stream_data_written(s);
    }

    // codeHash [0] EXPLICIT OCTET STRING OPTIONAL
    n20_asn1_octetstring(s, inputs->code_hash, sizeof(inputs->code_hash));
    n20_asn1_header(s,
                    N20_ASN1_CLASS_CONTEXT_SPECIFIC,
                    /*constructed=*/true,
                    /*tag=*/0,
                    n20_asn1_stream_data_written(s) - mark);
    mark = n20_asn1_stream_data_written(s);

    n20_asn1_header(s,
                    N20_ASN1_CLASS_UNIVERSAL,
                    /*constructed=*/true,
                    N20_ASN1_TAG_SEQUENCE,
                    n20_asn1_stream_data_written(s) - sequence_mark);
}
