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
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>

static void n20_x509_ext_open_dice_input_sequence_content(n20_asn1_stream_t *const s,
                                                          void *context) {
    n20_x509_ext_open_dice_input_t const *open_dice_input = context;
    if (open_dice_input == NULL) {
        return;
    }

    n20_x509_ext_open_dice_inputs_t const *inputs = open_dice_input->inputs;
    if (inputs == NULL) {
        return;
    }

    // profileName [7] EXPLICIT UTF8String OPTIONAL
    // Don't include this if it's NULL.
    if (open_dice_input->profile_name != NULL) {
        n20_asn1_printablestring(s, open_dice_input->profile_name, n20_asn1_tag_info_explicit(7));
    }

    // Mode ::= INTEGER (0..3)
    // mode [6] EXPLICIT Mode OPTIONAL
    n20_asn1_uint64(s, inputs->mode, n20_asn1_tag_info_explicit(6));

    // authorityDescriptor [5] EXPLICIT OCTET STRING OPTIONAL
    // Don't include this if it's NULL.
    if (inputs->authority_descriptor.buffer != NULL) {
        n20_asn1_octetstring(s, &inputs->authority_descriptor, n20_asn1_tag_info_explicit(5));
    }

    // authorityHash [4] EXPLICIT OCTET STRING OPTIONAL
    n20_asn1_octetstring(s, &inputs->authority_hash, n20_asn1_tag_info_explicit(4));

    switch (inputs->configuration_format) {
        case n20_x509_ext_open_dice_configuration_format_inline_e:
            // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(s, &inputs->configuration_inline, n20_asn1_tag_info_explicit(3));
            break;
        case n20_x509_ext_open_dice_configuration_format_descriptor_e:
            // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(
                s, &inputs->configuration_descriptor, n20_asn1_tag_info_explicit(3));

            // configurationHash [2] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(s, &inputs->configuration_hash, n20_asn1_tag_info_explicit(2));
            break;
    }

    // codeDescriptor [1] EXPLICIT OCTET STRING OPTIONAL
    // Don't include this if it's NULL.
    if (inputs->code_descriptor.buffer != NULL) {
        n20_asn1_octetstring(s, &inputs->code_descriptor, n20_asn1_tag_info_explicit(1));
    }

    // codeHash [0] EXPLICIT OCTET STRING OPTIONAL
    n20_asn1_octetstring(s, &inputs->code_hash, n20_asn1_tag_info_explicit(0));
}

void n20_x509_ext_open_dice_input_content(n20_asn1_stream_t *const s, void *context) {
    if (context == NULL) {
        return;
    }

    n20_asn1_sequence(
        s, n20_x509_ext_open_dice_input_sequence_content, context, n20_asn1_tag_info_no_override());
}
