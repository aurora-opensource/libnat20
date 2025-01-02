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

    n20_asn1_tag_info_t tag_info;

    // profileName [7] EXPLICIT UTF8String OPTIONAL
    // Don't include this if it's NULL.
    if (open_dice_input->profile_name != NULL) {
        tag_info = n20_asn1_explicit_tag(7);
        n20_asn1_printablestring(s, open_dice_input->profile_name, &tag_info);
    }

    // Mode ::= INTEGER (0..3)
    // mode [6] EXPLICIT Mode OPTIONAL
    tag_info = n20_asn1_explicit_tag(6);
    n20_asn1_uint64(s, inputs->mode, &tag_info);

    // authorityDescriptor [5] EXPLICIT OCTET STRING OPTIONAL
    // Don't include this if it's NULL.
    if (inputs->authority_descriptor.buffer != NULL) {
        tag_info = n20_asn1_explicit_tag(5);
        n20_asn1_octetstring(s, &inputs->authority_descriptor, &tag_info);
    }

    // authorityHash [4] EXPLICIT OCTET STRING OPTIONAL
    tag_info = n20_asn1_explicit_tag(4);
    n20_asn1_octetstring(s, &inputs->authority_hash, &tag_info);

    switch (inputs->configuration_format) {
        case n20_x509_ext_open_dice_configuration_format_inline_e:
            // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
            tag_info = n20_asn1_explicit_tag(3);
            n20_asn1_octetstring(s, &inputs->configuration_inline, &tag_info);
            break;
        case n20_x509_ext_open_dice_configuration_format_descriptor_e:
            // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
            tag_info = n20_asn1_explicit_tag(3);
            n20_asn1_octetstring(s, &inputs->configuration_descriptor, &tag_info);

            tag_info = n20_asn1_explicit_tag(2);
            // configurationHash [2] EXPLICIT OCTET STRING OPTIONAL
            n20_asn1_octetstring(s, &inputs->configuration_hash, &tag_info);
            break;
    }

    // codeDescriptor [1] EXPLICIT OCTET STRING OPTIONAL
    // Don't include this if it's NULL.
    if (inputs->code_descriptor.buffer != NULL) {
        tag_info = n20_asn1_explicit_tag(1);
        n20_asn1_octetstring(s, &inputs->code_descriptor, &tag_info);
    }

    // codeHash [0] EXPLICIT OCTET STRING OPTIONAL
    tag_info = n20_asn1_explicit_tag(0);
    n20_asn1_octetstring(s, &inputs->code_hash, &tag_info);
}

void n20_x509_ext_open_dice_input_content(n20_asn1_stream_t *const s, void *context) {
    if (context == NULL) {
        return;
    }

    n20_asn1_sequence(s, n20_x509_ext_open_dice_input_sequence_content, context, /*tag_info=*/NULL);
}
