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

#include <nat20/asn1.h>
#include <nat20/stream.h>
#include <nat20/x509.h>
#include <nat20/x509_ext_open_dice_input.h>

static void n20_x509_ext_open_dice_input_sequence_content(n20_stream_t *const s, void *context) {
    n20_x509_ext_open_dice_input_t const *open_dice_input = context;

    // Don't need to check open_dice_input for NULL as it's checked in
    // n20_x509_ext_open_dice_input_content.

    // profileName [7] EXPLICIT UTF8String OPTIONAL
    if (open_dice_input->profile_name.buffer != NULL) {
        n20_asn1_utf8_string(s, &open_dice_input->profile_name, n20_asn1_tag_info_explicit(7));
    }

    // Mode ::= INTEGER (0..3)
    // mode [6] EXPLICIT Mode OPTIONAL
    n20_asn1_uint64(s, open_dice_input->mode, n20_asn1_tag_info_explicit(6));

    // authorityDescriptor [5] EXPLICIT OCTET STRING OPTIONAL
    if (open_dice_input->authority_descriptor.buffer != NULL) {
        n20_asn1_octetstring(
            s, &open_dice_input->authority_descriptor, n20_asn1_tag_info_explicit(5));
    }

    // authorityHash [4] EXPLICIT OCTET STRING OPTIONAL
    if (open_dice_input->authority_hash.buffer != NULL) {
        n20_asn1_octetstring(s, &open_dice_input->authority_hash, n20_asn1_tag_info_explicit(4));
    }

    // configurationDescriptor [3] EXPLICIT OCTET STRING OPTIONAL
    if (open_dice_input->configuration_descriptor.buffer != NULL) {
        n20_asn1_octetstring(
            s, &open_dice_input->configuration_descriptor, n20_asn1_tag_info_explicit(3));
    }

    // configurationHash [2] EXPLICIT OCTET STRING OPTIONAL
    if (open_dice_input->configuration_hash.buffer != NULL) {
        n20_asn1_octetstring(
            s, &open_dice_input->configuration_hash, n20_asn1_tag_info_explicit(2));
    }

    // codeDescriptor [1] EXPLICIT OCTET STRING OPTIONAL
    if (open_dice_input->code_descriptor.buffer != NULL) {
        n20_asn1_octetstring(s, &open_dice_input->code_descriptor, n20_asn1_tag_info_explicit(1));
    }

    // codeHash [0] EXPLICIT OCTET STRING OPTIONAL
    if (open_dice_input->code_hash.buffer != NULL) {
        n20_asn1_octetstring(s, &open_dice_input->code_hash, n20_asn1_tag_info_explicit(0));
    }
}

void n20_x509_ext_open_dice_input_content(n20_stream_t *const s, void *context) {
    if (context == NULL) {
        return;
    }

    n20_asn1_sequence(
        s, n20_x509_ext_open_dice_input_sequence_content, context, n20_asn1_tag_info_no_override());
}
