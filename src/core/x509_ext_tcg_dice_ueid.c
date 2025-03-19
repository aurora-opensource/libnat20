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
#include <nat20/x509_ext_tcg_dice_ueid.h>

static void n20_x509_ext_tcg_dice_ueid_sequence_content(n20_stream_t *const s, void *context) {
    n20_x509_ext_tcg_dice_ueid_t const *const tcg_dice_ueid =
        (n20_x509_ext_tcg_dice_ueid_t const *)context;

    // tcg_dice_ueid is never NULL since it's checked by n20_x509_ext_tcg_dice_ueid_content.
    n20_asn1_octetstring(s, &tcg_dice_ueid->ueid, n20_asn1_tag_info_no_override());
}

void n20_x509_ext_tcg_dice_ueid_content(n20_stream_t *const s, void *context) {
    if (NULL == context) {
        return;
    }

    n20_asn1_sequence(
        s, n20_x509_ext_tcg_dice_ueid_sequence_content, context, n20_asn1_tag_info_no_override());
}
