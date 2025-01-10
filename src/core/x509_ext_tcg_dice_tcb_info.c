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
#include <nat20/x509.h>
#include <nat20/x509_ext_tcg_dice_tcb_info.h>

static void n20_x509_tcg_dice_tcb_info_fwid_content(n20_asn1_stream_t *const s, void *context) {
    n20_x509_ext_tcg_dice_tcb_info_fwid_t const *const fwid =
        (n20_x509_ext_tcg_dice_tcb_info_fwid_t const *)context;

    // fwid is never NULL since it's always called from n20_x509_tcg_dice_tcb_info_fwid_list_content
    // with a valid pointer.

    // digest OCTET STRING
    n20_asn1_octetstring(s, &fwid->digest, n20_asn1_tag_info_no_override());

    // hashAlg OBJECT IDENTIFIER
    n20_asn1_object_identifier(s, &fwid->hash_algo, n20_asn1_tag_info_no_override());
}

static void n20_x509_tcg_dice_tcb_info_fwid_list_content(n20_asn1_stream_t *const s,
                                                         void *context) {
    n20_x509_ext_tcg_dice_tcb_info_fwid_list_t const *const fwid_list =
        (n20_x509_ext_tcg_dice_tcb_info_fwid_list_t const *)context;

    // fwid_list is never NULL since it's always called from
    // n20_x509_ext_tcg_dice_tcb_info_sequence_content with a valid pointer. Additionally,
    // fwid_list->list isn't NULL since it was checked in
    // n20_x509_ext_tcg_dice_tcb_info_sequence_content.
    for (size_t count = fwid_list->count; count != 0; --count) {
        n20_asn1_sequence(s,
                          n20_x509_tcg_dice_tcb_info_fwid_content,
                          (void *)&fwid_list->list[count - 1],
                          n20_asn1_tag_info_no_override());
    }
}

static void n20_x509_ext_tcg_dice_tcb_info_sequence_content(n20_asn1_stream_t *const s,
                                                            void *context) {
    n20_x509_ext_tcg_dice_tcb_info_t const *tcg_dice_tcb_info = context;

    // tcg_dice_tcb_info is never null since it's checked by n20_x509_ext_tcg_dice_tcb_info_content.

    // flagsMask [10] IMPLICIT OperationalFlagsMask OPTIONAL
    n20_asn1_bitstring(s,
                       tcg_dice_tcb_info->flags_mask.operational_flags_mask,
                       8 * sizeof(tcg_dice_tcb_info->flags_mask.operational_flags_mask),
                       n20_asn1_tag_info_implicit(10));

    // type [9] IMPLICIT OCTET STRING OPTIONAL
    if (NULL != tcg_dice_tcb_info->type.buffer) {
        n20_asn1_octetstring(s, &tcg_dice_tcb_info->type, n20_asn1_tag_info_implicit(9));
    }

    // vendorInfo [8] IMPLICIT OCTET STRING OPTIONAL
    if (NULL != tcg_dice_tcb_info->vendor_info.buffer) {
        n20_asn1_octetstring(s, &tcg_dice_tcb_info->vendor_info, n20_asn1_tag_info_implicit(8));
    }

    // flags [7] IMPLICIT OperationalFlags OPTIONAL
    n20_asn1_bitstring(s,
                       tcg_dice_tcb_info->flags.operational_flags_mask,
                       8 * sizeof(tcg_dice_tcb_info->flags.operational_flags_mask),
                       n20_asn1_tag_info_implicit(7));

    // fwids [6] IMPLICIT FWIDLIST OPTIONAL
    if (NULL != tcg_dice_tcb_info->fwids.list) {
        n20_asn1_sequence(s,
                          n20_x509_tcg_dice_tcb_info_fwid_list_content,
                          (void *)&tcg_dice_tcb_info->fwids,
                          n20_asn1_tag_info_implicit(6));
    }

    // index [5] IMPLICIT INTEGER OPTIONAL
    n20_asn1_int64(s, tcg_dice_tcb_info->index, n20_asn1_tag_info_implicit(5));

    // layer [4] IMPLICIT INTEGER OPTIONAL
    n20_asn1_int64(s, tcg_dice_tcb_info->layer, n20_asn1_tag_info_implicit(4));

    // svn [3] IMPLICIT INTEGER OPTIONAL
    n20_asn1_int64(s, tcg_dice_tcb_info->svn, n20_asn1_tag_info_implicit(3));

    // version [2] IMPLICIT UTF8String OPTIONAL
    if (NULL != tcg_dice_tcb_info->version) {
        n20_asn1_utf8_string(s, tcg_dice_tcb_info->version, n20_asn1_tag_info_implicit(2));
    }

    // model [1] IMPLICIT UTF8String OPTIONAL
    if (NULL != tcg_dice_tcb_info->model) {
        n20_asn1_utf8_string(s, tcg_dice_tcb_info->model, n20_asn1_tag_info_implicit(1));
    }

    // vendor [0] IMPLICIT UTF8String OPTIONAL
    if (NULL != tcg_dice_tcb_info->vendor) {
        n20_asn1_utf8_string(s, tcg_dice_tcb_info->vendor, n20_asn1_tag_info_implicit(0));
    }
}

void n20_x509_ext_tcg_dice_tcb_info_content(n20_asn1_stream_t *const s, void *context) {
    if (NULL == context) {
        return;
    }

    n20_asn1_sequence(s,
                      n20_x509_ext_tcg_dice_tcb_info_sequence_content,
                      context,
                      n20_asn1_tag_info_no_override());
}

static void n20_x509_ext_tcg_dice_multi_tcb_info_sequence_content(n20_asn1_stream_t *const s,
                                                                  void *context) {
    n20_x509_ext_tcg_dice_multi_tcb_info_t const *const tcg_dice_multi_tcb_info = context;

    // tcg_dice_multi_tcb_info is never NULL since it's checked by
    // n20_x509_ext_tcg_dice_multi_tcb_info_content.
    if (NULL == tcg_dice_multi_tcb_info->list) {
        return;
    }

    for (size_t count = tcg_dice_multi_tcb_info->count; count != 0; --count) {
        n20_x509_ext_tcg_dice_tcb_info_content(s,
                                               (void *)&tcg_dice_multi_tcb_info->list[count - 1]);
    }
}

void n20_x509_ext_tcg_dice_multi_tcb_info_content(n20_asn1_stream_t *const s, void *context) {
    if (NULL == context) {
        return;
    }

    n20_asn1_sequence(s,
                      n20_x509_ext_tcg_dice_multi_tcb_info_sequence_content,
                      context,
                      n20_asn1_tag_info_no_override());
}
