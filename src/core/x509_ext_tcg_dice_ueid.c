/*
 * Copyright 2025 Aurora Operations, Inc.
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
