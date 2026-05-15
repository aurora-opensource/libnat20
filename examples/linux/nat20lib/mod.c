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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <nat20/cbor.h>
#include <nat20/cose.h>
#include <nat20/crypto/nat20/crypto.h>
#include <nat20/crypto/nat20/rfc6979.h>
#include <nat20/cwt.h>
#include <nat20/functionality.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/service_message_dispatch.h>

static int __init nat20lib_init(void) {
    printk(KERN_INFO "nat20lib - init\n");
    return 0;
}

static void __exit nat20lib_exit(void) { printk(KERN_INFO "nat20lib - cleanup\n"); }

EXPORT_SYMBOL(n20_cbor_read_header);
EXPORT_SYMBOL(n20_cbor_read_skip_item);
EXPORT_SYMBOL(n20_cbor_write_byte_string);
EXPORT_SYMBOL(n20_cbor_write_int);
EXPORT_SYMBOL(n20_cbor_write_map_header);
EXPORT_SYMBOL(n20_cbor_write_null);
EXPORT_SYMBOL(n20_cbor_write_tag);
EXPORT_SYMBOL(n20_cbor_write_text_string);
EXPORT_SYMBOL(n20_cbor_write_header);
EXPORT_SYMBOL(n20_compress_input);
EXPORT_SYMBOL(n20_cose_get_signature_size);
EXPORT_SYMBOL(n20_cose_render_sign1_with_payload);
EXPORT_SYMBOL(n20_cose_write_key);
EXPORT_SYMBOL(n20_cwt_key_info_to_cose);
EXPORT_SYMBOL(n20_gnostic_service_ops);
EXPORT_SYMBOL(n20_hmac);
EXPORT_SYMBOL(n20_hkdf);
EXPORT_SYMBOL(n20_hkdf_expand);
EXPORT_SYMBOL(n20_hkdf_extract);
EXPORT_SYMBOL(n20_issue_certificate);
EXPORT_SYMBOL(n20_istream_get_slice);
EXPORT_SYMBOL(n20_istream_get_string_slice);
EXPORT_SYMBOL(n20_istream_has_buffer_underrun);
EXPORT_SYMBOL(n20_istream_init);
EXPORT_SYMBOL(n20_istream_read_position);
EXPORT_SYMBOL(n20_open_dice_cdi_id);
EXPORT_SYMBOL(n20_open_dice_cwt_write);
EXPORT_SYMBOL(n20_rfc6979_k_generation);
EXPORT_SYMBOL(n20_service_message_dispatch);
EXPORT_SYMBOL(n20_stream_byte_count);
EXPORT_SYMBOL(n20_stream_has_buffer_overflow);
EXPORT_SYMBOL(n20_stream_has_write_position_overflow);
EXPORT_SYMBOL(n20_stream_init);
EXPORT_SYMBOL(n20_stream_prepend);
EXPORT_SYMBOL(n20_stream_put);
EXPORT_SYMBOL(n20_stream_skip);

module_init(nat20lib_init);
module_exit(nat20lib_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Aurora Operations, Inc.");
MODULE_DESCRIPTION("NAT20 Library Module");
