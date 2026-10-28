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

/* Differential-test harness: issue a CDI-type COSE certificate with the C
 * libnat20 + BoringSSL backend, using the same fixed inputs as the Rust
 * test suite, and print the certificate as hex. */

#include <nat20/crypto_bssl/crypto.h>
#include <nat20/error.h>
#include <nat20/functionality.h>
#include <nat20/open_dice.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    n20_crypto_context_t *ctx = NULL;
    n20_error_t err = n20_crypto_boringssl_open(&ctx);
    if (err != n20_error_ok_e) {
        fprintf(stderr, "open failed: %d\n", err);
        return 1;
    }

    uint8_t cdi_bytes[32];
    memset(cdi_bytes, 0x42, sizeof(cdi_bytes));
    n20_slice_t cdi_slice = {.size = sizeof(cdi_bytes), .buffer = cdi_bytes};
    n20_crypto_key_t cdi = NULL;
    err = n20_crypto_boringssl_make_secret(ctx, &cdi_slice, &cdi);
    if (err != n20_error_ok_e) {
        fprintf(stderr, "make_secret failed: %d\n", err);
        return 1;
    }

    static uint8_t code_hash[64];
    static uint8_t config_hash[64];
    static uint8_t authority_hash[64];
    static uint8_t hidden[32];
    memset(code_hash, 0x11, sizeof(code_hash));
    memset(config_hash, 0x22, sizeof(config_hash));
    memset(authority_hash, 0x33, sizeof(authority_hash));
    memset(hidden, 0x44, sizeof(hidden));
    static char const code_descriptor[] = "next stage v1.0";
    static char const config_descriptor[] = "boot config";
    static char const profile[] = "example.dice.profile";

    n20_open_dice_cert_info_t cert_info;

    for (int query = 1; query >= 0; --query) {
        memset(&cert_info, 0, sizeof(cert_info));
        cert_info.cert_type = n20_cert_type_cdi_e;
        cert_info.open_dice_input.code_hash =
            (n20_slice_t){.size = sizeof(code_hash), .buffer = code_hash};
        cert_info.open_dice_input.code_descriptor = (n20_slice_t){
            .size = strlen(code_descriptor), .buffer = (uint8_t const *)code_descriptor};
        cert_info.open_dice_input.configuration_hash =
            (n20_slice_t){.size = sizeof(config_hash), .buffer = config_hash};
        cert_info.open_dice_input.configuration_descriptor = (n20_slice_t){
            .size = strlen(config_descriptor), .buffer = (uint8_t const *)config_descriptor};
        cert_info.open_dice_input.authority_hash =
            (n20_slice_t){.size = sizeof(authority_hash), .buffer = authority_hash};
        cert_info.open_dice_input.mode = n20_open_dice_mode_normal_e;
        cert_info.open_dice_input.profile_name =
            (n20_string_slice_t){.size = strlen(profile), .buffer = profile};
        cert_info.open_dice_input.hidden = (n20_slice_t){.size = sizeof(hidden), .buffer = hidden};

        static uint8_t *buf = NULL;
        static size_t size = 0;
        if (query) {
            err = n20_issue_certificate(ctx,
                                        cdi,
                                        n20_crypto_key_type_ed25519_e,
                                        n20_crypto_key_type_ed25519_e,
                                        &cert_info,
                                        n20_certificate_format_cose_e,
                                        NULL,
                                        &size);
            if (err != n20_error_insufficient_buffer_size_e) {
                fprintf(stderr, "size query failed: %d\n", err);
                return 1;
            }
            fprintf(stderr, "required size: %zu\n", size);
            buf = malloc(size);
        } else {
            err = n20_issue_certificate(ctx,
                                        cdi,
                                        n20_crypto_key_type_ed25519_e,
                                        n20_crypto_key_type_ed25519_e,
                                        &cert_info,
                                        n20_certificate_format_cose_e,
                                        buf,
                                        &size);
            if (err != n20_error_ok_e) {
                fprintf(stderr, "issue failed: %d\n", err);
                return 1;
            }
            for (size_t i = 0; i < size; ++i) {
                printf("%02x", buf[i]);
            }
            printf("\n");
        }
    }
    return 0;
}
