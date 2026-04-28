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

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <nat20/cbor.h>
#include <nat20/crypto.h>
#include <nat20/service/gnostic.h>
#include <nat20/service/service_message_dispatch.h>
#include <nat20crypto.h>
#include <nat20device.h>

struct nat20sw_node_state {
    n20_gnostic_node_state_t gnostic_node_state;
    struct mutex dispatch_lock;
    u8* cached_dice_chain;
    size_t cached_dice_chain_size;
};

static void nat20sw_cleanup_gnostic_node(struct nat20sw_node_state* node_state) {
    if (node_state == NULL) {
        return;
    }

    mutex_destroy(&node_state->dispatch_lock);

    if (node_state->gnostic_node_state.min_cdi != NULL) {
        if (node_state->gnostic_node_state.crypto_context != NULL) {
            node_state->gnostic_node_state.crypto_context->key_free(
                node_state->gnostic_node_state.crypto_context,
                node_state->gnostic_node_state.min_cdi);
        } else {
            printk(
                KERN_WARNING
                "Gnostic node state has min_cdi but no crypto context potential resource leak.\n");
        }
        node_state->gnostic_node_state.min_cdi = NULL;
    }

    if (node_state->gnostic_node_state.crypto_context != NULL) {
        nat20crypto_close(node_state->gnostic_node_state.crypto_context);
        node_state->gnostic_node_state.crypto_context = NULL;
    }

    if (node_state->cached_dice_chain != NULL) {
        kfree(node_state->cached_dice_chain);
        node_state->cached_dice_chain = NULL;
        node_state->cached_dice_chain_size = 0;
    }

    kfree(node_state);
}

static void nat20sw_render_dice_chain(n20_stream_t* stream, n20_slice_t certificate) {
    n20_stream_put(stream, 0xff);  // Terminator for CBOR indefinite length array
    n20_cbor_write_byte_string(stream, certificate);
    n20_cbor_write_tag(
        stream,
        80150);  // CBOR tag #6.80150 for byte string containing DER encoded X.509 certificate
    n20_stream_put(stream, 0x9f);  // Start of CBOR indefinite length array
}

static struct nat20sw_node_state* nat20sw_make_gnostic_node_with_linux_crypto(void) {
    int err;
    struct nat20sw_node_state* node_state = kzalloc(sizeof(struct nat20sw_node_state), GFP_KERNEL);
    if (node_state == NULL) {
        return ERR_PTR(-ENOMEM);
    }

    mutex_init(&node_state->dispatch_lock);

    /* Linux crypto context initialization. */
    n20_error_t rc = nat20crypto_open(&node_state->gnostic_node_state.crypto_context);
    if (rc != n20_error_ok_e || node_state->gnostic_node_state.crypto_context == NULL) {
        err = -ENOMEM;
        goto err_out;
    }

    n20_slice_t info = {.size = 18, .buffer = (uint8_t*)"example_info_value"};

    n20_slice_t salt = {.size = 18, .buffer = (uint8_t*)"example_salt_value"};

    n20_slice_t ikm = {.size = 22, .buffer = (uint8_t*)"example_uds_passphrase"};

    uint8_t uds[32] = {0};  // Example UDS passphrase buffer.

    rc = node_state->gnostic_node_state.crypto_context->digest_ctx.hkdf(
        &node_state->gnostic_node_state.crypto_context->digest_ctx,
        n20_crypto_digest_algorithm_sha2_256_e,
        ikm,
        salt,
        info,
        32,
        uds);
    if (rc != n20_error_ok_e) {
        err = -EINVAL;
        goto err_out;
    }

    n20_slice_t uds_slice = {.size = sizeof(uds), .buffer = uds};

    node_state->gnostic_node_state.min_cdi = NULL;

    rc = nat20crypto_make_secret(node_state->gnostic_node_state.crypto_context,
                                 &uds_slice,
                                 &node_state->gnostic_node_state.min_cdi);
    if (rc != n20_error_ok_e) {
        err = -EINVAL;
        goto err_out;
    }

    n20_open_dice_cert_info_t cert_info = {0};
    cert_info.cert_type = n20_cert_type_self_signed_e;
    size_t certificate_size = 0;
    /* Issue certificate to determine required buffer size. */
    rc = n20_issue_certificate(node_state->gnostic_node_state.crypto_context,
                               node_state->gnostic_node_state.min_cdi,
                               n20_crypto_key_type_secp256r1_e,
                               n20_crypto_key_type_secp256r1_e,
                               &cert_info,
                               n20_certificate_format_x509_e,
                               NULL,
                               &certificate_size);

    if (rc != n20_error_insufficient_buffer_size_e) {
        err = -EFAULT;
        goto err_out;
    }

    /* Allocate buffer for certificate. */
    uint8_t* certificate_buffer = kzalloc(certificate_size, GFP_KERNEL);
    if (certificate_buffer == NULL) {
        err = -ENOMEM;
        goto err_out;
    }

    size_t actual_certificate_size = certificate_size;
    /* Issue certificate with allocated buffer. */
    rc = n20_issue_certificate(node_state->gnostic_node_state.crypto_context,
                               node_state->gnostic_node_state.min_cdi,
                               n20_crypto_key_type_secp256r1_e,
                               n20_crypto_key_type_secp256r1_e,
                               &cert_info,
                               n20_certificate_format_x509_e,
                               certificate_buffer,
                               &certificate_size);
    if (rc != n20_error_ok_e) {
        kfree(certificate_buffer);
        err = -EFAULT;
        goto err_out;
    }
    if (certificate_size != actual_certificate_size) {
        printk(KERN_ERR
               "Certificate issuance returned success but actual certificate size %zu does not "
               "match previously computed expected size %zu.\n",
               certificate_size,
               actual_certificate_size);
        kfree(certificate_buffer);
        err = -EFAULT;
        goto err_out;
    }

    n20_stream_t stream;
    n20_stream_init(&stream, NULL, 0);
    /* Render dice chain with NULL buffer to measure size. */
    nat20sw_render_dice_chain(
        &stream, (n20_slice_t){.size = certificate_size, .buffer = certificate_buffer});
    if (n20_stream_has_write_position_overflow(&stream)) {
        kfree(certificate_buffer);
        err = -EFAULT;
        goto err_out;
    }

    /* Allocate buffer for cached dice chain. */
    node_state->cached_dice_chain = kzalloc(n20_stream_byte_count(&stream), GFP_KERNEL);
    if (node_state->cached_dice_chain == NULL) {
        kfree(certificate_buffer);
        err = -ENOMEM;
        goto err_out;
    }
    node_state->cached_dice_chain_size = n20_stream_byte_count(&stream);

    /* Render dice chain with actual buffer. */
    n20_stream_init(&stream, node_state->cached_dice_chain, node_state->cached_dice_chain_size);
    nat20sw_render_dice_chain(
        &stream, (n20_slice_t){.size = certificate_size, .buffer = certificate_buffer});

    /* Free temporary buffer unconditionally. */
    kfree(certificate_buffer);

    if (n20_stream_has_buffer_overflow(&stream)) {
        err = -EFAULT;
        goto err_out;
    }

    return node_state;

err_out:
    nat20sw_cleanup_gnostic_node(node_state);
    return ERR_PTR(err);
}

static ssize_t nat20sw_dice_chain_read(void* ctx, char __user* buf, size_t len, loff_t* f_pos) {
    struct nat20sw_node_state* node_state = (struct nat20sw_node_state*)ctx;
    if (node_state == NULL) {
        return -EINVAL;
    }

    if (*f_pos < 0) {
        return -EINVAL;
    }

    if (*f_pos >= node_state->cached_dice_chain_size) {
        return 0;
    }

    size_t bytes_to_read = min(len, node_state->cached_dice_chain_size - (size_t)(*f_pos));
    if (copy_to_user(buf, node_state->cached_dice_chain + (size_t)(*f_pos), bytes_to_read)) {
        return -EFAULT;
    }

    *f_pos += bytes_to_read;
    return bytes_to_read;
}

static struct nat20device_driver* nat20sw_registered_driver = NULL;
static struct nat20sw_node_state* nat20sw_node_state = NULL;

static int nat20sw_service_message_dispatch(void* ctx,
                                            void const* request_buffer,
                                            size_t request_size,
                                            struct nat20device_buffer* response) {
    struct nat20sw_node_state* node_state = (struct nat20sw_node_state*)ctx;
    if (node_state == NULL || response == NULL) {
        return -EINVAL;
    }

    if (response->data != NULL || response->size != 0) {
        return -EINVAL;
    }

    n20_service_message_dispatch_ctx_t dispatch_ctx = {
        .ops = &n20_gnostic_service_ops,
        .ctx = (void*)&node_state->gnostic_node_state,
    };

    /* Use a heuristic to estimate the initial response buffer size. */
    /* Heuristic: request size + overhead for CBOR encoding and response metadata */
    response->size = request_size + 384;
    response->data = kzalloc(response->size, GFP_KERNEL);
    if (response->data == NULL) {
        return -ENOMEM;
    }

    size_t actual_response_size = response->size;

    mutex_lock(&node_state->dispatch_lock);
    n20_error_t rc =
        n20_service_message_dispatch(&dispatch_ctx,
                                     response->data,
                                     &actual_response_size,
                                     (n20_slice_t){.size = request_size, .buffer = request_buffer});
    mutex_unlock(&node_state->dispatch_lock);

    if (rc == n20_error_insufficient_buffer_size_e) {
        /* Slow path: The heuristic yielded an insufficient buffer size. */
        printk(KERN_INFO
               "Service message dispatch returned insufficient buffer size. Heuristic buffer size "
               "%zu, actual response size %zu. Retrying with actual response size.\n",
               response->size,
               actual_response_size);
        kfree(response->data);
        response->size = 0;
        response->data = kzalloc(actual_response_size, GFP_KERNEL);
        if (response->data == NULL) {
            return -ENOMEM;
        }
        response->size = actual_response_size;
        mutex_lock(&node_state->dispatch_lock);
        rc = n20_service_message_dispatch(
            &dispatch_ctx,
            response->data,
            &actual_response_size,
            (n20_slice_t){.size = request_size, .buffer = request_buffer});
        mutex_unlock(&node_state->dispatch_lock);
        if (rc == n20_error_ok_e && actual_response_size > response->size) {
            /* The actual response exceeds the estimated buffer size.
             * This indicates a bug in the size estimation. */
            printk(KERN_ERR
                   "Service message dispatch returned success but actual response size %zu "
                   "exceeds estimated buffer size %zu.\n",
                   actual_response_size,
                   response->size);
            kfree(response->data);
            response->data = NULL;
            response->size = 0;
            return -EFAULT;
        }
    }

    if (rc != n20_error_ok_e) {
        kfree(response->data);
        response->data = NULL;
        response->size = 0;
        return -EFAULT;
    }

    memmove(response->data,
            response->data + (response->size - actual_response_size),
            actual_response_size);
    response->size = actual_response_size;

    return 0;
}

static struct nat20device_driver_ops const nat20sw_driver_ops = {
    .dispatch = nat20sw_service_message_dispatch,
    .dice_chain_read = nat20sw_dice_chain_read,
};

static int __init nat20sw_init(void) {
    printk(KERN_INFO "nat20sw - init\n");

    nat20sw_node_state = nat20sw_make_gnostic_node_with_linux_crypto();
    if (IS_ERR(nat20sw_node_state)) {
        return PTR_ERR(nat20sw_node_state);
    }

    nat20sw_registered_driver =
        nat20device_register_driver(&nat20sw_driver_ops, nat20sw_node_state, THIS_MODULE);
    if (IS_ERR(nat20sw_registered_driver)) {
        nat20sw_cleanup_gnostic_node(nat20sw_node_state);
        nat20sw_node_state = NULL;
        return PTR_ERR(nat20sw_registered_driver);
    }
    return 0;
}

static void __exit nat20sw_exit(void) {
    printk(KERN_INFO "nat20sw - cleanup\n");

    if (nat20sw_node_state != NULL) {
        nat20device_unregister_driver(nat20sw_registered_driver);
        nat20sw_registered_driver = NULL;

        nat20sw_cleanup_gnostic_node(nat20sw_node_state);
        nat20sw_node_state = NULL;
    }
}

module_init(nat20sw_init);
module_exit(nat20sw_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Aurora Operations, Inc.");
MODULE_DESCRIPTION("NAT20 DICE Software Module");
