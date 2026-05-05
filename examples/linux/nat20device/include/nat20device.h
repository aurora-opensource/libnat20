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

#pragma once

#include <linux/module.h>
#include <linux/types.h>

struct nat20device_driver {};

/**
 * struct nat20device_buffer - Buffer for dispatch function response
 * @data: Pointer to buffer data
 * @size: Size of the buffer in bytes
 */
struct nat20device_buffer {
    void* data;
    size_t size;
};

/**
 * typedef nat20device_dispatch_fn - Dispatch function callback
 * @ctx: Driver-specific context
 * @request: Request buffer from userspace
 * @request_len: Length of request buffer
 * @response: Pointer to response buffer (allocated by driver)
 *
 * The dispatch function processes a request and returns a response buffer.
 * The driver must allocate the response buffer, which will be freed by
 * the framework using kfree after the read operation completes,
 * on the next write if the buffer has not been read yet, or when the file is closed.
 *
 * The framework serializes calls per open file descriptor. However, if the
 * device is opened multiple times, dispatch may be called concurrently with
 * the same @ctx from different file descriptors. The implementer must protect
 * shared state in @ctx against concurrent access.
 *
 * Return: 0 on success, negative error code on failure
 */
typedef int (*nat20device_dispatch_fn)(void* ctx,
                                       void const* request,
                                       size_t request_len,
                                       struct nat20device_buffer* response);

/**
 * typedef nat20device_dice_chain_read - DICE chain read function callback
 * @ctx: Driver-specific context
 * @buf: User-space buffer to read DICE chain data into
 * @len: Length of the buffer
 * @f_pos: File position offset
 *
 * Reads the DICE certificate chain into the provided user-space buffer.
 * The data is encoded as a CBOR indefinite-length array. See
 * examples/linux/README.md for the encoding specification.
 *
 * This function may be called concurrently from multiple readers via the
 * securityfs interface. The implementer must ensure that concurrent access
 * to the underlying data is safe.
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
typedef ssize_t (*nat20device_dice_chain_read)(void* ctx,
                                               char __user* buf,
                                               size_t len,
                                               loff_t* f_pos);

/**
 * struct nat20device_driver_ops - Driver operations
 * @dispatch: Dispatch function for handling requests
 * @dice_chain_read: DICE chain read function for reading the boot certificate chain
 */
struct nat20device_driver_ops {
    nat20device_dispatch_fn dispatch;
    nat20device_dice_chain_read dice_chain_read;
};

/**
 * nat20device_register_driver - Register a new NAT20 driver instance
 * @ops: Driver operations structure
 * @ctx: Driver-specific context
 * @owner: Module owner (usually THIS_MODULE). This is used to manage module
 * 	  reference counting for the driver instance. Blocks the removal
 *    of the module while a device node remains open.
 *
 * Registers a new driver instance and creates a character device node
 * with the name "nat20X" where X is an automatically assigned number.
 *
 * Return: Pointer to registered driver on success, ERR_PTR on failure
 */
struct nat20device_driver* nat20device_register_driver(const struct nat20device_driver_ops* ops,
                                                       void* ctx,
                                                       struct module* owner);

/**
 * nat20device_unregister_driver - Unregister a NAT20 driver instance
 * @driver: Driver instance to unregister
 *
 * Unregisters a driver instance and removes its character device node.
 *
 * IMPORTANT:
 * This function must only be called from the registering module's exit
 * function. The file_operations.owner field is set to the registering
 * module, causing the kernel to hold a module reference for each open
 * file descriptor. This guarantees that module unload (and thus this
 * function) cannot execute while any file descriptor is still open.
 * Calling this function from any other context voids this guarantee
 * and results in undefined behavior.
 */
void nat20device_unregister_driver(struct nat20device_driver* driver);
