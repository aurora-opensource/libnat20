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

#include "nat20device.h"

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define NAT20DEVICE_DEVICE_NAME "nat20"
#define NAT20DEVICE_MAX_INSTANCES 256
#define NAT20DEVICE_MAX_REQUEST_SIZE (1024 * 1024) /* 1 MB max request */

/**
 * struct nat20device_driver_instance - Internal driver instance data
 * @driver: Embedded driver structure (returned as opaque handle to callers)
 * @cdev: Character device structure
 * @device: Device structure for /dev/nat20<N>
 * @ops: Driver operations (dispatch and dice_chain_read callbacks)
 * @cdev_fops: File operations for the character device
 * @dice_chain_fops: File operations for the DICE chain securityfs file
 * @ctx: Driver-specific context passed to ops callbacks
 * @id: Instance ID (minor number and securityfs directory suffix)
 * @nat20device_dice_chain_dir: Securityfs directory dentry, or NULL
 * @nat20device_dice_chain_file: Securityfs dice_chain file dentry, or NULL
 */
struct nat20device_driver_instance {
    struct nat20device_driver driver;
    struct cdev cdev;
    struct device* device;
    const struct nat20device_driver_ops* ops;
    struct file_operations cdev_fops;
    struct file_operations dice_chain_fops;
    void* ctx;
    int id;
    struct dentry* nat20device_dice_chain_dir;
    struct dentry* nat20device_dice_chain_file;
};

/**
 * struct nat20device_file_private - Per-file-descriptor state
 * @instance: Back-pointer to the owning driver instance
 * @lock: Protects @response against concurrent read/write
 * @response: Response buffer from the most recent dispatch, or empty
 */
struct nat20device_file_private {
    struct nat20device_driver_instance* instance;
    struct mutex lock;
    struct nat20device_buffer response;
};

static dev_t nat20device_dev_number;
static struct class* nat20device_class;
static DEFINE_IDA(nat20device_ida);

#define to_nat20device_instance(drv) container_of(drv, struct nat20device_driver_instance, driver)

/**
 * nat20device_open - Open file operation
 */
static int nat20device_open(struct inode* inode, struct file* filp) {
    struct nat20device_driver_instance* instance;
    instance = container_of(inode->i_cdev, struct nat20device_driver_instance, cdev);
    struct nat20device_file_private* file_priv = kzalloc(sizeof(*file_priv), GFP_KERNEL);
    if (!file_priv) return -ENOMEM;

    file_priv->instance = instance;
    mutex_init(&file_priv->lock);
    filp->private_data = file_priv;
    return 0;
}

/**
 * nat20device_release - Release file operation
 */
static int nat20device_release(struct inode* inode, struct file* filp) {
    (void)inode;
    struct nat20device_file_private* file_priv = filp->private_data;

    mutex_destroy(&file_priv->lock);
    kfree(file_priv->response.data);
    kfree(file_priv);
    filp->private_data = NULL;

    return 0;
}

/**
 * nat20device_write - Write file operation
 *
 * Copies a request from userspace, frees any unconsumed prior response,
 * dispatches the request to the driver, and resets the file position to 0
 * so that the response can be read back.
 */
static ssize_t nat20device_write(struct file* filp,
                                 char __user const* buf,
                                 size_t count,
                                 loff_t* f_pos) {
    struct nat20device_file_private* file_priv = filp->private_data;
    struct nat20device_driver_instance* instance = file_priv->instance;
    void* request_buf;
    int ret;

    if (count == 0) return 0;

    if (count > NAT20DEVICE_MAX_REQUEST_SIZE) return -EINVAL;

    /* Allocate request buffer */
    request_buf = kmalloc(count, GFP_KERNEL);
    if (!request_buf) return -ENOMEM;

    /* Copy request from userspace */
    if (copy_from_user(request_buf, buf, count)) {
        kfree(request_buf);
        return -EFAULT;
    }

    mutex_lock(&file_priv->lock);

    /* Free any previous response buffer */
    kfree(file_priv->response.data);
    file_priv->response.data = NULL;
    file_priv->response.size = 0;

    /* Dispatch the request */
    ret = instance->ops->dispatch(instance->ctx, request_buf, count, &file_priv->response);
    if (ret < 0) goto out;

    /* Reset file position so that a subsequent read starts at offset 0. */
    *f_pos = 0;

    ret = count;

out:
    mutex_unlock(&file_priv->lock);
    kfree(request_buf);
    return ret;
}

/**
 * nat20device_read - Read file operation
 *
 * Returns the current response buffer to userspace. Once the entire
 * response has been read, the buffer is freed and subsequent reads
 * return -EAGAIN until a new request is dispatched via write.
 */
static ssize_t nat20device_read(struct file* filp, char __user* buf, size_t count, loff_t* f_pos) {
    struct nat20device_file_private* file_priv = filp->private_data;
    size_t bytes_to_read;
    size_t bytes_remaining;
    ssize_t ret;

    if (*f_pos < 0) return -EINVAL;

    mutex_lock(&file_priv->lock);

    /* Check if we have a response buffer */
    if (!file_priv->response.data) {
        ret = -EAGAIN;
        goto out;
    }

    /* Calculate bytes remaining from current offset */
    if (file_priv->response.size <= *f_pos) {
        ret = 0;
        goto out;
    }
    bytes_remaining = file_priv->response.size - *f_pos;

    /* Read up to count bytes */
    bytes_to_read = min(count, bytes_remaining);

    /* Copy to userspace */
    if (copy_to_user(buf, (char*)file_priv->response.data + *f_pos, bytes_to_read)) {
        ret = -EFAULT;
        goto out;
    }

    /* Update offset */
    *f_pos += bytes_to_read;

    /* Response fully consumed — free it so subsequent reads
     * return -EAGAIN until the next write/dispatch cycle. */
    if (*f_pos >= file_priv->response.size) {
        kfree(file_priv->response.data);
        file_priv->response.data = NULL;
        file_priv->response.size = 0;
    }

    ret = bytes_to_read;

out:
    mutex_unlock(&file_priv->lock);
    return ret;
}

static int nat20device_dice_chain_fops_open(struct inode* inode, struct file* filp) {
    filp->private_data = inode->i_private;
    return 0;
}

static int nat20device_dice_chain_fops_release(struct inode* inode, struct file* filp) {
    (void)inode;
    filp->private_data = NULL;
    return 0;
}

static ssize_t nat20device_dice_chain_fops_read(struct file* filp,
                                                char __user* buf,
                                                size_t len,
                                                loff_t* f_pos) {
    struct nat20device_driver_instance* instance = filp->private_data;
    if (!instance->ops || !instance->ops->dice_chain_read) {
        return -ENODEV;
    }
    return instance->ops->dice_chain_read(instance->ctx, buf, len, f_pos);
}

/**
 * nat20device_register_driver - Register a new NAT20 driver instance
 */
struct nat20device_driver* nat20device_register_driver(const struct nat20device_driver_ops* ops,
                                                       void* ctx,
                                                       struct module* owner) {
    struct nat20device_driver_instance* instance;
    int ret;
    int id;

    if (!ops || !ops->dispatch) return ERR_PTR(-EINVAL);

    /* Allocate instance */
    instance = kzalloc(sizeof(*instance), GFP_KERNEL);
    if (!instance) return ERR_PTR(-ENOMEM);

    /* Allocate ID */
    ret = ida_alloc(&nat20device_ida, GFP_KERNEL);
    if (ret < 0) goto err_free_instance;
    id = ret;

    /* Initialize instance */
    instance->ops = ops;
    instance->ctx = ctx;
    instance->id = id;
    instance->cdev_fops.owner = owner;
    instance->cdev_fops.open = nat20device_open;
    instance->cdev_fops.release = nat20device_release;
    instance->cdev_fops.write = nat20device_write;
    instance->cdev_fops.read = nat20device_read;
    instance->dice_chain_fops.owner = owner;
    instance->dice_chain_fops.open = nat20device_dice_chain_fops_open;
    instance->dice_chain_fops.release = nat20device_dice_chain_fops_release;
    instance->dice_chain_fops.read = nat20device_dice_chain_fops_read;

    /* Initialize character device */
    cdev_init(&instance->cdev, &instance->cdev_fops);
    instance->cdev.owner = owner;

    /* Add character device */
    ret = cdev_add(&instance->cdev, nat20device_dev_number + id, 1);
    if (ret) goto err_free_id;

    /* Create device node */
    instance->device = device_create(nat20device_class,
                                     NULL,
                                     nat20device_dev_number + id,
                                     NULL,
                                     NAT20DEVICE_DEVICE_NAME "%d",
                                     id);
    if (IS_ERR(instance->device)) {
        ret = PTR_ERR(instance->device);
        goto err_del_cdev;
    }

    if (ops->dice_chain_read) {
        char dir_name[32];
        snprintf(dir_name, sizeof(dir_name), NAT20DEVICE_DEVICE_NAME "%d", id);
        instance->nat20device_dice_chain_dir = securityfs_create_dir(dir_name, NULL);
        if (IS_ERR(instance->nat20device_dice_chain_dir)) {
            ret = PTR_ERR(instance->nat20device_dice_chain_dir);
            goto err_destroy_device;
        }

        instance->nat20device_dice_chain_file =
            securityfs_create_file("dice_chain",
                                   0444,
                                   instance->nat20device_dice_chain_dir,
                                   instance,
                                   &instance->dice_chain_fops);
        if (IS_ERR(instance->nat20device_dice_chain_file)) {
            ret = PTR_ERR(instance->nat20device_dice_chain_file);
            goto err_destroy_dice_chain_dir;
        }
    }

    pr_info("NAT20: Registered driver instance %s%d\n", NAT20DEVICE_DEVICE_NAME, id);

    return &instance->driver;

err_destroy_dice_chain_dir:
    securityfs_remove(instance->nat20device_dice_chain_dir);
err_destroy_device:
    device_destroy(nat20device_class, nat20device_dev_number + id);
err_del_cdev:
    cdev_del(&instance->cdev);
err_free_id:
    ida_free(&nat20device_ida, id);
err_free_instance:
    kfree(instance);
    return ERR_PTR(ret);
}
EXPORT_SYMBOL(nat20device_register_driver);

/**
 * nat20device_unregister_driver - Unregister a NAT20 driver instance
 */
void nat20device_unregister_driver(struct nat20device_driver* driver) {
    struct nat20device_driver_instance* instance;

    if (!driver) return;

    instance = to_nat20device_instance(driver);

    pr_info("NAT20: Unregistering driver instance %s%d\n", NAT20DEVICE_DEVICE_NAME, instance->id);

    if (instance->nat20device_dice_chain_file) {
        securityfs_remove(instance->nat20device_dice_chain_file);
    }
    if (instance->nat20device_dice_chain_dir) {
        securityfs_remove(instance->nat20device_dice_chain_dir);
    }

    /* Remove device node */
    device_destroy(nat20device_class, nat20device_dev_number + instance->id);

    /* Remove character device */
    cdev_del(&instance->cdev);

    /* Free ID */
    ida_free(&nat20device_ida, instance->id);

    /* Free instance */
    kfree(instance);
}
EXPORT_SYMBOL(nat20device_unregister_driver);

static int __init nat20device_device_init(void) {
    int ret;

    /* Allocate device numbers */
    ret = alloc_chrdev_region(
        &nat20device_dev_number, 0, NAT20DEVICE_MAX_INSTANCES, NAT20DEVICE_DEVICE_NAME);
    if (ret < 0) {
        pr_err("NAT20: Failed to allocate device numbers: %d\n", ret);
        return ret;
    }

    /* Create device class */
#if defined(class_create)
    nat20device_class = class_create(THIS_MODULE, NAT20DEVICE_DEVICE_NAME);
#else
    nat20device_class = class_create(NAT20DEVICE_DEVICE_NAME);
#endif

    if (IS_ERR(nat20device_class)) {
        ret = PTR_ERR(nat20device_class);
        pr_err("NAT20: Failed to create device class: %d\n", ret);
        goto err_unregister_chrdev;
    }

    pr_info("NAT20: Device framework initialized\n");
    return 0;

err_unregister_chrdev:
    unregister_chrdev_region(nat20device_dev_number, NAT20DEVICE_MAX_INSTANCES);
    return ret;
}

static void __exit nat20device_device_exit(void) {
    /* Destroy device class */
    class_destroy(nat20device_class);

    /* Unregister device numbers */
    unregister_chrdev_region(nat20device_dev_number, NAT20DEVICE_MAX_INSTANCES);

    pr_info("NAT20: Device framework exited\n");
}

module_init(nat20device_device_init);
module_exit(nat20device_device_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Aurora Operations, Inc.");
MODULE_DESCRIPTION("NAT20 device driver framework");
