// SPDX-License-Identifier: GPL-2.0
/*
 * cryptorecovery: driver for the QEMU "pcie-cryptorecovery" device.
 *
 * The recovery key never passes through this driver: the storage device
 * fetches it over its own link (recovery Option B). The guest can only see
 * the device's status and arm or disarm it, so that recovery needs an
 * explicit guest action (in addition to the host presence event, R2).
 *
 *   /dev/cryptorecoveryN    root only: status, arm, disarm
 */
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "cryptostore_regs.h"
#include "cryptostore_ioctl.h"

#define DRV_NAME        "cryptorecovery"
#define CR_MAX_DEVS     4

static dev_t cr_devt;
static DEFINE_IDA(cr_ida);

static char *cr_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0600;
	return NULL;
}

static const struct class cr_class = {
	.name = DRV_NAME,
	.devnode = cr_devnode,
};

struct cr_dev {
	struct pci_dev *pdev;
	void __iomem *regs;
	int minor;
	struct device dev;
	struct cdev cdev;
	struct mutex lock;
	bool removed;
};

static int cr_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev, struct cr_dev, cdev);
	return 0;
}

static long cr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cr_dev *rd = file->private_data;
	void __user *argp = (void __user *)arg;
	struct cryptorecovery_status st = { .abi_version = CRYPTOSTORE_ABI_VERSION };
	struct cryptorecovery_cmd c = { 0 };
	int i;

	mutex_lock(&rd->lock);
	if (rd->removed) {
		mutex_unlock(&rd->lock);
		return -ENODEV;
	}
	switch (cmd) {
	case CRYPTORECOVERY_IOC_STATUS:
		st.status = ioread32(rd->regs + CR_REG_STATUS);
		st.last_result = ioread32(rd->regs + CR_REG_RESULT);
		for (i = 0; i < 4; i++) {
			u32 w = ioread32(rd->regs + CR_REG_UUID0 + 4 * i);

			memcpy(st.bound_uuid + 4 * i, &w, 4);
		}
		strscpy(st.pci_name, pci_name(rd->pdev), sizeof(st.pci_name));
		mutex_unlock(&rd->lock);
		return copy_to_user(argp, &st, sizeof(st)) ? -EFAULT : 0;
	case CRYPTORECOVERY_IOC_ARM:
	case CRYPTORECOVERY_IOC_DISARM:
		if (!capable(CAP_SYS_ADMIN)) {
			mutex_unlock(&rd->lock);
			return -EPERM;
		}
		iowrite32(cmd == CRYPTORECOVERY_IOC_ARM ? CR_CMD_ARM : CR_CMD_DISARM,
			  rd->regs + CR_REG_CMD);
		c.result = ioread32(rd->regs + CR_REG_RESULT);	/* completes immediately */
		mutex_unlock(&rd->lock);
		return copy_to_user(argp, &c, sizeof(c)) ? -EFAULT : 0;
	default:
		mutex_unlock(&rd->lock);
		return -ENOTTY;
	}
}

static const struct file_operations cr_fops = {
	.owner		= THIS_MODULE,
	.open		= cr_open,
	.unlocked_ioctl	= cr_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.llseek		= noop_llseek,
};

static void cr_release(struct device *dev)
{
	struct cr_dev *rd = container_of(dev, struct cr_dev, dev);

	ida_free(&cr_ida, rd->minor);
	kfree(rd);
}

static int cr_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct cr_dev *rd;
	u32 magic;
	int ret;

	rd = kzalloc(sizeof(*rd), GFP_KERNEL);
	if (!rd)
		return -ENOMEM;
	rd->pdev = pdev;
	mutex_init(&rd->lock);

	ret = pci_enable_device(pdev);
	if (ret)
		goto err_free;
	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		goto err_disable;
	rd->regs = pci_iomap(pdev, 0, CR_BAR0_SIZE);
	if (!rd->regs) {
		ret = -ENOMEM;
		goto err_release;
	}
	magic = ioread32(rd->regs + CR_REG_ID);
	if (magic != CR_MAGIC) {
		dev_err(&pdev->dev, "bad ID register 0x%08x\n", magic);
		ret = -ENODEV;
		goto err_unmap;
	}
	ret = ida_alloc_max(&cr_ida, CR_MAX_DEVS - 1, GFP_KERNEL);
	if (ret < 0)
		goto err_unmap;
	rd->minor = ret;

	device_initialize(&rd->dev);
	rd->dev.class = &cr_class;
	rd->dev.parent = &pdev->dev;
	rd->dev.devt = MKDEV(MAJOR(cr_devt), rd->minor);
	rd->dev.release = cr_release;
	ret = dev_set_name(&rd->dev, DRV_NAME "%d", rd->minor);
	if (ret)
		goto err_put;
	cdev_init(&rd->cdev, &cr_fops);
	rd->cdev.owner = THIS_MODULE;
	pci_set_drvdata(pdev, rd);
	ret = cdev_device_add(&rd->cdev, &rd->dev);
	if (ret)
		goto err_put;
	dev_info(&pdev->dev, "%s: pcie-cryptorecovery, key %s\n", dev_name(&rd->dev),
		 ioread32(rd->regs + CR_REG_STATUS) & CR_STATUS_KEY_PRESENT ? "present" : "absent");
	return 0;

err_put:
	pci_iounmap(pdev, rd->regs);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	put_device(&rd->dev);
	return ret;
err_unmap:
	pci_iounmap(pdev, rd->regs);
err_release:
	pci_release_regions(pdev);
err_disable:
	pci_disable_device(pdev);
err_free:
	kfree(rd);
	return ret;
}

static void cr_remove(struct pci_dev *pdev)
{
	struct cr_dev *rd = pci_get_drvdata(pdev);

	mutex_lock(&rd->lock);
	rd->removed = true;
	mutex_unlock(&rd->lock);
	cdev_device_del(&rd->cdev, &rd->dev);
	pci_iounmap(pdev, rd->regs);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	put_device(&rd->dev);
}

static const struct pci_device_id cr_ids[] = {
	{ PCI_DEVICE(CR_VENDOR_ID, CR_DEVICE_ID) },
	{ }
};
MODULE_DEVICE_TABLE(pci, cr_ids);

static struct pci_driver cr_driver = {
	.name		= DRV_NAME,
	.id_table	= cr_ids,
	.probe		= cr_probe,
	.remove		= cr_remove,
};

static int __init cr_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&cr_devt, 0, CR_MAX_DEVS, DRV_NAME);
	if (ret)
		return ret;
	ret = class_register(&cr_class);
	if (ret)
		goto err_chr;
	ret = pci_register_driver(&cr_driver);
	if (ret)
		goto err_class;
	return 0;
err_class:
	class_unregister(&cr_class);
err_chr:
	unregister_chrdev_region(cr_devt, CR_MAX_DEVS);
	return ret;
}

static void __exit cr_exit(void)
{
	pci_unregister_driver(&cr_driver);
	class_unregister(&cr_class);
	unregister_chrdev_region(cr_devt, CR_MAX_DEVS);
}

module_init(cr_init);
module_exit(cr_exit);

MODULE_DESCRIPTION("Driver for the QEMU pcie-cryptorecovery device");
MODULE_LICENSE("GPL");
