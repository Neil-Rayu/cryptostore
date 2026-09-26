// SPDX-License-Identifier: GPL-2.0
/*
 * pcie_hello: driver for the QEMU "pcie-hello" PCI Express endpoint.
 *
 * Each bound device gets a character device /dev/pcie_helloN:
 *   read()/write()  access the device's message buffer
 *   ioctl()         info, scratch test, GREET and UPPER commands
 *
 * Commands complete via interrupt (MSI-X, falling back to MSI, then INTx).
 * All device access is serialized by a per-device mutex; a command that the
 * device does not complete within cmd_timeout_ms fails with -ETIMEDOUT.
 * Function Level Reset is handled through reset_prepare/reset_done.
 */
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "pcie_hello_regs.h"
#include "pcie_hello_ioctl.h"

#define DRV_NAME                "pcie_hello"
#define PCIE_HELLO_MAX_DEVS     16

static char *irq_mode = "auto";
module_param(irq_mode, charp, 0444);
MODULE_PARM_DESC(irq_mode, "Interrupt type: auto (MSI-X, MSI, INTx), msix, msi or intx");

static unsigned int cmd_timeout_ms = 1000;
module_param(cmd_timeout_ms, uint, 0644);
MODULE_PARM_DESC(cmd_timeout_ms, "Command completion timeout in milliseconds");

static dev_t pcie_hello_devt;
static DEFINE_IDA(pcie_hello_ida);

static const struct class pcie_hello_class = {
	.name = DRV_NAME,
};

struct pcie_hello {
	struct pci_dev *pdev;
	void __iomem *regs;
	u32 buf_size;

	/* Char device; hd->dev's refcount owns this structure. */
	struct device dev;
	struct cdev cdev;
	int minor;

	/* Serializes all device access. Held across a function reset. */
	struct mutex lock;
	bool removed;		/* driver unbound; fops return -ENODEV */
	bool broken;		/* device did not come back from reset */

	/* Interrupt state, protected by irq_lock */
	spinlock_t irq_lock;
	struct completion done;
	u32 irq_status;		/* INT_STATUS bits seen since last command */
	u64 irq_count;

	int irq;
	enum pcie_hello_irq_mode irq_type;
	char irq_name[32];

	/* Statistics, protected by lock */
	u64 cmd_count;
	u32 cmd_timeouts;
	u32 resets;
};

static const char *const irq_type_names[] = {
	[PCIE_HELLO_IRQ_NONE] = "none",
	[PCIE_HELLO_IRQ_INTX] = "INTx",
	[PCIE_HELLO_IRQ_MSI]  = "MSI",
	[PCIE_HELLO_IRQ_MSIX] = "MSI-X",
};

static inline u32 hello_rd(struct pcie_hello *hd, unsigned int reg)
{
	return ioread32(hd->regs + reg);
}

static inline void hello_wr(struct pcie_hello *hd, unsigned int reg, u32 val)
{
	iowrite32(val, hd->regs + reg);
}

static irqreturn_t pcie_hello_irq(int irq, void *data)
{
	struct pcie_hello *hd = data;
	u32 status;

	spin_lock(&hd->irq_lock);
	status = hello_rd(hd, PCIE_HELLO_REG_INT_STATUS);
	/* 0: not ours (shared INTx) or stale; ~0: device gone or in reset */
	if (!status || status == ~0u) {
		spin_unlock(&hd->irq_lock);
		return IRQ_NONE;
	}
	hello_wr(hd, PCIE_HELLO_REG_INT_ACK, status);
	/* Flush the posted ack so a level INTx deasserts before we return */
	hello_rd(hd, PCIE_HELLO_REG_INT_STATUS);

	hd->irq_status |= status;
	hd->irq_count++;
	complete(&hd->done);
	spin_unlock(&hd->irq_lock);

	return IRQ_HANDLED;
}

/* Returns 0, -ENODEV (unbound), -EIO (broken) or -EBUSY. Caller holds lock. */
static int pcie_hello_check(struct pcie_hello *hd)
{
	u32 status;

	lockdep_assert_held(&hd->lock);
	if (hd->removed)
		return -ENODEV;
	if (hd->broken)
		return -EIO;
	status = hello_rd(hd, PCIE_HELLO_REG_STATUS);
	if (status == ~0u)
		return -ENODEV;
	if (status & PCIE_HELLO_STATUS_BUSY)
		return -EBUSY;	/* e.g. still finishing a timed-out command */
	return 0;
}

static int pcie_hello_run_cmd(struct pcie_hello *hd, u32 cmd)
{
	long left;
	u32 status;
	int ret;

	ret = pcie_hello_check(hd);
	if (ret)
		return ret;

	/*
	 * Clear anything left over (e.g. the late completion of a command that
	 * timed out) under irq_lock, so the handler can only complete 'done'
	 * for bits the device raises for the command issued below.
	 */
	spin_lock_irq(&hd->irq_lock);
	hello_wr(hd, PCIE_HELLO_REG_INT_ACK, PCIE_HELLO_INT_ALL);
	hd->irq_status = 0;
	reinit_completion(&hd->done);
	spin_unlock_irq(&hd->irq_lock);

	hello_wr(hd, PCIE_HELLO_REG_CMD, cmd);

	left = wait_for_completion_killable_timeout(&hd->done,
					msecs_to_jiffies(cmd_timeout_ms));
	if (left < 0)
		return left;	/* fatal signal; device finishes on its own */
	if (left == 0) {
		hd->cmd_timeouts++;
		dev_warn(&hd->dev, "command 0x%x timed out after %u ms (STATUS 0x%x)\n",
			 cmd, cmd_timeout_ms, hello_rd(hd, PCIE_HELLO_REG_STATUS));
		return -ETIMEDOUT;
	}

	spin_lock_irq(&hd->irq_lock);
	status = hd->irq_status;
	spin_unlock_irq(&hd->irq_lock);

	if (status & PCIE_HELLO_INT_CMD_ERROR) {
		dev_warn(&hd->dev, "command 0x%x failed\n", cmd);
		return -EIO;
	}
	hd->cmd_count++;
	return 0;
}

/* Copy the valid part of the device buffer into msg. Caller holds lock. */
static void pcie_hello_read_msg(struct pcie_hello *hd, struct pcie_hello_msg *msg)
{
	u32 len = min(hello_rd(hd, PCIE_HELLO_REG_BUF_LEN), hd->buf_size);

	memset(msg, 0, sizeof(*msg));
	memcpy_fromio(msg->data, hd->regs + PCIE_HELLO_REG_BUF, len);
	msg->len = len;
}

/* ---- file operations ---- */

static int pcie_hello_open(struct inode *inode, struct file *file)
{
	/* The open cdev holds a reference on hd->dev, keeping hd alive. */
	file->private_data = container_of(inode->i_cdev, struct pcie_hello, cdev);
	return 0;
}

static ssize_t pcie_hello_read(struct file *file, char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct pcie_hello *hd = file->private_data;
	u8 kbuf[PCIE_HELLO_MSG_MAX];
	size_t n = 0;
	u32 len;
	int ret;

	if (mutex_lock_interruptible(&hd->lock))
		return -ERESTARTSYS;
	ret = pcie_hello_check(hd);
	if (!ret) {
		len = min(hello_rd(hd, PCIE_HELLO_REG_BUF_LEN), hd->buf_size);
		if (*ppos < len) {
			n = min_t(size_t, count, len - *ppos);
			memcpy_fromio(kbuf, hd->regs + PCIE_HELLO_REG_BUF + *ppos, n);
		}
	}
	mutex_unlock(&hd->lock);
	if (ret)
		return ret;

	if (copy_to_user(ubuf, kbuf, n))
		return -EFAULT;
	*ppos += n;
	return n;
}

/* Writes data at *ppos and sets BUF_LEN to the end of what was written. */
static ssize_t pcie_hello_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct pcie_hello *hd = file->private_data;
	u8 kbuf[PCIE_HELLO_MSG_MAX];
	size_t n;
	int ret;

	if (*ppos >= hd->buf_size)
		return count ? -ENOSPC : 0;
	n = min_t(size_t, count, hd->buf_size - *ppos);
	if (copy_from_user(kbuf, ubuf, n))
		return -EFAULT;

	if (mutex_lock_interruptible(&hd->lock))
		return -ERESTARTSYS;
	ret = pcie_hello_check(hd);
	if (!ret) {
		memcpy_toio(hd->regs + PCIE_HELLO_REG_BUF + *ppos, kbuf, n);
		hello_wr(hd, PCIE_HELLO_REG_BUF_LEN, *ppos + n);
	}
	mutex_unlock(&hd->lock);
	if (ret)
		return ret;

	*ppos += n;
	return n;
}

static long pcie_hello_ioctl_info(struct pcie_hello *hd, void __user *argp)
{
	struct pcie_hello_info info = { .abi_version = PCIE_HELLO_ABI_VERSION };

	mutex_lock(&hd->lock);
	if (hd->removed) {
		mutex_unlock(&hd->lock);
		return -ENODEV;
	}
	info.id = hello_rd(hd, PCIE_HELLO_REG_ID);
	info.hw_version = hello_rd(hd, PCIE_HELLO_REG_VERSION);
	info.serial = hello_rd(hd, PCIE_HELLO_REG_SERIAL);
	info.buf_size = hd->buf_size;
	info.status = hello_rd(hd, PCIE_HELLO_REG_STATUS);
	info.irq_mode = hd->irq_type;
	info.irq = hd->irq;
	info.cmd_count = hd->cmd_count;
	info.cmd_timeouts = hd->cmd_timeouts;
	info.resets = hd->resets;
	strscpy(info.pci_name, pci_name(hd->pdev), sizeof(info.pci_name));
	spin_lock_irq(&hd->irq_lock);
	info.irq_count = hd->irq_count;
	spin_unlock_irq(&hd->irq_lock);
	mutex_unlock(&hd->lock);

	return copy_to_user(argp, &info, sizeof(info)) ? -EFAULT : 0;
}

static long pcie_hello_ioctl_scratch(struct pcie_hello *hd, void __user *argp)
{
	struct pcie_hello_scratch sc;
	int ret;

	if (copy_from_user(&sc, argp, sizeof(sc)))
		return -EFAULT;

	mutex_lock(&hd->lock);
	ret = hd->removed ? -ENODEV : hd->broken ? -EIO : 0;
	if (!ret) {
		hello_wr(hd, PCIE_HELLO_REG_SCRATCH, sc.in);
		sc.out = hello_rd(hd, PCIE_HELLO_REG_SCRATCH);
	}
	mutex_unlock(&hd->lock);
	if (ret)
		return ret;

	return copy_to_user(argp, &sc, sizeof(sc)) ? -EFAULT : 0;
}

static long pcie_hello_ioctl_cmd(struct pcie_hello *hd, unsigned int ioc,
				 void __user *argp)
{
	struct pcie_hello_msg msg;
	int ret;

	if (ioc == PCIE_HELLO_IOC_UPPER) {
		if (copy_from_user(&msg, argp, sizeof(msg)))
			return -EFAULT;
		if (msg.reserved || msg.len > hd->buf_size)
			return -EINVAL;
	}

	if (mutex_lock_killable(&hd->lock))
		return -EINTR;
	if (ioc == PCIE_HELLO_IOC_UPPER) {
		ret = pcie_hello_check(hd);
		if (ret)
			goto out;
		memcpy_toio(hd->regs + PCIE_HELLO_REG_BUF, msg.data, msg.len);
		hello_wr(hd, PCIE_HELLO_REG_BUF_LEN, msg.len);
		ret = pcie_hello_run_cmd(hd, PCIE_HELLO_CMD_UPPER);
	} else {
		ret = pcie_hello_run_cmd(hd, PCIE_HELLO_CMD_GREET);
	}
	if (!ret)
		pcie_hello_read_msg(hd, &msg);
out:
	mutex_unlock(&hd->lock);
	if (ret)
		return ret;

	return copy_to_user(argp, &msg, sizeof(msg)) ? -EFAULT : 0;
}

static long pcie_hello_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct pcie_hello *hd = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case PCIE_HELLO_IOC_INFO:
		return pcie_hello_ioctl_info(hd, argp);
	case PCIE_HELLO_IOC_SCRATCH:
		return pcie_hello_ioctl_scratch(hd, argp);
	case PCIE_HELLO_IOC_GREET:
	case PCIE_HELLO_IOC_UPPER:
		return pcie_hello_ioctl_cmd(hd, cmd, argp);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations pcie_hello_fops = {
	.owner		= THIS_MODULE,
	.open		= pcie_hello_open,
	.read		= pcie_hello_read,
	.write		= pcie_hello_write,
	.llseek		= default_llseek,
	.unlocked_ioctl	= pcie_hello_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

/* ---- PCI glue ---- */

static int pcie_hello_setup_irq(struct pcie_hello *hd)
{
	struct pci_dev *pdev = hd->pdev;
	unsigned int flags;
	int ret;

	if (!strcmp(irq_mode, "msix"))
		flags = PCI_IRQ_MSIX;
	else if (!strcmp(irq_mode, "msi"))
		flags = PCI_IRQ_MSI;
	else if (!strcmp(irq_mode, "intx"))
		flags = PCI_IRQ_INTX;
	else
		flags = PCI_IRQ_MSIX | PCI_IRQ_MSI | PCI_IRQ_INTX;

	ret = pci_alloc_irq_vectors(pdev, 1, 1, flags);
	if (ret < 0) {
		dev_err(&pdev->dev, "no usable interrupt (irq_mode=%s): %d\n",
			irq_mode, ret);
		return ret;
	}

	if (pdev->msix_enabled)
		hd->irq_type = PCIE_HELLO_IRQ_MSIX;
	else if (pdev->msi_enabled)
		hd->irq_type = PCIE_HELLO_IRQ_MSI;
	else
		hd->irq_type = PCIE_HELLO_IRQ_INTX;

	hd->irq = pci_irq_vector(pdev, 0);
	snprintf(hd->irq_name, sizeof(hd->irq_name), DRV_NAME "@%s",
		 pci_name(pdev));
	ret = request_irq(hd->irq, pcie_hello_irq,
			  hd->irq_type == PCIE_HELLO_IRQ_INTX ? IRQF_SHARED : 0,
			  hd->irq_name, hd);
	if (ret) {
		dev_err(&pdev->dev, "request_irq(%d) failed: %d\n", hd->irq, ret);
		pci_free_irq_vectors(pdev);
	}
	return ret;
}

/* Undo everything probe did to the PCI device, in reverse order. */
static void pcie_hello_hw_teardown(struct pcie_hello *hd)
{
	struct pci_dev *pdev = hd->pdev;

	hello_wr(hd, PCIE_HELLO_REG_INT_ENABLE, 0);
	free_irq(hd->irq, hd);
	pci_free_irq_vectors(pdev);
	pci_clear_master(pdev);
	pci_iounmap(pdev, hd->regs);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static void pcie_hello_dev_release(struct device *dev)
{
	struct pcie_hello *hd = container_of(dev, struct pcie_hello, dev);

	ida_free(&pcie_hello_ida, hd->minor);
	kfree(hd);
}

static int pcie_hello_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct pcie_hello *hd;
	u32 magic, version;
	int ret;

	hd = kzalloc(sizeof(*hd), GFP_KERNEL);
	if (!hd)
		return -ENOMEM;
	hd->pdev = pdev;
	mutex_init(&hd->lock);
	spin_lock_init(&hd->irq_lock);
	init_completion(&hd->done);

	ret = pci_enable_device(pdev);
	if (ret)
		goto err_free;
	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		goto err_disable;
	if (pci_resource_len(pdev, 0) < PCIE_HELLO_BAR0_SIZE) {
		dev_err(&pdev->dev, "BAR0 too small (%llu bytes)\n",
			(unsigned long long)pci_resource_len(pdev, 0));
		ret = -ENODEV;
		goto err_release;
	}
	hd->regs = pci_iomap(pdev, 0, PCIE_HELLO_BAR0_SIZE);
	if (!hd->regs) {
		ret = -ENOMEM;
		goto err_release;
	}

	magic = hello_rd(hd, PCIE_HELLO_REG_ID);
	version = hello_rd(hd, PCIE_HELLO_REG_VERSION);
	if (magic != PCIE_HELLO_MAGIC) {
		dev_err(&pdev->dev, "bad ID register 0x%08x (expected 0x%08x)\n",
			magic, PCIE_HELLO_MAGIC);
		ret = -ENODEV;
		goto err_unmap;
	}
	if (version >> 16 != PCIE_HELLO_VERSION_MAJOR) {
		dev_err(&pdev->dev, "unsupported device version %u.%u\n",
			version >> 16, version & 0xffff);
		ret = -ENODEV;
		goto err_unmap;
	}
	hd->buf_size = min_t(u32, hello_rd(hd, PCIE_HELLO_REG_BUF_SIZE),
			     PCIE_HELLO_MSG_MAX);
	if (!hd->buf_size) {
		dev_err(&pdev->dev, "device reports no message buffer\n");
		ret = -ENODEV;
		goto err_unmap;
	}

	/* Quiesce interrupts before hooking up the handler */
	hello_wr(hd, PCIE_HELLO_REG_INT_ENABLE, 0);
	hello_wr(hd, PCIE_HELLO_REG_INT_ACK, PCIE_HELLO_INT_ALL);

	/* MSI/MSI-X are memory writes from the device: needs bus mastering */
	pci_set_master(pdev);
	ret = pcie_hello_setup_irq(hd);
	if (ret)
		goto err_master;

	ret = ida_alloc_max(&pcie_hello_ida, PCIE_HELLO_MAX_DEVS - 1, GFP_KERNEL);
	if (ret < 0)
		goto err_irq;
	hd->minor = ret;

	/* From here on, hd is freed by put_device() -> pcie_hello_dev_release */
	device_initialize(&hd->dev);
	hd->dev.class = &pcie_hello_class;
	hd->dev.parent = &pdev->dev;
	hd->dev.devt = MKDEV(MAJOR(pcie_hello_devt), hd->minor);
	hd->dev.release = pcie_hello_dev_release;
	ret = dev_set_name(&hd->dev, DRV_NAME "%d", hd->minor);
	if (ret)
		goto err_put;
	cdev_init(&hd->cdev, &pcie_hello_fops);
	hd->cdev.owner = THIS_MODULE;

	pci_set_drvdata(pdev, hd);
	hello_wr(hd, PCIE_HELLO_REG_INT_ENABLE, PCIE_HELLO_INT_ALL);

	ret = cdev_device_add(&hd->cdev, &hd->dev);
	if (ret)
		goto err_put;

	dev_info(&pdev->dev, "%s: pcie-hello v%u.%u serial %u, %u-byte buffer, irq %d (%s)\n",
		 dev_name(&hd->dev), version >> 16, version & 0xffff,
		 hello_rd(hd, PCIE_HELLO_REG_SERIAL), hd->buf_size, hd->irq,
		 irq_type_names[hd->irq_type]);
	return 0;

err_put:
	pcie_hello_hw_teardown(hd);
	put_device(&hd->dev);
	return ret;
err_irq:
	hello_wr(hd, PCIE_HELLO_REG_INT_ENABLE, 0);
	free_irq(hd->irq, hd);
	pci_free_irq_vectors(pdev);
err_master:
	pci_clear_master(pdev);
err_unmap:
	pci_iounmap(pdev, hd->regs);
err_release:
	pci_release_regions(pdev);
err_disable:
	pci_disable_device(pdev);
err_free:
	kfree(hd);
	return ret;
}

static void pcie_hello_remove(struct pci_dev *pdev)
{
	struct pcie_hello *hd = pci_get_drvdata(pdev);

	/* Waits for any in-flight operation; later fops see removed. */
	mutex_lock(&hd->lock);
	hd->removed = true;
	mutex_unlock(&hd->lock);

	cdev_device_del(&hd->cdev, &hd->dev);
	pcie_hello_hw_teardown(hd);
	dev_info(&pdev->dev, "%s: removed\n", dev_name(&hd->dev));
	put_device(&hd->dev);	/* freed once the last open file is closed */
}

/*
 * Function reset (e.g. "echo 1 > /sys/bus/pci/devices/.../reset", which uses
 * FLR). The PCI core saves/restores config space (including MSI-X) around
 * the reset; the device itself comes back with all state cleared, so we
 * block device access during the reset and re-arm interrupts afterwards.
 */
static void pcie_hello_reset_prepare(struct pci_dev *pdev)
{
	struct pcie_hello *hd = pci_get_drvdata(pdev);

	mutex_lock(&hd->lock);	/* released in reset_done */
	dev_info(&pdev->dev, "%s: function reset starting\n", dev_name(&hd->dev));
}

static void pcie_hello_reset_done(struct pci_dev *pdev)
{
	struct pcie_hello *hd = pci_get_drvdata(pdev);
	u32 magic = hello_rd(hd, PCIE_HELLO_REG_ID);

	hd->resets++;
	spin_lock_irq(&hd->irq_lock);
	hd->irq_status = 0;
	spin_unlock_irq(&hd->irq_lock);

	if (magic != PCIE_HELLO_MAGIC) {
		hd->broken = true;
		dev_err(&pdev->dev, "%s: device did not come back from reset (ID 0x%08x)\n",
			dev_name(&hd->dev), magic);
	} else {
		hd->broken = false;
		hello_wr(hd, PCIE_HELLO_REG_INT_ENABLE, PCIE_HELLO_INT_ALL);
		dev_info(&pdev->dev, "%s: function reset done, device state cleared, interrupts re-armed\n",
			 dev_name(&hd->dev));
	}
	mutex_unlock(&hd->lock);
}

static const struct pci_error_handlers pcie_hello_err_handlers = {
	.reset_prepare	= pcie_hello_reset_prepare,
	.reset_done	= pcie_hello_reset_done,
};

static const struct pci_device_id pcie_hello_ids[] = {
	{ PCI_DEVICE(PCIE_HELLO_VENDOR_ID, PCIE_HELLO_DEVICE_ID) },
	{ }
};
MODULE_DEVICE_TABLE(pci, pcie_hello_ids);

static struct pci_driver pcie_hello_driver = {
	.name		= DRV_NAME,
	.id_table	= pcie_hello_ids,
	.probe		= pcie_hello_probe,
	.remove		= pcie_hello_remove,
	.err_handler	= &pcie_hello_err_handlers,
};

static int __init pcie_hello_init(void)
{
	int ret;

	if (strcmp(irq_mode, "auto") && strcmp(irq_mode, "msix") &&
	    strcmp(irq_mode, "msi") && strcmp(irq_mode, "intx")) {
		pr_err(DRV_NAME ": invalid irq_mode '%s'\n", irq_mode);
		return -EINVAL;
	}

	ret = alloc_chrdev_region(&pcie_hello_devt, 0, PCIE_HELLO_MAX_DEVS,
				  DRV_NAME);
	if (ret)
		return ret;
	ret = class_register(&pcie_hello_class);
	if (ret)
		goto err_chrdev;
	ret = pci_register_driver(&pcie_hello_driver);
	if (ret)
		goto err_class;
	return 0;

err_class:
	class_unregister(&pcie_hello_class);
err_chrdev:
	unregister_chrdev_region(pcie_hello_devt, PCIE_HELLO_MAX_DEVS);
	return ret;
}

static void __exit pcie_hello_exit(void)
{
	pci_unregister_driver(&pcie_hello_driver);
	class_unregister(&pcie_hello_class);
	unregister_chrdev_region(pcie_hello_devt, PCIE_HELLO_MAX_DEVS);
}

module_init(pcie_hello_init);
module_exit(pcie_hello_exit);

MODULE_DESCRIPTION("Driver for the QEMU pcie-hello PCI Express endpoint");
MODULE_LICENSE("GPL");
