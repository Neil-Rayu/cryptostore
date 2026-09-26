// SPDX-License-Identifier: GPL-2.0
/*
 * cryptostore: driver for the QEMU "pcie-cryptostore" encrypted storage
 * device (docs/cryptostore-datasheet.md).
 *
 * Per device:
 *   /dev/cryptostoreN       block device; capacity 0 unless the device is
 *                           UNLOCKED (D5), normal disk permissions (SR-19)
 *   /dev/cryptostore-ctlN   control node, root only: status, format,
 *                           unlock, lock, passwd, recover, enroll-recovery
 *
 * The device transfers at most 8 sectors per command through an MMIO
 * window, so the queue is limited to 8-sector requests and each request is
 * one device command, bounced through a buffer that is wiped afterwards.
 * Everything that touches the device is serialized by a per-device mutex.
 */
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/bvec.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "cryptostore_regs.h"
#include "cryptostore_ioctl.h"

#define DRV_NAME            "cryptostore"
#define CS_MAX_DEVS         16
#define CS_PART_MINORS      16

static char *irq_mode = "auto";
module_param(irq_mode, charp, 0444);
MODULE_PARM_DESC(irq_mode, "Interrupt type: auto (MSI-X, MSI, INTx), msix, msi or intx");

static unsigned int io_timeout_ms = 10000;
module_param(io_timeout_ms, uint, 0644);
MODULE_PARM_DESC(io_timeout_ms, "Timeout for READ/WRITE/FLUSH/LOCK commands");

static unsigned int auth_timeout_ms = 120000;
module_param(auth_timeout_ms, uint, 0644);
MODULE_PARM_DESC(auth_timeout_ms, "Timeout for UNLOCK/PASSWD/RECOVER (KDF + padding)");

static unsigned int format_timeout_ms = 1800000;
module_param(format_timeout_ms, uint, 0644);
MODULE_PARM_DESC(format_timeout_ms, "Timeout for FORMAT (calibration + random fill)");

static dev_t cs_ctl_devt;
static int cs_blk_major;
static DEFINE_IDA(cs_ida);

static char *cs_devnode(const struct device *dev, umode_t *mode);

static const struct class cs_class = {
	.name = "cryptostore",
	.devnode = cs_devnode,
};

struct cs_dev {
	struct pci_dev *pdev;
	void __iomem *regs;
	int minor;

	/* Control node; its refcount owns this structure. */
	struct device ctl_dev;
	struct cdev cdev;

	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;

	struct mutex lock;		/* serializes all device access */
	bool removed;

	spinlock_t irq_lock;
	struct completion done;
	u32 irq_status;
	int irq;
	u32 irq_type;			/* 1 INTx, 2 MSI, 3 MSI-X */
	char irq_name[32];

	u8 bounce[CS_WIN_DATA_SIZE];	/* plaintext; wiped after every request */
};

static inline u32 cs_rd(struct cs_dev *cd, unsigned int reg)
{
	return ioread32(cd->regs + reg);
}

static inline void cs_wr(struct cs_dev *cd, unsigned int reg, u32 val)
{
	iowrite32(val, cd->regs + reg);
}

static irqreturn_t cs_irq(int irq, void *data)
{
	struct cs_dev *cd = data;
	u32 status;

	spin_lock(&cd->irq_lock);
	status = cs_rd(cd, CS_REG_INT_STATUS);
	if (!status || status == ~0u) {
		spin_unlock(&cd->irq_lock);
		return IRQ_NONE;
	}
	cs_wr(cd, CS_REG_INT_ACK, status);
	cs_rd(cd, CS_REG_INT_STATUS);		/* flush the posted ack */
	cd->irq_status |= status;
	complete(&cd->done);
	spin_unlock(&cd->irq_lock);
	return IRQ_HANDLED;
}

/*
 * Run one device command and wait for its interrupt. Returns 0 and the
 * device result in *result, or a negative errno if the command could not
 * run or did not complete. Caller holds cd->lock.
 */
static int cs_exec(struct cs_dev *cd, u32 cmd, unsigned int timeout_ms,
		   bool killable, u32 *result, u32 *aux)
{
	long left;
	u32 status;

	lockdep_assert_held(&cd->lock);
	if (cd->removed)
		return -ENODEV;
	status = cs_rd(cd, CS_REG_STATUS);
	if (status == ~0u)
		return -ENODEV;
	if (status & CS_STATUS_BUSY)
		return -EBUSY;

	/* Discard stale completions before issuing the next command. */
	spin_lock_irq(&cd->irq_lock);
	cs_wr(cd, CS_REG_INT_ACK, CS_INT_ALL);
	cd->irq_status = 0;
	reinit_completion(&cd->done);
	spin_unlock_irq(&cd->irq_lock);

	cs_wr(cd, CS_REG_CMD, cmd);
	if (killable)
		left = wait_for_completion_killable_timeout(&cd->done,
							    msecs_to_jiffies(timeout_ms));
	else
		left = wait_for_completion_timeout(&cd->done, msecs_to_jiffies(timeout_ms));
	if (left < 0)
		return left;
	if (left == 0) {
		dev_warn(&cd->ctl_dev, "command 0x%x timed out after %u ms\n", cmd, timeout_ms);
		return -ETIMEDOUT;
	}
	*result = cs_rd(cd, CS_REG_RESULT);
	if (aux)
		*aux = cs_rd(cd, CS_REG_RESULT_AUX);
	return 0;
}

/* Reflect the device's lock state in the disk's capacity (D5). */
static void cs_update_capacity(struct cs_dev *cd)
{
	u64 cap = 0;

	if (cs_rd(cd, CS_REG_STATE) == CS_STATE_UNLOCKED)
		cap = cs_rd(cd, CS_REG_CAPACITY_LO) |
		      ((u64)cs_rd(cd, CS_REG_CAPACITY_HI) << 32);
	if (get_capacity(cd->disk) == cap)
		return;
	set_capacity_and_notify(cd->disk, cap);
	/*
	 * Drop the page cache (plaintext) and anything cached about the old
	 * contents, and rescan partitions on the next open.
	 */
	disk_force_media_change(cd->disk);
}

/* ---- block device ---- */

static blk_status_t cs_blk_status(int err, u32 result)
{
	if (err)
		return err == -ETIMEDOUT ? BLK_STS_TIMEOUT : BLK_STS_IOERR;
	return result == CS_OK ? BLK_STS_OK : BLK_STS_IOERR;
}

static blk_status_t cs_rq_rw(struct cs_dev *cd, struct request *rq)
{
	unsigned int nsect = blk_rq_sectors(rq), bytes = nsect * CS_SECTOR_SIZE, off = 0;
	bool write = req_op(rq) == REQ_OP_WRITE;
	sector_t sector = blk_rq_pos(rq);
	struct req_iterator iter;
	struct bio_vec bv;
	u32 result = 0;
	int err;

	if (!nsect || nsect > CS_MAX_SECTORS)
		return BLK_STS_IOERR;

	mutex_lock(&cd->lock);
	cs_wr(cd, CS_REG_LBA_LO, lower_32_bits(sector));
	cs_wr(cd, CS_REG_LBA_HI, upper_32_bits(sector));
	cs_wr(cd, CS_REG_COUNT, nsect);
	if (write) {
		rq_for_each_segment(bv, rq, iter) {
			if (off + bv.bv_len > bytes)
				break;
			memcpy_from_bvec(cd->bounce + off, &bv);
			off += bv.bv_len;
		}
		memcpy_toio(cd->regs + CS_WIN_DATA, cd->bounce, bytes);
		err = cs_exec(cd, CS_CMD_WRITE, io_timeout_ms, false, &result, NULL);
		if (!err && result == CS_OK && (rq->cmd_flags & REQ_FUA))
			err = cs_exec(cd, CS_CMD_FLUSH, io_timeout_ms, false, &result, NULL);
	} else {
		err = cs_exec(cd, CS_CMD_READ, io_timeout_ms, false, &result, NULL);
		if (!err && result == CS_OK) {
			memcpy_fromio(cd->bounce, cd->regs + CS_WIN_DATA, bytes);
			rq_for_each_segment(bv, rq, iter) {
				if (off + bv.bv_len > bytes)
					break;
				memcpy_to_bvec(&bv, cd->bounce + off);
				off += bv.bv_len;
			}
		}
	}
	memzero_explicit(cd->bounce, sizeof(cd->bounce));
	mutex_unlock(&cd->lock);

	if (!err && result != CS_OK)
		dev_dbg(&cd->ctl_dev, "%s sector %llu: device result 0x%x\n",
			write ? "write" : "read", (unsigned long long)sector, result);
	return cs_blk_status(err, result);
}

static blk_status_t cs_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct cs_dev *cd = hctx->queue->queuedata;
	struct request *rq = bd->rq;
	blk_status_t st;
	u32 result = 0;
	int err;

	blk_mq_start_request(rq);
	switch (req_op(rq)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		st = cs_rq_rw(cd, rq);
		break;
	case REQ_OP_FLUSH:
		mutex_lock(&cd->lock);
		err = cs_exec(cd, CS_CMD_FLUSH, io_timeout_ms, false, &result, NULL);
		mutex_unlock(&cd->lock);
		st = cs_blk_status(err, result);
		break;
	default:
		st = BLK_STS_NOTSUPP;
		break;
	}
	blk_mq_end_request(rq, st);
	return BLK_STS_OK;
}

static const struct blk_mq_ops cs_mq_ops = {
	.queue_rq = cs_queue_rq,
};

static const struct block_device_operations cs_bdops = {
	.owner = THIS_MODULE,
};

/* ---- control node ---- */

static int cs_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev, struct cs_dev, cdev);
	return 0;
}

static int cs_check_pw(const struct cryptostore_password *pw, bool allow_empty)
{
	if (pw->reserved || pw->len > CRYPTOSTORE_PW_MAX || (!pw->len && !allow_empty))
		return -EINVAL;
	return 0;
}

static void cs_load_pw(struct cs_dev *cd, unsigned int win, unsigned int len_reg,
		       const struct cryptostore_password *pw)
{
	memcpy_toio(cd->regs + win, pw->data, pw->len);
	cs_wr(cd, len_reg, pw->len);
}

static long cs_ioctl_status(struct cs_dev *cd, void __user *argp)
{
	struct cryptostore_status st = { .abi_version = CRYPTOSTORE_ABI_VERSION };
	int i;

	mutex_lock(&cd->lock);
	if (cd->removed) {
		mutex_unlock(&cd->lock);
		return -ENODEV;
	}
	st.state = cs_rd(cd, CS_REG_STATE);
	st.caps = cs_rd(cd, CS_REG_CAPS);
	st.fail_count = cs_rd(cd, CS_REG_FAIL_COUNT);
	st.slot_map = cs_rd(cd, CS_REG_SLOT_MAP);
	st.last_result = cs_rd(cd, CS_REG_RESULT);
	st.sector_size = cs_rd(cd, CS_REG_SECTOR_SIZE);
	st.irq_mode = cd->irq_type;
	st.capacity = cs_rd(cd, CS_REG_CAPACITY_LO) |
		      ((u64)cs_rd(cd, CS_REG_CAPACITY_HI) << 32);
	for (i = 0; i < 4; i++) {
		u32 w = cs_rd(cd, CS_REG_UUID0 + 4 * i);

		memcpy(st.uuid + 4 * i, &w, 4);	/* little-endian register order */
	}
	strscpy(st.disk_name, cd->disk->disk_name, sizeof(st.disk_name));
	strscpy(st.pci_name, pci_name(cd->pdev), sizeof(st.pci_name));
	mutex_unlock(&cd->lock);

	return copy_to_user(argp, &st, sizeof(st)) ? -EFAULT : 0;
}

static long cs_ioctl_cmd(struct cs_dev *cd, unsigned int ioc, void __user *argp)
{
	struct cryptostore_cmd *c;
	unsigned int timeout = auth_timeout_ms;
	bool update = false;
	u32 op;
	long ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* Heap, not stack: two passwords; wiped with memzero_explicit (SR-14). */
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	if (copy_from_user(c, argp, sizeof(*c))) {
		ret = -EFAULT;
		goto out;
	}
	c->result = 0;
	c->aux = 0;

	switch (ioc) {
	case CRYPTOSTORE_IOC_FORMAT:
		op = CS_CMD_FORMAT;
		timeout = format_timeout_ms;
		ret = cs_check_pw(&c->pw, false);
		update = true;
		break;
	case CRYPTOSTORE_IOC_UNLOCK:
		op = CS_CMD_UNLOCK;
		ret = cs_check_pw(&c->pw, false);
		update = true;
		break;
	case CRYPTOSTORE_IOC_LOCK:
		op = CS_CMD_LOCK;
		timeout = io_timeout_ms;
		ret = c->flags & ~CRYPTOSTORE_LOCK_FORCE ? -EINVAL : 0;
		/* D6: refuse while the disk is open unless forced (O4 caveat). */
		if (!ret && !(c->flags & CRYPTOSTORE_LOCK_FORCE) && disk_openers(cd->disk))
			ret = -EBUSY;
		update = true;
		break;
	case CRYPTOSTORE_IOC_PASSWD:
		op = CS_CMD_PASSWD;
		ret = cs_check_pw(&c->pw, true) ?: cs_check_pw(&c->new_pw, false);
		update = true;
		break;
	case CRYPTOSTORE_IOC_RECOVER:
		op = CS_CMD_RECOVER;
		ret = 0;
		update = true;
		break;
	case CRYPTOSTORE_IOC_ENROLL_RECOVERY:
		op = CS_CMD_ENROLL_RECOVERY;
		ret = 0;
		break;
	case CRYPTOSTORE_IOC_REKEY:
		op = CS_CMD_REKEY;
		ret = 0;
		break;
	default:
		ret = -ENOTTY;
	}
	if (ret)
		goto out;

	if (mutex_lock_killable(&cd->lock)) {
		ret = -EINTR;
		goto out;
	}
	if (op == CS_CMD_FORMAT || op == CS_CMD_UNLOCK || op == CS_CMD_PASSWD)
		cs_load_pw(cd, CS_WIN_PW_A, CS_REG_PW_LEN, &c->pw);
	if (op == CS_CMD_PASSWD)
		cs_load_pw(cd, CS_WIN_PW_B, CS_REG_PW2_LEN, &c->new_pw);
	ret = cs_exec(cd, op, timeout, true, &c->result, &c->aux);
	mutex_unlock(&cd->lock);
	if (update && !cd->removed)
		cs_update_capacity(cd);

out:
	/* Never hand the passwords back; the caller's copy is cleared too. */
	memzero_explicit(&c->pw, sizeof(c->pw));
	memzero_explicit(&c->new_pw, sizeof(c->new_pw));
	if (!ret && copy_to_user(argp, c, sizeof(*c)))
		ret = -EFAULT;
	kfree_sensitive(c);
	return ret;
}

static long cs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cs_dev *cd = file->private_data;
	void __user *argp = (void __user *)arg;

	if (cmd == CRYPTOSTORE_IOC_STATUS)
		return cs_ioctl_status(cd, argp);
	return cs_ioctl_cmd(cd, cmd, argp);
}

static const struct file_operations cs_fops = {
	.owner		= THIS_MODULE,
	.open		= cs_open,
	.unlocked_ioctl	= cs_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.llseek		= noop_llseek,
};

static char *cs_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0600;			/* control node: root only (SR-19) */
	return NULL;
}

/* ---- PCI glue ---- */

static int cs_setup_irq(struct cs_dev *cd)
{
	struct pci_dev *pdev = cd->pdev;
	unsigned int flags = PCI_IRQ_MSIX | PCI_IRQ_MSI | PCI_IRQ_INTX;
	int ret;

	if (!strcmp(irq_mode, "msix"))
		flags = PCI_IRQ_MSIX;
	else if (!strcmp(irq_mode, "msi"))
		flags = PCI_IRQ_MSI;
	else if (!strcmp(irq_mode, "intx"))
		flags = PCI_IRQ_INTX;

	ret = pci_alloc_irq_vectors(pdev, 1, 1, flags);
	if (ret < 0)
		return ret;
	cd->irq_type = pdev->msix_enabled ? 3 : pdev->msi_enabled ? 2 : 1;
	cd->irq = pci_irq_vector(pdev, 0);
	snprintf(cd->irq_name, sizeof(cd->irq_name), DRV_NAME "@%s", pci_name(pdev));
	ret = request_irq(cd->irq, cs_irq, cd->irq_type == 1 ? IRQF_SHARED : 0,
			  cd->irq_name, cd);
	if (ret)
		pci_free_irq_vectors(pdev);
	return ret;
}

static void cs_hw_teardown(struct cs_dev *cd)
{
	struct pci_dev *pdev = cd->pdev;

	cs_wr(cd, CS_REG_INT_ENABLE, 0);
	free_irq(cd->irq, cd);
	pci_free_irq_vectors(pdev);
	pci_clear_master(pdev);
	pci_iounmap(pdev, cd->regs);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static void cs_ctl_release(struct device *dev)
{
	struct cs_dev *cd = container_of(dev, struct cs_dev, ctl_dev);

	ida_free(&cs_ida, cd->minor);
	kfree_sensitive(cd);
}

static int cs_add_disk(struct cs_dev *cd)
{
	struct queue_limits lim = {
		.logical_block_size	= CS_SECTOR_SIZE,
		.physical_block_size	= CS_SECTOR_SIZE,
		.max_hw_sectors		= CS_MAX_SECTORS,
		.features		= BLK_FEAT_WRITE_CACHE | BLK_FEAT_FUA,
	};
	int ret;

	cd->tag_set.ops = &cs_mq_ops;
	cd->tag_set.nr_hw_queues = 1;
	cd->tag_set.queue_depth = 1;
	cd->tag_set.numa_node = NUMA_NO_NODE;
	cd->tag_set.flags = BLK_MQ_F_BLOCKING;	/* commands sleep on the device */
	cd->tag_set.driver_data = cd;
	ret = blk_mq_alloc_tag_set(&cd->tag_set);
	if (ret)
		return ret;

	cd->disk = blk_mq_alloc_disk(&cd->tag_set, &lim, cd);
	if (IS_ERR(cd->disk)) {
		ret = PTR_ERR(cd->disk);
		cd->disk = NULL;
		blk_mq_free_tag_set(&cd->tag_set);
		return ret;
	}
	cd->disk->major = cs_blk_major;
	cd->disk->first_minor = cd->minor * CS_PART_MINORS;
	cd->disk->minors = CS_PART_MINORS;
	cd->disk->fops = &cs_bdops;
	cd->disk->private_data = cd;
	snprintf(cd->disk->disk_name, DISK_NAME_LEN, DRV_NAME "%d", cd->minor);
	set_capacity(cd->disk, 0);
	return 0;
}

static int cs_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct cs_dev *cd;
	u32 magic, version;
	int ret;

	cd = kzalloc(sizeof(*cd), GFP_KERNEL);
	if (!cd)
		return -ENOMEM;
	cd->pdev = pdev;
	mutex_init(&cd->lock);
	spin_lock_init(&cd->irq_lock);
	init_completion(&cd->done);

	ret = pci_enable_device(pdev);
	if (ret)
		goto err_free;
	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		goto err_disable;
	cd->regs = pci_iomap(pdev, 0, CS_BAR0_SIZE);
	if (!cd->regs) {
		ret = -ENOMEM;
		goto err_release;
	}
	magic = cs_rd(cd, CS_REG_ID);
	version = cs_rd(cd, CS_REG_VERSION);
	if (magic != CS_MAGIC || version >> 16 != CS_VERSION_MAJOR) {
		dev_err(&pdev->dev, "not a supported pcie-cryptostore (ID 0x%08x, version 0x%08x)\n",
			magic, version);
		ret = -ENODEV;
		goto err_unmap;
	}
	cs_wr(cd, CS_REG_INT_ENABLE, 0);
	cs_wr(cd, CS_REG_INT_ACK, CS_INT_ALL);
	pci_set_master(pdev);		/* MSI/MSI-X are writes from the device */
	ret = cs_setup_irq(cd);
	if (ret)
		goto err_master;

	ret = ida_alloc_max(&cs_ida, CS_MAX_DEVS - 1, GFP_KERNEL);
	if (ret < 0)
		goto err_irq;
	cd->minor = ret;

	ret = cs_add_disk(cd);
	if (ret) {
		ida_free(&cs_ida, cd->minor);
		goto err_irq;
	}

	/* From here on cd is freed by put_device(&cd->ctl_dev). */
	device_initialize(&cd->ctl_dev);
	cd->ctl_dev.class = &cs_class;
	cd->ctl_dev.parent = &pdev->dev;
	cd->ctl_dev.devt = MKDEV(MAJOR(cs_ctl_devt), cd->minor);
	cd->ctl_dev.release = cs_ctl_release;
	ret = dev_set_name(&cd->ctl_dev, DRV_NAME "-ctl%d", cd->minor);
	if (ret)
		goto err_put;
	cdev_init(&cd->cdev, &cs_fops);
	cd->cdev.owner = THIS_MODULE;
	pci_set_drvdata(pdev, cd);
	cs_wr(cd, CS_REG_INT_ENABLE, CS_INT_ALL);

	ret = cdev_device_add(&cd->cdev, &cd->ctl_dev);
	if (ret)
		goto err_put;
	ret = device_add_disk(&pdev->dev, cd->disk, NULL);
	if (ret) {
		cdev_device_del(&cd->cdev, &cd->ctl_dev);
		goto err_put;
	}
	cs_update_capacity(cd);

	dev_info(&pdev->dev, "%s: pcie-cryptostore v%u.%u, state %u, irq %d (%s)\n",
		 cd->disk->disk_name, version >> 16, version & 0xffff,
		 cs_rd(cd, CS_REG_STATE), cd->irq,
		 cd->irq_type == 3 ? "MSI-X" : cd->irq_type == 2 ? "MSI" : "INTx");
	return 0;

err_put:
	put_disk(cd->disk);
	blk_mq_free_tag_set(&cd->tag_set);
	cs_hw_teardown(cd);
	put_device(&cd->ctl_dev);
	return ret;
err_irq:
	cs_wr(cd, CS_REG_INT_ENABLE, 0);
	free_irq(cd->irq, cd);
	pci_free_irq_vectors(pdev);
err_master:
	pci_clear_master(pdev);
err_unmap:
	pci_iounmap(pdev, cd->regs);
err_release:
	pci_release_regions(pdev);
err_disable:
	pci_disable_device(pdev);
err_free:
	kfree(cd);
	return ret;
}

static void cs_remove(struct pci_dev *pdev)
{
	struct cs_dev *cd = pci_get_drvdata(pdev);

	mutex_lock(&cd->lock);
	cd->removed = true;		/* in-flight and new commands get -ENODEV */
	mutex_unlock(&cd->lock);

	del_gendisk(cd->disk);
	cdev_device_del(&cd->cdev, &cd->ctl_dev);
	put_disk(cd->disk);
	blk_mq_free_tag_set(&cd->tag_set);
	cs_hw_teardown(cd);
	dev_info(&pdev->dev, "removed\n");
	put_device(&cd->ctl_dev);
}

/*
 * FLR: the device comes back LOCKED with its keys zeroized (SR-02). Block
 * device access is held off during the reset and the capacity drops to 0.
 */
static void cs_reset_prepare(struct pci_dev *pdev)
{
	struct cs_dev *cd = pci_get_drvdata(pdev);

	mutex_lock(&cd->lock);
	dev_info(&pdev->dev, "function reset: device will be LOCKED\n");
}

static void cs_reset_done(struct pci_dev *pdev)
{
	struct cs_dev *cd = pci_get_drvdata(pdev);

	cs_wr(cd, CS_REG_INT_ENABLE, CS_INT_ALL);
	mutex_unlock(&cd->lock);
	cs_update_capacity(cd);
	dev_info(&pdev->dev, "function reset done, state %u\n", cs_rd(cd, CS_REG_STATE));
}

static const struct pci_error_handlers cs_err_handlers = {
	.reset_prepare	= cs_reset_prepare,
	.reset_done	= cs_reset_done,
};

static const struct pci_device_id cs_ids[] = {
	{ PCI_DEVICE(CS_VENDOR_ID, CS_DEVICE_ID) },
	{ }
};
MODULE_DEVICE_TABLE(pci, cs_ids);

static struct pci_driver cs_driver = {
	.name		= DRV_NAME,
	.id_table	= cs_ids,
	.probe		= cs_probe,
	.remove		= cs_remove,
	.err_handler	= &cs_err_handlers,
};

static int __init cs_init(void)
{
	int ret;

	cs_blk_major = register_blkdev(0, DRV_NAME);
	if (cs_blk_major < 0)
		return cs_blk_major;
	ret = alloc_chrdev_region(&cs_ctl_devt, 0, CS_MAX_DEVS, DRV_NAME "-ctl");
	if (ret)
		goto err_blk;
	ret = class_register(&cs_class);
	if (ret)
		goto err_chr;
	ret = pci_register_driver(&cs_driver);
	if (ret)
		goto err_class;
	return 0;
err_class:
	class_unregister(&cs_class);
err_chr:
	unregister_chrdev_region(cs_ctl_devt, CS_MAX_DEVS);
err_blk:
	unregister_blkdev(cs_blk_major, DRV_NAME);
	return ret;
}

static void __exit cs_exit(void)
{
	pci_unregister_driver(&cs_driver);
	class_unregister(&cs_class);
	unregister_chrdev_region(cs_ctl_devt, CS_MAX_DEVS);
	unregister_blkdev(cs_blk_major, DRV_NAME);
}

module_init(cs_init);
module_exit(cs_exit);

MODULE_DESCRIPTION("Driver for the QEMU pcie-cryptostore encrypted storage device");
MODULE_LICENSE("GPL");
