/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note OR MIT */
/*
 * pcie_hello ioctl ABI, shared by the kernel driver and pcie_hello_ctl.
 *
 * Structures have fixed-size fields and explicit padding so the layout is
 * identical for 32- and 64-bit userspace (the driver uses compat_ptr_ioctl).
 * Keep the structures append-only; bump PCIE_HELLO_ABI_VERSION on changes.
 */
#ifndef PCIE_HELLO_IOCTL_H
#define PCIE_HELLO_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PCIE_HELLO_ABI_VERSION  1
#define PCIE_HELLO_MSG_MAX      256

enum pcie_hello_irq_mode {
    PCIE_HELLO_IRQ_NONE = 0,
    PCIE_HELLO_IRQ_INTX = 1,
    PCIE_HELLO_IRQ_MSI  = 2,
    PCIE_HELLO_IRQ_MSIX = 3,
};

struct pcie_hello_info {
    __u32 abi_version;      /* PCIE_HELLO_ABI_VERSION */
    __u32 id;               /* REG_ID */
    __u32 hw_version;       /* REG_VERSION: major << 16 | minor */
    __u32 serial;           /* REG_SERIAL */
    __u32 buf_size;         /* REG_BUF_SIZE */
    __u32 status;           /* REG_STATUS at the time of the call */
    __u32 irq_mode;         /* enum pcie_hello_irq_mode */
    __u32 irq;              /* Linux IRQ number */
    __u64 irq_count;        /* interrupts handled by this device */
    __u64 cmd_count;        /* commands completed successfully */
    __u32 cmd_timeouts;     /* commands that timed out */
    __u32 resets;           /* function resets observed (FLR etc.) */
    char  pci_name[32];     /* e.g. "0000:01:00.0" */
};

struct pcie_hello_scratch {
    __u32 in;               /* written to REG_SCRATCH */
    __u32 out;              /* read back; device returns ~in */
};

struct pcie_hello_msg {
    __u32 len;              /* bytes valid in data[] */
    __u32 reserved;         /* must be 0 */
    __u8  data[PCIE_HELLO_MSG_MAX];
};

#define PCIE_HELLO_IOC_MAGIC    0xE7

/* Device identification, interrupt mode and driver statistics */
#define PCIE_HELLO_IOC_INFO     _IOR(PCIE_HELLO_IOC_MAGIC, 0x00, struct pcie_hello_info)
/* Write in to SCRATCH, return what the device reads back in out */
#define PCIE_HELLO_IOC_SCRATCH  _IOWR(PCIE_HELLO_IOC_MAGIC, 0x01, struct pcie_hello_scratch)
/* Run GREET; returns the resulting buffer contents */
#define PCIE_HELLO_IOC_GREET    _IOR(PCIE_HELLO_IOC_MAGIC, 0x02, struct pcie_hello_msg)
/* Load msg into the buffer, run UPPER, return the result (atomic) */
#define PCIE_HELLO_IOC_UPPER    _IOWR(PCIE_HELLO_IOC_MAGIC, 0x03, struct pcie_hello_msg)

#endif /* PCIE_HELLO_IOCTL_H */
