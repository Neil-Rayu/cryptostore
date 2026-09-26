/* SPDX-License-Identifier: GPL-2.0-or-later OR MIT */
/*
 * pcie-hello hardware interface: PCI IDs and BAR0 register map.
 *
 * Shared by the QEMU device model (hw/misc/pcie_hello.c), the Linux driver
 * and the documentation, so that all three agree on one "datasheet".
 * Plain #defines only; no types, so it compiles in QEMU, kernel and userspace.
 *
 * All registers are 32-bit, little-endian, and must be accessed with aligned
 * 32-bit loads/stores. The message buffer accepts 1, 2 or 4 byte accesses.
 */
#ifndef PCIE_HELLO_REGS_H
#define PCIE_HELLO_REGS_H

/*
 * 1af4:10f0..10ff is documented by QEMU (docs/specs/pci-ids.rst) as available
 * for experimental use without registration.
 */
#define PCIE_HELLO_VENDOR_ID        0x1af4
#define PCIE_HELLO_DEVICE_ID        0x10f0
#define PCIE_HELLO_REVISION         0x01

#define PCIE_HELLO_BAR0_SIZE        0x1000      /* registers + buffer */
#define PCIE_HELLO_MSIX_BAR         2           /* MSI-X table + PBA */
#define PCIE_HELLO_MSIX_VECTORS     1

/* Register offsets in BAR0 */
#define PCIE_HELLO_REG_ID           0x000   /* RO  magic, PCIE_HELLO_MAGIC */
#define PCIE_HELLO_REG_VERSION      0x004   /* RO  major << 16 | minor */
#define PCIE_HELLO_REG_SCRATCH      0x008   /* RW  reads back ~(last write) */
#define PCIE_HELLO_REG_BUF_SIZE     0x00c   /* RO  message buffer size, bytes */
#define PCIE_HELLO_REG_SERIAL       0x010   /* RO  instance serial (property) */
#define PCIE_HELLO_REG_CMD          0x020   /* WO  write opcode to start */
#define PCIE_HELLO_REG_STATUS       0x024   /* RO  PCIE_HELLO_STATUS_* */
#define PCIE_HELLO_REG_BUF_LEN      0x028   /* RW  valid bytes in buffer */
#define PCIE_HELLO_REG_INT_STATUS   0x030   /* RO  PCIE_HELLO_INT_* pending */
#define PCIE_HELLO_REG_INT_ENABLE   0x034   /* RW  PCIE_HELLO_INT_* enabled */
#define PCIE_HELLO_REG_INT_ACK      0x038   /* WO  write 1 to clear status */
#define PCIE_HELLO_REG_BUF          0x100   /* RW  message buffer */

#define PCIE_HELLO_MAGIC            0x48454c4fu /* "HELO" */
#define PCIE_HELLO_VERSION_MAJOR    1
#define PCIE_HELLO_VERSION_MINOR    0
#define PCIE_HELLO_VERSION \
    ((PCIE_HELLO_VERSION_MAJOR << 16) | PCIE_HELLO_VERSION_MINOR)
#define PCIE_HELLO_BUF_SIZE         256

/* Command opcodes (REG_CMD) */
#define PCIE_HELLO_CMD_GREET        0x01    /* write greeting into buffer */
#define PCIE_HELLO_CMD_UPPER        0x02    /* uppercase buffer[0..BUF_LEN) */

/* REG_STATUS bits */
#define PCIE_HELLO_STATUS_BUSY      (1u << 0)   /* command in progress */
#define PCIE_HELLO_STATUS_ERROR     (1u << 1)   /* last command failed */

/* REG_INT_STATUS / REG_INT_ENABLE / REG_INT_ACK bits */
#define PCIE_HELLO_INT_CMD_DONE     (1u << 0)   /* command succeeded */
#define PCIE_HELLO_INT_CMD_ERROR    (1u << 1)   /* command failed */
#define PCIE_HELLO_INT_ALL \
    (PCIE_HELLO_INT_CMD_DONE | PCIE_HELLO_INT_CMD_ERROR)

#endif /* PCIE_HELLO_REGS_H */
