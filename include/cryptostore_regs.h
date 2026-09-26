/* SPDX-License-Identifier: GPL-2.0-or-later OR MIT */
/*
 * pcie-cryptostore and pcie-cryptorecovery hardware interface.
 *
 * The normative description is docs/cryptostore-datasheet.md; this header is
 * its machine-readable form, shared by the QEMU device models, the Linux
 * drivers and the tests. Plain #defines only.
 */
#ifndef CRYPTOSTORE_REGS_H
#define CRYPTOSTORE_REGS_H

/* ---- pcie-cryptostore ---- */

#define CS_VENDOR_ID            0x1af4
#define CS_DEVICE_ID            0x10f1
#define CS_REVISION             0x01
#define CS_CLASS                0x0180      /* mass storage, other */

#define CS_BAR0_SIZE            0x2000
#define CS_MSIX_BAR             2
#define CS_MSIX_VECTORS         1

#define CS_MAGIC                0x43525354u /* "CRST" */
#define CS_VERSION_MAJOR        1
#define CS_VERSION_MINOR        0
#define CS_VERSION              ((CS_VERSION_MAJOR << 16) | CS_VERSION_MINOR)

#define CS_SECTOR_SIZE          512
#define CS_MAX_SECTORS          8
#define CS_PW_MAX               128

/* Registers (32-bit) */
#define CS_REG_ID               0x000
#define CS_REG_VERSION          0x004
#define CS_REG_CAPS             0x008
#define CS_REG_SECTOR_SIZE      0x00c
#define CS_REG_MAX_SECTORS      0x010
#define CS_REG_PW_MAX           0x014
#define CS_REG_CAPACITY_LO      0x018
#define CS_REG_CAPACITY_HI      0x01c
#define CS_REG_STATE            0x020
#define CS_REG_STATUS           0x024
#define CS_REG_RESULT           0x028
#define CS_REG_RESULT_AUX       0x02c
#define CS_REG_FAIL_COUNT       0x030
#define CS_REG_SLOT_MAP         0x034
#define CS_REG_CMD              0x038
#define CS_REG_LBA_LO           0x040
#define CS_REG_LBA_HI           0x044
#define CS_REG_COUNT            0x048
#define CS_REG_PW_LEN           0x04c
#define CS_REG_PW2_LEN          0x050
#define CS_REG_INT_STATUS       0x060
#define CS_REG_INT_ENABLE       0x064
#define CS_REG_INT_ACK          0x068
#define CS_REG_UUID0            0x080       /* UUID bytes 0-3, LE */
#define CS_REG_UUID3            0x08c

/* Windows */
#define CS_WIN_PW_A             0x100
#define CS_WIN_PW_B             0x180
#define CS_WIN_PW_SIZE          0x080
#define CS_WIN_DATA             0x1000
#define CS_WIN_DATA_SIZE        (CS_MAX_SECTORS * CS_SECTOR_SIZE)

/* CAPS */
#define CS_CAPS_RECOVERY        (1u << 0)
#define CS_CAPS_DMA             (1u << 1)
#define CS_CAPS_FAULT_HOOKS     (1u << 2)

/* STATE (guest view; the device encodes states internally, SR-21) */
#define CS_STATE_UNFORMATTED    1
#define CS_STATE_LOCKED         2
#define CS_STATE_UNLOCKED       3
#define CS_STATE_RECOVERED      4
#define CS_STATE_LOCKED_OUT     5
#define CS_STATE_ERROR          6

/* STATUS */
#define CS_STATUS_BUSY          (1u << 0)

/* SLOT_MAP */
#define CS_SLOT_MAP_ACTIVE_MASK 0xffu
#define CS_SLOT_MAP_RECOVERY    (1u << 8)

/* INT_* */
#define CS_INT_CMD_DONE         (1u << 0)
#define CS_INT_ALL              CS_INT_CMD_DONE

/* Commands */
#define CS_CMD_FORMAT           0x01
#define CS_CMD_UNLOCK           0x02
#define CS_CMD_LOCK             0x03
#define CS_CMD_READ             0x04
#define CS_CMD_WRITE            0x05
#define CS_CMD_FLUSH            0x06
#define CS_CMD_PASSWD           0x07
#define CS_CMD_RECOVER          0x08
#define CS_CMD_ENROLL_RECOVERY  0x09
#define CS_CMD_REKEY            0x0a

/* Result codes */
#define CS_OK                   0x00
#define CS_ERR_INVALID_CMD      0x01
#define CS_ERR_STATE            0x02
#define CS_ERR_LOCKED           0x03
#define CS_ERR_AUTH             0x04
#define CS_ERR_BACKOFF          0x05
#define CS_ERR_LOCKED_OUT       0x06
#define CS_ERR_INTEGRITY        0x07
#define CS_ERR_NO_RECOVERY      0x08
#define CS_ERR_NOT_ARMED        0x09
#define CS_ERR_RANGE            0x0a
#define CS_ERR_IO               0x0b
#define CS_ERR_PASSWD_REQUIRED  0x0c
#define CS_ERR_FAULT            0x0d
#define CS_ERR_UNSUPPORTED      0x0e

/* Lockout policy (threat model 11.10) */
#define CS_LOCKOUT_N            10
#define CS_FREE_FAILURES        3
#define CS_BACKOFF_CAP_S        300

/* ---- pcie-cryptorecovery ---- */

#define CR_VENDOR_ID            0x1af4
#define CR_DEVICE_ID            0x10f2
#define CR_REVISION             0x01
#define CR_CLASS                0x1080      /* encryption controller, other */

#define CR_BAR0_SIZE            0x1000
#define CR_MAGIC                0x43525243u /* "CRRC" */
#define CR_VERSION              0x00010000

#define CR_REG_ID               0x000
#define CR_REG_VERSION          0x004
#define CR_REG_STATUS           0x008
#define CR_REG_CMD              0x00c
#define CR_REG_RESULT           0x010
#define CR_REG_UUID0            0x020
#define CR_REG_UUID3            0x02c

#define CR_STATUS_KEY_PRESENT   (1u << 0)
#define CR_STATUS_ARMED         (1u << 1)
#define CR_STATUS_RELEASED      (1u << 2)
#define CR_STATUS_HOST_ARMED    (1u << 3)

#define CR_CMD_ARM              0x01
#define CR_CMD_DISARM           0x02

#define CR_OK                   0x00
#define CR_ERR_INVALID_CMD      0x01
#define CR_ERR_NO_KEY           0x02

#define CR_HOST_ARM_WINDOW_MS   120000

#endif /* CRYPTOSTORE_REGS_H */
