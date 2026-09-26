/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note OR MIT */
/*
 * ioctl ABI of the cryptostore and cryptorecovery drivers, shared with
 * cryptoctl. Fixed-size fields and explicit padding, so 32- and 64-bit
 * userspace see the same layout. Append-only; bump the ABI version on
 * changes.
 *
 * Commands that reach the device return 0 from ioctl() and report the
 * device's result code (CS_OK, CS_ERR_*, include/cryptostore_regs.h) in
 * @result; errno is only used for driver-level failures (EBUSY, ETIMEDOUT,
 * ENODEV, EFAULT, EINVAL, EPERM).
 */
#ifndef CRYPTOSTORE_IOCTL_H
#define CRYPTOSTORE_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define CRYPTOSTORE_ABI_VERSION     1
#define CRYPTOSTORE_PW_MAX          128

/* Raw password bytes plus length (D7). Wiped by the driver after use. */
struct cryptostore_password {
    __u32 len;
    __u32 reserved;                 /* must be 0 */
    __u8  data[CRYPTOSTORE_PW_MAX];
};

#define CRYPTOSTORE_LOCK_FORCE      (1u << 0)   /* lock even if the disk is open */

struct cryptostore_cmd {
    struct cryptostore_password pw;         /* FORMAT, UNLOCK; PASSWD: old */
    struct cryptostore_password new_pw;     /* PASSWD: new */
    __u32 flags;                            /* LOCK: CRYPTOSTORE_LOCK_FORCE */
    __u32 result;                           /* out: device result code */
    __u32 aux;                              /* out: RESULT_AUX (backoff seconds) */
    __u32 reserved;
};

struct cryptostore_status {
    __u32 abi_version;
    __u32 state;                    /* CS_STATE_* */
    __u32 caps;                     /* CS_CAPS_* */
    __u32 fail_count;
    __u32 slot_map;                 /* CS_SLOT_MAP_* */
    __u32 last_result;
    __u32 sector_size;
    __u32 irq_mode;                 /* 1 INTx, 2 MSI, 3 MSI-X */
    __u64 capacity;                 /* sectors; 0 unless UNLOCKED */
    __u8  uuid[16];
    char  disk_name[32];            /* e.g. "cryptostore0" */
    char  pci_name[32];
};

#define CRYPTOSTORE_IOC_MAGIC       0xE8
#define CRYPTOSTORE_IOC_STATUS      _IOR(CRYPTOSTORE_IOC_MAGIC, 0x00, struct cryptostore_status)
#define CRYPTOSTORE_IOC_FORMAT      _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x01, struct cryptostore_cmd)
#define CRYPTOSTORE_IOC_UNLOCK      _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x02, struct cryptostore_cmd)
#define CRYPTOSTORE_IOC_LOCK        _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x03, struct cryptostore_cmd)
#define CRYPTOSTORE_IOC_PASSWD      _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x04, struct cryptostore_cmd)
#define CRYPTOSTORE_IOC_RECOVER     _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x05, struct cryptostore_cmd)
#define CRYPTOSTORE_IOC_ENROLL_RECOVERY _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x06, struct cryptostore_cmd)
#define CRYPTOSTORE_IOC_REKEY       _IOWR(CRYPTOSTORE_IOC_MAGIC, 0x07, struct cryptostore_cmd)

/* ---- cryptorecovery ---- */

struct cryptorecovery_status {
    __u32 abi_version;
    __u32 status;                   /* CR_STATUS_* */
    __u32 last_result;
    __u32 reserved;
    __u8  bound_uuid[16];
    char  pci_name[32];
};

struct cryptorecovery_cmd {
    __u32 result;                   /* out: CR_OK / CR_ERR_* */
    __u32 reserved;
};

#define CRYPTORECOVERY_IOC_MAGIC    0xE9
#define CRYPTORECOVERY_IOC_STATUS   _IOR(CRYPTORECOVERY_IOC_MAGIC, 0x00, struct cryptorecovery_status)
#define CRYPTORECOVERY_IOC_ARM      _IOR(CRYPTORECOVERY_IOC_MAGIC, 0x01, struct cryptorecovery_cmd)
#define CRYPTORECOVERY_IOC_DISARM   _IOR(CRYPTORECOVERY_IOC_MAGIC, 0x02, struct cryptorecovery_cmd)

#endif /* CRYPTOSTORE_IOCTL_H */
