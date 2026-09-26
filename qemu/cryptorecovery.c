/*
 * pcie-cryptorecovery: holds the recovery key for one pcie-cryptostore
 * image in its own drive and releases it to the storage device, never to
 * the guest (threat model Section 9, datasheet section 11).
 *
 * Release requires both a guest ARM command and a host presence event
 * (the "host-armed" property, set with qom-set, valid for 120 s), and
 * happens at most once per machine boot (F8). The device's own FLR does not
 * clear the released flag.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/module.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pcie.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "system/block-backend.h"
#include "migration/vmstate.h"
#include "crypto/random.h"
#include "trace.h"
#include "cryptostore_regs.h"
#include "cryptostore_fi.h"
#include "cryptorecovery.h"

#define CR_FILE_SIZE        512
#define CR_MAGIC_STR        "CRYPTORC"
#define CR_OFF_VERSION      0x08
#define CR_OFF_STATE        0x0c
#define CR_OFF_UUID         0x10
#define CR_OFF_KEY          0x20
#define CR_STATE_KEY        0x5a3ca5c3u

struct CryptoRecoveryState {
    PCIDevice parent_obj;

    MemoryRegion mmio;
    BlockBackend *blk;
    char *label;

    /* From storage (not the key itself: read on demand, wiped after use) */
    bool key_present;
    uint8_t bound_uuid[CSF_UUID_LEN];

    /* Guest-visible */
    bool armed;
    uint32_t result;

    /* Host presence event (R2) */
    int64_t host_armed_at_ms;       /* 0 = not armed */

    /*
     * Release-once state. Two independent representations (F8, SR-22):
     * a fail-secure flag and a count. Survives FLR, cleared on machine reset.
     */
    uint32_t released_fs;
    uint32_t release_count;

#ifdef CRYPTOSTORE_FAULT_HOOKS
    char *fault;
#endif
};

static bool cr_host_armed(CryptoRecoveryState *r)
{
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    return r->host_armed_at_ms &&
           now - r->host_armed_at_ms <= CR_HOST_ARM_WINDOW_MS;
}

static bool cr_fault_hook(CryptoRecoveryState *r, const char *name)
{
#ifdef CRYPTOSTORE_FAULT_HOOKS
    if (r->fault && !strcmp(r->fault, name)) {
        g_free(r->fault);
        r->fault = NULL;
        return true;
    }
#endif
    return false;
}

static uint32_t cr_jitter_cycles(void)
{
    uint32_t v = 0;

    qcrypto_random_bytes(&v, sizeof(v), NULL);
    return 1024 + (v & 0x3fff);
}

static uint32_t cr_status(CryptoRecoveryState *r)
{
    return (r->key_present ? CR_STATUS_KEY_PRESENT : 0) |
           (r->armed ? CR_STATUS_ARMED : 0) |
           (r->released_fs == CS_FS_TRUE ? CR_STATUS_RELEASED : 0) |
           (cr_host_armed(r) ? CR_STATUS_HOST_ARMED : 0);
}

bool cryptorecovery_available(CryptoRecoveryState *r)
{
    return r && DEVICE(r)->realized && r->blk;
}

/* First evaluation of release-once uses the fail-secure flag (F8 check A). */
static CrRelease cr_can_release(CryptoRecoveryState *r, const uint8_t uuid[CSF_UUID_LEN],
                                bool glitch_once_check)
{
    if (!cryptorecovery_available(r) || !r->key_present ||
        memcmp(r->bound_uuid, uuid, CSF_UUID_LEN) != 0) {
        return CR_NO_KEY;
    }
    if (!r->armed || !cr_host_armed(r) ||
        (r->released_fs != CS_FS_FALSE && !glitch_once_check)) {
        return CR_NOT_ARMED;
    }
    return CR_RELEASED;
}

static bool cr_fault_peek(CryptoRecoveryState *r, const char *name)
{
#ifdef CRYPTOSTORE_FAULT_HOOKS
    return r->fault && !strcmp(r->fault, name);
#else
    return false;
#endif
}

CrRelease cryptorecovery_can_release(CryptoRecoveryState *r,
                                     const uint8_t uuid[CSF_UUID_LEN])
{
    /* A simulated F8 glitch affects every evaluation until release consumes it. */
    return cr_can_release(r, uuid, r && cr_fault_peek(r, "f8"));
}

CrRelease cryptorecovery_release(CryptoRecoveryState *r,
                                 const uint8_t uuid[CSF_UUID_LEN],
                                 uint8_t key[CSF_RECOVERY_KEY_LEN])
{
    uint8_t buf[CR_FILE_SIZE];
    CrRelease can = cr_can_release(r, uuid, r && cr_fault_hook(r, "f8"));

    if (can != CR_RELEASED) {
        trace_cryptorecovery_event(r ? r->label : "-", "release refused");
        return can;
    }

    /*
     * F8 check B, after a CSPRNG jitter delay and immediately before the
     * release: a different representation (the count) must agree (SR-22).
     */
    if (!cs_secure_jitter(cr_jitter_cycles())) {
        goto fault;
    }
    if (cs_launder32(r->release_count) != 0 || r->released_fs != CS_FS_FALSE) {
        goto fault;
    }

    /* Consume first, then read: a failure below still counts as a release. */
    r->released_fs = CS_FS_TRUE;
    r->release_count++;
    r->armed = false;
    r->host_armed_at_ms = 0;

    if (blk_pread(r->blk, 0, sizeof(buf), buf, 0) < 0 ||
        memcmp(buf + CR_OFF_UUID, uuid, CSF_UUID_LEN) != 0) {
        explicit_bzero(buf, sizeof(buf));
        return CR_NO_KEY;
    }
    memcpy(key, buf + CR_OFF_KEY, CSF_RECOVERY_KEY_LEN);
    explicit_bzero(buf, sizeof(buf));
    trace_cryptorecovery_event(r->label, "key released");
    return CR_RELEASED;

fault:
    r->released_fs = CS_FS_TRUE;
    r->armed = false;
    r->host_armed_at_ms = 0;
    warn_report("%s: fault detected in the release-once check; key withheld", r->label);
    return CR_FAULT;
}

bool cryptorecovery_store(CryptoRecoveryState *r, const uint8_t uuid[CSF_UUID_LEN],
                          const uint8_t key[CSF_RECOVERY_KEY_LEN], Error **errp)
{
    uint8_t buf[CR_FILE_SIZE] = { 0 }, check[CR_FILE_SIZE];
    bool ok;

    if (!cryptorecovery_available(r)) {
        error_setg(errp, "recovery device not available");
        return false;
    }
    memcpy(buf, CR_MAGIC_STR, 8);
    csf_put_le32(buf + CR_OFF_VERSION, 1);
    csf_put_le32(buf + CR_OFF_STATE, CR_STATE_KEY);
    memcpy(buf + CR_OFF_UUID, uuid, CSF_UUID_LEN);
    memcpy(buf + CR_OFF_KEY, key, CSF_RECOVERY_KEY_LEN);

    ok = blk_pwrite(r->blk, 0, sizeof(buf), buf, 0) >= 0 &&
         blk_flush(r->blk) >= 0 &&
         blk_pread(r->blk, 0, sizeof(check), check, 0) >= 0 &&
         memcmp(buf, check, sizeof(buf)) == 0;          /* SR-25 */
    explicit_bzero(buf, sizeof(buf));
    explicit_bzero(check, sizeof(check));
    if (!ok) {
        error_setg(errp, "recovery device storage write failed");
        return false;
    }
    r->key_present = true;
    memcpy(r->bound_uuid, uuid, CSF_UUID_LEN);
    trace_cryptorecovery_event(r->label, "key stored");
    return true;
}

static uint64_t cr_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    CryptoRecoveryState *r = opaque;
    uint64_t val = 0;

    if (size != 4) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: invalid %u-byte read at 0x%" HWADDR_PRIx "\n",
                      r->label, size, addr);
        return 0;
    }
    switch (addr) {
    case CR_REG_ID:
        val = CR_MAGIC;
        break;
    case CR_REG_VERSION:
        val = CR_VERSION;
        break;
    case CR_REG_STATUS:
        val = cr_status(r);
        break;
    case CR_REG_RESULT:
        val = r->result;
        break;
    case CR_REG_UUID0 ... CR_REG_UUID3:
        if (r->key_present && !(addr & 3)) {
            val = csf_le32(r->bound_uuid + (addr - CR_REG_UUID0));
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: read from unmapped offset 0x%" HWADDR_PRIx "\n",
                      r->label, addr);
    }
    trace_cryptorecovery_mmio(r->label, false, addr, val);
    return val;
}

static void cr_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    CryptoRecoveryState *r = opaque;

    trace_cryptorecovery_mmio(r->label, true, addr, val);
    if (size != 4 || addr != CR_REG_CMD) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: invalid %u-byte write at 0x%" HWADDR_PRIx "\n",
                      r->label, size, addr);
        return;
    }
    switch (val) {
    case CR_CMD_ARM:
        if (!r->key_present) {
            r->result = CR_ERR_NO_KEY;
            break;
        }
        r->armed = true;
        r->result = CR_OK;
        trace_cryptorecovery_event(r->label, "armed by guest");
        break;
    case CR_CMD_DISARM:
        r->armed = false;
        r->result = CR_OK;
        break;
    default:
        r->result = CR_ERR_INVALID_CMD;
    }
}

static const MemoryRegionOps cr_mmio_ops = {
    .read = cr_mmio_read,
    .write = cr_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

static void cr_reset_hold(Object *obj, ResetType type)
{
    CryptoRecoveryState *r = PCIE_CRYPTORECOVERY(obj);
    PCIDevice *pdev = PCI_DEVICE(obj);
    bool flr = pci_is_express(pdev) && pdev->exp.exp_cap &&
               (pci_get_word(pdev->config + pdev->exp.exp_cap + PCI_EXP_DEVCTL) &
                PCI_EXP_DEVCTL_BCR_FLR);

    r->armed = false;
    r->result = 0;
    if (!flr) {
        /* Machine reset starts a new "boot": one more release allowed. */
        r->released_fs = CS_FS_FALSE;
        r->release_count = 0;
        r->host_armed_at_ms = 0;
    }
    trace_cryptorecovery_event(r->label, flr ? "flr (release-once state kept)" : "reset");
}

static void cr_config_write(PCIDevice *pdev, uint32_t addr, uint32_t val, int len)
{
    pci_default_write_config(pdev, addr, val, len);
    pcie_cap_flr_write_config(pdev, addr, val, len);
}

static void cr_realize(PCIDevice *pdev, Error **errp)
{
    CryptoRecoveryState *r = PCIE_CRYPTORECOVERY(pdev);
    uint8_t buf[CR_FILE_SIZE];

    if (!pci_bus_is_express(pci_get_bus(pdev))) {
        error_setg(errp, "%s must be plugged into a PCI Express bus", TYPE_PCIE_CRYPTORECOVERY);
        return;
    }
    if (!r->blk) {
        error_setg(errp, "%s needs a drive= for its key storage", TYPE_PCIE_CRYPTORECOVERY);
        return;
    }
    if (blk_set_perm(r->blk, BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                     BLK_PERM_CONSISTENT_READ, errp) < 0) {
        return;
    }
    if (blk_getlength(r->blk) < CR_FILE_SIZE) {
        error_setg(errp, "%s: drive must be at least %d bytes", TYPE_PCIE_CRYPTORECOVERY,
                   CR_FILE_SIZE);
        return;
    }
    if (blk_pread(r->blk, 0, sizeof(buf), buf, 0) < 0) {
        error_setg(errp, "%s: cannot read the drive", TYPE_PCIE_CRYPTORECOVERY);
        return;
    }
    if (buffer_is_zero(buf, sizeof(buf))) {
        r->key_present = false;
    } else if (memcmp(buf, CR_MAGIC_STR, 8) == 0 && csf_le32(buf + CR_OFF_VERSION) == 1 &&
               csf_le32(buf + CR_OFF_STATE) == CR_STATE_KEY) {
        r->key_present = true;
        memcpy(r->bound_uuid, buf + CR_OFF_UUID, CSF_UUID_LEN);
    } else {
        explicit_bzero(buf, sizeof(buf));
        error_setg(errp, "%s: drive does not hold a recovery key image", TYPE_PCIE_CRYPTORECOVERY);
        return;
    }
    explicit_bzero(buf, sizeof(buf));

    r->label = g_strdup(DEVICE(pdev)->id ? DEVICE(pdev)->id : TYPE_PCIE_CRYPTORECOVERY);
    r->released_fs = CS_FS_FALSE;
    r->release_count = 0;

    if (pci_pm_init(pdev, 0x40, errp) < 0) {
        return;
    }
    if (pcie_endpoint_cap_init(pdev, 0x80) < 0) {
        error_setg(errp, "failed to add PCI Express capability");
        return;
    }
    pcie_cap_flr_init(pdev);
    pcie_cap_deverr_init(pdev);

    memory_region_init_io(&r->mmio, OBJECT(r), &cr_mmio_ops, r, "pcie-cryptorecovery-mmio",
                          CR_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &r->mmio);
}

static void cr_exit(PCIDevice *pdev)
{
    CryptoRecoveryState *r = PCIE_CRYPTORECOVERY(pdev);

    r->armed = false;
    r->host_armed_at_ms = 0;
    g_free(r->label);
    r->label = NULL;
}

static bool cr_get_host_armed(Object *obj, Error **errp)
{
    return cr_host_armed(PCIE_CRYPTORECOVERY(obj));
}

static void cr_set_host_armed(Object *obj, bool value, Error **errp)
{
    CryptoRecoveryState *r = PCIE_CRYPTORECOVERY(obj);

    r->host_armed_at_ms = value ? qemu_clock_get_ms(QEMU_CLOCK_REALTIME) : 0;
    trace_cryptorecovery_event(r->label ? r->label : "-",
                               value ? "host presence event (armed 120 s)" : "host disarmed");
}

#ifdef CRYPTOSTORE_FAULT_HOOKS
static char *cr_get_fault(Object *obj, Error **errp)
{
    CryptoRecoveryState *r = PCIE_CRYPTORECOVERY(obj);

    return g_strdup(r->fault ? r->fault : "");
}

static void cr_set_fault(Object *obj, const char *value, Error **errp)
{
    CryptoRecoveryState *r = PCIE_CRYPTORECOVERY(obj);

    g_free(r->fault);
    r->fault = *value ? g_strdup(value) : NULL;
}
#endif

static void cr_instance_init(Object *obj)
{
    object_property_add_bool(obj, "host-armed", cr_get_host_armed, cr_set_host_armed);
#ifdef CRYPTOSTORE_FAULT_HOOKS
    /* Test builds only (SR-29): one-shot simulated fault, e.g. "f8". */
    object_property_add_str(obj, "x-fault", cr_get_fault, cr_set_fault);
#endif
}

static const Property cr_props[] = {
    DEFINE_PROP_DRIVE("drive", CryptoRecoveryState, blk),
};

static const VMStateDescription vmstate_cr = {
    .name = TYPE_PCIE_CRYPTORECOVERY,
    .unmigratable = 1,          /* SR-12 */
};

static void cr_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = cr_realize;
    k->exit = cr_exit;
    k->config_write = cr_config_write;
    k->vendor_id = CR_VENDOR_ID;
    k->device_id = CR_DEVICE_ID;
    k->revision = CR_REVISION;
    k->class_id = CR_CLASS;
    rc->phases.hold = cr_reset_hold;
    dc->desc = "Recovery-key holder for pcie-cryptostore";
    dc->vmsd = &vmstate_cr;
    device_class_set_props(dc, cr_props);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo cr_types[] = {
    {
        .name          = TYPE_PCIE_CRYPTORECOVERY,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(CryptoRecoveryState),
        .instance_init = cr_instance_init,
        .class_init    = cr_class_init,
        .interfaces    = (const InterfaceInfo[]) {
            { INTERFACE_PCIE_DEVICE },
            { },
        },
    },
};

DEFINE_TYPES(cr_types)
