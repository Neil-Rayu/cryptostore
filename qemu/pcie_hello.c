/*
 * pcie-hello: a minimal PCI Express endpoint for toolchain bring-up.
 *
 * Register map and IDs live in pcie_hello_regs.h (shared with the Linux
 * driver). The structure follows hw/misc/edu.c; the PCIe/MSI-X/FLR setup
 * follows hw/nvme/ctrl.c.
 *
 * Commands complete after "latency-ms" of virtual time and signal
 * completion through MSI-X, MSI or INTx, whichever the guest enabled.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pcie.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "trace.h"
#include "pcie_hello_regs.h"

#define TYPE_PCIE_HELLO "pcie-hello"
OBJECT_DECLARE_SIMPLE_TYPE(PCIeHelloState, PCIE_HELLO)

/* Config space layout */
#define PCIE_HELLO_PM_OFFSET    0x40
#define PCIE_HELLO_MSI_OFFSET   0x50
#define PCIE_HELLO_EXP_OFFSET   0x80

#define PCIE_HELLO_DEFAULT_LATENCY_MS 50

struct PCIeHelloState {
    PCIDevice parent_obj;

    MemoryRegion mmio;
    QEMUTimer cmd_timer;
    char *label;            /* for traces: qdev id or type name */

    /* Properties */
    uint32_t serial;
    bool use_msix;
    bool use_msi;
    uint32_t latency_ms;    /* runtime-settable via qom-set */

    /* Device state; everything below is cleared by reset/FLR */
    uint32_t scratch;
    uint32_t status;
    uint32_t buf_len;
    uint32_t int_status;
    uint32_t int_enable;
    uint32_t cur_cmd;
    bool intx_level;
    uint8_t buf[PCIE_HELLO_BUF_SIZE];
};

static const char *pcie_hello_reg_name(hwaddr addr)
{
    switch (addr) {
    case PCIE_HELLO_REG_ID:         return "ID";
    case PCIE_HELLO_REG_VERSION:    return "VERSION";
    case PCIE_HELLO_REG_SCRATCH:    return "SCRATCH";
    case PCIE_HELLO_REG_BUF_SIZE:   return "BUF_SIZE";
    case PCIE_HELLO_REG_SERIAL:     return "SERIAL";
    case PCIE_HELLO_REG_CMD:        return "CMD";
    case PCIE_HELLO_REG_STATUS:     return "STATUS";
    case PCIE_HELLO_REG_BUF_LEN:    return "BUF_LEN";
    case PCIE_HELLO_REG_INT_STATUS: return "INT_STATUS";
    case PCIE_HELLO_REG_INT_ENABLE: return "INT_ENABLE";
    case PCIE_HELLO_REG_INT_ACK:    return "INT_ACK";
    default:                        return "?";
    }
}

/*
 * Recompute interrupt outputs. @newly_set holds INT_* bits that just became
 * pending-and-enabled; MSI/MSI-X are edge-triggered and fire only for those,
 * INTx is a level that follows (int_status & int_enable).
 */
static void pcie_hello_update_irq(PCIeHelloState *s, uint32_t newly_set)
{
    PCIDevice *pdev = PCI_DEVICE(s);
    bool pending = s->int_status & s->int_enable;
    bool level = false;

    if (msix_enabled(pdev)) {
        if (newly_set) {
            trace_pcie_hello_irq(s->label, "msix", s->int_status,
                                 s->int_enable);
            msix_notify(pdev, 0);
        }
    } else if (msi_enabled(pdev)) {
        if (newly_set) {
            trace_pcie_hello_irq(s->label, "msi", s->int_status,
                                 s->int_enable);
            msi_notify(pdev, 0);
        }
    } else {
        level = pending;
    }

    if (level != s->intx_level) {
        trace_pcie_hello_irq(s->label, level ? "intx-assert" : "intx-deassert",
                             s->int_status, s->int_enable);
        s->intx_level = level;
        pci_set_irq(pdev, level);
    }
}

static void pcie_hello_raise(PCIeHelloState *s, uint32_t bits)
{
    uint32_t newly = bits & ~s->int_status & s->int_enable;

    s->int_status |= bits;
    pcie_hello_update_irq(s, newly);
}

static void pcie_hello_cmd_start(PCIeHelloState *s, uint32_t cmd)
{
    if (s->status & PCIE_HELLO_STATUS_BUSY) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: command 0x%x written while busy, ignored\n",
                      s->label, cmd);
        return;
    }

    trace_pcie_hello_cmd_start(s->label, cmd, s->latency_ms);
    s->cur_cmd = cmd;
    s->status = PCIE_HELLO_STATUS_BUSY;
    timer_mod(&s->cmd_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + s->latency_ms);
}

static void pcie_hello_cmd_done(void *opaque)
{
    PCIeHelloState *s = opaque;
    bool ok = true;
    uint32_t i;

    switch (s->cur_cmd) {
    case PCIE_HELLO_CMD_GREET:
        s->buf_len = snprintf((char *)s->buf, sizeof(s->buf),
                              "Hello from pcie-hello #%u!", s->serial);
        break;
    case PCIE_HELLO_CMD_UPPER:
        for (i = 0; i < s->buf_len; i++) {
            s->buf[i] = g_ascii_toupper(s->buf[i]);
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: unknown command 0x%x\n",
                      s->label, s->cur_cmd);
        ok = false;
        break;
    }

    trace_pcie_hello_cmd_done(s->label, s->cur_cmd, ok, s->buf_len);
    s->status = ok ? 0 : PCIE_HELLO_STATUS_ERROR;
    pcie_hello_raise(s, ok ? PCIE_HELLO_INT_CMD_DONE
                           : PCIE_HELLO_INT_CMD_ERROR);
}

static bool pcie_hello_is_buf(hwaddr addr, unsigned size)
{
    return addr >= PCIE_HELLO_REG_BUF &&
           addr + size <= PCIE_HELLO_REG_BUF + PCIE_HELLO_BUF_SIZE;
}

static uint64_t pcie_hello_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    PCIeHelloState *s = opaque;
    uint64_t val = 0;
    unsigned i;

    if (pcie_hello_is_buf(addr, size)) {
        for (i = 0; i < size; i++) {
            val |= (uint64_t)s->buf[addr - PCIE_HELLO_REG_BUF + i] << (8 * i);
        }
        trace_pcie_hello_buf_read(s->label, addr - PCIE_HELLO_REG_BUF, size,
                                  val);
        return val;
    }

    if (size != 4) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: invalid %u-byte read at 0x%" HWADDR_PRIx
                      " (registers are 32-bit only)\n",
                      s->label, size, addr);
        return 0;
    }

    switch (addr) {
    case PCIE_HELLO_REG_ID:
        val = PCIE_HELLO_MAGIC;
        break;
    case PCIE_HELLO_REG_VERSION:
        val = PCIE_HELLO_VERSION;
        break;
    case PCIE_HELLO_REG_SCRATCH:
        val = ~s->scratch;
        break;
    case PCIE_HELLO_REG_BUF_SIZE:
        val = PCIE_HELLO_BUF_SIZE;
        break;
    case PCIE_HELLO_REG_SERIAL:
        val = s->serial;
        break;
    case PCIE_HELLO_REG_STATUS:
        val = s->status;
        break;
    case PCIE_HELLO_REG_BUF_LEN:
        val = s->buf_len;
        break;
    case PCIE_HELLO_REG_INT_STATUS:
        val = s->int_status;
        break;
    case PCIE_HELLO_REG_INT_ENABLE:
        val = s->int_enable;
        break;
    case PCIE_HELLO_REG_CMD:
    case PCIE_HELLO_REG_INT_ACK:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: read from write-only register %s\n",
                      s->label, pcie_hello_reg_name(addr));
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: read from unmapped offset 0x%" HWADDR_PRIx "\n",
                      s->label, addr);
        break;
    }

    trace_pcie_hello_mmio_read(s->label, addr, pcie_hello_reg_name(addr),
                               val);
    return val;
}

static void pcie_hello_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                                  unsigned size)
{
    PCIeHelloState *s = opaque;
    bool busy = s->status & PCIE_HELLO_STATUS_BUSY;
    uint32_t old;
    unsigned i;

    if (pcie_hello_is_buf(addr, size)) {
        trace_pcie_hello_buf_write(s->label, addr - PCIE_HELLO_REG_BUF, size,
                                   val);
        if (busy) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: buffer write while busy, ignored\n", s->label);
            return;
        }
        for (i = 0; i < size; i++) {
            s->buf[addr - PCIE_HELLO_REG_BUF + i] = val >> (8 * i);
        }
        return;
    }

    if (size != 4) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: invalid %u-byte write at 0x%" HWADDR_PRIx
                      " (registers are 32-bit only)\n",
                      s->label, size, addr);
        return;
    }

    trace_pcie_hello_mmio_write(s->label, addr, pcie_hello_reg_name(addr),
                                val);

    switch (addr) {
    case PCIE_HELLO_REG_SCRATCH:
        s->scratch = val;
        break;
    case PCIE_HELLO_REG_CMD:
        pcie_hello_cmd_start(s, val);
        break;
    case PCIE_HELLO_REG_BUF_LEN:
        if (busy) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: BUF_LEN write while busy, ignored\n", s->label);
            break;
        }
        if (val > PCIE_HELLO_BUF_SIZE) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: BUF_LEN %" PRIu64 " too large, clamped to %u\n",
                          s->label, val, PCIE_HELLO_BUF_SIZE);
            val = PCIE_HELLO_BUF_SIZE;
        }
        s->buf_len = val;
        break;
    case PCIE_HELLO_REG_INT_ENABLE:
        old = s->int_enable;
        s->int_enable = val & PCIE_HELLO_INT_ALL;
        /* Enabling an already-pending source fires an edge interrupt. */
        pcie_hello_update_irq(s, s->int_enable & ~old & s->int_status);
        break;
    case PCIE_HELLO_REG_INT_ACK:
        s->int_status &= ~val;
        pcie_hello_update_irq(s, 0);
        break;
    case PCIE_HELLO_REG_ID:
    case PCIE_HELLO_REG_VERSION:
    case PCIE_HELLO_REG_BUF_SIZE:
    case PCIE_HELLO_REG_SERIAL:
    case PCIE_HELLO_REG_STATUS:
    case PCIE_HELLO_REG_INT_STATUS:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: write 0x%" PRIx64 " to read-only register %s\n",
                      s->label, val, pcie_hello_reg_name(addr));
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: write 0x%" PRIx64 " to unmapped offset 0x%"
                      HWADDR_PRIx "\n", s->label, val, addr);
        break;
    }
}

static const MemoryRegionOps pcie_hello_mmio_ops = {
    .read = pcie_hello_mmio_read,
    .write = pcie_hello_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,   /* 8-byte accesses are split in two */
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

/*
 * Runs on machine reset and on Function Level Reset (pci_device_reset()).
 * All device state is cleared here; the real device zeroizes keys here too.
 */
static void pcie_hello_reset_hold(Object *obj, ResetType type)
{
    PCIeHelloState *s = PCIE_HELLO(obj);
    PCIDevice *pdev = PCI_DEVICE(obj);
    bool flr = false;

    if (pci_is_express(pdev) && pdev->exp.exp_cap) {
        /* pcie_cap_flr_write_config() clears this bit after reset returns */
        flr = pci_get_word(pdev->config + pdev->exp.exp_cap +
                           PCI_EXP_DEVCTL) & PCI_EXP_DEVCTL_BCR_FLR;
    }
    trace_pcie_hello_reset(s->label, flr ? "flr" : "reset");

    timer_del(&s->cmd_timer);
    s->scratch = 0;
    s->status = 0;
    s->buf_len = 0;
    s->int_status = 0;
    s->int_enable = 0;
    s->cur_cmd = 0;
    s->intx_level = false;      /* the PCI core deasserts INTx itself */
    memset(s->buf, 0, sizeof(s->buf));
}

static void pcie_hello_config_write(PCIDevice *pdev, uint32_t addr,
                                    uint32_t val, int len)
{
    pci_default_write_config(pdev, addr, val, len);
    pcie_cap_flr_write_config(pdev, addr, val, len);
}

static void pcie_hello_add_pm_cap(PCIDevice *pdev, Error **errp)
{
    uint8_t off = PCIE_HELLO_PM_OFFSET;

    if (pci_pm_init(pdev, off, errp) < 0) {
        return;
    }
    pci_set_word(pdev->config + off + PCI_PM_PMC, PCI_PM_CAP_VER_1_2);
    pci_set_word(pdev->config + off + PCI_PM_CTRL, PCI_PM_CTRL_NO_SOFT_RESET);
    pci_set_word(pdev->wmask + off + PCI_PM_CTRL, PCI_PM_CTRL_STATE_MASK);
}

static void pcie_hello_realize(PCIDevice *pdev, Error **errp)
{
    ERRP_GUARD();
    PCIeHelloState *s = PCIE_HELLO(pdev);
    Error *err = NULL;
    int ret;

    if (!pci_bus_is_express(pci_get_bus(pdev))) {
        error_setg(errp, "%s must be plugged into a PCI Express bus "
                   "(e.g. a pcie-root-port on the q35 machine)",
                   TYPE_PCIE_HELLO);
        return;
    }

    s->label = g_strdup(DEVICE(pdev)->id ? DEVICE(pdev)->id : TYPE_PCIE_HELLO);
    pci_config_set_interrupt_pin(pdev->config, 1);

    pcie_hello_add_pm_cap(pdev, errp);
    if (*errp) {
        return;
    }

    if (s->use_msi) {
        ret = msi_init(pdev, PCIE_HELLO_MSI_OFFSET, 1, true, false, &err);
        if (ret == -ENOTSUP) {
            warn_report_err(err);   /* no MSI on this board; INTx only */
            err = NULL;
        } else if (ret < 0) {
            error_propagate(errp, err);
            return;
        }
    }

    ret = pcie_endpoint_cap_init(pdev, PCIE_HELLO_EXP_OFFSET);
    if (ret < 0) {
        error_setg(errp, "failed to add PCI Express capability");
        goto err_msi;
    }
    pcie_cap_flr_init(pdev);
    pcie_cap_deverr_init(pdev);

    memory_region_init_io(&s->mmio, OBJECT(s), &pcie_hello_mmio_ops, s,
                          "pcie-hello-mmio", PCIE_HELLO_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &s->mmio);

    if (s->use_msix) {
        ret = msix_init_exclusive_bar(pdev, PCIE_HELLO_MSIX_VECTORS,
                                      PCIE_HELLO_MSIX_BAR, &err);
        if (ret == -ENOTSUP) {
            warn_report_err(err);
            err = NULL;
        } else if (ret < 0) {
            error_propagate(errp, err);
            goto err_msi;
        } else {
            /* msix_notify() ignores vectors that are not marked in use */
            msix_vector_use(pdev, 0);
        }
    }

    timer_init_ms(&s->cmd_timer, QEMU_CLOCK_VIRTUAL, pcie_hello_cmd_done, s);
    return;

err_msi:
    msi_uninit(pdev);
}

static void pcie_hello_exit(PCIDevice *pdev)
{
    PCIeHelloState *s = PCIE_HELLO(pdev);

    timer_del(&s->cmd_timer);
    if (msix_present(pdev)) {
        msix_vector_unuse(pdev, 0);
        msix_uninit_exclusive_bar(pdev);
    }
    msi_uninit(pdev);
    g_free(s->label);
}

static void pcie_hello_instance_init(Object *obj)
{
    PCIeHelloState *s = PCIE_HELLO(obj);

    /* A plain QOM property, so it can also be changed at runtime (qom-set) */
    s->latency_ms = PCIE_HELLO_DEFAULT_LATENCY_MS;
    object_property_add_uint32_ptr(obj, "latency-ms", &s->latency_ms,
                                   OBJ_PROP_FLAG_READWRITE);
}

static const Property pcie_hello_props[] = {
    DEFINE_PROP_UINT32("serial", PCIeHelloState, serial, 0),
    DEFINE_PROP_BOOL("msix", PCIeHelloState, use_msix, true),
    DEFINE_PROP_BOOL("msi", PCIeHelloState, use_msi, true),
};

static const VMStateDescription vmstate_pcie_hello = {
    .name = TYPE_PCIE_HELLO,
    .unmigratable = 1,
};

static void pcie_hello_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pcie_hello_realize;
    k->exit = pcie_hello_exit;
    k->config_write = pcie_hello_config_write;
    k->vendor_id = PCIE_HELLO_VENDOR_ID;
    k->device_id = PCIE_HELLO_DEVICE_ID;
    k->revision = PCIE_HELLO_REVISION;
    k->class_id = PCI_CLASS_OTHERS;

    rc->phases.hold = pcie_hello_reset_hold;

    dc->desc = "PCI Express hello-world endpoint";
    dc->vmsd = &vmstate_pcie_hello;
    device_class_set_props(dc, pcie_hello_props);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo pcie_hello_types[] = {
    {
        .name          = TYPE_PCIE_HELLO,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(PCIeHelloState),
        .instance_init = pcie_hello_instance_init,
        .class_init    = pcie_hello_class_init,
        .interfaces    = (const InterfaceInfo[]) {
            { INTERFACE_PCIE_DEVICE },
            { },
        },
    },
};

DEFINE_TYPES(pcie_hello_types)
