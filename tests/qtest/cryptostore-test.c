/*
 * qtest for pcie-cryptostore and pcie-cryptorecovery.
 *
 * Drives BAR0 directly, with no guest OS (threat model section 13, layer 1).
 * Test names carry the requirement they verify. Tests that need fault hooks
 * or a clock offset run only when CAPS.FAULT_HOOKS is set (test builds,
 * SR-29) and are skipped otherwise.
 *
 * The devices sit on pcie.0 (q35) because qtest has no firmware to
 * configure root ports; the device logic does not depend on the topology.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include <math.h>
#include "qemu/cutils.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "qobject/qdict.h"
#include "hw/pci/pci_regs.h"
#include "cryptostore_regs.h"
#include "cryptostore_format.h"

#define IMG_SECTORS     8192u                       /* 4 MiB of data */
#define IMG_SIZE        (CSF_DATA_OFFSET + IMG_SECTORS * CSF_SECTOR)
#define PW_GOOD         "correct horse battery staple"
#define PW_BAD          "wrong password"
#define PW_NEW          "a brand new passphrase"

static char *tmpdir;
static char *template_img;          /* formatted with PW_GOOD, no recovery */
static char *template_rec_img;      /* formatted with PW_GOOD and recovery */
static char *template_rec_key;      /* the matching recovery-device image */

typedef struct Cs {
    QTestState *qts;
    QPCIBus *bus;
    QPCIDevice *dev;
    QPCIBar bar;
    QPCIDevice *rdev;
    QPCIBar rbar;
} Cs;

/* ---- image files ---- */

static char *new_path(const char *name)
{
    static int n;

    return g_strdup_printf("%s/%s-%d.img", tmpdir, name, n++);
}

static char *blank_image(uint64_t size)
{
    char *p = new_path("blank");
    int fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0600);

    g_assert(fd >= 0);
    g_assert(ftruncate(fd, size) == 0);
    close(fd);
    return p;
}

static char *copy_image(const char *src)
{
    char *p = new_path("copy");
    gchar *data;
    gsize len;

    g_assert(g_file_get_contents(src, &data, &len, NULL));
    g_assert(g_file_set_contents(p, data, len, NULL));
    g_free(data);
    return p;
}

static void file_rw(const char *path, off_t off, void *buf, size_t len, bool write)
{
    int fd = open(path, O_RDWR);

    g_assert(fd >= 0);
    if (write) {
        g_assert(pwrite(fd, buf, len, off) == (ssize_t)len);
    } else {
        g_assert(pread(fd, buf, len, off) == (ssize_t)len);
    }
    close(fd);
}

static void set_fail_record(const char *path, uint32_t count)
{
    uint8_t rec[CSF_FAIL_SIZE];

    csf_encode_fail(count, 0, rec);
    file_rw(path, CSF_OFF_FAIL, rec, sizeof(rec), true);
}

/* ---- device access ---- */

static void cs_map(Cs *c)
{
    qpci_device_enable(c->dev);
    c->bar = qpci_iomap(c->dev, 0, NULL);
    if (c->rdev) {
        qpci_device_enable(c->rdev);
        c->rbar = qpci_iomap(c->rdev, 0, NULL);
    }
}

static Cs *cs_start_full(const char *img, const char *rec_img, const char *extra)
{
    Cs *c = g_new0(Cs, 1);
    g_autofree char *rec = rec_img ?
        g_strdup_printf("-drive if=none,id=r0,file=%s,format=raw "
                        "-device pcie-cryptorecovery,addr=05.0,drive=r0,id=rec0 ", rec_img) :
        g_strdup("");

    c->qts = qtest_initf("-machine q35 -drive if=none,id=d0,file=%s,format=raw %s"
                         "-device pcie-cryptostore,addr=04.0,drive=d0,id=cs0%s %s",
                         img, rec, rec_img ? ",recovery=rec0" : "", extra ? extra : "");
    c->bus = qpci_new_pc(c->qts, NULL);
    c->dev = qpci_device_find(c->bus, QPCI_DEVFN(4, 0));
    g_assert(c->dev);
    if (rec_img) {
        c->rdev = qpci_device_find(c->bus, QPCI_DEVFN(5, 0));
        g_assert(c->rdev);
    }
    cs_map(c);
    return c;
}

static Cs *cs_start(const char *img)
{
    return cs_start_full(img, NULL, NULL);
}

static void cs_stop(Cs *c)
{
    g_free(c->dev);
    g_free(c->rdev);
    qpci_free_pc(c->bus);
    qtest_quit(c->qts);
    g_free(c);
}

static uint32_t rd(Cs *c, uint32_t off)
{
    return qpci_io_readl(c->dev, c->bar, off);
}

static void wr(Cs *c, uint32_t off, uint32_t v)
{
    qpci_io_writel(c->dev, c->bar, off, v);
}

static uint32_t rrd(Cs *c, uint32_t off)
{
    return qpci_io_readl(c->rdev, c->rbar, off);
}

static void rwr(Cs *c, uint32_t off, uint32_t v)
{
    qpci_io_writel(c->rdev, c->rbar, off, v);
}

static void set_pw(Cs *c, uint32_t win, const char *pw)
{
    qpci_memwrite(c->dev, c->bar, win, pw, strlen(pw));
    wr(c, win == CS_WIN_PW_A ? CS_REG_PW_LEN : CS_REG_PW2_LEN, strlen(pw));
}

static bool fault_hooks(Cs *c)
{
    return rd(c, CS_REG_CAPS) & CS_CAPS_FAULT_HOOKS;
}

/* Issue a command and wait for it to finish; returns RESULT. */
static uint32_t cmd_timed(Cs *c, uint32_t op, double *secs)
{
    gint64 start = g_get_monotonic_time();

    wr(c, CS_REG_CMD, op);
    for (int i = 0; i < 120000 / 5; i++) {
        if (!(rd(c, CS_REG_STATUS) & CS_STATUS_BUSY)) {
            break;
        }
        g_usleep(5000);
    }
    g_assert_false(rd(c, CS_REG_STATUS) & CS_STATUS_BUSY);
    if (secs) {
        *secs = (g_get_monotonic_time() - start) / 1e6;
    }
    wr(c, CS_REG_INT_ACK, CS_INT_ALL);
    return rd(c, CS_REG_RESULT);
}

static uint32_t cmd(Cs *c, uint32_t op)
{
    return cmd_timed(c, op, NULL);
}

static uint32_t unlock(Cs *c, const char *pw)
{
    set_pw(c, CS_WIN_PW_A, pw);
    return cmd(c, CS_CMD_UNLOCK);
}

static uint32_t io(Cs *c, uint32_t op, uint64_t lba, uint32_t count)
{
    wr(c, CS_REG_LBA_LO, (uint32_t)lba);
    wr(c, CS_REG_LBA_HI, lba >> 32);
    wr(c, CS_REG_COUNT, count);
    return cmd(c, op);
}

static void qom_set_str(Cs *c, const char *path, const char *prop, const char *val)
{
    qtest_qmp_assert_success(c->qts, "{'execute': 'qom-set', 'arguments': "
                             "{'path': %s, 'property': %s, 'value': %s}}", path, prop, val);
}

static void qom_set_int(Cs *c, const char *path, const char *prop, int64_t val)
{
    qtest_qmp_assert_success(c->qts, "{'execute': 'qom-set', 'arguments': "
                             "{'path': %s, 'property': %s, 'value': %" PRId64 "}}",
                             path, prop, val);
}

static void flr(Cs *c)
{
    uint8_t cap = qpci_find_capability(c->dev, PCI_CAP_ID_EXP, 0);
    uint16_t ctl;

    g_assert(cap);
    ctl = qpci_config_readw(c->dev, cap + PCI_EXP_DEVCTL);
    qpci_config_writew(c->dev, cap + PCI_EXP_DEVCTL, ctl | PCI_EXP_DEVCTL_BCR_FLR);
    cs_map(c);
}

static void sys_reset(Cs *c)
{
    qtest_system_reset(c->qts);
    cs_map(c);
}

/* Advance the device's view of the host clock past any backoff (test builds). */
static void skip_backoff(Cs *c)
{
    static int64_t offset;

    offset += CS_BACKOFF_CAP_S * 1000 + 1000;
    qom_set_int(c, "/machine/peripheral/cs0", "x-time-offset-ms", offset);
}

/* ---- templates ---- */

static char *format_new(const char *rec_img)
{
    char *img = blank_image(IMG_SIZE);
    Cs *c = cs_start_full(img, rec_img, NULL);

    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_UNFORMATTED);
    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    g_assert_cmpuint(cmd(c, CS_CMD_FORMAT), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    cs_stop(c);
    return img;
}

/* ---- tests ---- */

/* M1 gate, SR-16/35: blank -> UNFORMATTED, garbage or tiny -> ERROR. */
static void test_realize_states(void)
{
    char *blank = blank_image(IMG_SIZE), *tiny = blank_image(100), *junk = blank_image(IMG_SIZE);
    uint8_t garbage[64];
    Cs *c;

    memset(garbage, 0x41, sizeof(garbage));
    file_rw(junk, 0x40, garbage, sizeof(garbage), true);

    c = cs_start(blank);
    g_assert_cmpuint(rd(c, CS_REG_ID), ==, CS_MAGIC);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_UNFORMATTED);
    g_assert_cmpuint(rd(c, CS_REG_SLOT_MAP), ==, 0);
    cs_stop(c);

    c = cs_start(tiny);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_ERROR);
    cs_stop(c);

    /* A non-zero header that doesn't parse is ERROR, never UNFORMATTED (C5). */
    c = cs_start(junk);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_ERROR);
    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    g_assert_cmpuint(cmd(c, CS_CMD_FORMAT), ==, CS_ERR_STATE);
    cs_stop(c);
    g_free(blank);
    g_free(tiny);
    g_free(junk);
}

/* M1 gate: header written by FORMAT and re-parsed; SR-35, SR-36, SR-03. */
static void test_format_reparse(void)
{
    char *img = copy_image(template_img);
    uint8_t hdr[CSF_HDR_SIZE], sector[CSF_SECTOR];
    CsfHeader h;
    const char *why;
    Cs *c;

    file_rw(img, 0, hdr, sizeof(hdr), false);
    g_assert_cmpint(csf_parse(hdr, IMG_SIZE, &h, &why), ==, CSF_VALID);
    g_assert_cmpuint(h.capacity, ==, IMG_SECTORS);
    g_assert_cmpuint(h.slot[0].type, ==, CSF_TYPE_PASSWORD);
    g_assert_cmpuint(h.slot[0].iters, >=, CSF_PBKDF2_MIN_ITERS);
    g_assert_cmpuint(h.fail_count, ==, 0);

    /* SR-36: the data area is random, not zero. */
    for (uint32_t s = 0; s < IMG_SECTORS; s += 997) {
        file_rw(img, CSF_DATA_OFFSET + (off_t)s * CSF_SECTOR, sector, sizeof(sector), false);
        g_assert_false(buffer_is_zero(sector, sizeof(sector)));
    }

    c = cs_start(img);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_cmpuint(rd(c, CS_REG_SLOT_MAP), ==, 1);
    g_assert_cmpuint(rd(c, CS_REG_UUID0), ==, csf_le32(h.uuid));
    g_assert_cmpuint(rd(c, CS_REG_CAPACITY_LO), ==, 0);    /* hidden until unlocked (B4) */
    /* SR-35: FORMAT is refused on a formatted image. */
    set_pw(c, CS_WIN_PW_A, PW_BAD);
    g_assert_cmpuint(cmd(c, CS_CMD_FORMAT), ==, CS_ERR_STATE);
    cs_stop(c);
    g_free(img);
}

/* SR-04, datasheet 7: counted before verification, reset on success. */
static void test_unlock_counter(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 1);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_UNLOCKED);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 0);
    g_assert_cmpuint(rd(c, CS_REG_CAPACITY_LO), ==, IMG_SECTORS);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_STATE);
    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_cmpuint(rd(c, CS_REG_CAPACITY_LO), ==, 0);
    /* PW_LEN out of range is ERR_RANGE and not counted. */
    wr(c, CS_REG_PW_LEN, 0);
    g_assert_cmpuint(cmd(c, CS_CMD_UNLOCK), ==, CS_ERR_RANGE);
    wr(c, CS_REG_PW_LEN, CS_PW_MAX + 1);
    g_assert_cmpuint(cmd(c, CS_CMD_UNLOCK), ==, CS_ERR_RANGE);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 0);
    cs_stop(c);
    g_free(img);
}

/* SR-01: data commands refused and nothing transferred unless UNLOCKED. */
static void test_locked_refuses_data(void)
{
    char *blank = blank_image(IMG_SIZE), *img = copy_image(template_img);
    uint8_t buf[64];
    Cs *c = cs_start(blank);

    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_LOCKED);
    cs_stop(c);

    c = cs_start(img);
    for (uint32_t op = CS_CMD_READ; op <= CS_CMD_FLUSH; op++) {
        g_assert_cmpuint(io(c, op, 0, 1), ==, CS_ERR_LOCKED);
    }
    memset(buf, 0x5a, sizeof(buf));
    qpci_memwrite(c->dev, c->bar, CS_WIN_DATA, buf, sizeof(buf));  /* ignored */
    qpci_memread(c->dev, c->bar, CS_WIN_DATA, buf, sizeof(buf));
    g_assert_true(buffer_is_zero(buf, sizeof(buf)));
    cs_stop(c);
    g_free(blank);
    g_free(img);
}

/* SR-06, M3 gate: round trip; known plaintext absent; identical sectors differ. */
static void test_data_path(void)
{
    char *img = copy_image(template_img);
    static const char marker[] = "KNOWN-PLAINTEXT-MARKER-7f3a9c";
    uint8_t pt[4 * CSF_SECTOR], back[4 * CSF_SECTOR], c0[CSF_SECTOR], c1[CSF_SECTOR];
    g_autofree gchar *raw = NULL;
    gsize rawlen;
    Cs *c = cs_start(img);

    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    for (size_t i = 0; i < sizeof(pt); i += sizeof(marker)) {
        memcpy(pt + i, marker, MIN(sizeof(marker), sizeof(pt) - i));
    }
    /* Sectors 100 and 101 get identical plaintext. */
    memcpy(pt + CSF_SECTOR, pt, CSF_SECTOR);
    qpci_memwrite(c->dev, c->bar, CS_WIN_DATA, pt, sizeof(pt));
    g_assert_cmpuint(io(c, CS_CMD_WRITE, 100, 4), ==, CS_OK);
    g_assert_cmpuint(io(c, CS_CMD_FLUSH, 0, 0), ==, CS_OK);

    g_assert_cmpuint(io(c, CS_CMD_READ, 100, 4), ==, CS_OK);
    qpci_memread(c->dev, c->bar, CS_WIN_DATA, back, sizeof(back));
    g_assert_cmpmem(back, sizeof(back), pt, sizeof(pt));
    /* The last sector of the device works; READ zeroes the rest of the window. */
    g_assert_cmpuint(io(c, CS_CMD_READ, IMG_SECTORS - 1, 1), ==, CS_OK);
    qpci_memread(c->dev, c->bar, CS_WIN_DATA + CSF_SECTOR, back, CSF_SECTOR);
    g_assert_true(buffer_is_zero(back, CSF_SECTOR));

    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
    qpci_memread(c->dev, c->bar, CS_WIN_DATA, back, sizeof(back));
    g_assert_true(buffer_is_zero(back, sizeof(back)));
    cs_stop(c);

    g_assert(g_file_get_contents(img, &raw, &rawlen, NULL));
    g_assert_null(memmem(raw, rawlen, marker, strlen(marker)));
    file_rw(img, CSF_DATA_OFFSET + 100 * CSF_SECTOR, c0, sizeof(c0), false);
    file_rw(img, CSF_DATA_OFFSET + 101 * CSF_SECTOR, c1, sizeof(c1), false);
    g_assert_cmpint(memcmp(c0, c1, CSF_SECTOR), !=, 0);
    g_free(img);
}

/* SR-10: bounds, overflow-safe. */
static void test_bounds(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 0), ==, CS_ERR_RANGE);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, CS_MAX_SECTORS + 1), ==, CS_ERR_RANGE);
    g_assert_cmpuint(io(c, CS_CMD_READ, IMG_SECTORS, 1), ==, CS_ERR_RANGE);
    g_assert_cmpuint(io(c, CS_CMD_READ, IMG_SECTORS - 1, 2), ==, CS_ERR_RANGE);
    g_assert_cmpuint(io(c, CS_CMD_READ, UINT64_MAX, 2), ==, CS_ERR_RANGE);
    g_assert_cmpuint(io(c, CS_CMD_WRITE, UINT64_MAX - 1, 8), ==, CS_ERR_RANGE);
    g_assert_cmpuint(io(c, CS_CMD_READ, IMG_SECTORS - 8, 8), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_UNLOCKED);
    cs_stop(c);
    g_free(img);
}

/* SR-09: password windows are write-only and cleared after each command. */
static void test_windows(void)
{
    char *img = copy_image(template_img);
    uint8_t buf[CS_WIN_PW_SIZE];
    Cs *c = cs_start(img);

    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    set_pw(c, CS_WIN_PW_B, PW_NEW);
    qpci_memread(c->dev, c->bar, CS_WIN_PW_A, buf, sizeof(buf));
    g_assert_true(buffer_is_zero(buf, sizeof(buf)));
    qpci_memread(c->dev, c->bar, CS_WIN_PW_B, buf, sizeof(buf));
    g_assert_true(buffer_is_zero(buf, sizeof(buf)));
    /* Invalid register accesses are ignored (logged as guest errors). */
    qpci_io_writeb(c->dev, c->bar, CS_REG_STATE, 3);
    wr(c, CS_REG_STATE, CS_STATE_UNLOCKED);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    cs_stop(c);
    g_free(img);
}

/* SR-04, V11: counter survives system reset and restart; backoff after 3. */
static void test_counter_persists(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);
    g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);
    sys_reset(c);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 2);
    cs_stop(c);

    c = cs_start(img);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 2);
    g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);       /* third: free */
    /* Fourth attempt within 1 s: refused, not counted, no KDF (11.10). */
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_BACKOFF);
    g_assert_cmpuint(rd(c, CS_REG_RESULT_AUX), >=, 1);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 3);
    g_usleep(1100 * 1000);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 0);
    cs_stop(c);
    g_free(img);
}

/* SR-05 (qtest part, R10): wrong and right passwords both complete at >= 1 s. */
static void test_timing_padding(void)
{
    char *img = copy_image(template_img);
    double t_bad, t_good;
    Cs *c = cs_start(img);

    set_pw(c, CS_WIN_PW_A, PW_BAD);
    g_assert_cmpuint(cmd_timed(c, CS_CMD_UNLOCK, &t_bad), ==, CS_ERR_AUTH);
    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    g_assert_cmpuint(cmd_timed(c, CS_CMD_UNLOCK, &t_good), ==, CS_OK);
    g_test_message("UNLOCK wrong %.3f s, right %.3f s", t_bad, t_good);
    g_assert_cmpfloat(t_bad, >=, 0.99);
    g_assert_cmpfloat(t_good, >=, 0.99);
    g_assert_cmpfloat(fabs(t_bad - t_good), <, 0.25);
    cs_stop(c);
    g_free(img);
}

/* SR-02, SR-33: reset and FLR lock and zeroize. */
static void test_reset_flr_lock(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    flr(c);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_cmpuint(rd(c, CS_REG_CAPACITY_LO), ==, 0);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_LOCKED);

    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    sys_reset(c);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_LOCKED);
    cs_stop(c);
    g_free(img);
}

/* SR-40, B3: LOCK and FLR during the KDF job cancel it; the result is discarded. */
static void test_lock_cancels_kdf(void)
{
    char *img = copy_image(template_img);
    double t;
    Cs *c = cs_start(img);

    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    wr(c, CS_REG_CMD, CS_CMD_UNLOCK);
    g_usleep(50 * 1000);
    g_assert_true(rd(c, CS_REG_STATUS) & CS_STATUS_BUSY);
    g_assert_cmpuint(cmd_timed(c, CS_CMD_LOCK, &t), ==, CS_OK);
    g_assert_cmpfloat(t, <, 0.5);
    g_usleep(2500 * 1000);          /* the worker finishes; nothing may apply */
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_cmpuint(rd(c, CS_REG_RESULT), ==, CS_OK);
    g_assert_false(rd(c, CS_REG_STATUS) & CS_STATUS_BUSY);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 1);   /* counted before the KDF */

    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    wr(c, CS_REG_CMD, CS_CMD_UNLOCK);
    g_usleep(50 * 1000);
    flr(c);
    g_usleep(2500 * 1000);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
    g_assert_false(rd(c, CS_REG_STATUS) & CS_STATUS_BUSY);
    cs_stop(c);
    g_free(img);
}

/* SR-07, SR-39, SR-41: tampering. */
static void test_tamper(void)
{
    char *a = copy_image(template_img), *b = format_new(NULL);
    uint8_t buf[8];
    Cs *c;

    /* Iterations below the floor: rejected at parse. */
    {
        char *img = copy_image(a);
        uint8_t it[4];
        csf_put_le32(it, 1000);
        file_rw(img, CSF_OFF_SLOTS + CSF_SLOT_OFF_ITERS, it, 4, true);
        c = cs_start(img);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_ERROR);
        cs_stop(c);
        g_free(img);
    }
    /* A keyslot copied from another image (different UUID and DEK): ERR_AUTH. */
    {
        char *img = copy_image(a);
        uint8_t slot[CSF_SLOT_SIZE];
        file_rw(b, CSF_OFF_SLOTS, slot, sizeof(slot), false);
        file_rw(img, CSF_OFF_SLOTS, slot, sizeof(slot), true);
        c = cs_start(img);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
        g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_AUTH);
        cs_stop(c);
        g_free(img);
    }
    /* A header field changed: correct password gives ERR_INTEGRITY and ERROR. */
    {
        char *img = copy_image(a);
        csf_put_le64(buf, IMG_SECTORS - 1);
        file_rw(img, CSF_OFF_CAPACITY, buf, 8, true);
        c = cs_start(img);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
        g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);
        g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_INTEGRITY);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_ERROR);
        g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_LOCKED);
        cs_stop(c);
        {
            uint8_t hdr[CSF_HDR_SIZE];
            CsfHeader h;
            file_rw(img, 0, hdr, sizeof(hdr), false);
            g_assert_cmpint(csf_parse(hdr, IMG_SIZE, &h, NULL), ==, CSF_VALID);
            g_assert_cmpuint(h.fail_count, ==, 0);   /* B5: counter reset */
        }
        g_free(img);
    }
    /* A corrupt failure record means LOCKED_OUT (R7). */
    {
        char *img = copy_image(a);
        uint8_t rec[4] = { 1, 0, 0, 0 };
        file_rw(img, CSF_OFF_FAIL + 4, rec, 4, true);
        c = cs_start(img);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);
        g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_LOCKED_OUT);
        cs_stop(c);
        g_free(img);
    }
    g_free(a);
    g_free(b);
}

/* SR-32, 11.4: PASSWD writes a fresh slot and retires the old one. */
static void test_passwd(void)
{
    char *img = copy_image(template_img);
    uint8_t before[CSF_HDR_SIZE], after[CSF_HDR_SIZE];
    CsfHeader hb, ha;
    int newslot = -1;
    Cs *c;

    file_rw(img, 0, before, sizeof(before), false);
    g_assert_cmpint(csf_parse(before, IMG_SIZE, &hb, NULL), ==, CSF_VALID);

    c = cs_start(img);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    set_pw(c, CS_WIN_PW_A, PW_BAD);
    set_pw(c, CS_WIN_PW_B, PW_NEW);
    g_assert_cmpuint(cmd(c, CS_CMD_PASSWD), ==, CS_ERR_AUTH);    /* counted (R8) */
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 1);
    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    set_pw(c, CS_WIN_PW_B, PW_NEW);
    g_assert_cmpuint(cmd(c, CS_CMD_PASSWD), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_UNLOCKED);
    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_AUTH);
    g_assert_cmpuint(unlock(c, PW_NEW), ==, CS_OK);
    cs_stop(c);

    file_rw(img, 0, after, sizeof(after), false);
    g_assert_cmpint(csf_parse(after, IMG_SIZE, &ha, NULL), ==, CSF_VALID);
    g_assert_cmpuint(ha.slot[0].state, ==, CSF_SLOT_INACTIVE);
    for (int i = 0; i < CSF_NUM_SLOTS; i++) {
        if (ha.slot[i].state == CSF_SLOT_ACTIVE) {
            newslot = i;
        }
    }
    g_assert_cmpint(newslot, >, 0);
    g_assert_cmpmem(ha.uuid, 16, hb.uuid, 16);
    g_assert_cmpint(memcmp(ha.slot[newslot].salt, hb.slot[0].salt, CSF_SALT_LEN), !=, 0);
    g_free(img);
}

/* SR-37, SR-38, Section 9: recovery device, both configurations. */
static void test_recovery(void)
{
    char *img = copy_image(template_rec_img), *key = copy_image(template_rec_key);
    char *norec = copy_image(template_img);
    Cs *c;

    /* Absent: no capability, ERR_NO_RECOVERY. */
    c = cs_start(norec);
    g_assert_false(rd(c, CS_REG_CAPS) & CS_CAPS_RECOVERY);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_ERR_NO_RECOVERY);
    cs_stop(c);

    c = cs_start_full(img, key, NULL);
    g_assert_true(rd(c, CS_REG_CAPS) & CS_CAPS_RECOVERY);
    g_assert_true(rd(c, CS_REG_SLOT_MAP) & CS_SLOT_MAP_RECOVERY);
    g_assert_cmpuint(rrd(c, CR_REG_ID), ==, CR_MAGIC);
    g_assert_true(rrd(c, CR_REG_STATUS) & CR_STATUS_KEY_PRESENT);
    g_assert_cmpuint(rrd(c, CR_REG_UUID0), ==, rd(c, CS_REG_UUID0));

    /* Neither armed, guest only, host only: all refused and not counted. */
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_ERR_NOT_ARMED);
    rwr(c, CR_REG_CMD, CR_CMD_ARM);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_ERR_NOT_ARMED);
    rwr(c, CR_REG_CMD, CR_CMD_DISARM);
    qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_ERR_NOT_ARMED);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 0);

    /* Guest arm plus host presence: RECOVERED, then a forced password change. */
    rwr(c, CR_REG_CMD, CR_CMD_ARM);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_RECOVERED);
    g_assert_true(rrd(c, CR_REG_STATUS) & CR_STATUS_RELEASED);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_PASSWD_REQUIRED);
    set_pw(c, CS_WIN_PW_B, PW_NEW);
    g_assert_cmpuint(cmd(c, CS_CMD_PASSWD), ==, CS_OK);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_UNLOCKED);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_OK);
    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_AUTH);   /* old password gone */
    g_assert_cmpuint(unlock(c, PW_NEW), ==, CS_OK);
    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);

    /* Release once per boot: armed again, still refused; allowed after reset. */
    rwr(c, CR_REG_CMD, CR_CMD_ARM);
    qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_ERR_NOT_ARMED);
    sys_reset(c);
    g_assert_false(rrd(c, CR_REG_STATUS) & CR_STATUS_RELEASED);
    rwr(c, CR_REG_CMD, CR_CMD_ARM);
    qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_OK);
    cs_stop(c);
    g_free(img);
    g_free(key);
    g_free(norec);
}

/* Section 9, 11.10: LOCKED_OUT is left only through RECOVER. */
static void test_locked_out_recover(void)
{
    char *img = copy_image(template_rec_img), *key = copy_image(template_rec_key);
    Cs *c;

    set_fail_record(img, CS_LOCKOUT_N);
    c = cs_start_full(img, key, NULL);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_LOCKED_OUT);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, CS_LOCKOUT_N);
    rwr(c, CR_REG_CMD, CR_CMD_ARM);
    qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_OK);     /* no backoff here */
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_RECOVERED);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, 0);
    cs_stop(c);
    g_free(img);
    g_free(key);
}

/* Section 9: ENROLL_RECOVERY adds a recovery slot to an image formatted without one. */
static void test_enroll_recovery(void)
{
    char *img = copy_image(template_img), *key = blank_image(4096);
    Cs *c = cs_start_full(img, key, NULL);

    g_assert_false(rd(c, CS_REG_SLOT_MAP) & CS_SLOT_MAP_RECOVERY);
    g_assert_cmpuint(cmd(c, CS_CMD_ENROLL_RECOVERY), ==, CS_ERR_STATE);  /* locked */
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    g_assert_cmpuint(cmd(c, CS_CMD_ENROLL_RECOVERY), ==, CS_OK);
    g_assert_true(rd(c, CS_REG_SLOT_MAP) & CS_SLOT_MAP_RECOVERY);
    g_assert_cmpuint(cmd(c, CS_CMD_ENROLL_RECOVERY), ==, CS_ERR_STATE);  /* only one */
    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
    rwr(c, CR_REG_CMD, CR_CMD_ARM);
    qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
    g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_OK);
    cs_stop(c);
    g_free(img);
    g_free(key);
}

/* Datasheet 5/6: reserved and unknown commands. */
static void test_misc_commands(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    g_assert_cmpuint(cmd(c, CS_CMD_REKEY), ==, CS_ERR_UNSUPPORTED);
    g_assert_cmpuint(cmd(c, 0x7f), ==, CS_ERR_INVALID_CMD);
    g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);       /* LOCK valid in every state */
    set_pw(c, CS_WIN_PW_A, PW_GOOD);
    set_pw(c, CS_WIN_PW_B, PW_NEW);
    g_assert_cmpuint(cmd(c, CS_CMD_PASSWD), ==, CS_ERR_STATE);
    cs_stop(c);
    g_free(img);
}

/* SR-12: no migration or snapshot, in any state. */
static void test_migration_refused(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);
    QDict *rsp;

    for (int round = 0; round < 2; round++) {
        rsp = qtest_qmp(c->qts, "{'execute': 'migrate', 'arguments': "
                        "{'uri': 'exec:cat > /dev/null'}}");
        g_assert_true(qdict_haskey(rsp, "error"));
        qobject_unref(rsp);
        if (round == 0) {
            g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
        }
    }
    cs_stop(c);
    g_free(img);
}

/* SR-30, M1 gate: the image cannot be opened by a second QEMU. */
static void test_image_locking(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);
    g_autofree char *drive = g_strdup_printf("if=none,id=d0,file=%s,format=raw", img);
    g_autofree char *out = NULL, *err = NULL;
    const char *argv[] = {
        "timeout", "20", qtest_qemu_binary(NULL), "-machine", "q35", "-accel", "qtest",
        "-display", "none", "-S", "-drive", drive,
        "-device", "pcie-cryptostore,drive=d0", NULL,
    };
    int status;

    g_assert(g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                          &out, &err, &status, NULL));
    g_test_message("second QEMU: %s", err);
    /* Must exit with an error by itself: 124 would mean timeout(1) killed it. */
    g_assert_true(WIFEXITED(status) && WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 124);
    g_assert_nonnull(strstr(err, "lock"));
    cs_stop(c);
    g_free(img);
}

/* ---- test builds only (SR-29) ---- */

static bool skip_unless_hooks(Cs *c)
{
    if (!fault_hooks(c)) {
        g_test_skip("needs a test build (CAPS.FAULT_HOOKS)");
        return true;
    }
    return false;
}

/* SR-04, 11.10: backoff schedule and LOCKED_OUT at N = 10. */
static void test_lockout_at_n(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    if (skip_unless_hooks(c)) {
        goto out;
    }
    for (uint32_t f = 0; f < CS_LOCKOUT_N; f++) {
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
        if (f >= CS_FREE_FAILURES) {
            uint32_t want = MIN(1u << (f - CS_FREE_FAILURES), (unsigned)CS_BACKOFF_CAP_S);
            g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_BACKOFF);
            g_assert_cmpuint(rd(c, CS_REG_RESULT_AUX), <=, want);
            g_assert_cmpuint(rd(c, CS_REG_RESULT_AUX), >=, want - 1 ? want - 1 : 1);
            skip_backoff(c);
        }
        g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);
        g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), ==, f + 1);
    }
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);
    g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_ERR_LOCKED_OUT);
out:
    cs_stop(c);
    g_free(img);
}

typedef struct FaultCase {
    const char *hook;
    const char *setup;      /* "locked", "unlocked" */
    uint32_t op;
} FaultCase;

/* SR-22 to SR-27: every simulated fault is detected and answered the same way. */
static void test_fault(gconstpointer data)
{
    const FaultCase *fc = data;
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    if (skip_unless_hooks(c)) {
        goto out;
    }
    if (!strcmp(fc->setup, "unlocked")) {
        g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
    }
    if (!strcmp(fc->hook, "f2")) {
        /* Put the device inside a backoff window so the glitch would matter. */
        for (int i = 0; i < CS_FREE_FAILURES; i++) {
            g_assert_cmpuint(unlock(c, PW_BAD), ==, CS_ERR_AUTH);
        }
    }
    qom_set_str(c, "/machine/peripheral/cs0", "x-fault", fc->hook);
    if (fc->op == CS_CMD_UNLOCK || fc->op == CS_CMD_PASSWD) {
        set_pw(c, CS_WIN_PW_A, !strcmp(fc->hook, "f9") ? PW_BAD : PW_GOOD);
        set_pw(c, CS_WIN_PW_B, PW_NEW);
        g_assert_cmpuint(cmd(c, fc->op), ==, CS_ERR_FAULT);
    } else if (fc->op == CS_CMD_WRITE || fc->op == CS_CMD_READ) {
        uint64_t lba = !strcmp(fc->hook, "f6") ? IMG_SECTORS : 0;
        g_assert_cmpuint(io(c, fc->op, lba, 1), ==, CS_ERR_FAULT);
    } else {
        g_assert_cmpuint(cmd(c, fc->op), ==, CS_ERR_FAULT);
    }
    /* SR-27: keys gone, LOCKED_OUT, counted, and the hook fired exactly once. */
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);
    g_assert_cmpuint(rd(c, CS_REG_FAIL_COUNT), >=, CS_LOCKOUT_N);
    g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_LOCKED);
    cs_stop(c);
    c = cs_start(img);
    g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);   /* persisted */
out:
    cs_stop(c);
    g_free(img);
}

/* F4: a data command while LOCKED whose first lock check is glitched. */
static void test_fault_f4(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    if (!skip_unless_hooks(c)) {
        qom_set_str(c, "/machine/peripheral/cs0", "x-fault", "f4");
        g_assert_cmpuint(io(c, CS_CMD_READ, 0, 1), ==, CS_ERR_FAULT);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);
    }
    cs_stop(c);
    g_free(img);
}

/* F8: the recovery device's release-once check is glitched on a second release. */
static void test_fault_f8(void)
{
    char *img = copy_image(template_rec_img), *key = copy_image(template_rec_key);
    Cs *c = cs_start_full(img, key, NULL);

    if (!skip_unless_hooks(c)) {
        rwr(c, CR_REG_CMD, CR_CMD_ARM);
        qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
        g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_OK);
        g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
        rwr(c, CR_REG_CMD, CR_CMD_ARM);
        qtest_qom_set_bool(c->qts, "/machine/peripheral/rec0", "host-armed", true);
        qom_set_str(c, "/machine/peripheral/rec0", "x-fault", "f8");
        g_assert_cmpuint(cmd(c, CS_CMD_RECOVER), ==, CS_ERR_FAULT);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED_OUT);
    }
    cs_stop(c);
    g_free(img);
    g_free(key);
}

/* Issue @op with a power cut after the @k-th metadata write; wait for QEMU to die. */
static void cmd_with_power_cut(Cs *c, uint32_t op, uint32_t k)
{
    qom_set_int(c, "/machine/peripheral/cs0", "x-crash-after-writes", k);
    qtest_set_expected_status(c->qts, 99);
    wr(c, CS_REG_CMD, op);
    for (int i = 0; i < 6000 && qtest_probe_child(c->qts); i++) {
        g_usleep(10 * 1000);
    }
    g_assert_false(qtest_probe_child(c->qts));
    cs_stop(c);
}

/*
 * SR-32, M4 gate: a power cut after every metadata write of PASSWD leaves at
 * least one working password. Writes: 1 counter +1, 2 counter reset,
 * 3 new slot, 4 old slot retired.
 */
static void test_passwd_power_cut(void)
{
    static const struct { bool old_ok, new_ok; } want[] = {
        [1] = { true, false }, [2] = { true, false }, [3] = { true, true }, [4] = { false, true },
    };
    Cs *probe = cs_start(template_img);
    bool hooks = fault_hooks(probe);

    cs_stop(probe);
    if (!hooks) {
        g_test_skip("needs a test build (CAPS.FAULT_HOOKS)");
        return;
    }
    for (uint32_t k = 1; k <= 4; k++) {
        char *img = copy_image(template_img);
        uint8_t hdr[CSF_HDR_SIZE];
        bool old_ok, new_ok;
        Cs *c = cs_start(img);

        g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
        set_pw(c, CS_WIN_PW_A, PW_GOOD);
        set_pw(c, CS_WIN_PW_B, PW_NEW);
        cmd_with_power_cut(c, CS_CMD_PASSWD, k);

        file_rw(img, 0, hdr, sizeof(hdr), false);
        g_assert_cmpint(csf_parse(hdr, IMG_SIZE, NULL, NULL), ==, CSF_VALID);
        c = cs_start(img);
        g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
        old_ok = unlock(c, PW_GOOD) == CS_OK;
        if (old_ok) {
            g_assert_cmpuint(cmd(c, CS_CMD_LOCK), ==, CS_OK);
        }
        new_ok = unlock(c, PW_NEW) == CS_OK;
        g_test_message("power cut after write %u: old password %s, new password %s", k,
                       old_ok ? "works" : "rejected", new_ok ? "works" : "rejected");
        g_assert_true(old_ok || new_ok);
        g_assert_cmpint(old_ok, ==, want[k].old_ok);
        g_assert_cmpint(new_ok, ==, want[k].new_ok);
        cs_stop(c);
        g_free(img);
    }
}

/* Datasheet 10.6: a power cut between FORMAT's two header writes gives ERROR, not garbage. */
static void test_format_power_cut(void)
{
    Cs *probe = cs_start(template_img);
    bool hooks = fault_hooks(probe);

    cs_stop(probe);
    if (!hooks) {
        g_test_skip("needs a test build (CAPS.FAULT_HOOKS)");
        return;
    }
    for (uint32_t k = 1; k <= 2; k++) {
        char *img = blank_image(IMG_SIZE);
        Cs *c = cs_start(img);

        set_pw(c, CS_WIN_PW_A, PW_GOOD);
        cmd_with_power_cut(c, CS_CMD_FORMAT, k);
        c = cs_start(img);
        g_test_message("FORMAT power cut after header write %u: state %u", k,
                       rd(c, CS_REG_STATE));
        if (k == 1) {
            g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_ERROR);
        } else {
            g_assert_cmpuint(rd(c, CS_REG_STATE), ==, CS_STATE_LOCKED);
            g_assert_cmpuint(unlock(c, PW_GOOD), ==, CS_OK);
        }
        cs_stop(c);
        g_free(img);
    }
}

/* SR-34: a failing known-answer test stops the device from attaching. */
static void test_selftest_failure(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);
    bool hooks = fault_hooks(c);
    g_autofree char *drive = g_strdup_printf("if=none,id=d0,file=%s,format=raw", img);
    g_autofree char *out = NULL, *err = NULL;
    const char *argv[] = {
        "timeout", "20", qtest_qemu_binary(NULL), "-machine", "q35", "-accel", "qtest",
        "-display", "none", "-S", "-drive", drive,
        "-device", "pcie-cryptostore,drive=d0,x-fault=selftest", NULL,
    };
    int status;

    cs_stop(c);
    if (!hooks) {
        g_test_skip("needs a test build (CAPS.FAULT_HOOKS)");
        g_free(img);
        return;
    }
    g_assert(g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                          &out, &err, &status, NULL));
    /* Must exit with an error by itself: 124 would mean timeout(1) killed it. */
    g_assert_true(WIFEXITED(status) && WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 124);
    g_assert_nonnull(strstr(err, "self-test failed"));
    g_free(img);
}

/* SR-29: release builds expose no hooks. */
static void test_caps_hooks(void)
{
    char *img = copy_image(template_img);
    Cs *c = cs_start(img);

    g_test_message("CAPS.FAULT_HOOKS = %d", fault_hooks(c));
    g_assert_cmpuint(rd(c, CS_REG_CAPS) & ~(CS_CAPS_RECOVERY | CS_CAPS_FAULT_HOOKS), ==, 0);
    cs_stop(c);
    g_free(img);
}

static const FaultCase fault_cases[] = {
    { "f1", "locked", CS_CMD_UNLOCK },
    { "f2", "locked", CS_CMD_UNLOCK },
    { "f3", "unlocked", CS_CMD_LOCK },
    { "f5", "locked", CS_CMD_UNLOCK },
    { "f6", "unlocked", CS_CMD_READ },
    { "f7", "unlocked", CS_CMD_WRITE },
    { "f9", "locked", CS_CMD_UNLOCK },
    { "cfi", "locked", CS_CMD_UNLOCK },
    { "jitter", "locked", CS_CMD_UNLOCK },
};

int main(int argc, char **argv)
{
    char *key;
    int ret;

    g_test_init(&argc, &argv, NULL);
    tmpdir = g_dir_make_tmp("cryptostore-test-XXXXXX", NULL);
    g_assert(tmpdir);

    /* Formatted templates, created once and copied per test. */
    template_img = format_new(NULL);
    key = blank_image(4096);
    template_rec_img = format_new(key);
    template_rec_key = key;

    qtest_add_func("/cryptostore/realize-states", test_realize_states);
    qtest_add_func("/cryptostore/format-reparse", test_format_reparse);
    qtest_add_func("/cryptostore/sr04-unlock-counter", test_unlock_counter);
    qtest_add_func("/cryptostore/sr01-locked-refuses-data", test_locked_refuses_data);
    qtest_add_func("/cryptostore/sr06-data-path", test_data_path);
    qtest_add_func("/cryptostore/sr10-bounds", test_bounds);
    qtest_add_func("/cryptostore/sr09-windows", test_windows);
    qtest_add_func("/cryptostore/sr04-counter-persists", test_counter_persists);
    qtest_add_func("/cryptostore/sr05-timing-padding", test_timing_padding);
    qtest_add_func("/cryptostore/sr02-reset-flr-lock", test_reset_flr_lock);
    qtest_add_func("/cryptostore/sr40-lock-cancels-kdf", test_lock_cancels_kdf);
    qtest_add_func("/cryptostore/sr07-tamper", test_tamper);
    qtest_add_func("/cryptostore/sr32-passwd", test_passwd);
    qtest_add_func("/cryptostore/sr37-recovery", test_recovery);
    qtest_add_func("/cryptostore/locked-out-recover", test_locked_out_recover);
    qtest_add_func("/cryptostore/enroll-recovery", test_enroll_recovery);
    qtest_add_func("/cryptostore/misc-commands", test_misc_commands);
    qtest_add_func("/cryptostore/sr12-migration-refused", test_migration_refused);
    qtest_add_func("/cryptostore/sr30-image-locking", test_image_locking);
    qtest_add_func("/cryptostore/sr29-caps-hooks", test_caps_hooks);
    qtest_add_func("/cryptostore/hooks/lockout-at-n", test_lockout_at_n);
    qtest_add_func("/cryptostore/hooks/sr34-selftest-failure", test_selftest_failure);
    qtest_add_func("/cryptostore/hooks/fault-f4", test_fault_f4);
    qtest_add_func("/cryptostore/hooks/fault-f8", test_fault_f8);
    qtest_add_func("/cryptostore/hooks/sr32-passwd-power-cut", test_passwd_power_cut);
    qtest_add_func("/cryptostore/hooks/format-power-cut", test_format_power_cut);
    for (size_t i = 0; i < G_N_ELEMENTS(fault_cases); i++) {
        g_autofree char *path = g_strdup_printf("/cryptostore/hooks/fault-%s", fault_cases[i].hook);
        qtest_add_data_func(path, &fault_cases[i], test_fault);
    }

    ret = g_test_run();
    g_autofree char *cmdline = g_strdup_printf("rm -rf %s", tmpdir);
    g_assert(system(cmdline) == 0);
    return ret;
}
