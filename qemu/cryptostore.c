/*
 * pcie-cryptostore: encrypted PCIe storage device with password unlock.
 *
 * Normative description: docs/cryptostore-datasheet.md (registers, command x
 * state matrix, backoff, backing-file format) and docs/threat-model.md
 * (requirements SR-xx referenced in comments below).
 *
 * Structure:
 *   MMIO doorbell -> cmd_bh (main loop) -> synchronous commands, or
 *   a KDF job on the thread pool (B3) -> cs_job_done (main loop) ->
 *   a padded completion (SR-05) -> cs_finalize applies the outcome.
 * All state lives under the BQL; the worker only computes on its own copy.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pcie.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "system/block-backend.h"
#include "block/thread-pool.h"
#include "migration/vmstate.h"
#include "crypto/random.h"
#include "trace.h"
#include "cryptostore_regs.h"
#include "cryptostore_format.h"
#include "cryptostore_crypto.h"
#include "cryptostore_fi.h"
#include "cryptorecovery.h"

#define TYPE_PCIE_CRYPTOSTORE "pcie-cryptostore"
OBJECT_DECLARE_SIMPLE_TYPE(CryptoStoreState, PCIE_CRYPTOSTORE)

#define CS_PM_OFFSET        0x40
#define CS_MSI_OFFSET       0x50
#define CS_EXP_OFFSET       0x80

#define CS_PAD_MS           1000        /* SR-05, D8 */
#define CS_CALIBRATE_MS     500         /* SR-03 */
#define CS_FILL_CHUNK       (1024 * 1024)

/* Control-flow integrity for UNLOCK/RECOVER (SR-24) */
#define CFI_PARAMS          (1u << 0)
#define CFI_BACKOFF         (1u << 1)
#define CFI_COUNTER         (1u << 2)
#define CFI_KDFMIN          (1u << 3)
#define CFI_DISPATCH        (1u << 4)
#define CFI_TAG             (1u << 5)
#define CFI_HDRMAC          (1u << 6)
#define CFI_ALL             0x7fu
#define CFI_STEPS           7u

typedef enum CsJobKind {
    JOB_FORMAT = 1,
    JOB_UNLOCK,
    JOB_PASSWD,             /* UNLOCKED: verify old password, wrap new slot */
    JOB_PASSWD_RECOVERED,   /* RECOVERED: wrap new slot only */
    JOB_RECOVER,
} CsJobKind;

typedef struct CryptoStoreState CryptoStoreState;

/* A KDF job: pure computation on its own copies (B3, SR-40). */
typedef struct CsJob {
    CryptoStoreState *dev;      /* NULL once cancelled or the device is gone */
    bool cancelled;
    CsJobKind kind;

    uint8_t secret[CS_PW_MAX];  /* password or recovery key */
    size_t nsecret;
    uint8_t newpw[CS_PW_MAX];
    size_t nnewpw;
    uint8_t uuid[CSF_UUID_LEN];
    CsfSlot slots[CSF_NUM_SLOTS];
    uint32_t try_mask;
    bool force_tag_match;       /* F9 test hook */
    uint32_t calib_iters;       /* 0: calibrate in the worker */

    bool want_newslot;
    unsigned newindex;
    CsfSlot newslot;
    bool want_recslot;
    unsigned recindex;
    CsfSlot recslot;
    uint8_t reckey[CSF_RECOVERY_KEY_LEN];
    uint8_t fixed[CSF_MAC_COVER_LEN];
    uint8_t mac[CSF_MAC_LEN];
    uint8_t dek[CSF_DEK_LEN];   /* input (FORMAT, PASSWD_RECOVERED) or output */

    bool ok;
    bool match;
    bool fault;
    int match_index;
} CsJob;

/* Outcome of an attempt, applied at the padded completion time (SR-05). */
typedef struct CsPending {
    bool valid;
    uint32_t result;
    uint32_t aux;
    uint32_t next_state;
    bool counter_reset;
    bool failure_stamp;         /* backoff is measured from the failure (11.10) */
    bool integrity_event;
    bool load_dek;
    uint8_t dek[CSF_DEK_LEN];
    bool write_newslot;
    unsigned newindex;
    CsfSlot newslot;
    uint32_t retire_mask;
} CsPending;

struct CryptoStoreState {
    PCIDevice parent_obj;

    MemoryRegion mmio;
    BlockBackend *blk;
    CryptoRecoveryState *recovery;
    char *label;
    int64_t file_size;

    /* Persistent metadata, as parsed or as last written by this device */
    CsfHeader hdr;
    uint32_t state;             /* CS_ST_*, fail-secure encoding (SR-21) */

    /* Registers */
    bool busy;
    uint32_t cur_cmd;
    uint32_t result;
    uint32_t result_aux;
    uint64_t lba;
    uint32_t count;
    uint32_t pw_len;
    uint32_t pw2_len;
    uint32_t int_status;
    uint32_t int_enable;
    bool intx_level;
    uint8_t pw_a[CS_WIN_PW_SIZE];
    uint8_t pw_b[CS_WIN_PW_SIZE];
    uint8_t data[CS_WIN_DATA_SIZE];

    /* Keys: present only in UNLOCKED and RECOVERED (SR-02) */
    uint8_t dek[CSF_DEK_LEN];
    uint32_t dek_loaded;        /* CS_FS_TRUE/FALSE: second representation (F4) */
    QCryptoCipher *xts;

    /* Asynchronous machinery */
    QEMUBH *cmd_bh;
    QEMUBH *fill_bh;
    QEMUTimer pad_timer;
    CsJob *job;
    int64_t cmd_start_ms;
    CsPending pend;
    uint32_t calib_iters;

    /* FORMAT in progress (between the KDF job and the header commit) */
    bool fmt_active;
    uint64_t fmt_next;
    uint64_t fmt_capacity;
    uint8_t fmt_hdr[CSF_HDR_SIZE];

    /* Control-flow integrity of the current attempt (SR-24) */
    uint32_t cfi_mask;
    uint32_t cfi_count;

    /* Test hooks (SR-29): present in all builds, active only with hooks */
    char *fault;
    int64_t time_offset_ms;
    uint32_t crash_after_writes;    /* simulated power cut (SR-32 test) */
};

static void cs_fault(CryptoStoreState *s);
static void cs_complete(CryptoStoreState *s, uint32_t result, uint32_t aux);

/* ---------------------------------------------------------------------- */
/* Small helpers                                                          */
/* ---------------------------------------------------------------------- */

static bool cs_hook(CryptoStoreState *s, const char *name)
{
#ifdef CRYPTOSTORE_FAULT_HOOKS
    if (s->fault && !strcmp(s->fault, name)) {
        g_free(s->fault);
        s->fault = NULL;
        trace_cryptostore_fault_hook(s->label, name);
        return true;
    }
#endif
    return false;
}

static int64_t cs_host_now_ms(CryptoStoreState *s)
{
    return qemu_clock_get_ms(QEMU_CLOCK_HOST) + s->time_offset_ms;
}

static bool cs_random(void *buf, size_t len)
{
    return qcrypto_random_bytes(buf, len, NULL) == 0;
}

/* CSPRNG-seeded jitter before a control-plane check (SR-23). */
static bool cs_jitter(CryptoStoreState *s)
{
    uint32_t v = 0;

    if (cs_hook(s, "jitter")) {
        return false;   /* simulated corruption of the delay loop */
    }
    cs_random(&v, sizeof(v));
    return cs_secure_jitter(1024 + (v & 0x3fff));
}

static bool cs_verify_zero(const void *p, size_t len)
{
    volatile const uint8_t *v = p;
    uint8_t acc = 0;

    for (size_t i = 0; i < len; i++) {
        acc |= v[i];
    }
    return acc == 0;
}

static const char *cs_state_name(uint32_t st)
{
    switch (st) {
    case CS_ST_UNFORMATTED: return "UNFORMATTED";
    case CS_ST_LOCKED:      return "LOCKED";
    case CS_ST_UNLOCKED:    return "UNLOCKED";
    case CS_ST_RECOVERED:   return "RECOVERED";
    case CS_ST_LOCKED_OUT:  return "LOCKED_OUT";
    case CS_ST_ERROR:       return "ERROR";
    default:                return "INVALID";
    }
}

static uint32_t cs_state_reg(uint32_t st)
{
    switch (st) {
    case CS_ST_UNFORMATTED: return CS_STATE_UNFORMATTED;
    case CS_ST_LOCKED:      return CS_STATE_LOCKED;
    case CS_ST_UNLOCKED:    return CS_STATE_UNLOCKED;
    case CS_ST_RECOVERED:   return CS_STATE_RECOVERED;
    case CS_ST_ERROR:       return CS_STATE_ERROR;
    default:                return CS_STATE_LOCKED_OUT;  /* fail secure */
    }
}

static bool cs_state_valid(uint32_t st)
{
    return st == CS_ST_UNFORMATTED || st == CS_ST_LOCKED || st == CS_ST_UNLOCKED ||
           st == CS_ST_RECOVERED || st == CS_ST_LOCKED_OUT || st == CS_ST_ERROR;
}

static void cs_set_state(CryptoStoreState *s, uint32_t st)
{
    if (s->state != st) {
        trace_cryptostore_state(s->label, cs_state_name(s->state), cs_state_name(st));
    }
    s->state = st;
}

static bool cs_recovery_available(CryptoStoreState *s)
{
    return s->recovery && cryptorecovery_available(s->recovery);
}

static int cs_find_slot(CryptoStoreState *s, uint16_t type)
{
    for (int i = 0; i < CSF_NUM_SLOTS; i++) {
        if (s->hdr.slot[i].state == CSF_SLOT_ACTIVE && s->hdr.slot[i].type == type) {
            return i;
        }
    }
    return -1;
}

static int cs_free_slot(CryptoStoreState *s)
{
    for (int i = 0; i < CSF_NUM_SLOTS; i++) {
        if (s->hdr.slot[i].state != CSF_SLOT_ACTIVE) {
            return i;
        }
    }
    return -1;
}

static uint32_t cs_slot_mask(CryptoStoreState *s, uint16_t type)
{
    uint32_t m = 0;

    for (int i = 0; i < CSF_NUM_SLOTS; i++) {
        if (s->hdr.slot[i].state == CSF_SLOT_ACTIVE && s->hdr.slot[i].type == type) {
            m |= 1u << i;
        }
    }
    return m;
}

static uint32_t cs_slot_map(CryptoStoreState *s)
{
    uint32_t map = 0;

    if (s->state == CS_ST_UNFORMATTED || s->state == CS_ST_ERROR) {
        return 0;
    }
    map = cs_slot_mask(s, CSF_TYPE_PASSWORD) | cs_slot_mask(s, CSF_TYPE_RECOVERY);
    if (cs_find_slot(s, CSF_TYPE_RECOVERY) >= 0) {
        map |= CS_SLOT_MAP_RECOVERY;
    }
    return map;
}

static void cs_cfi(CryptoStoreState *s, uint32_t step)
{
    s->cfi_mask |= step;
    s->cfi_count++;
}

/* ---------------------------------------------------------------------- */
/* Interrupts (same model as pcie-hello)                                  */
/* ---------------------------------------------------------------------- */

static void cs_update_irq(CryptoStoreState *s, uint32_t newly_set)
{
    PCIDevice *pdev = PCI_DEVICE(s);
    bool level = false;

    if (msix_enabled(pdev)) {
        if (newly_set) {
            trace_cryptostore_irq(s->label, "msix", s->int_status, s->int_enable);
            msix_notify(pdev, 0);
        }
    } else if (msi_enabled(pdev)) {
        if (newly_set) {
            trace_cryptostore_irq(s->label, "msi", s->int_status, s->int_enable);
            msi_notify(pdev, 0);
        }
    } else {
        level = s->int_status & s->int_enable;
    }
    if (level != s->intx_level) {
        trace_cryptostore_irq(s->label, level ? "intx-assert" : "intx-deassert",
                              s->int_status, s->int_enable);
        s->intx_level = level;
        pci_set_irq(pdev, level);
    }
}

static void cs_raise(CryptoStoreState *s, uint32_t bits)
{
    uint32_t newly = bits & ~s->int_status & s->int_enable;

    s->int_status |= bits;
    cs_update_irq(s, newly);
}

/* ---------------------------------------------------------------------- */
/* Keys and cancellation                                                  */
/* ---------------------------------------------------------------------- */

static void cs_job_free(CsJob *job)
{
    cs_wipe(job, sizeof(*job));
    g_free(job);
}

/* Wipe windows and keys, then verify (SR-02, SR-25, F3). */
static bool cs_zeroize(CryptoStoreState *s, bool allow_hook)
{
    bool ok = true;

    if (!(allow_hook && cs_hook(s, "f3"))) {
        explicit_bzero(s->dek, sizeof(s->dek));
    }
    s->dek_loaded = CS_FS_FALSE;
    if (s->xts) {
        qcrypto_cipher_free(s->xts);
        s->xts = NULL;
    }
    explicit_bzero(s->pw_a, sizeof(s->pw_a));
    explicit_bzero(s->pw_b, sizeof(s->pw_b));
    explicit_bzero(s->data, sizeof(s->data));
    explicit_bzero(s->pend.dek, sizeof(s->pend.dek));
    explicit_bzero(s->fmt_hdr, sizeof(s->fmt_hdr));
    cs_compiler_barrier();

    if (allow_hook && !cs_jitter(s)) {
        ok = false;
    }
    ok &= cs_verify_zero(s->dek, sizeof(s->dek)) &&
          cs_verify_zero(s->pw_a, sizeof(s->pw_a)) &&
          cs_verify_zero(s->pw_b, sizeof(s->pw_b)) &&
          cs_verify_zero(s->data, sizeof(s->data)) &&
          cs_verify_zero(s->pend.dek, sizeof(s->pend.dek));
    return ok;
}

/* Stop everything in flight: KDF job, padded completion, FORMAT fill (SR-33, SR-40). */
static void cs_cancel_all(CryptoStoreState *s)
{
    if (s->job) {
        s->job->cancelled = true;
        s->job->dev = NULL;         /* the worker's result is discarded */
        s->job = NULL;
    }
    timer_del(&s->pad_timer);
    memset(&s->pend, 0, sizeof(s->pend));
    qemu_bh_cancel(s->cmd_bh);
    qemu_bh_cancel(s->fill_bh);
    s->fmt_active = false;
}

/*
 * The LOCK / reset / FLR / unplug path (datasheet section 8). Returns false
 * if the zeroization could not be verified; the caller runs cs_fault().
 */
static bool cs_lock_path(CryptoStoreState *s)
{
    bool ok;

    cs_cancel_all(s);
    ok = cs_zeroize(s, true);
    if (s->state == CS_ST_UNLOCKED || s->state == CS_ST_RECOVERED) {
        cs_set_state(s, CS_ST_LOCKED);
    }
    s->busy = false;
    return ok;
}

/* ---------------------------------------------------------------------- */
/* Metadata I/O (every write flushed and verified, SR-25)                 */
/* ---------------------------------------------------------------------- */

typedef enum { META_OK, META_IO_ERROR, META_MISMATCH } CsMetaResult;

static CsMetaResult cs_meta_write(CryptoStoreState *s, int64_t off, const void *buf,
                                  size_t len, bool skip_write)
{
    g_autofree uint8_t *check = g_malloc(len);
    CsMetaResult r = META_OK;

    if (!skip_write) {
        if (blk_pwrite(s->blk, off, len, buf, 0) < 0 || blk_flush(s->blk) < 0) {
            return META_IO_ERROR;
        }
#ifdef CRYPTOSTORE_FAULT_HOOKS
        if (s->crash_after_writes && --s->crash_after_writes == 0) {
            /* Power cut right after this write reached the disk (SR-32 test). */
            _exit(99);
        }
#endif
    }
    if (blk_pread(s->blk, off, len, check, 0) < 0) {
        r = META_IO_ERROR;
    } else if (memcmp(check, buf, len) != 0) {
        r = META_MISMATCH;
    }
    explicit_bzero(check, len);
    return r;
}

/* Handle a failed metadata write: I/O error -> ERROR, mismatch -> fault. */
static void cs_meta_failed(CryptoStoreState *s, CsMetaResult r)
{
    if (r == META_MISMATCH) {
        cs_fault(s);
        return;
    }
    error_report("%s: backing-file I/O error on metadata; device is in ERROR", s->label);
    cs_cancel_all(s);
    cs_zeroize(s, false);
    cs_set_state(s, CS_ST_ERROR);
    if (s->busy) {
        cs_complete(s, CS_ERR_FAULT, 0);
    }
}

static CsMetaResult cs_persist_counter(CryptoStoreState *s, uint32_t count, uint64_t ms,
                                       bool skip_write)
{
    uint8_t rec[CSF_FAIL_SIZE];
    CsMetaResult r;

    csf_encode_fail(count, ms, rec);
    r = cs_meta_write(s, CSF_OFF_FAIL, rec, sizeof(rec), skip_write);
    if (r == META_OK) {
        s->hdr.fail_count = count;
        s->hdr.fail_record_ok = true;
        s->hdr.last_attempt_ms = ms;
    }
    return r;
}

static CsMetaResult cs_write_slot(CryptoStoreState *s, unsigned index, const CsfSlot *slot)
{
    uint8_t buf[CSF_SLOT_SIZE];
    CsMetaResult r;

    csf_encode_slot(slot, buf);
    r = cs_meta_write(s, CSF_OFF_SLOTS + index * CSF_SLOT_SIZE, buf, sizeof(buf), false);
    if (r == META_OK) {
        s->hdr.slot[index] = *slot;
    }
    return r;
}

/* ---------------------------------------------------------------------- */
/* Fault response (SR-27)                                                 */
/* ---------------------------------------------------------------------- */

static void cs_fault(CryptoStoreState *s)
{
    uint32_t count;

    trace_cryptostore_fault(s->label);
    cs_cancel_all(s);
    cs_zeroize(s, false);

    if (s->state == CS_ST_UNFORMATTED || s->state == CS_ST_ERROR) {
        cs_set_state(s, CS_ST_ERROR);   /* no header to record a lockout in */
    } else {
        /* Counts as a failure, and locks out: persist max(f + 1, N). */
        count = MAX(s->hdr.fail_count + 1, (uint32_t)CS_LOCKOUT_N);
        cs_persist_counter(s, count, cs_host_now_ms(s), false);
        s->hdr.fail_count = count;
        cs_set_state(s, CS_ST_LOCKED_OUT);
    }
    /* Non-secret event; never says which check fired. */
    warn_report("%s: fault detected; keys zeroized, device is %s", s->label,
                cs_state_name(s->state));
    if (s->busy) {
        cs_complete(s, CS_ERR_FAULT, 0);
    }
}

/* ---------------------------------------------------------------------- */
/* Command completion                                                     */
/* ---------------------------------------------------------------------- */

static void cs_complete(CryptoStoreState *s, uint32_t result, uint32_t aux)
{
    trace_cryptostore_cmd_done(s->label, s->cur_cmd, result, cs_state_name(s->state));
    s->result = result;
    s->result_aux = aux;
    explicit_bzero(s->pw_a, sizeof(s->pw_a));
    explicit_bzero(s->pw_b, sizeof(s->pw_b));
    s->busy = false;
    cs_raise(s, CS_INT_CMD_DONE);
}

/* ---------------------------------------------------------------------- */
/* Attempt accounting (datasheet section 7)                               */
/* ---------------------------------------------------------------------- */

/* Required wait before the next attempt, path A: shifts. */
static int64_t cs_backoff_wait_ms_a(uint32_t f)
{
    if (f < CS_FREE_FAILURES) {
        return 0;
    }
    if (f - CS_FREE_FAILURES >= 9) {
        return CS_BACKOFF_CAP_S * 1000;
    }
    return MIN(1 << (f - CS_FREE_FAILURES), CS_BACKOFF_CAP_S) * 1000;
}

/* Path B: repeated doubling (a different code path for F2). */
static bool cs_backoff_allowed_b(uint32_t f, int64_t last, int64_t now)
{
    int64_t w = 0;

    if (f >= CS_FREE_FAILURES) {
        w = 1;
        for (uint32_t i = CS_FREE_FAILURES; i < f && w < CS_BACKOFF_CAP_S; i++) {
            w *= 2;
        }
        w = MIN(w, (int64_t)CS_BACKOFF_CAP_S);
    }
    if (w == 0) {
        return true;
    }
    if (now < last) {
        return false;           /* clock went backwards: full wait */
    }
    return now - last >= w * 1000;
}

/*
 * Backoff check, counter increment and flush before verification (SR-04).
 * Returns true if the attempt may proceed; otherwise the command has been
 * completed (or the fault response has run).
 */
static bool cs_attempt_begin(CryptoStoreState *s, bool apply_backoff)
{
    int64_t now = cs_host_now_ms(s);
    uint32_t f = s->hdr.fail_count;
    uint8_t rec[CSF_FAIL_SIZE];
    CsMetaResult r;

    s->cfi_mask = 0;
    s->cfi_count = 0;
    cs_cfi(s, CFI_PARAMS);

    if (apply_backoff) {
        int64_t wait = cs_backoff_wait_ms_a(f);
        int64_t remaining = now < (int64_t)s->hdr.last_attempt_ms ? wait :
                            (int64_t)s->hdr.last_attempt_ms + wait - now;
        uint32_t a1 = (wait == 0 || remaining <= 0) ? CS_FS_TRUE : CS_FS_FALSE;
        uint32_t a2;

        if (cs_hook(s, "f2")) {
            a1 = CS_FS_TRUE;
        }
        if (!cs_jitter(s)) {
            cs_fault(s);
            return false;
        }
        a2 = cs_backoff_allowed_b(f, s->hdr.last_attempt_ms, now) ? CS_FS_TRUE : CS_FS_FALSE;
        if (cs_launder32(a1) != cs_launder32(a2) ||
            (a1 != CS_FS_TRUE && a1 != CS_FS_FALSE)) {
            cs_fault(s);
            return false;
        }
        if (a1 == CS_FS_FALSE) {
            cs_complete(s, CS_ERR_BACKOFF, (uint32_t)((remaining + 999) / 1000));
            return false;
        }
    }
    cs_cfi(s, CFI_BACKOFF);

    /* F1: persist f + 1 before any secret is tested; verify it advanced. */
    r = cs_persist_counter(s, f + 1, now, cs_hook(s, "f1"));
    if (r != META_OK) {
        cs_meta_failed(s, r);
        return false;
    }
    if (!cs_jitter(s) ||
        blk_pread(s->blk, CSF_OFF_FAIL, sizeof(rec), rec, 0) < 0 ||
        csf_le32(rec) != f + 1 || csf_le32(rec + 4) != ~(f + 1) ||
        cs_launder32(s->hdr.fail_count) != f + 1) {
        cs_fault(s);
        return false;
    }
    cs_cfi(s, CFI_COUNTER);
    return true;
}

/* F5: KDF parameter minimums, evaluated twice by different code paths. */
static bool cs_check_kdf_params(CryptoStoreState *s, uint32_t mask)
{
    bool glitch = cs_hook(s, "f5");

    for (int i = 0; i < CSF_NUM_SLOTS; i++) {
        CsfSlot *sl = &s->hdr.slot[i];
        bool c1, c2;

        if (!(mask & (1u << i)) || sl->kdf != CSF_KDF_PBKDF2_SHA256) {
            continue;
        }
        if (glitch) {
            sl->iters = 1;          /* simulated corruption of a loaded value */
        }
        c1 = (sl->iters >= CSF_PBKDF2_MIN_ITERS && sl->iters <= CSF_PBKDF2_MAX_ITERS) || glitch;
        if (!cs_jitter(s)) {
            return false;
        }
        /*
         * Path B divides by volatile bounds so the optimizer cannot fold it
         * into path A's range check (found by the -O2 review, SR-28).
         */
        {
            volatile uint32_t lo = CSF_PBKDF2_MIN_ITERS, hi = CSF_PBKDF2_MAX_ITERS + 1u;
            uint32_t it = cs_launder32(sl->iters);

            c2 = it / lo != 0 && it / hi == 0;
        }
        if (c1 != c2 || !c2) {
            return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------------- */
/* KDF worker (thread pool)                                               */
/* ---------------------------------------------------------------------- */

static int cs_job_run(void *opaque)
{
    CsJob *job = opaque;
    uint8_t kek[CS_KEY_LEN], dek[CSF_DEK_LEN];
    Error *err = NULL;
    uint32_t iters = job->calib_iters;
    bool ok = true;

    if ((job->want_newslot || job->kind == JOB_FORMAT) && !iters) {
        iters = cs_pbkdf2_calibrate(CS_CALIBRATE_MS, &err);
        ok = iters != 0;
    }
    if (ok && (job->want_newslot || job->kind == JOB_FORMAT)) {
        job->newslot.iters = iters;
        job->calib_iters = iters;
    }

    switch (job->kind) {
    case JOB_FORMAT:
        ok = ok &&
             cs_pbkdf2(job->secret, job->nsecret, job->newslot.salt, iters, kek, &err) == 0 &&
             cs_slot_wrap(&job->newslot, kek, job->uuid, job->newindex, job->dek, &err) == 0;
        if (ok && job->want_recslot) {
            ok = cs_hkdf_extract(job->recslot.salt, CSF_SALT_LEN, job->reckey,
                                 CSF_RECOVERY_KEY_LEN, kek, &err) == 0 &&
                 cs_slot_wrap(&job->recslot, kek, job->uuid, job->recindex, job->dek, &err) == 0;
        }
        ok = ok && cs_header_mac(job->dek, job->uuid, job->fixed, job->mac, &err) == 0;
        break;

    case JOB_UNLOCK:
    case JOB_PASSWD:
    case JOB_RECOVER:
        /* Try every candidate slot, no early exit (SR-05). */
        for (int i = 0; ok && i < CSF_NUM_SLOTS; i++) {
            bool m, f;

            if (!(job->try_mask & (1u << i))) {
                continue;
            }
            ok = cs_slot_kek(&job->slots[i], job->secret, job->nsecret, kek, &err) == 0 &&
                 cs_slot_unwrap(&job->slots[i], kek, job->uuid, i, dek, &m, &f,
                                job->force_tag_match, &err) == 0;
            job->fault |= f;
            if (ok && m && !job->match) {
                job->match = true;
                job->match_index = i;
                memcpy(job->dek, dek, sizeof(dek));
            }
        }
        if (ok && job->kind == JOB_PASSWD && job->match && !job->fault) {
            ok = cs_pbkdf2(job->newpw, job->nnewpw, job->newslot.salt, iters, kek, &err) == 0 &&
                 cs_slot_wrap(&job->newslot, kek, job->uuid, job->newindex, job->dek, &err) == 0;
        }
        break;

    case JOB_PASSWD_RECOVERED:
        ok = ok &&
             cs_pbkdf2(job->newpw, job->nnewpw, job->newslot.salt, iters, kek, &err) == 0 &&
             cs_slot_wrap(&job->newslot, kek, job->uuid, job->newindex, job->dek, &err) == 0;
        break;
    }

    /* The worker wipes its own buffers before exiting (B3). */
    cs_wipe(kek, sizeof(kek));
    cs_wipe(dek, sizeof(dek));
    cs_wipe(job->secret, sizeof(job->secret));
    cs_wipe(job->newpw, sizeof(job->newpw));
    /* job->reckey is still needed: FORMAT delivers it after the job; cs_job_free wipes it. */
    if (err) {
        /* Library errors carry no secret material. */
        error_free(err);
    }
    job->ok = ok;
    return 0;
}

static void cs_job_done(void *opaque, int ret);

static CsJob *cs_job_new(CryptoStoreState *s, CsJobKind kind)
{
    CsJob *job = g_new0(CsJob, 1);

    job->dev = s;
    job->kind = kind;
    job->calib_iters = s->calib_iters;
    memcpy(job->uuid, s->hdr.uuid, CSF_UUID_LEN);
    memcpy(job->slots, s->hdr.slot, sizeof(job->slots));
    return job;
}

static void cs_job_dispatch(CryptoStoreState *s, CsJob *job)
{
    /* The job holds its own copy; the windows are cleared now (datasheet 3.2). */
    explicit_bzero(s->pw_a, sizeof(s->pw_a));
    explicit_bzero(s->pw_b, sizeof(s->pw_b));
    s->job = job;
    trace_cryptostore_kdf_dispatch(s->label, job->kind);
    thread_pool_submit_aio(cs_job_run, job, cs_job_done, job);
}

static void cs_copy_pw(uint8_t *dst, size_t *ndst, const uint8_t *src, uint32_t len)
{
    memcpy(dst, src, len);
    *ndst = len;
}

/* ---------------------------------------------------------------------- */
/* Padded completion (SR-05)                                              */
/* ---------------------------------------------------------------------- */

static void cs_schedule_padded(CryptoStoreState *s)
{
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    int64_t elapsed = now - s->cmd_start_ms;
    int64_t pad = MAX(elapsed, (int64_t)CS_PAD_MS);

    pad = (pad + 999) / 1000 * 1000;    /* next whole second (D8) */
    s->pend.valid = true;
    timer_mod(&s->pad_timer, s->cmd_start_ms + pad);
}

static void cs_finalize(void *opaque)
{
    CryptoStoreState *s = opaque;
    CsPending *p = &s->pend;
    CsMetaResult r;

    if (!p->valid) {
        return;
    }
    if (p->counter_reset || p->failure_stamp) {
        r = p->counter_reset ? cs_persist_counter(s, 0, 0, false) :
            cs_persist_counter(s, s->hdr.fail_count, cs_host_now_ms(s), false);
        if (r != META_OK) {
            memset(p, 0, sizeof(*p));
            cs_meta_failed(s, r);
            return;
        }
    }
    if (p->write_newslot) {
        CsfSlot empty = { 0 };

        r = cs_write_slot(s, p->newindex, &p->newslot);
        for (int i = 0; r == META_OK && i < CSF_NUM_SLOTS; i++) {
            if (p->retire_mask & (1u << i)) {
                r = cs_write_slot(s, i, &empty);     /* SR-32: only after the new slot */
            }
        }
        if (r != META_OK) {
            memset(p, 0, sizeof(*p));
            cs_meta_failed(s, r);
            return;
        }
    }
    if (p->load_dek) {
        memcpy(s->dek, p->dek, sizeof(s->dek));
        s->xts = cs_xts_new(s->dek, NULL);
        s->dek_loaded = s->xts ? CS_FS_TRUE : CS_FS_FALSE;
    }
    if (p->integrity_event) {
        warn_report("%s: header MAC mismatch with a correct password: "
                    "image tampered with; device is in ERROR", s->label);
    }
    if (p->next_state == CS_ST_LOCKED_OUT || p->next_state == CS_ST_ERROR ||
        p->next_state == CS_ST_LOCKED) {
        cs_zeroize(s, false);
    }
    if (p->next_state) {
        cs_set_state(s, p->next_state);
    }
    cs_complete(s, p->result, p->aux);
    explicit_bzero(p->dek, sizeof(p->dek));
    memset(p, 0, sizeof(*p));
}

/* ---------------------------------------------------------------------- */
/* KDF job completion (main loop)                                         */
/* ---------------------------------------------------------------------- */

static void cs_format_after_kdf(CryptoStoreState *s, CsJob *job);

/* UNLOCK and RECOVER: decide the outcome, apply it after padding. */
static void cs_auth_result(CryptoStoreState *s, CsJob *job, uint32_t ok_state)
{
    CsPending *p = &s->pend;
    uint8_t fixed[CSF_MAC_COVER_LEN], mac[CSF_MAC_LEN];
    uint32_t verdict;

    memset(p, 0, sizeof(*p));
    if (job->fault) {
        cs_fault(s);
        return;
    }
    if (!job->match) {
        p->result = CS_ERR_AUTH;
        p->failure_stamp = true;
        if (s->hdr.fail_count >= CS_LOCKOUT_N) {
            p->next_state = CS_ST_LOCKED_OUT;
        }
        cs_schedule_padded(s);
        return;
    }
    cs_cfi(s, CFI_TAG);

    /* Header MAC over the fixed fields (R1), compared twice (F9 pattern). */
    csf_encode_fixed(s->hdr.uuid, s->hdr.capacity, fixed);
    if (cs_header_mac(job->dek, s->hdr.uuid, fixed, mac, NULL) < 0) {
        cs_fault(s);
        return;
    }
    verdict = cs_tag_verdict(mac, s->hdr.hdr_mac, CSF_MAC_LEN, false);
    if (verdict != CS_FS_TRUE && verdict != CS_FS_FALSE) {
        cs_fault(s);
        return;
    }
    if (verdict == CS_FS_FALSE) {
        /* Correct password, tampered header (B5, SR-39). */
        p->result = CS_ERR_INTEGRITY;
        p->next_state = CS_ST_ERROR;
        p->counter_reset = true;
        p->integrity_event = true;
        cs_schedule_padded(s);
        return;
    }
    cs_cfi(s, CFI_HDRMAC);

    /* SR-24: every step of the sequence ran exactly once. */
    if (cs_launder32(s->cfi_mask) != CFI_ALL || cs_launder32(s->cfi_count) != CFI_STEPS) {
        cs_fault(s);
        return;
    }
    p->result = CS_OK;
    p->next_state = ok_state;
    p->counter_reset = true;
    p->load_dek = true;
    memcpy(p->dek, job->dek, CSF_DEK_LEN);
    cs_schedule_padded(s);
}

static void cs_passwd_result(CryptoStoreState *s, CsJob *job)
{
    CsPending *p = &s->pend;

    memset(p, 0, sizeof(*p));
    if (job->fault) {
        cs_fault(s);
        return;
    }
    if (!job->match) {
        p->result = CS_ERR_AUTH;
        p->failure_stamp = true;
        if (s->hdr.fail_count >= CS_LOCKOUT_N) {
            p->next_state = CS_ST_LOCKED_OUT;   /* zeroizes even though UNLOCKED (R8) */
        }
        cs_schedule_padded(s);
        return;
    }
    /* The old password must open the key that is loaded. */
    if (!cs_ct_equal(job->dek, s->dek, CSF_DEK_LEN)) {
        cs_fault(s);
        return;
    }
    p->result = CS_OK;
    p->counter_reset = true;
    p->write_newslot = true;
    p->newindex = job->newindex;
    p->newslot = job->newslot;
    p->retire_mask = 1u << job->match_index;
    cs_schedule_padded(s);
}

static void cs_job_done(void *opaque, int ret)
{
    CsJob *job = opaque;
    CryptoStoreState *s = job->dev;

    if (!s || job->cancelled) {
        cs_job_free(job);
        return;
    }
    s->job = NULL;
    if (!job->ok) {
        error_report("%s: crypto operation failed; device is in ERROR", s->label);
        cs_cancel_all(s);
        cs_zeroize(s, false);
        cs_set_state(s, CS_ST_ERROR);
        cs_complete(s, CS_ERR_FAULT, 0);
        cs_job_free(job);
        return;
    }
    if (job->calib_iters) {
        s->calib_iters = job->calib_iters;
    }

    switch (job->kind) {
    case JOB_FORMAT:
        cs_format_after_kdf(s, job);
        break;
    case JOB_UNLOCK:
        cs_auth_result(s, job, CS_ST_UNLOCKED);
        break;
    case JOB_RECOVER:
        cs_auth_result(s, job, CS_ST_RECOVERED);
        break;
    case JOB_PASSWD:
        cs_passwd_result(s, job);
        break;
    case JOB_PASSWD_RECOVERED: {
        CsMetaResult r = cs_write_slot(s, job->newindex, &job->newslot);
        CsfSlot empty = { 0 };

        /* The forgotten password's slots go once the new one is written. */
        for (int i = 0; r == META_OK && i < CSF_NUM_SLOTS; i++) {
            if (i != (int)job->newindex && s->hdr.slot[i].state == CSF_SLOT_ACTIVE &&
                s->hdr.slot[i].type == CSF_TYPE_PASSWORD) {
                r = cs_write_slot(s, i, &empty);
            }
        }
        if (r != META_OK) {
            cs_meta_failed(s, r);
        } else {
            cs_set_state(s, CS_ST_UNLOCKED);
            cs_complete(s, CS_OK, 0);
        }
        break;
    }
    }
    cs_job_free(job);
}

/* ---------------------------------------------------------------------- */
/* FORMAT                                                                 */
/* ---------------------------------------------------------------------- */

static bool cs_new_dek(uint8_t dek[CSF_DEK_LEN])
{
    do {
        if (!cs_random(dek, CSF_DEK_LEN)) {
            return false;
        }
    } while (!memcmp(dek, dek + 32, 32));   /* XTS halves must differ */
    return true;
}

static void cs_cmd_format(CryptoStoreState *s)
{
    CsJob *job;
    uint64_t cap = csf_capacity_for_size(s->file_size);

    if (s->state != CS_ST_UNFORMATTED) {
        cs_complete(s, CS_ERR_STATE, 0);
        return;
    }
    if (s->pw_len < 1 || s->pw_len > CS_PW_MAX || cap == 0) {
        cs_complete(s, CS_ERR_RANGE, 0);
        return;
    }
    job = cs_job_new(s, JOB_FORMAT);
    memset(job->slots, 0, sizeof(job->slots));
    cs_copy_pw(job->secret, &job->nsecret, s->pw_a, s->pw_len);
    job->newindex = 0;
    job->newslot = (CsfSlot) { .state = CSF_SLOT_ACTIVE, .type = CSF_TYPE_PASSWORD,
                               .kdf = CSF_KDF_PBKDF2_SHA256 };
    if (!cs_random(job->uuid, CSF_UUID_LEN) || !cs_new_dek(job->dek) ||
        !cs_random(job->newslot.salt, CSF_SALT_LEN) ||
        !cs_random(job->newslot.iv, CSF_IV_LEN)) {
        cs_job_free(job);
        cs_complete(s, CS_ERR_FAULT, 0);
        return;
    }
    job->uuid[6] = (job->uuid[6] & 0x0f) | 0x40;    /* RFC 4122 version 4 */
    job->uuid[8] = (job->uuid[8] & 0x3f) | 0x80;
    if (cs_recovery_available(s)) {
        job->want_recslot = true;
        job->recindex = 1;
        job->recslot = (CsfSlot) { .state = CSF_SLOT_ACTIVE, .type = CSF_TYPE_RECOVERY,
                                   .kdf = CSF_KDF_HKDF_SHA256 };
        if (!cs_random(job->reckey, CSF_RECOVERY_KEY_LEN) ||
            !cs_random(job->recslot.salt, CSF_SALT_LEN) ||
            !cs_random(job->recslot.iv, CSF_IV_LEN)) {
            cs_job_free(job);
            cs_complete(s, CS_ERR_FAULT, 0);
            return;
        }
    }
    s->fmt_capacity = cap;
    csf_encode_fixed(job->uuid, cap, job->fixed);
    cs_job_dispatch(s, job);
}

static void cs_format_after_kdf(CryptoStoreState *s, CsJob *job)
{
    uint8_t *h = s->fmt_hdr;

    /* Build the complete header image now; it is written after the fill. */
    memset(h, 0, CSF_HDR_SIZE);
    memcpy(h, job->fixed, CSF_MAC_COVER_LEN);
    csf_encode_slot(&job->newslot, h + CSF_OFF_SLOTS + job->newindex * CSF_SLOT_SIZE);
    if (job->want_recslot) {
        csf_encode_slot(&job->recslot, h + CSF_OFF_SLOTS + job->recindex * CSF_SLOT_SIZE);
    }
    memcpy(h + CSF_OFF_HDR_MAC, job->mac, CSF_MAC_LEN);
    csf_encode_fail(0, 0, h + CSF_OFF_FAIL);

    /* Step 2: deliver the recovery key before anything is committed (10.6). */
    if (job->want_recslot) {
        Error *err = NULL;

        if (!cryptorecovery_store(s->recovery, job->uuid, job->reckey, &err)) {
            error_free(err);
            explicit_bzero(h, CSF_HDR_SIZE);
            cs_complete(s, CS_ERR_IO, 0);
            return;
        }
    }
    /* Step 1 (random fill, SR-36) runs in chunks so LOCK/reset can cancel it. */
    s->fmt_active = true;
    s->fmt_next = 0;
    qemu_bh_schedule(s->fill_bh);
}

static void cs_format_commit(CryptoStoreState *s)
{
    const char *why = NULL;
    CsMetaResult r;
    CsfHeader parsed;

    /* Step 3: everything except sector 0; step 4: sector 0 last (10.6). */
    r = cs_meta_write(s, CSF_SECTOR, s->fmt_hdr + CSF_SECTOR, CSF_HDR_SIZE - CSF_SECTOR, false);
    if (r == META_OK) {
        r = cs_meta_write(s, 0, s->fmt_hdr, CSF_SECTOR, false);
    }
    if (r != META_OK) {
        cs_meta_failed(s, r);
        return;
    }
    /* M1 gate: the header written is re-parsed with the same parser. */
    if (csf_parse(s->fmt_hdr, s->file_size, &parsed, &why) != CSF_VALID) {
        error_report("%s: freshly written header does not parse: %s", s->label, why);
        cs_zeroize(s, false);
        cs_set_state(s, CS_ST_ERROR);
        cs_complete(s, CS_ERR_FAULT, 0);
        return;
    }
    s->hdr = parsed;
    explicit_bzero(s->fmt_hdr, sizeof(s->fmt_hdr));
    s->fmt_active = false;
    cs_set_state(s, CS_ST_LOCKED);
    cs_complete(s, CS_OK, 0);
}

static void cs_fill_bh(void *opaque)
{
    CryptoStoreState *s = opaque;
    g_autofree uint8_t *buf = NULL;
    uint64_t sectors, total = s->fmt_capacity;

    if (!s->fmt_active) {
        return;
    }
    if (s->fmt_next >= total) {
        if (blk_flush(s->blk) < 0) {
            cs_meta_failed(s, META_IO_ERROR);
            return;
        }
        cs_format_commit(s);
        return;
    }
    sectors = MIN(total - s->fmt_next, (uint64_t)(CS_FILL_CHUNK / CSF_SECTOR));
    buf = g_malloc(sectors * CSF_SECTOR);
    if (!cs_random(buf, sectors * CSF_SECTOR) ||
        blk_pwrite(s->blk, CSF_DATA_OFFSET + s->fmt_next * CSF_SECTOR,
                   sectors * CSF_SECTOR, buf, 0) < 0) {
        s->fmt_active = false;
        cs_complete(s, CS_ERR_IO, 0);
        return;
    }
    s->fmt_next += sectors;
    qemu_bh_schedule(s->fill_bh);
}

/* ---------------------------------------------------------------------- */
/* UNLOCK, PASSWD, RECOVER, ENROLL_RECOVERY                               */
/* ---------------------------------------------------------------------- */

static void cs_cmd_unlock(CryptoStoreState *s)
{
    uint32_t mask;
    CsJob *job;

    if (s->state == CS_ST_LOCKED_OUT) {
        cs_complete(s, CS_ERR_LOCKED_OUT, 0);
        return;
    }
    if (s->state != CS_ST_LOCKED) {
        cs_complete(s, CS_ERR_STATE, 0);
        return;
    }
    if (s->pw_len < 1 || s->pw_len > CS_PW_MAX) {
        cs_complete(s, CS_ERR_RANGE, 0);
        return;
    }
    if (!cs_attempt_begin(s, true)) {
        return;
    }
    mask = cs_slot_mask(s, CSF_TYPE_PASSWORD);
    if (!cs_check_kdf_params(s, mask)) {
        cs_fault(s);
        return;
    }
    if (!cs_hook(s, "cfi")) {
        cs_cfi(s, CFI_KDFMIN);      /* the CFI hook simulates a skipped step */
    }
    job = cs_job_new(s, JOB_UNLOCK);
    job->try_mask = mask;
    job->force_tag_match = cs_hook(s, "f9");
    cs_copy_pw(job->secret, &job->nsecret, s->pw_a, s->pw_len);
    cs_cfi(s, CFI_DISPATCH);
    cs_job_dispatch(s, job);
}

static void cs_cmd_passwd(CryptoStoreState *s)
{
    int idx = cs_free_slot(s);
    CsJob *job;

    if (s->state == CS_ST_LOCKED_OUT) {
        cs_complete(s, CS_ERR_LOCKED_OUT, 0);
        return;
    }
    if (s->state != CS_ST_UNLOCKED && s->state != CS_ST_RECOVERED) {
        cs_complete(s, CS_ERR_STATE, 0);
        return;
    }
    if (s->pw2_len < 1 || s->pw2_len > CS_PW_MAX ||
        (s->state == CS_ST_UNLOCKED && (s->pw_len < 1 || s->pw_len > CS_PW_MAX))) {
        cs_complete(s, CS_ERR_RANGE, 0);
        return;
    }
    if (idx < 0) {
        cs_complete(s, CS_ERR_STATE, 0);   /* no free keyslot */
        return;
    }

    if (s->state == CS_ST_RECOVERED) {
        job = cs_job_new(s, JOB_PASSWD_RECOVERED);
        memcpy(job->dek, s->dek, CSF_DEK_LEN);
    } else {
        uint32_t mask = cs_slot_mask(s, CSF_TYPE_PASSWORD);

        if (!cs_attempt_begin(s, true)) {
            return;
        }
        if (!cs_check_kdf_params(s, mask)) {
            cs_fault(s);
            return;
        }
        job = cs_job_new(s, JOB_PASSWD);
        job->try_mask = mask;
        job->force_tag_match = cs_hook(s, "f9");
        cs_copy_pw(job->secret, &job->nsecret, s->pw_a, s->pw_len);
    }
    cs_copy_pw(job->newpw, &job->nnewpw, s->pw_b, s->pw2_len);
    job->want_newslot = true;
    job->newindex = idx;
    job->newslot = (CsfSlot) { .state = CSF_SLOT_ACTIVE, .type = CSF_TYPE_PASSWORD,
                               .kdf = CSF_KDF_PBKDF2_SHA256 };
    /* Fresh salt and IV on every wrap (11.4). */
    if (!cs_random(job->newslot.salt, CSF_SALT_LEN) ||
        !cs_random(job->newslot.iv, CSF_IV_LEN)) {
        cs_job_free(job);
        cs_complete(s, CS_ERR_FAULT, 0);
        return;
    }
    cs_job_dispatch(s, job);
}

static void cs_cmd_recover(CryptoStoreState *s)
{
    int idx = cs_find_slot(s, CSF_TYPE_RECOVERY);
    bool locked_out = s->state == CS_ST_LOCKED_OUT;
    uint8_t key[CSF_RECOVERY_KEY_LEN];
    CrRelease rel;
    CsJob *job;

    if (s->state != CS_ST_LOCKED && !locked_out) {
        cs_complete(s, CS_ERR_STATE, 0);
        return;
    }
    if (idx < 0 || !cs_recovery_available(s)) {
        cs_complete(s, CS_ERR_NO_RECOVERY, 0);
        return;
    }
    /* Checked before counting: an unarmed device is not a guess. */
    rel = cryptorecovery_can_release(s->recovery, s->hdr.uuid);
    if (rel != CR_RELEASED) {
        cs_complete(s, rel == CR_NO_KEY ? CS_ERR_NO_RECOVERY : CS_ERR_NOT_ARMED, 0);
        return;
    }
    if (!cs_attempt_begin(s, !locked_out)) {
        return;
    }
    rel = cryptorecovery_release(s->recovery, s->hdr.uuid, key);
    if (rel == CR_FAULT) {
        cs_fault(s);
        return;
    }
    if (rel != CR_RELEASED) {
        cs_complete(s, CS_ERR_NOT_ARMED, 0);
        return;
    }
    cs_cfi(s, CFI_KDFMIN);          /* HKDF: no iteration parameters to check */
    job = cs_job_new(s, JOB_RECOVER);
    job->try_mask = 1u << idx;
    job->force_tag_match = cs_hook(s, "f9");
    memcpy(job->secret, key, sizeof(key));
    job->nsecret = sizeof(key);
    explicit_bzero(key, sizeof(key));
    cs_cfi(s, CFI_DISPATCH);
    cs_job_dispatch(s, job);
}

static void cs_cmd_enroll_recovery(CryptoStoreState *s)
{
    uint8_t key[CSF_RECOVERY_KEY_LEN], kek[CS_KEY_LEN];
    CsfSlot slot = { .state = CSF_SLOT_ACTIVE, .type = CSF_TYPE_RECOVERY,
                     .kdf = CSF_KDF_HKDF_SHA256 };
    int idx = cs_free_slot(s);
    Error *err = NULL;
    CsMetaResult r;
    bool ok;

    if (s->state != CS_ST_UNLOCKED) {
        cs_complete(s, CS_ERR_STATE, 0);
        return;
    }
    if (!cs_recovery_available(s)) {
        cs_complete(s, CS_ERR_NO_RECOVERY, 0);
        return;
    }
    if (cs_find_slot(s, CSF_TYPE_RECOVERY) >= 0 || idx < 0) {
        cs_complete(s, CS_ERR_STATE, 0);
        return;
    }
    ok = cs_random(key, sizeof(key)) && cs_random(slot.salt, CSF_SALT_LEN) &&
         cs_random(slot.iv, CSF_IV_LEN) &&
         cs_hkdf_extract(slot.salt, CSF_SALT_LEN, key, sizeof(key), kek, &err) == 0 &&
         cs_slot_wrap(&slot, kek, s->hdr.uuid, idx, s->dek, &err) == 0 &&
         /* Deliver first, then write the slot (10.6). */
         cryptorecovery_store(s->recovery, s->hdr.uuid, key, &err);
    cs_wipe(key, sizeof(key));
    cs_wipe(kek, sizeof(kek));
    error_free(err);
    if (!ok) {
        cs_complete(s, CS_ERR_IO, 0);
        return;
    }
    r = cs_write_slot(s, idx, &slot);
    if (r != META_OK) {
        cs_meta_failed(s, r);
        return;
    }
    cs_complete(s, CS_OK, 0);
}

/* ---------------------------------------------------------------------- */
/* Data path: READ, WRITE, FLUSH                                          */
/* ---------------------------------------------------------------------- */

/* F4 check B: a different representation of "unlocked". */
static bool cs_unlocked_b(CryptoStoreState *s)
{
    return cs_launder32(s->dek_loaded) == CS_FS_TRUE && s->xts != NULL &&
           cs_launder32(s->state) == CS_ST_UNLOCKED;
}

static void cs_cmd_data(CryptoStoreState *s, uint32_t cmd)
{
    uint8_t ct[CSF_SECTOR], chk[CSF_SECTOR];
    bool unlocked_a = s->state == CS_ST_UNLOCKED;
    uint64_t cap = s->hdr.capacity;
    bool in_range;

    /* F4 check A at command entry. */
    if (cs_hook(s, "f4")) {
        unlocked_a = true;
    }
    if (!unlocked_a) {
        cs_complete(s, s->state == CS_ST_RECOVERED ? CS_ERR_PASSWD_REQUIRED : CS_ERR_LOCKED, 0);
        return;
    }
    if (cmd == CS_CMD_FLUSH) {
        if (!cs_unlocked_b(s)) {
            cs_fault(s);
            return;
        }
        cs_complete(s, blk_flush(s->blk) < 0 ? CS_ERR_IO : CS_OK, 0);
        return;
    }
    /* Bounds check A, overflow-free (SR-10). */
    in_range = s->count >= 1 && s->count <= CS_MAX_SECTORS &&
               s->lba <= cap && s->count <= cap - s->lba;
    if (cs_hook(s, "f6")) {
        in_range = true;
    }
    if (!in_range) {
        cs_complete(s, CS_ERR_RANGE, 0);
        return;
    }
    trace_cryptostore_io(s->label, cmd == CS_CMD_READ ? "read" : "write", s->lba, s->count);

    for (uint32_t i = 0; i < s->count && i < CS_MAX_SECTORS; i++) {
        uint64_t sector = s->lba + i;
        uint8_t *win = s->data + i * CSF_SECTOR;
        int64_t off = CSF_DATA_OFFSET + (int64_t)sector * CSF_SECTOR;

        /* Bounds check B and F4 check B, immediately before the access. */
        if (!(sector < cap) || !cs_unlocked_b(s)) {
            cs_fault(s);
            return;
        }
        if (cmd == CS_CMD_READ) {
            if (blk_pread(s->blk, off, CSF_SECTOR, ct, 0) < 0) {
                explicit_bzero(s->data, sizeof(s->data));
                cs_complete(s, CS_ERR_IO, 0);
                return;
            }
            /* F7: decrypt, then re-encrypt and compare before releasing. */
            if (cs_xts_sector(s->xts, sector, false, ct, win, NULL) < 0 ||
                cs_xts_sector(s->xts, sector, true, win, chk, NULL) < 0 ||
                (cs_hook(s, "f7") && (chk[0] ^= 1, true)) ||
                memcmp(chk, ct, CSF_SECTOR) != 0) {
                explicit_bzero(s->data, sizeof(s->data));
                cs_fault(s);
                return;
            }
        } else {
            /* F7: encrypt, then decrypt and compare before writing. */
            if (cs_xts_sector(s->xts, sector, true, win, ct, NULL) < 0) {
                cs_fault(s);
                return;
            }
            if (cs_hook(s, "f7")) {
                ct[0] ^= 1;
            }
            if (cs_xts_sector(s->xts, sector, false, ct, chk, NULL) < 0 ||
                memcmp(chk, win, CSF_SECTOR) != 0) {
                explicit_bzero(s->data, sizeof(s->data));
                cs_fault(s);
                return;
            }
            if (blk_pwrite(s->blk, off, CSF_SECTOR, ct, 0) < 0) {
                explicit_bzero(s->data, sizeof(s->data));
                cs_complete(s, CS_ERR_IO, 0);
                return;
            }
        }
    }
    explicit_bzero(chk, sizeof(chk));
    if (cmd == CS_CMD_READ) {
        /* Output stays in DATA[0 .. COUNT*512); the rest is zero (3.3). */
        memset(s->data + s->count * CSF_SECTOR, 0, sizeof(s->data) - s->count * CSF_SECTOR);
    } else {
        explicit_bzero(s->data, sizeof(s->data));
    }
    cs_complete(s, CS_OK, 0);
}

/* ---------------------------------------------------------------------- */
/* Command dispatch                                                       */
/* ---------------------------------------------------------------------- */

static void cs_cmd_bh(void *opaque)
{
    CryptoStoreState *s = opaque;

    if (!s->busy) {
        return;
    }
    if (!cs_state_valid(s->state)) {
        cs_fault(s);        /* corrupted state encoding (SR-21) */
        return;
    }
    trace_cryptostore_cmd_start(s->label, s->cur_cmd, cs_state_name(s->state));

    switch (s->cur_cmd) {
    case CS_CMD_FORMAT:
        cs_cmd_format(s);
        break;
    case CS_CMD_UNLOCK:
        cs_cmd_unlock(s);
        break;
    case CS_CMD_LOCK:
        if (!cs_lock_path(s)) {
            s->busy = true;
            cs_fault(s);
        } else {
            cs_complete(s, CS_OK, 0);
        }
        break;
    case CS_CMD_READ:
    case CS_CMD_WRITE:
    case CS_CMD_FLUSH:
        cs_cmd_data(s, s->cur_cmd);
        break;
    case CS_CMD_PASSWD:
        cs_cmd_passwd(s);
        break;
    case CS_CMD_RECOVER:
        cs_cmd_recover(s);
        break;
    case CS_CMD_ENROLL_RECOVERY:
        cs_cmd_enroll_recovery(s);
        break;
    case CS_CMD_REKEY:
        cs_complete(s, CS_ERR_UNSUPPORTED, 0);
        break;
    default:
        cs_complete(s, CS_ERR_INVALID_CMD, 0);
        break;
    }
}

/* ---------------------------------------------------------------------- */
/* MMIO                                                                   */
/* ---------------------------------------------------------------------- */

static const char *cs_reg_name(hwaddr addr)
{
    switch (addr) {
    case CS_REG_ID:          return "ID";
    case CS_REG_VERSION:     return "VERSION";
    case CS_REG_CAPS:        return "CAPS";
    case CS_REG_SECTOR_SIZE: return "SECTOR_SIZE";
    case CS_REG_MAX_SECTORS: return "MAX_SECTORS";
    case CS_REG_PW_MAX:      return "PW_MAX";
    case CS_REG_CAPACITY_LO: return "CAPACITY_LO";
    case CS_REG_CAPACITY_HI: return "CAPACITY_HI";
    case CS_REG_STATE:       return "STATE";
    case CS_REG_STATUS:      return "STATUS";
    case CS_REG_RESULT:      return "RESULT";
    case CS_REG_RESULT_AUX:  return "RESULT_AUX";
    case CS_REG_FAIL_COUNT:  return "FAIL_COUNT";
    case CS_REG_SLOT_MAP:    return "SLOT_MAP";
    case CS_REG_CMD:         return "CMD";
    case CS_REG_LBA_LO:      return "LBA_LO";
    case CS_REG_LBA_HI:      return "LBA_HI";
    case CS_REG_COUNT:       return "COUNT";
    case CS_REG_PW_LEN:      return "PW_LEN";
    case CS_REG_PW2_LEN:     return "PW2_LEN";
    case CS_REG_INT_STATUS:  return "INT_STATUS";
    case CS_REG_INT_ENABLE:  return "INT_ENABLE";
    case CS_REG_INT_ACK:     return "INT_ACK";
    default:                 return "?";
    }
}

static bool cs_data_window_open(CryptoStoreState *s)
{
    return s->state == CS_ST_UNLOCKED && !s->busy;
}

static uint32_t cs_caps(CryptoStoreState *s)
{
    uint32_t caps = cs_recovery_available(s) ? CS_CAPS_RECOVERY : 0;
#ifdef CRYPTOSTORE_FAULT_HOOKS
    caps |= CS_CAPS_FAULT_HOOKS;
#endif
    return caps;
}

static uint64_t cs_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    CryptoStoreState *s = opaque;
    bool unlocked = s->state == CS_ST_UNLOCKED;
    uint64_t val = 0;

    if (addr >= CS_WIN_DATA && addr + size <= CS_WIN_DATA + CS_WIN_DATA_SIZE) {
        if (cs_data_window_open(s)) {
            for (unsigned i = 0; i < size; i++) {
                val |= (uint64_t)s->data[addr - CS_WIN_DATA + i] << (8 * i);
            }
        }
        trace_cryptostore_window(s->label, "DATA", false, addr - CS_WIN_DATA, size);
        return val;     /* SR-01: reads 0 unless UNLOCKED */
    }
    if (addr >= CS_WIN_PW_A && addr + size <= CS_WIN_PW_B + CS_WIN_PW_SIZE) {
        trace_cryptostore_window(s->label, addr < CS_WIN_PW_B ? "PW_A" : "PW_B", false,
                                 addr & (CS_WIN_PW_SIZE - 1), size);
        return 0;       /* SR-09: write-only */
    }
    if (size != 4 || (addr & 3)) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: invalid %u-byte register read at 0x%" HWADDR_PRIx "\n",
                      s->label, size, addr);
        return 0;
    }

    switch (addr) {
    case CS_REG_ID:          val = CS_MAGIC; break;
    case CS_REG_VERSION:     val = CS_VERSION; break;
    case CS_REG_CAPS:        val = cs_caps(s); break;
    case CS_REG_SECTOR_SIZE: val = CS_SECTOR_SIZE; break;
    case CS_REG_MAX_SECTORS: val = CS_MAX_SECTORS; break;
    case CS_REG_PW_MAX:      val = CS_PW_MAX; break;
    case CS_REG_CAPACITY_LO: val = unlocked ? (uint32_t)s->hdr.capacity : 0; break;
    case CS_REG_CAPACITY_HI: val = unlocked ? (uint32_t)(s->hdr.capacity >> 32) : 0; break;
    case CS_REG_STATE:       val = cs_state_reg(s->state); break;
    case CS_REG_STATUS:      val = s->busy ? CS_STATUS_BUSY : 0; break;
    case CS_REG_RESULT:      val = s->result; break;
    case CS_REG_RESULT_AUX:  val = s->result_aux; break;
    case CS_REG_FAIL_COUNT:
        val = (s->state == CS_ST_UNFORMATTED || s->state == CS_ST_ERROR) ? 0 : s->hdr.fail_count;
        break;
    case CS_REG_SLOT_MAP:    val = cs_slot_map(s); break;
    case CS_REG_LBA_LO:      val = (uint32_t)s->lba; break;
    case CS_REG_LBA_HI:      val = (uint32_t)(s->lba >> 32); break;
    case CS_REG_COUNT:       val = s->count; break;
    case CS_REG_PW_LEN:      val = s->pw_len; break;
    case CS_REG_PW2_LEN:     val = s->pw2_len; break;
    case CS_REG_INT_STATUS:  val = s->int_status; break;
    case CS_REG_INT_ENABLE:  val = s->int_enable; break;
    case CS_REG_UUID0 ... CS_REG_UUID3:
        if (s->state != CS_ST_UNFORMATTED && s->state != CS_ST_ERROR) {
            val = csf_le32(s->hdr.uuid + (addr - CS_REG_UUID0));
        }
        break;
    case CS_REG_CMD:
    case CS_REG_INT_ACK:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: read from write-only register %s\n",
                      s->label, cs_reg_name(addr));
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: read from unmapped offset 0x%" HWADDR_PRIx "\n",
                      s->label, addr);
    }
    trace_cryptostore_mmio_read(s->label, addr, cs_reg_name(addr), val);
    return val;
}

static void cs_doorbell(CryptoStoreState *s, uint32_t cmd)
{
    if (s->busy) {
        if (cmd == CS_CMD_LOCK) {
            /* LOCK acts immediately; the cancelled command never completes (8). */
            trace_cryptostore_cmd_start(s->label, cmd, "BUSY");
            s->cur_cmd = cmd;
            if (!cs_lock_path(s)) {
                s->busy = true;
                cs_fault(s);
                return;
            }
            s->busy = true;
            cs_complete(s, CS_OK, 0);
            return;
        }
        qemu_log_mask(LOG_GUEST_ERROR, "%s: command 0x%x while busy, ignored\n", s->label, cmd);
        return;
    }
    s->busy = true;
    s->cur_cmd = cmd;
    s->cmd_start_ms = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    if (cmd != CS_CMD_WRITE) {
        explicit_bzero(s->data, sizeof(s->data));      /* 3.3 */
    }
    qemu_bh_schedule(s->cmd_bh);
}

static void cs_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    CryptoStoreState *s = opaque;
    uint32_t old;

    if (addr >= CS_WIN_DATA && addr + size <= CS_WIN_DATA + CS_WIN_DATA_SIZE) {
        trace_cryptostore_window(s->label, "DATA", true, addr - CS_WIN_DATA, size);
        if (!cs_data_window_open(s)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: DATA window write while not UNLOCKED or busy, "
                          "ignored\n", s->label);
            return;
        }
        for (unsigned i = 0; i < size; i++) {
            s->data[addr - CS_WIN_DATA + i] = val >> (8 * i);
        }
        return;
    }
    if (addr >= CS_WIN_PW_A && addr + size <= CS_WIN_PW_B + CS_WIN_PW_SIZE) {
        uint8_t *win = addr < CS_WIN_PW_B ? s->pw_a : s->pw_b;

        trace_cryptostore_window(s->label, addr < CS_WIN_PW_B ? "PW_A" : "PW_B", true,
                                 addr & (CS_WIN_PW_SIZE - 1), size);
        if (s->busy) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: password window write while busy, ignored\n",
                          s->label);
            return;
        }
        for (unsigned i = 0; i < size; i++) {
            win[(addr & (CS_WIN_PW_SIZE - 1)) + i] = val >> (8 * i);
        }
        return;
    }
    if (size != 4 || (addr & 3)) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: invalid %u-byte register write at 0x%" HWADDR_PRIx "\n",
                      s->label, size, addr);
        return;
    }
    trace_cryptostore_mmio_write(s->label, addr, cs_reg_name(addr), val);

    switch (addr) {
    case CS_REG_CMD:
        cs_doorbell(s, val);
        return;
    case CS_REG_INT_ENABLE:
        old = s->int_enable;
        s->int_enable = val & CS_INT_ALL;
        cs_update_irq(s, s->int_enable & ~old & s->int_status);
        return;
    case CS_REG_INT_ACK:
        s->int_status &= ~val;
        cs_update_irq(s, 0);
        return;
    case CS_REG_LBA_LO:
    case CS_REG_LBA_HI:
    case CS_REG_COUNT:
    case CS_REG_PW_LEN:
    case CS_REG_PW2_LEN:
        if (s->busy) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: %s written while busy, ignored\n",
                          s->label, cs_reg_name(addr));
            return;
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: write to read-only or unmapped register %s "
                      "(0x%" HWADDR_PRIx ")\n", s->label, cs_reg_name(addr), addr);
        return;
    }

    switch (addr) {
    case CS_REG_LBA_LO:
        s->lba = (s->lba & ~0xffffffffull) | (uint32_t)val;
        break;
    case CS_REG_LBA_HI:
        s->lba = (s->lba & 0xffffffffull) | ((uint64_t)val << 32);
        break;
    case CS_REG_COUNT:
        s->count = val;
        break;
    case CS_REG_PW_LEN:
        s->pw_len = val;
        break;
    case CS_REG_PW2_LEN:
        s->pw2_len = val;
        break;
    }
}

static const MemoryRegionOps cs_mmio_ops = {
    .read = cs_mmio_read,
    .write = cs_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

/* ---------------------------------------------------------------------- */
/* Reset, realize, unrealize                                              */
/* ---------------------------------------------------------------------- */

static void cs_reset_hold(Object *obj, ResetType type)
{
    CryptoStoreState *s = PCIE_CRYPTOSTORE(obj);
    PCIDevice *pdev = PCI_DEVICE(obj);
    bool flr = pci_is_express(pdev) && pdev->exp.exp_cap &&
               (pci_get_word(pdev->config + pdev->exp.exp_cap + PCI_EXP_DEVCTL) &
                PCI_EXP_DEVCTL_BCR_FLR);
    bool ok;

    trace_cryptostore_reset(s->label, flr ? "flr" : "reset");
    ok = cs_lock_path(s);   /* datasheet section 8 */
    s->cur_cmd = 0;
    s->result = 0;
    s->result_aux = 0;
    s->lba = 0;
    s->count = 0;
    s->pw_len = 0;
    s->pw2_len = 0;
    s->int_status = 0;
    s->int_enable = 0;
    s->intx_level = false;
    if (!ok) {
        cs_fault(s);
    }
}

static void cs_config_write(PCIDevice *pdev, uint32_t addr, uint32_t val, int len)
{
    pci_default_write_config(pdev, addr, val, len);
    pcie_cap_flr_write_config(pdev, addr, val, len);
}

static void cs_realize(PCIDevice *pdev, Error **errp)
{
    ERRP_GUARD();
    CryptoStoreState *s = PCIE_CRYPTOSTORE(pdev);
    uint8_t hdr[CSF_HDR_SIZE] = { 0 };
    const char *why = NULL;
    Error *err = NULL;
    int ret;

    s->label = g_strdup(DEVICE(pdev)->id ? DEVICE(pdev)->id : TYPE_PCIE_CRYPTOSTORE);

    if (!pci_bus_is_express(pci_get_bus(pdev))) {
        error_setg(errp, "%s must be plugged into a PCI Express bus", TYPE_PCIE_CRYPTOSTORE);
        return;
    }
    /* SR-34: known-answer tests before touching anything. */
    if (cs_selftest(cs_hook(s, "selftest"), errp) < 0) {
        return;
    }
    if (!s->blk) {
        error_setg(errp, "%s needs drive= (the backing image)", TYPE_PCIE_CRYPTOSTORE);
        return;
    }
    if (!blk_supports_write_perm(s->blk)) {
        error_setg(errp, "%s: the backing image must be writable", TYPE_PCIE_CRYPTOSTORE);
        return;
    }
    /* The device is the only writer of the image (SR-30, reference monitor). */
    if (blk_set_perm(s->blk, BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                     BLK_PERM_CONSISTENT_READ, errp) < 0) {
        return;
    }
    s->file_size = blk_getlength(s->blk);
    if (s->file_size < 0) {
        error_setg(errp, "%s: cannot get the image size", TYPE_PCIE_CRYPTOSTORE);
        return;
    }
    if (blk_pread(s->blk, 0, MIN(s->file_size, (int64_t)CSF_HDR_SIZE), hdr, 0) < 0) {
        error_setg(errp, "%s: cannot read the image header", TYPE_PCIE_CRYPTOSTORE);
        return;
    }

    switch (csf_parse(hdr, s->file_size, &s->hdr, &why)) {
    case CSF_UNFORMATTED:
        s->state = CS_ST_UNFORMATTED;
        break;
    case CSF_VALID:
        s->state = (!s->hdr.fail_record_ok || s->hdr.fail_count >= CS_LOCKOUT_N) ?
                   CS_ST_LOCKED_OUT : CS_ST_LOCKED;
        break;
    default:
        s->state = CS_ST_ERROR;
        warn_report("%s: image rejected (%s); device is in ERROR", s->label, why);
        break;
    }
    explicit_bzero(hdr, sizeof(hdr));
    trace_cryptostore_state(s->label, "realize", cs_state_name(s->state));

    s->dek_loaded = CS_FS_FALSE;
    pci_config_set_interrupt_pin(pdev->config, 1);
    if (pci_pm_init(pdev, CS_PM_OFFSET, errp) < 0) {
        return;
    }
    ret = msi_init(pdev, CS_MSI_OFFSET, 1, true, false, &err);
    if (ret == -ENOTSUP) {
        warn_report_err(err);
        err = NULL;
    } else if (ret < 0) {
        error_propagate(errp, err);
        return;
    }
    if (pcie_endpoint_cap_init(pdev, CS_EXP_OFFSET) < 0) {
        error_setg(errp, "failed to add PCI Express capability");
        goto err_msi;
    }
    pcie_cap_flr_init(pdev);
    pcie_cap_deverr_init(pdev);

    memory_region_init_io(&s->mmio, OBJECT(s), &cs_mmio_ops, s, "pcie-cryptostore-mmio",
                          CS_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &s->mmio);
    ret = msix_init_exclusive_bar(pdev, CS_MSIX_VECTORS, CS_MSIX_BAR, &err);
    if (ret == -ENOTSUP) {
        warn_report_err(err);
        err = NULL;
    } else if (ret < 0) {
        error_propagate(errp, err);
        goto err_msi;
    } else {
        msix_vector_use(pdev, 0);
    }

    s->cmd_bh = qemu_bh_new_guarded(cs_cmd_bh, s, &DEVICE(pdev)->mem_reentrancy_guard);
    s->fill_bh = qemu_bh_new_guarded(cs_fill_bh, s, &DEVICE(pdev)->mem_reentrancy_guard);
    timer_init_ms(&s->pad_timer, QEMU_CLOCK_REALTIME, cs_finalize, s);
    return;

err_msi:
    msi_uninit(pdev);
}

static void cs_exit(PCIDevice *pdev)
{
    CryptoStoreState *s = PCIE_CRYPTOSTORE(pdev);

    cs_cancel_all(s);
    cs_zeroize(s, false);          /* SR-02: unrealize */
    timer_del(&s->pad_timer);
    qemu_bh_delete(s->cmd_bh);
    qemu_bh_delete(s->fill_bh);
    if (msix_present(pdev)) {
        msix_vector_unuse(pdev, 0);
        msix_uninit_exclusive_bar(pdev);
    }
    msi_uninit(pdev);
    g_free(s->label);
    s->label = NULL;
}

/* ---------------------------------------------------------------------- */
/* QOM                                                                    */
/* ---------------------------------------------------------------------- */

#ifdef CRYPTOSTORE_FAULT_HOOKS
static char *cs_get_fault(Object *obj, Error **errp)
{
    CryptoStoreState *s = PCIE_CRYPTOSTORE(obj);

    return g_strdup(s->fault ? s->fault : "");
}

static void cs_set_fault(Object *obj, const char *value, Error **errp)
{
    CryptoStoreState *s = PCIE_CRYPTOSTORE(obj);

    g_free(s->fault);
    s->fault = *value ? g_strdup(value) : NULL;
}

static void cs_prop_time_offset(Object *obj, Visitor *v, const char *name,
                                void *opaque, Error **errp)
{
    CryptoStoreState *s = PCIE_CRYPTOSTORE(obj);

    visit_type_int64(v, name, &s->time_offset_ms, errp);
}
#endif

static void cs_instance_init(Object *obj)
{
#ifdef CRYPTOSTORE_FAULT_HOOKS
    /* Test builds only (SR-29): one-shot simulated faults and a clock offset. */
    object_property_add_str(obj, "x-fault", cs_get_fault, cs_set_fault);
    object_property_add(obj, "x-time-offset-ms", "int64", cs_prop_time_offset,
                        cs_prop_time_offset, NULL, NULL);
    object_property_add_uint32_ptr(obj, "x-crash-after-writes",
                                   &PCIE_CRYPTOSTORE(obj)->crash_after_writes,
                                   OBJ_PROP_FLAG_READWRITE);
#endif
}

static const Property cs_props[] = {
    DEFINE_PROP_DRIVE("drive", CryptoStoreState, blk),
    DEFINE_PROP_LINK("recovery", CryptoStoreState, recovery,
                     TYPE_PCIE_CRYPTORECOVERY, CryptoRecoveryState *),
};

static const VMStateDescription vmstate_cs = {
    .name = TYPE_PCIE_CRYPTOSTORE,
    .unmigratable = 1,          /* SR-12: never migrate or snapshot */
};

static void cs_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = cs_realize;
    k->exit = cs_exit;
    k->config_write = cs_config_write;
    k->vendor_id = CS_VENDOR_ID;
    k->device_id = CS_DEVICE_ID;
    k->revision = CS_REVISION;
    k->class_id = CS_CLASS;
    rc->phases.hold = cs_reset_hold;
    dc->desc = "Encrypted PCIe storage with password unlock";
    dc->vmsd = &vmstate_cs;
    device_class_set_props(dc, cs_props);
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}

static const TypeInfo cs_types[] = {
    {
        .name          = TYPE_PCIE_CRYPTOSTORE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(CryptoStoreState),
        .instance_init = cs_instance_init,
        .class_init    = cs_class_init,
        .interfaces    = (const InterfaceInfo[]) {
            { INTERFACE_PCIE_DEVICE },
            { },
        },
    },
};

DEFINE_TYPES(cs_types)
