/*
 * Unit tests for the pcie-cryptostore crypto constructions
 * (qemu/cryptostore_crypto.c, datasheet 10.4).
 *
 *   - SR-34: the realize-time known-answer tests pass, and the slower
 *     RFC 7914 vector 2 (80000 iterations) too
 *   - keyslot wrap/unwrap round trip; any tampered field fails the tag
 *   - SR-05 (R10): the verification routine takes the same time for a
 *     near-miss and a far-miss, over 1000 runs each
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include <math.h>
#include "qapi/error.h"
#include "crypto/init.h"
#include "crypto/pbkdf.h"
#include "cryptostore_crypto.h"
#include "cryptostore_kat.h"

static void test_selftest(void)
{
    Error *err = NULL;

    g_assert_cmpint(cs_selftest(false, &err), ==, 0);
    g_assert_null(err);
    g_assert_cmpint(cs_selftest(true, &err), <, 0);
    g_assert_nonnull(strstr(error_get_pretty(err), "forced failure"));
    error_free(err);
}

static void test_pbkdf2_rfc7914_slow(void)
{
    uint8_t dk[KAT_PBKDF2_2_DK_LEN];

    g_assert_cmpint(qcrypto_pbkdf2(QCRYPTO_HASH_ALGO_SHA256, (const uint8_t *)KAT_PBKDF2_2_P,
                                   strlen(KAT_PBKDF2_2_P), (const uint8_t *)KAT_PBKDF2_2_S,
                                   strlen(KAT_PBKDF2_2_S), KAT_PBKDF2_2_C, dk, sizeof(dk),
                                   &error_abort), ==, 0);
    g_assert_cmpmem(dk, sizeof(dk), kat_pbkdf2_2_dk, sizeof(dk));
}

static void make_slot(CsfSlot *s, uint8_t kek[CS_KEY_LEN], uint8_t uuid[16], uint8_t dek[64])
{
    memset(s, 0, sizeof(*s));
    s->state = CSF_SLOT_ACTIVE;
    s->type = CSF_TYPE_PASSWORD;
    s->kdf = CSF_KDF_PBKDF2_SHA256;
    s->iters = CSF_PBKDF2_MIN_ITERS;
    for (int i = 0; i < CSF_SALT_LEN; i++) s->salt[i] = i;
    for (int i = 0; i < CSF_IV_LEN; i++) s->iv[i] = 0xa0 + i;
    for (int i = 0; i < CS_KEY_LEN; i++) kek[i] = 0x11 * (i + 1);
    for (int i = 0; i < 16; i++) uuid[i] = 0x40 + i;
    for (int i = 0; i < 64; i++) dek[i] = 0x80 ^ i;
    g_assert_cmpint(cs_slot_wrap(s, kek, uuid, 3, dek, &error_abort), ==, 0);
}

static void test_wrap_unwrap(void)
{
    uint8_t kek[CS_KEY_LEN], uuid[16], dek[64], out[64];
    bool match, fault;
    CsfSlot s, t;

    make_slot(&s, kek, uuid, dek);
    g_assert_cmpint(memcmp(s.wrapped, dek, 64), !=, 0);         /* actually encrypted */
    g_assert_cmpint(cs_slot_unwrap(&s, kek, uuid, 3, out, &match, &fault, false,
                                   &error_abort), ==, 0);
    g_assert_true(match);
    g_assert_false(fault);
    g_assert_cmpmem(out, 64, dek, 64);

    /* Wrong KEK, index, UUID, or any tag-covered field: no match, no fault. */
    kek[0] ^= 1;
    cs_slot_unwrap(&s, kek, uuid, 3, out, &match, &fault, false, &error_abort);
    g_assert_false(match);
    kek[0] ^= 1;
    cs_slot_unwrap(&s, kek, uuid, 4, out, &match, &fault, false, &error_abort);
    g_assert_false(match);
    uuid[15] ^= 1;
    cs_slot_unwrap(&s, kek, uuid, 3, out, &match, &fault, false, &error_abort);
    g_assert_false(match);
    uuid[15] ^= 1;
    G_STATIC_ASSERT(offsetof(CsfSlot, tag) == 4 + 2 + 2 + 4 + 32 + 16 + 64);  /* no padding */
    for (size_t off = 0; off < offsetof(CsfSlot, tag); off++) {
        t = s;
        ((uint8_t *)&t)[off] ^= 0x01;
        cs_slot_unwrap(&t, kek, uuid, 3, out, &match, &fault, false, &error_abort);
        g_assert_false(match);
    }
    /* The F9 hook: first compare forced to "match" is caught by the second. */
    kek[0] ^= 1;
    cs_slot_unwrap(&s, kek, uuid, 3, out, &match, &fault, true, &error_abort);
    g_assert_false(match);
    g_assert_true(fault);
}

static void test_header_mac(void)
{
    uint8_t dek[64], uuid[16], fixed[CSF_MAC_COVER_LEN], m1[32], m2[32];

    memset(dek, 7, sizeof(dek));
    memset(uuid, 9, sizeof(uuid));
    csf_encode_fixed(uuid, 4096, fixed);
    cs_header_mac(dek, uuid, fixed, m1, &error_abort);
    csf_encode_fixed(uuid, 4095, fixed);
    cs_header_mac(dek, uuid, fixed, m2, &error_abort);
    g_assert_cmpint(memcmp(m1, m2, 32), !=, 0);
    dek[63] ^= 1;
    csf_encode_fixed(uuid, 4096, fixed);
    cs_header_mac(dek, uuid, fixed, m2, &error_abort);
    g_assert_cmpint(memcmp(m1, m2, 32), !=, 0);
}

static void test_xts_tweak(void)
{
    g_autoptr(QCryptoCipher) x = NULL;
    uint8_t dek[64], pt[512], c0[512], c1[512], back[512];

    for (int i = 0; i < 64; i++) dek[i] = i * 3 + 1;
    memset(pt, 0x33, sizeof(pt));
    x = cs_xts_new(dek, &error_abort);
    cs_xts_sector(x, 100, true, pt, c0, &error_abort);
    cs_xts_sector(x, 101, true, pt, c1, &error_abort);
    g_assert_cmpint(memcmp(c0, c1, 512), !=, 0);    /* SR-06: per-sector tweak */
    cs_xts_sector(x, 100, false, c0, back, &error_abort);
    g_assert_cmpmem(back, 512, pt, 512);
}

static void test_wipe(void)
{
    uint8_t buf[64];

    memset(buf, 0xff, sizeof(buf));
    g_assert_true(cs_wipe(buf, sizeof(buf)));
    for (size_t i = 0; i < sizeof(buf); i++) {
        g_assert_cmpuint(buf[i], ==, 0);
    }
}

/* Median of @n timings (ns) of one unwrap. */
static double time_unwrap(CsfSlot *s, uint8_t kek[CS_KEY_LEN], uint8_t uuid[16], int n)
{
    g_autofree double *t = g_new(double, n);
    uint8_t out[64];
    bool match, fault;

    for (int i = 0; i < n; i++) {
        struct timespec ts0, ts1;

        clock_gettime(CLOCK_MONOTONIC, &ts0);
        cs_slot_unwrap(s, kek, uuid, 3, out, &match, &fault, false, &error_abort);
        clock_gettime(CLOCK_MONOTONIC, &ts1);
        t[i] = (ts1.tv_sec - ts0.tv_sec) * 1e9 + (ts1.tv_nsec - ts0.tv_nsec);
    }
    for (int i = 1; i < n; i++) {            /* insertion sort, n is small */
        double v = t[i];
        int j = i - 1;
        while (j >= 0 && t[j] > v) {
            t[j + 1] = t[j];
            j--;
        }
        t[j + 1] = v;
    }
    return t[n / 2];
}

/*
 * SR-05 / R10: how close a wrong key is must not change the time. A
 * near-miss slot (stored tag differs only in its last byte) and a far-miss
 * slot (differs in every byte) are timed 1000 times each; the medians must
 * agree within 10%. The compare itself is also timed in isolation.
 */
static void test_timing(void)
{
    uint8_t kek[CS_KEY_LEN], uuid[16], dek[64];
    CsfSlot s, near_miss, far_miss;
    double t_near, t_far, c_first, c_last;
    uint8_t a[32] = { 0 }, b_first[32] = { 0 }, b_last[32] = { 0 };
    const int n = 1000;
    struct timespec t0, t1;
    volatile bool sink = false;

    make_slot(&s, kek, uuid, dek);
    near_miss = s;
    near_miss.tag[31] ^= 1;
    far_miss = s;
    for (int i = 0; i < 32; i++) far_miss.tag[i] ^= 0xff;

    time_unwrap(&s, kek, uuid, 50);         /* warm up */
    t_near = time_unwrap(&near_miss, kek, uuid, n);
    t_far = time_unwrap(&far_miss, kek, uuid, n);
    g_test_message("unwrap median over %d runs: near-miss %.0f ns, far-miss %.0f ns", n,
                   t_near, t_far);
    g_assert_cmpfloat(fabs(t_near - t_far) / MAX(t_near, t_far), <, 0.10);

    /*
     * The compare in isolation: alternate the two cases over 21 rounds and
     * compare medians, so CPU frequency drift and ordering cancel out.
     */
    b_first[0] = 1;
    b_last[31] = 1;
    {
        double rf[21], rl[21];

        for (int r = 0; r < 21; r++) {
            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int i = 0; i < 20000; i++) sink ^= cs_ct_equal(a, b_first, 32);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            rf[r] = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int i = 0; i < 20000; i++) sink ^= cs_ct_equal(a, b_last, 32);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            rl[r] = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
        }
        for (int i = 1; i < 21; i++) {
            for (int j = i; j > 0 && rf[j - 1] > rf[j]; j--) {
                double v = rf[j]; rf[j] = rf[j - 1]; rf[j - 1] = v;
            }
            for (int j = i; j > 0 && rl[j - 1] > rl[j]; j--) {
                double v = rl[j]; rl[j] = rl[j - 1]; rl[j - 1] = v;
            }
        }
        c_first = rf[10];
        c_last = rl[10];
    }
    g_test_message("cs_ct_equal, median of 21 rounds x 20000: first-byte difference "
                   "%.1f us, last-byte %.1f us", c_first / 1e3, c_last / 1e3);
    g_assert_cmpfloat(fabs(c_first - c_last) / MAX(c_first, c_last), <, 0.10);
    (void)sink;
}

static void test_calibrate(void)
{
    uint32_t iters = cs_pbkdf2_calibrate(500, &error_abort);

    g_test_message("PBKDF2-HMAC-SHA256 iterations for 0.5 s on this host: %u", iters);
    g_assert_cmpuint(iters, >=, CSF_PBKDF2_MIN_ITERS);
    g_assert_cmpuint(iters, <=, CSF_PBKDF2_MAX_ITERS);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert(qcrypto_init(NULL) == 0);

    g_test_add_func("/cryptostore/sr34-selftest", test_selftest);
    g_test_add_func("/cryptostore/pbkdf2-rfc7914-vector2", test_pbkdf2_rfc7914_slow);
    g_test_add_func("/cryptostore/wrap-unwrap", test_wrap_unwrap);
    g_test_add_func("/cryptostore/header-mac", test_header_mac);
    g_test_add_func("/cryptostore/sr06-xts-tweak", test_xts_tweak);
    g_test_add_func("/cryptostore/wipe", test_wipe);
    g_test_add_func("/cryptostore/sr05-timing", test_timing);
    g_test_add_func("/cryptostore/sr03-calibrate", test_calibrate);
    return g_test_run();
}
