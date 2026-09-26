/*
 * Fault-injection hardening primitives for pcie-cryptostore
 * (threat model section 10, SR-21 to SR-27).
 *
 * In an emulated device these model the countermeasures rather than provide
 * them (O1): anyone with host access can read QEMU's memory. They are still
 * implemented and tested with simulated faults (SR-29).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef CRYPTOSTORE_FI_H
#define CRYPTOSTORE_FI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fail-secure encodings (SR-21). Constants were chosen with a minimum
 * pairwise Hamming distance of 14 bits, so a corrupted value decodes as
 * "invalid" instead of as another valid state. Zero is never valid.
 */
#define CS_ST_UNFORMATTED   0xc7df9d6eu
#define CS_ST_LOCKED        0x6db4bffau
#define CS_ST_UNLOCKED      0x28e94a2fu
#define CS_ST_RECOVERED     0xe166f920u
#define CS_ST_LOCKED_OUT    0xd5bc511au
#define CS_ST_ERROR         0xf25b1a30u

#define CS_FS_TRUE          0x889725b9u
#define CS_FS_FALSE         0xb5afe1c7u

/* Optimization barrier: the compiler must assume @v may have changed. */
static inline uint32_t cs_launder32(uint32_t v)
{
    __asm__ __volatile__("" : "+r"(v));
    return v;
}

static inline void cs_compiler_barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/*
 * C port of secure_jitter (ECE397-MP2 Pattern 10, docs/reference/
 * secure_jitter.md). Returns true when all three redundant checks pass,
 * false when a fault is detected; the caller runs the detection response
 * (SR-27) instead of panicking. @cycles must come from the CSPRNG (SR-23).
 *
 * 1. launder the delay value (black_box)
 * 2. keep two volatile copies of it
 * 3. volatile countdown loop with a nop each iteration
 * 4. counter is zero; saved copy equals the input; counter re-read is zero
 */
static inline __attribute__((always_inline)) bool cs_secure_jitter(uint32_t cycles_in)
{
    uint32_t cycles = cs_launder32(cycles_in);
    volatile uint32_t limit = cycles;
    volatile uint32_t saved = cycles;

    while (limit > 0) {
        __asm__ __volatile__("nop");
        limit = limit - 1;
    }
    if (cs_launder32(limit) != 0) {
        return false;
    }
    if (cs_launder32(saved) != cs_launder32(cycles)) {
        return false;
    }
    if (cs_launder32(limit) != 0) {
        return false;
    }
    return true;
}

/* Constant-time equality (SR-05), two independent implementations (F9). */
bool cs_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);
bool cs_ct_equal_alt(const uint8_t *a, const uint8_t *b, size_t len);

/*
 * F9 tag decision: CS_FS_TRUE (match), CS_FS_FALSE (no match), anything else
 * is a fault. Callers must compare against both constants explicitly.
 */
uint32_t cs_tag_verdict(const uint8_t *computed, const uint8_t *stored, size_t len,
                        bool force_first_match);

/* Fault-hook targets (SR-29). Hooks exist only in test builds. */
typedef enum CsFaultTarget {
    CS_FT_NONE = 0,
    CS_FT_F1_COUNTER,       /* skip the failure-counter write */
    CS_FT_F2_BACKOFF,       /* first backoff evaluation says "allowed" */
    CS_FT_F3_WIPE,          /* skip the DEK wipe */
    CS_FT_F4_LOCKCHECK,     /* first lock-state check says "unlocked" */
    CS_FT_F5_KDFMIN,        /* corrupt loaded iterations; first check passes */
    CS_FT_F6_BOUNDS,        /* first bounds check passes */
    CS_FT_F7_AES,           /* corrupt one AES output byte */
    CS_FT_F8_RELEASE,       /* recovery release-once check passes */
    CS_FT_F9_TAG,           /* first tag compare says "match" */
    CS_FT_CFI,              /* skip one step of the unlock sequence */
    CS_FT_JITTER,           /* corrupt the jitter loop counter */
    CS_FT_SELFTEST,         /* make a realize-time known-answer test fail */
    CS_FT__MAX,
} CsFaultTarget;

#endif /* CRYPTOSTORE_FI_H */
