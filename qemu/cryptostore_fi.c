/*
 * pcie-cryptostore FI-hardened decision helpers, free of QEMU dependencies
 * so the instruction-skip campaign (threat model 12.4) runs the same code as
 * the device.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "cryptostore_fi.h"

/* noinline: the two compares must stay distinct code paths (F9, SR-28). */
__attribute__((noinline))
bool cs_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t acc = 0;

    for (size_t i = 0; i < len; i++) {
        acc |= a[i] ^ b[i];
    }
    return cs_launder32(acc) == 0;
}

/* Different code path for the redundant compare (F9): backwards, by subtraction. */
__attribute__((noinline))
bool cs_ct_equal_alt(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint32_t acc = 0;

    for (size_t i = len; i > 0; i--) {
        acc |= (uint32_t)(uint8_t)(a[i - 1] - b[i - 1]);
    }
    return cs_launder32(acc) == 0;
}

/*
 * Each compare contributes its own mask, so FS_TRUE needs both to say
 * "match": K1 ^ K2 == FS_FALSE ^ FS_TRUE. One compare alone yields
 * FS_FALSE ^ K1 or FS_FALSE ^ K2, 23-24 bits away from FS_TRUE, which callers
 * treat as a fault. An earlier version selected between the two constants
 * with a single sbb; the instruction-skip campaign showed that skipping that
 * sbb (or the cmp before it) turned a reject into an accept.
 */
#define CS_VERDICT_K1 0xf6d7fbb3u
#define CS_VERDICT_K2 0xcbef3fcdu
_Static_assert((CS_VERDICT_K1 ^ CS_VERDICT_K2) == (CS_FS_FALSE ^ CS_FS_TRUE),
               "verdict masks must combine to FS_TRUE");

__attribute__((noinline))
uint32_t cs_tag_verdict(const uint8_t *computed, const uint8_t *stored, size_t len,
                        bool force_first_match)
{
    uint32_t r = CS_FS_FALSE;
    uint32_t m1, m2;

    m1 = cs_ct_equal(computed, stored, len) || force_first_match;
    r ^= CS_VERDICT_K1 & (0u - cs_launder32(m1));
    cs_compiler_barrier();
    m2 = cs_ct_equal_alt(stored, computed, len);
    r ^= CS_VERDICT_K2 & (0u - cs_launder32(m2));
    return r;   /* FS_TRUE, FS_FALSE, or a fault value */
}
