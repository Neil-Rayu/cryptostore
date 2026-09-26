/*
 * Harness for the instruction-skip campaign (threat model 12.4 #3).
 * Runs one FI-hardened decision from qemu/cryptostore_fi.c and reports the
 * outcome in the exit code, so tools/fi-skip-campaign.py can run it under
 * gdb and skip one instruction per run.
 *
 *   harness jitter N          exit 20: no fault reported, 22: fault detected
 *   harness tag wrong POS     exit 10: accept, 11: reject, 12: fault
 *   harness tag right 0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cryptostore_fi.h"

/* The device inlines cs_secure_jitter; here it gets its own symbol to target. */
__attribute__((noinline)) bool jitter_probe(uint32_t cycles)
{
    return cs_secure_jitter(cycles);
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "jitter")) {
        return jitter_probe((uint32_t)atoi(argv[2])) ? 20 : 22;
    }
    if (argc == 4 && !strcmp(argv[1], "tag")) {
        uint8_t computed[32], stored[32];
        uint32_t v;

        memset(computed, 0x5a, sizeof(computed));
        memcpy(stored, computed, sizeof(stored));
        if (!strcmp(argv[2], "wrong")) {
            stored[atoi(argv[3]) % 32] ^= 0x01;
        }
        v = cs_tag_verdict(computed, stored, sizeof(computed), false);
        return v == CS_FS_TRUE ? 10 : v == CS_FS_FALSE ? 11 : 12;
    }
    fprintf(stderr, "usage: harness jitter N | tag wrong|right POS\n");
    return 2;
}
