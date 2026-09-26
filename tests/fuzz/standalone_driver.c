/*
 * Minimal mutation driver for LLVMFuzzerTestOneInput(), used when the
 * libFuzzer runtime (libclang-rt-*-dev) is not installed. Build with
 * -fsanitize=address,undefined so memory errors abort.
 *
 * usage: driver SECONDS SEED_FILE...
 *
 * Not coverage guided: each round picks a seed and applies 1-8 random
 * mutations (bit flips, byte sets, interesting 16/32/64-bit values at
 * field-aligned offsets, block copies). The seeds are structure-aware, so
 * the mutations exercise every validation step.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAXLEN 4104

static uint64_t rng_state;

static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static const uint64_t interesting[] = {
    0, 1, 2, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x1000, 0x7fff, 0x8000, 0xffff,
    2048, 2047, 599999, 600000, 400000000, 400000001, 0x5a3ca5c3,
    0x7fffffff, 0x80000000u, 0xffffffffu, 1ull << 32, (1ull << 32) + 1,
    0x7fffffffffffffffull, 0xffffffffffffffffull,
};

int main(int argc, char **argv)
{
    static uint8_t seeds[64][MAXLEN];
    static size_t seed_len[64];
    int nseeds = 0;
    uint8_t buf[MAXLEN];
    double secs;
    time_t end;
    unsigned long runs = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s SECONDS SEED...\n", argv[0]);
        return 2;
    }
    secs = atof(argv[1]);
    for (int i = 2; i < argc && nseeds < 64; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            perror(argv[i]);
            return 2;
        }
        seed_len[nseeds] = fread(seeds[nseeds], 1, MAXLEN, f);
        fclose(f);
        LLVMFuzzerTestOneInput(seeds[nseeds], seed_len[nseeds]);
        nseeds++;
    }
    rng_state = (uint64_t)time(NULL) * 0x9e3779b97f4a7c15ull | 1;
    end = time(NULL) + (time_t)secs;

    while (time(NULL) < end) {
        for (int batch = 0; batch < 1000; batch++) {
            int s = rnd() % nseeds;
            size_t len = seed_len[s];
            int nmut = 1 + rnd() % 8;

            memcpy(buf, seeds[s], len);
            for (int m = 0; m < nmut; m++) {
                size_t off = rnd() % len;
                switch (rnd() % 5) {
                case 0:
                    buf[off] ^= 1u << (rnd() % 8);
                    break;
                case 1:
                    buf[off] = rnd();
                    break;
                case 2: {
                    uint64_t v = interesting[rnd() % (sizeof(interesting) / sizeof(interesting[0]))];
                    size_t w = (size_t[]){2, 4, 8}[rnd() % 3];
                    off &= ~(size_t)(w - 1);
                    for (size_t k = 0; k < w && off + k < len; k++) {
                        buf[off + k] = v >> (8 * k);
                    }
                    break;
                }
                case 3: {
                    size_t src = rnd() % len, n = 1 + rnd() % 256;
                    if (src + n > len) n = len - src;
                    if (off + n > len) n = len - off;
                    memmove(buf + off, buf + src, n);
                    break;
                }
                case 4:
                    if (rnd() % 4 == 0 && len > 9) {
                        len = 8 + rnd() % (len - 8);      /* truncate */
                    }
                    break;
                }
            }
            LLVMFuzzerTestOneInput(buf, len);
            runs++;
        }
    }
    printf("standalone driver: %lu runs in %.0f s over %d seeds, no failures\n",
           runs, secs, nseeds);
    return 0;
}
