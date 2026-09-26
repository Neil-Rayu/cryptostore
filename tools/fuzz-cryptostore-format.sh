#!/usr/bin/env bash
# Fuzz the cryptostore header parser in isolation (SR-16, threat model 12.3).
#   tools/fuzz-cryptostore-format.sh [seconds]     (default 60)
# Builds qemu/cryptostore_format.c with ASan + UBSan, seeds the corpus with a
# valid header and malformed variants, and runs for a fixed time budget.
# Uses libFuzzer (coverage guided) when the clang runtime is installed
# (sudo apt install libclang-rt-18-dev); otherwise a built-in mutation driver.
# Any crash or failed round-trip property exits non-zero.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/fuzz"
SECS="${1:-60}"
SRC=("$ROOT/tests/fuzz/cryptostore_format_fuzz.c" "$ROOT/qemu/cryptostore_format.c")
mkdir -p "$OUT/corpus"
python3 "$ROOT/tools/cryptostore_image.py" seed-corpus "$OUT/corpus" >/dev/null

if clang -fsanitize=fuzzer -x c /dev/null -o /dev/null 2>/dev/null ||
   [ -e "$(clang -print-resource-dir 2>/dev/null)/lib/linux/libclang_rt.fuzzer-x86_64.a" ]; then
    echo "==> libFuzzer, ${SECS}s"
    clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
        -I"$ROOT/include" "${SRC[@]}" -o "$OUT/cryptostore_format_fuzz"
    "$OUT/cryptostore_format_fuzz" -max_total_time="$SECS" -max_len=4104 \
        -print_final_stats=1 "$OUT/corpus" 2>&1 | tail -n 15
else
    echo "==> libFuzzer runtime not installed; using the standalone mutation driver, ${SECS}s"
    gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
        -I"$ROOT/include" "${SRC[@]}" "$ROOT/tests/fuzz/standalone_driver.c" \
        -o "$OUT/cryptostore_format_fuzz_standalone"
    "$OUT/cryptostore_format_fuzz_standalone" "$SECS" "$OUT"/corpus/*
fi
