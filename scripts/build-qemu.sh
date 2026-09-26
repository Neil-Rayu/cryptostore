#!/usr/bin/env bash
# Build QEMU (x86_64 system emulator) with the CryptoStore devices.
#
# - Clones QEMU at $QEMU_REF into build/qemu-src (once).
# - Applies qemu/cryptostore-build-hooks.patch (Kconfig + meson + trace-events + tests).
# - Symlinks qemu/*.{c,h} and the shared include/ headers into hw/misc/,
#   so editing them in this repo and re-running this script is enough.
# - Configures a debug build with KVM, virtfs (9p), slirp and the "log"
#   trace backend, then builds with ninja.
#
# Env: QEMU_REF (default v11.1.1), RECONFIGURE=1 to re-run configure,
#      TEST_BUILD=1 to build the fault-injection test build instead
#      (build/qemu-src/build-test, -DCRYPTOSTORE_FAULT_HOOKS; SR-29).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QEMU_REF="${QEMU_REF:-v11.1.1}"
SRC="$ROOT/build/qemu-src"
BLD="$SRC/build"
EXTRA_CFLAGS=""
if [ "${TEST_BUILD:-0}" = 1 ]; then
    BLD="$SRC/build-test"
    EXTRA_CFLAGS="-DCRYPTOSTORE_FAULT_HOOKS"
fi

need_pkg() {
    if ! pkg-config --exists "$1"; then
        echo "error: missing pkg-config package '$1' ($2)" >&2
        echo "       try: sudo apt install $3" >&2
        exit 1
    fi
}
need_pkg glib-2.0 "QEMU core" libglib2.0-dev
need_pkg pixman-1 "QEMU core" libpixman-1-dev
need_pkg slirp "user-mode networking" libslirp-dev
need_pkg libcap-ng "virtfs/9p" libcap-ng-dev
for t in git ninja python3 flex bison; do
    command -v "$t" >/dev/null || { echo "error: '$t' not found" >&2; exit 1; }
done

if [ ! -d "$SRC/.git" ]; then
    echo "==> Cloning QEMU $QEMU_REF"
    mkdir -p "$ROOT/build"
    git clone --depth 1 --branch "$QEMU_REF" \
        https://gitlab.com/qemu-project/qemu.git "$SRC"
fi

cd "$SRC"
PATCH="$ROOT/qemu/cryptostore-build-hooks.patch"
python3 "$ROOT/scripts/clean-qemu-hooks.py" "$SRC"
if git apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "==> Build hooks already applied"
else
    echo "==> Applying build hooks"
    git apply "$PATCH"
fi
# Device sources and the shared hardware headers live in this repo.
for f in "$ROOT"/qemu/*.c "$ROOT"/qemu/*.h; do
    ln -sfn "../../../../qemu/$(basename "$f")" "hw/misc/$(basename "$f")"
done
for f in cryptostore_regs.h cryptostore_format.h; do
    ln -sfn "../../../../include/$f" "hw/misc/$f"
done
# qtest for the cryptostore devices (links the standalone format parser too).
ln -sfn ../../../../tests/qtest/cryptostore-test.c tests/qtest/cryptostore-test.c
ln -sfn ../../../../qemu/cryptostore_format.c tests/qtest/cryptostore_format.c
for f in cryptostore_regs.h cryptostore_format.h; do
    ln -sfn "../../../../include/$f" "tests/qtest/$f"
done
# Unit test for the crypto constructions (SR-34 KATs, SR-05 timing).
ln -sfn ../../../../tests/unit/test-cryptostore-crypto.c tests/unit/test-cryptostore-crypto.c
for f in cryptostore_crypto.c cryptostore_crypto.h cryptostore_format.c cryptostore_fi.c cryptostore_fi.h cryptostore_kat.h; do
    ln -sfn "../../../../qemu/$f" "tests/unit/$f"
done
ln -sfn ../../../../include/cryptostore_format.h tests/unit/cryptostore_format.h

if [ ! -f "$BLD/build.ninja" ] || [ "${RECONFIGURE:-0}" = 1 ]; then
    echo "==> Configuring"
    mkdir -p "$BLD"
    (cd "$BLD" && ../configure \
        --target-list=x86_64-softmmu \
        --enable-debug \
        --enable-kvm \
        --enable-virtfs \
        --enable-slirp \
        --enable-trace-backends=log \
        ${EXTRA_CFLAGS:+--extra-cflags="$EXTRA_CFLAGS"} \
        --disable-docs)
fi

echo "==> Building"
ninja -C "$BLD" qemu-system-x86_64 qemu-img tests/qtest/cryptostore-test tests/unit/test-cryptostore-crypto

echo "==> Checking the device is registered"
"$BLD/qemu-system-x86_64" -device help | grep -E 'pcie-(cryptostore|cryptorecovery)"'
echo "QEMU ready: $BLD/qemu-system-x86_64"
