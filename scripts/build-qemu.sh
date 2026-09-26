#!/usr/bin/env bash
# Build QEMU (x86_64 system emulator) with the pcie-hello device.
#
# - Clones QEMU at $QEMU_REF into build/qemu-src (once).
# - Applies qemu/pcie-hello-build-hooks.patch (Kconfig + meson + trace-events).
# - Symlinks qemu/pcie_hello.c and include/pcie_hello_regs.h into hw/misc/,
#   so editing them in this repo and re-running this script is enough.
# - Configures a debug build with KVM, virtfs (9p), slirp and the "log"
#   trace backend, then builds with ninja.
#
# Env: QEMU_REF (default v11.1.1), RECONFIGURE=1 to re-run configure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QEMU_REF="${QEMU_REF:-v11.1.1}"
SRC="$ROOT/build/qemu-src"
BLD="$SRC/build"

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
PATCH="$ROOT/qemu/pcie-hello-build-hooks.patch"
if git apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "==> Build hooks already applied"
else
    echo "==> Applying build hooks"
    git apply "$PATCH"
fi
ln -sfn ../../../../qemu/pcie_hello.c hw/misc/pcie_hello.c
ln -sfn ../../../../include/pcie_hello_regs.h hw/misc/pcie_hello_regs.h

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
        --disable-docs)
fi

echo "==> Building"
ninja -C "$BLD" qemu-system-x86_64 qemu-img

echo "==> Checking the device is registered"
"$BLD/qemu-system-x86_64" -device help | grep pcie-hello
echo "QEMU ready: $BLD/qemu-system-x86_64"
