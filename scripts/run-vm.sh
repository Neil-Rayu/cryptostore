#!/usr/bin/env bash
# Launch the CryptoStore development VM (q35 + KVM).
#
# Default topology:
#   rp1 -- rec0 (pcie-cryptorecovery, ~/cryptostore-images/rec0.img)
#   rp2 -- cs0 (pcie-cryptostore, ~/cryptostore-images/cs0.img, recovery=rec0)
#   one spare root port for hotplug experiments
#
# Only driver/, tools/ and include/ are shared into the guest (virtio-9p,
# mounted under /mnt/host), never the images or the QEMU tree (SR-30).
# QEMU traces and guest errors go to build/vm/qemu.log.
# HMP monitor: scripts/monitor.sh "info pci"
#
# Env:
#   NUM_CRYPTOSTORE  pcie-cryptostore devices (default 1)
#   RECOVERY         1 (default) attaches pcie-cryptorecovery linked to cs0
#   CS_IMAGES        image directory (default ~/cryptostore-images)
#   CS_SIZE_MIB      size of newly created images (default 64)
#   QEMU_BUILD       build (default) or build-test (fault-injection hooks)
#   TRACE            trace pattern (default "cryptostore_*;cryptorecovery_*")
#   SSH_PORT, MEM, SMP, HEADLESS=1
# Extra arguments are passed to QEMU unchanged.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM_DIR="$ROOT/build/vm"
QEMU="$ROOT/build/qemu-src/${QEMU_BUILD:-build}/qemu-system-x86_64"
NUM_CRYPTOSTORE="${NUM_CRYPTOSTORE:-1}"
RECOVERY="${RECOVERY:-1}"
CS_IMAGES="${CS_IMAGES:-$HOME/cryptostore-images}"
CS_SIZE_MIB="${CS_SIZE_MIB:-64}"
TRACE="${TRACE-cryptostore_*;cryptorecovery_*}"
SSH_PORT="${SSH_PORT:-2222}"

[ -x "$QEMU" ] || { echo "error: $QEMU missing; run scripts/build-qemu.sh" >&2; exit 1; }
[ -f "$VM_DIR/disk.qcow2" ] || { echo "error: run scripts/prepare-guest.sh first" >&2; exit 1; }

# SR-30: the backing images must never be reachable from the guest.
case "$(realpath -m "$CS_IMAGES")/" in
    "$ROOT"/*) echo "error: CS_IMAGES must be outside $ROOT (SR-30)" >&2; exit 1 ;;
esac
mkdir -p "$CS_IMAGES"
chmod 700 "$CS_IMAGES"

args=(
    -machine q35,accel=kvm
    -cpu host -smp "${SMP:-4}" -m "${MEM:-2G}"
    -drive if=virtio,file="$VM_DIR/disk.qcow2",format=qcow2
    -drive if=virtio,file="$VM_DIR/seed.img",format=raw,readonly=on
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22
    -device virtio-net-pci,netdev=net0
    -monitor unix:"$VM_DIR/monitor.sock",server=on,wait=off
    -D "$VM_DIR/qemu.log" -d guest_errors
)
for share in driver tools include; do
    args+=(-fsdev local,id=fs_$share,path="$ROOT/$share",security_model=none)
    args+=(-device virtio-9p-pci,fsdev=fs_$share,mount_tag=host$share)
done

port=0
root_port() {
    port=$((port + 1))
    args+=(-device pcie-root-port,id=rp$port,bus=pcie.0,chassis=$port,slot=$port)
}

if [ "$RECOVERY" = 1 ] && [ "$NUM_CRYPTOSTORE" -gt 0 ]; then
    rec="$CS_IMAGES/rec0.img"
    [ -f "$rec" ] || truncate -s 4096 "$rec"
    root_port
    args+=(-drive if=none,id=recd0,file="$rec",format=raw)
    args+=(-device pcie-cryptorecovery,bus=rp$port,id=rec0,drive=recd0)
fi
for i in $(seq 0 $((NUM_CRYPTOSTORE - 1))); do
    img="$CS_IMAGES/cs$i.img"
    [ -f "$img" ] || python3 "$ROOT/tools/cryptostore_image.py" create "$img" "$CS_SIZE_MIB"
    link=""
    [ "$RECOVERY" = 1 ] && [ "$i" = 0 ] && link=",recovery=rec0"
    root_port
    args+=(-drive if=none,id=csd$i,file="$img",format=raw)
    args+=(-device "pcie-cryptostore,bus=rp$port,id=cs$i,drive=csd$i$link")
done
root_port   # spare, for hotplug

# One -trace option per pattern (TRACE is ';'-separated).
IFS=';' read -ra trace_patterns <<< "$TRACE"
for t in "${trace_patterns[@]}"; do
    [ -n "$t" ] && args+=(-trace "$t")
done

if [ "${HEADLESS:-0}" = 1 ]; then
    args+=(-display none -serial file:"$VM_DIR/serial.log")
else
    args+=(-nographic)
    echo "Console on this terminal (login dev/dev). Quit QEMU: Ctrl-a x"
    echo "SSH: scripts/ssh-vm.sh    Traces: tail -f $VM_DIR/qemu.log"
fi

exec "$QEMU" "${args[@]}" "$@"
