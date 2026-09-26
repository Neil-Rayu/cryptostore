#!/usr/bin/env bash
# Launch the dev VM (q35 + KVM) with pcie-hello devices behind PCIe root ports.
#
# Topology (NUM_DEVICES=2):
#   pcie.0 -- rp1 (pcie-root-port) -- hello0 (pcie-hello, serial=1)
#          -- rp2 (pcie-root-port) -- hello1 (pcie-hello, serial=2)
#          -- rp3 (pcie-root-port)    empty, for hotplug experiments
#
# The repository is shared into the guest at /mnt/host (virtio-9p).
# QEMU traces and guest errors go to build/vm/qemu.log.
# HMP monitor: scripts/monitor.sh "info pci"   (unix socket build/vm/monitor.sock)
#
# Env:
#   NUM_DEVICES  number of pcie-hello devices (default 2)
#   HELLO_OPTS   extra -device options for every pcie-hello (e.g. "msix=off")
#   TRACE        trace pattern (default "pcie_hello_*"; empty disables)
#   SSH_PORT     host port forwarded to guest :22 (default 2222)
#   MEM, SMP     guest memory / CPUs (default 2G / 4)
#   HEADLESS=1   no console on stdio; serial goes to build/vm/serial.log
# Extra arguments are passed to QEMU unchanged.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM_DIR="$ROOT/build/vm"
QEMU="$ROOT/build/qemu-src/build/qemu-system-x86_64"
NUM_DEVICES="${NUM_DEVICES:-2}"
TRACE="${TRACE-pcie_hello_*}"
SSH_PORT="${SSH_PORT:-2222}"

[ -x "$QEMU" ] || { echo "error: run scripts/build-qemu.sh first" >&2; exit 1; }
[ -f "$VM_DIR/disk.qcow2" ] || { echo "error: run scripts/prepare-guest.sh first" >&2; exit 1; }

args=(
    -machine q35,accel=kvm
    -cpu host -smp "${SMP:-4}" -m "${MEM:-2G}"
    -drive if=virtio,file="$VM_DIR/disk.qcow2",format=qcow2
    -drive if=virtio,file="$VM_DIR/seed.img",format=raw,readonly=on
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22
    -device virtio-net-pci,netdev=net0
    -fsdev local,id=fs0,path="$ROOT",security_model=none
    -device virtio-9p-pci,fsdev=fs0,mount_tag=hostshare
    -monitor unix:"$VM_DIR/monitor.sock",server=on,wait=off
    -D "$VM_DIR/qemu.log" -d guest_errors
)

for i in $(seq 1 "$NUM_DEVICES"); do
    args+=(-device pcie-root-port,id=rp$i,bus=pcie.0,chassis=$i,slot=$i)
    args+=(-device "pcie-hello,bus=rp$i,id=hello$((i - 1)),serial=$i${HELLO_OPTS:+,$HELLO_OPTS}")
done
spare=$((NUM_DEVICES + 1))
args+=(-device pcie-root-port,id=rp$spare,bus=pcie.0,chassis=$spare,slot=$spare)

[ -n "$TRACE" ] && args+=(-trace "$TRACE")

if [ "${HEADLESS:-0}" = 1 ]; then
    args+=(-display none -serial file:"$VM_DIR/serial.log")
else
    args+=(-nographic)
    echo "Console on this terminal (login dev/dev). Quit QEMU: Ctrl-a x"
    echo "SSH: scripts/ssh-vm.sh    Traces: tail -f $VM_DIR/qemu.log"
fi

exec "$QEMU" "${args[@]}" "$@"
