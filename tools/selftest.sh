#!/usr/bin/env bash
# In-guest acceptance test for pcie-hello. Run from the shared repo:
#   cd /mnt/host && sudo tools/selftest.sh
# Builds the module and CLI, then checks: PCIe capabilities, raw BAR0 access,
# driver binding with MSI-X, every CLI command on every device, and FLR.
set -euo pipefail

cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*"; exit 1; }
CTL=tools/pcie_hello_ctl

mapfile -t BDFS < <(lspci -D -n -d 1af4:10f0 | awk '{print $1}')
[ ${#BDFS[@]} -gt 0 ] || fail "no pcie-hello devices found"
echo "devices: ${BDFS[*]}"

step "Build module and CLI"
lsmod | grep -q '^pcie_hello' && rmmod pcie_hello
make -s -C driver
make -s -C tools

step "PCIe capabilities (lspci -vvv)"
for b in "${BDFS[@]}"; do
    out="$(lspci -vvv -s "$b")"
    grep -q 'Express (v2) Endpoint' <<<"$out" || fail "$b: not an Express Endpoint"
    grep -q 'FLReset+' <<<"$out" || fail "$b: FLR not advertised"
    grep -q 'MSI-X: Enable' <<<"$out" || fail "$b: no MSI-X capability"
    echo "$b: Express Endpoint, FLReset+, MSI-X present"
done

step "Raw BAR0 access via sysfs resource0 (no driver)"
tools/bar0_poke.py "${BDFS[@]}"

step "Load driver"
dmesg -C
insmod driver/pcie_hello.ko
sleep 0.5
dmesg | grep pcie_hello
for b in "${BDFS[@]}"; do
    lspci -vvv -s "$b" | grep -q 'MSI-X: Enable+' || fail "$b: MSI-X not enabled"
    lspci -k -s "$b" | grep -q 'Kernel driver in use: pcie_hello' || fail "$b: not bound"
done

step "CLI on every device"
for dev in /dev/pcie_hello*; do
    echo "--- $dev"
    $CTL -d "$dev" info
    $CTL -d "$dev" scratch
    $CTL -d "$dev" greet
    $CTL -d "$dev" upper "hello from $(basename "$dev")"
    [ "$($CTL -d "$dev" read)" = "HELLO FROM $(basename "$dev" | tr a-z A-Z)" ] ||
        fail "$dev: read-back mismatch"
    $CTL -d "$dev" write "raw write works"
    $CTL -d "$dev" read
done

step "Function Level Reset"
b="${BDFS[0]}"
dev="/dev/$(ls /sys/bus/pci/devices/"$b"/pcie_hello)"
grep -q flr /sys/bus/pci/devices/"$b"/reset_method || fail "$b: flr not in reset_method"
$CTL -d "$dev" write "state before reset"
echo 1 > /sys/bus/pci/devices/"$b"/reset
dmesg | grep -E 'function reset' | tail -2
[ -z "$($CTL -d "$dev" read)" ] || fail "buffer not cleared by FLR"
echo "buffer cleared by FLR"
$CTL -d "$dev" scratch 0x1234
$CTL -d "$dev" greet
lspci -vvv -s "$b" | grep -q 'MSI-X: Enable+' || fail "MSI-X not restored after FLR"
echo "driver recovered, MSI-X still enabled"

step "Unload driver"
rmmod pcie_hello
[ ! -e /dev/pcie_hello0 ] || fail "device node left behind"

printf '\nALL TESTS PASSED\n'
