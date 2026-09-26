#!/usr/bin/env bash
# Full-system test for pcie-cryptostore (threat model section 13, layer 3).
#
# Boots the dev VM with fresh images in ~/cryptostore-images/systest, drives
# the guest over SSH and the host monitor, then shuts the VM down and checks
# the backing files offline. Covers the system-level parts of M2-M5 and
# SR-12, 13, 15, 19, 30.
#
#   scripts/cryptostore-system-test.sh          (refuses if a VM is running)
#   FORCE=1 scripts/cryptostore-system-test.sh  (stops a running VM first)
#   QEMU_BUILD=build-test ...                   (run against the test build)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMGDIR="$HOME/cryptostore-images/systest"
MON="$ROOT/scripts/monitor.sh"
PW="correct horse battery staple"
PW2="second passphrase 4711"
PW3="recovered passphrase 0815"
MARKER="TOP-SECRET-MARKER-$(date +%s)"
pass=0
fail=0

ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
step() { printf '\n== %s\n' "$*"; }
g()    { "$ROOT/scripts/ssh-vm.sh" "$@"; }
gctl() { g "sudo /mnt/host/tools/cryptoctl $*"; }

if "$MON" "info status" >/dev/null 2>&1; then
    [ "${FORCE:-0}" = 1 ] || { echo "a VM is running; stop it or use FORCE=1" >&2; exit 1; }
    "$MON" quit >/dev/null 2>&1
    sleep 3
fi

step "Fresh images in $IMGDIR (outside the repository, SR-30)"
rm -rf "$IMGDIR"
mkdir -p "$IMGDIR"
python3 "$ROOT/tools/cryptostore_image.py" create "$IMGDIR/cs0.img" 64 >/dev/null
truncate -s 4096 "$IMGDIR/rec0.img"
rm -f "$ROOT/build/vm/qemu.log"

step "Boot (1 cryptostore + recovery, traces on)"
NUM_DEVICES=0 NUM_CRYPTOSTORE=1 RECOVERY=1 CS_IMAGES="$IMGDIR" HEADLESS=1 \
    "$ROOT/scripts/run-vm.sh" > "$ROOT/build/vm/run.log" 2>&1 &
for _ in $(seq 1 60); do g -o ConnectTimeout=2 true 2>/dev/null && break; sleep 2; done
check "guest reachable over SSH" g true

step "Guest sees only driver/, tools/, include/ (SR-30)"
shares="$(g 'ls /mnt/host/driver >/dev/null; ls /mnt/host/tools >/dev/null; ls /mnt/host/include >/dev/null; ls /mnt/host | tr "\n" " "')"
check "shares are exactly driver include tools" test "$shares" = "driver include tools "
check "no image file reachable from the guest" \
    g '! sudo find / -xdev \( -name "cs0.img" -o -name "rec0.img" \) 2>/dev/null | grep -q .'

step "Build and load drivers"
g 'cd /mnt/host && make -s -C driver && make -s -C tools' >/dev/null
g 'sudo rmmod cryptostore cryptorecovery 2>/dev/null; sudo dmesg -C; sudo insmod /mnt/host/driver/cryptorecovery.ko && sudo insmod /mnt/host/driver/cryptostore.ko && sleep 1'
check "block node exists" g 'test -b /dev/cryptostore0'
check "control node exists" g 'test -c /dev/cryptostore-ctl0'
check "recovery node exists" g 'test -c /dev/cryptorecovery0'
lspci="$(g 'sudo lspci -vvv -d 1af4:10f1')"
check "Express (v2) Endpoint" grep -q 'Express (v2) Endpoint' <<<"$lspci"
check "FLReset+" grep -q 'FLReset+' <<<"$lspci"
check "MSI-X enabled by the driver" grep -q 'MSI-X: Enable+' <<<"$lspci"
check "recovery device is an Express Endpoint" g 'sudo lspci -vvv -d 1af4:10f2 | grep -q "Express (v2) Endpoint"'

step "Permissions (SR-19)"
check "control node is root-only (0600)" g 'test "$(stat -c %a /dev/cryptostore-ctl0)" = 600'
check "unprivileged user cannot open the control node" g '! /mnt/host/tools/cryptoctl status'
check "unprivileged user cannot read the block device" g '! dd if=/dev/cryptostore0 of=/dev/null count=1 2>/dev/null'

step "FORMAT and UNLOCK (M1, M2)"
check "status UNFORMATTED" g 'sudo /mnt/host/tools/cryptoctl status | grep -q UNFORMATTED'
check "format rejects a short password (O9)" g '! printf "short\nshort\n" | sudo /mnt/host/tools/cryptoctl format'
check "format" g "printf '%s\n%s\n' '$PW' '$PW' | sudo /mnt/host/tools/cryptoctl format"
check "status LOCKED with a recovery slot" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "1 password, 1 recovery"'
check "wrong password rejected" g "! printf 'nope nope nope\n' | sudo /mnt/host/tools/cryptoctl unlock"
check "failure counted" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "failed tries  : 1"'
t0=$(date +%s%N)
check "unlock" g "printf '%s\n' '$PW' | sudo /mnt/host/tools/cryptoctl unlock"
t1=$(date +%s%N)
echo "        unlock round trip $(( (t1 - t0) / 1000000 )) ms (device pads to whole seconds)"
check "capacity visible when unlocked" g 'test "$(sudo blockdev --getsize64 /dev/cryptostore0)" = 67108864'

step "SR-13: cryptoctl process hygiene while it waits for a password"
proc="$(g 'rm -f /tmp/pwfifo; mkfifo /tmp/pwfifo; exec 3<>/tmp/pwfifo; sudo /mnt/host/tools/cryptoctl unlock <&3 >/dev/null 2>&1 & sleep 1; pid=$(pgrep -x cryptoctl | head -1); echo "cmdline=$(sudo tr "\0" " " < /proc/$pid/cmdline)"; sudo grep -E "VmLck" /proc/$pid/status; sudo grep "Max core file size" /proc/$pid/limits; echo "x" >&3; wait; rm -f /tmp/pwfifo')"
echo "$proc" | sed 's/^/        /'
check "no secret on the command line" grep -q '^cmdline=/mnt/host/tools/cryptoctl unlock $' <<<"$proc"
check "memory locked (VmLck > 0)" grep -qE 'VmLck:\s+[1-9]' <<<"$proc"
check "core dumps disabled" grep -qE 'Max core file size\s+0\s+0' <<<"$proc"

step "Filesystem on the unlocked device (M3)"
g "sudo mkfs.ext4 -q /dev/cryptostore0 && sudo mkdir -p /mnt/cs && sudo mount /dev/cryptostore0 /mnt/cs && for i in \$(seq 1 300); do echo '$MARKER line' \$i; done | sudo tee /mnt/cs/secret.txt >/dev/null && sudo dd if=/dev/urandom of=/mnt/cs/blob bs=1M count=8 status=none && sync && md5sum /mnt/cs/blob | awk '{print \$1}' | sudo tee /root/blob.md5 >/dev/null"
check "mkfs + mount + write" g 'mountpoint -q /mnt/cs && test -s /mnt/cs/blob'
check "lock refused while mounted (D6)" g '! sudo /mnt/host/tools/cryptoctl lock'
g 'sudo umount /mnt/cs'
check "lock after unmount" g 'sudo /mnt/host/tools/cryptoctl lock'
check "capacity 0 when locked" g 'test "$(sudo blockdev --getsize64 /dev/cryptostore0)" = 0'
check "reads fail when locked" g '! sudo dd if=/dev/cryptostore0 of=/dev/null bs=4k count=1 iflag=direct 2>/dev/null || test "$(sudo dd if=/dev/cryptostore0 bs=4k count=1 2>/dev/null | wc -c)" = 0'
check "unlock again" g "printf '%s\n' '$PW' | sudo /mnt/host/tools/cryptoctl unlock"
check "data intact after lock/unlock" g 'sudo mount /dev/cryptostore0 /mnt/cs && test "$(md5sum /mnt/cs/blob | cut -d" " -f1)" = "$(sudo cat /root/blob.md5)" && grep -q "line 300" /mnt/cs/secret.txt'
g 'sudo umount /mnt/cs'

step "FLR from sysfs locks the device (SR-02, 11.2)"
bdf="$(g 'basename $(readlink -f /sys/class/cryptostore/cryptostore-ctl0/device)')"
g "echo 1 | sudo tee /sys/bus/pci/devices/$bdf/reset >/dev/null"
check "state LOCKED after FLR" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "state         : LOCKED"'
check "capacity 0 after FLR" g 'test "$(sudo blockdev --getsize64 /dev/cryptostore0)" = 0'
check "MSI-X still enabled after FLR" g "sudo lspci -vvv -s $bdf | grep -q 'MSI-X: Enable+'"
check "unlock after FLR" g "printf '%s\n' '$PW' | sudo /mnt/host/tools/cryptoctl unlock"

step "Password change (M4)"
check "passwd" g "printf '%s\n%s\n%s\n' '$PW' '$PW2' '$PW2' | sudo /mnt/host/tools/cryptoctl passwd"
g 'sudo /mnt/host/tools/cryptoctl lock' >/dev/null
check "old password rejected" g "! printf '%s\n' '$PW' | sudo /mnt/host/tools/cryptoctl unlock"
check "new password accepted" g "printf '%s\n' '$PW2' | sudo /mnt/host/tools/cryptoctl unlock"
g 'sudo /mnt/host/tools/cryptoctl lock' >/dev/null

step "Recovery (M5): guest arm alone is not enough (R2)"
check "recover without host presence fails" g "! printf '%s\n%s\n' '$PW3' '$PW3' | sudo /mnt/host/tools/cryptoctl recover"
"$MON" "qom-set /machine/peripheral/rec0 host-armed true" >/dev/null
check "recover with host presence" g "printf '%s\n%s\n' '$PW3' '$PW3' | sudo /mnt/host/tools/cryptoctl recover"
check "unlocked with the recovered password" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "state         : UNLOCKED"'
g 'sudo /mnt/host/tools/cryptoctl lock' >/dev/null
check "second recovery in the same boot refused (F8)" g "! printf '%s\n%s\n' '$PW3' '$PW3' | sudo /mnt/host/tools/cryptoctl recover"
check "old password gone after recovery" g "! printf '%s\n' '$PW2' | sudo /mnt/host/tools/cryptoctl unlock"
check "recovered password works" g "printf '%s\n' '$PW3' | sudo /mnt/host/tools/cryptoctl unlock"

step "lock --force while mounted (D6, O4 warning)"
g 'sudo mount /dev/cryptostore0 /mnt/cs'
check "--force help carries the page-cache warning" g '/mnt/host/tools/cryptoctl -h | grep -q "guest page cache"'
check "lock --force succeeds while mounted" g 'sudo /mnt/host/tools/cryptoctl lock --force'
check "device LOCKED" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "state         : LOCKED"'
g 'sudo umount -l /mnt/cs 2>/dev/null; true'

step "No migration or snapshots (SR-12)"
sv="$("$MON" "savevm snap1")"
echo "        savevm: $sv"
check "savevm refused" grep -qiE 'not migratable|migration is disabled|non-migratable|blocked' <<<"$sv"

step "Hot-unplug while UNLOCKED, re-plug comes back LOCKED (11.2)"
check "unlock" g "printf '%s\n' '$PW3' | sudo /mnt/host/tools/cryptoctl unlock"
"$MON" "device_del cs0" >/dev/null
for _ in $(seq 1 30); do g '! lspci -d 1af4:10f1 | grep -q .' 2>/dev/null && break; sleep 1; done
check "device removed from the guest" g '! test -e /dev/cryptostore-ctl0'
"$MON" "drive_add 0 if=none,id=csd0b,file=$IMGDIR/cs0.img,format=raw" >/dev/null
"$MON" "device_add pcie-cryptostore,bus=rp2,id=cs0b,drive=csd0b,recovery=rec0" >/dev/null
for _ in $(seq 1 30); do g 'test -c /dev/cryptostore-ctl0' 2>/dev/null && break; sleep 1; done
check "re-plugged device is LOCKED" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "state         : LOCKED"'
check "and unlocks with the password" g "printf '%s\n' '$PW3' | sudo /mnt/host/tools/cryptoctl unlock"
g 'sudo /mnt/host/tools/cryptoctl lock' >/dev/null

step "Recovery device unplugged: absent-safe (Section 9)"
"$MON" "device_del rec0" >/dev/null
sleep 3
check "CAPS reports no recovery device" g 'sudo /mnt/host/tools/cryptoctl status | grep -q "recovery dev  : absent"'
check "recover refused" g '! printf "x\n" | sudo /mnt/host/tools/cryptoctl recover'

step "No secrets in traces, logs or dmesg (SR-15)"
dm="$(g 'sudo dmesg')"
python3 - "$ROOT/build/vm/qemu.log" "$PW" "$PW2" "$PW3" <<'EOF' && ok "trace log (qemu.log) contains no password text or password words" || bad "password material found in qemu.log"
import sys
log = open(sys.argv[1], errors="replace").read()
assert "cryptostore_window" in log, "tracing was not active"
for pw in sys.argv[2:]:
    b = pw.encode()
    words = ["0x%x" % int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b) - 3, 4)]
    assert pw not in log, pw
    assert not any(w in log for w in words), pw
EOF
check "dmesg contains no password" bash -c "! grep -qF -e '$PW' -e '$PW2' -e '$PW3' <<<\"\$0\"" "$dm"

step "Shut down; offline checks on the backing files (M3, SR-36)"
"$MON" quit >/dev/null 2>&1
sleep 3
check "known plaintext not in the image" python3 "$ROOT/tools/cryptostore_image.py" grep "$IMGDIR/cs0.img" "$MARKER"
check "ext4 metadata not in the image" python3 "$ROOT/tools/cryptostore_image.py" grep "$IMGDIR/cs0.img" "lost+found"
ent="$(python3 "$ROOT/tools/cryptostore_image.py" entropy "$IMGDIR/cs0.img")"
echo "        $ent"
check "data area is indistinguishable from random" grep -qE 'entropy 7\.99[0-9]+|entropy 8\.0000' <<<"$ent"
check "header valid, LOCKED at next start" bash -c "python3 '$ROOT/tools/cryptostore_image.py' check '$IMGDIR/cs0.img' | grep -q 'realize as LOCKED'"
check "recovery image bound to the storage image" \
    bash -c "python3 '$ROOT/tools/cryptostore_image.py' recovery-info '$IMGDIR/rec0.img' | grep -q 'state KEY'"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
