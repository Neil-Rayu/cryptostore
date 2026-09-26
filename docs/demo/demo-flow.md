# Live demo flow

About 15 minutes. Three terminals, all starting in `~/neil-rayu`.

## Setup

**Terminal 1 (host): start the VM with a fresh demo disk**
```sh
rm -rf ~/cryptostore-images/demo
CS_IMAGES=~/cryptostore-images/demo NUM_DEVICES=0 scripts/run-vm.sh
```
Leave it running; quit later with `Ctrl-a x`.

**Terminal 2 (host): the device's point of view**
```sh
tail -f build/vm/qemu.log | grep -E 'cryptostore_(cmd|state|window|irq)|fault'
```

**Terminal 3: inside the guest**
```sh
scripts/ssh-vm.sh
cd /mnt/host && make -s -C driver && make -s -C tools
alias cc='sudo /mnt/host/tools/cryptoctl'
```

## 1. It's real PCIe hardware
```sh
lspci -tv
sudo lspci -vvv -d 1af4:10f1 | grep -E 'Mass storage|Express|FLReset|MSI-X'
```
**Say:** "Linux found a PCIe storage controller behind a root port. It supports Function Level Reset and MSI-X interrupts. The guest can't tell it's emulated."

## 2. The driver binds
```sh
sudo dmesg -C
sudo insmod driver/cryptorecovery.ko && sudo insmod driver/cryptostore.ko
dmesg
ls -l /dev/cryptostore* /dev/cryptorecovery*
cc status
```
**Point at:** `cryptostore0: ... irq NN (MSI-X)`; the control node is `crw------- root` (root only), the disk is `brw-rw---- root disk`; state `UNFORMATTED`.

## 3. Set a password
```sh
cc format        # asks twice, echo off, minimum 8 characters
cc status        # LOCKED, 1 password + 1 recovery keyslot
```
**Point at terminal 2:** `PW_A window ... (value not traced)`. The password never reaches a log.
**Say:** "FORMAT generated a random 512-bit data key inside the device, wrapped it under the password, gave a recovery key to the recovery device, and filled the disk with random bytes."

## 4. Wrong passwords are counted and slowed
```sh
cc unlock        # type a wrong password
cc status        # failed tries: 1 of 10
time cc unlock   # correct password
```
**Say:** "Every attempt is counted on disk before the password is checked, so resetting the VM doesn't help. Right and wrong answers both take exactly one second, so timing reveals nothing. After 3 free tries the device makes you wait 1, 2, 4... seconds; after 10 it locks out."

## 5. Use it like any disk
```sh
lsblk /dev/cryptostore0
sudo mkfs.ext4 -q /dev/cryptostore0 && sudo mkdir -p /mnt/cs && sudo mount /dev/cryptostore0 /mnt/cs
echo "TOP-SECRET-DEMO-12345" | sudo tee /mnt/cs/secret.txt; sync
grep cryptostore /proc/interrupts
```
**Point at:** 64M size; the interrupt counter keeps climbing, since every sector read or write completes through an MSI-X interrupt.

## 6. What the guest sees vs. what the host disk holds
Guest (plaintext):
```sh
sudo grep -a -b -m1 TOP-SECRET-DEMO /dev/cryptostore0     # prints BYTE_OFFSET:...
```
Host, with `SECTOR = BYTE_OFFSET / 512`:
```sh
python3 tools/attacker-view.py ~/cryptostore-images/demo/cs0.img \
    --secret TOP-SECRET-DEMO-12345 --sector SECTOR
```
**Point at:** the header is readable but holds only public metadata; the same sector is random bytes; the secret is `not found anywhere`; entropy `8.0000`; one offline guess costs about 0.9 s per core. Sample: [evidence/attacker-view.txt](evidence/attacker-view.txt).

## 7. Lock
```sh
cc lock                              # refused: the disk is mounted
sudo umount /mnt/cs && cc lock
lsblk /dev/cryptostore0              # 0B
sudo dd if=/dev/cryptostore0 bs=4k count=1 | wc -c     # 0
```

## 8. A reset wipes the key
```sh
cc unlock
echo 1 | sudo tee /sys/bus/pci/devices/$(basename $(readlink -f /sys/class/cryptostore/cryptostore-ctl0/device))/reset
dmesg | tail -2
cc status                            # LOCKED
```
**Say:** "A PCIe Function Level Reset zeroizes the key inside the device. The driver notices and drops the disk size to zero."

## 9. Forgotten password: recovery
```sh
cc lock
cc recover                           # refused: guest action alone is not enough
```
Host:
```sh
scripts/monitor.sh "qom-set /machine/peripheral/rec0 host-armed true"
```
Guest:
```sh
cc recover                           # works, forces a new password
cc recover                           # refused: once per boot
```
**Say:** "The recovery key never enters the guest. The storage device fetches it directly from the recovery device, and only if both the guest and the host administrator (physical presence) agree."

## 10. Snapshots can't capture the key
Host:
```sh
scripts/monitor.sh "savevm snap1"    # Error: blocked by non-migratable device
```

## 11. Tampering is detected
Quit QEMU (`Ctrl-a x` in terminal 1), then on the host:
```sh
python3 tools/cryptostore_image.py set-capacity ~/cryptostore-images/demo/cs0.img 131071
CS_IMAGES=~/cryptostore-images/demo NUM_DEVICES=0 scripts/run-vm.sh
```
Guest: reload the drivers as in step 2, then:
```sh
cc unlock      # "password correct, but the image header was tampered with"
```
The editing tool refuses to touch the image while a VM is running: the device is the only writer.

## 12. Fault-injection hardening (host, no VM needed)
```sh
python3 tools/fi-disasm-review.py
less build/fi-review/cs_jitter.isra.0.s
python3 tools/fi-skip-campaign.py --quick
cd build/qemu-src/build-test && QTEST_QEMU_BINARY=./qemu-system-x86_64 \
    ./tests/qtest/cryptostore-test -p /x86_64/cryptostore/hooks/fault-f9 --tap
```
Talk track: [fi-evidence.md](fi-evidence.md).

## If something goes wrong
| Symptom | Fix |
| --- | --- |
| `ssh: connection refused` | VM still booting; wait 10 s |
| `insmod: File exists` | `sudo rmmod cryptostore cryptorecovery` first |
| `lock: the disk is open or mounted` | `sudo umount /mnt/cs` |
| `too many recent failures; wait` | wait the seconds shown |
| `LOCKED_OUT` | `cc recover` (step 9), or with the VM stopped: `python3 tools/cryptostore_image.py reset-counter IMAGE` |
| `image is in use by a running QEMU` | stop the VM before editing an image |
