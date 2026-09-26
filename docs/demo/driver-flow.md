# How the PCIe driver flow works

**One line:** the card is emulated in C inside QEMU, but the guest talks to it exactly as it would to real hardware: by reading and writing memory-mapped registers and getting interrupts back.

```
 guest userspace        guest kernel                 host
 ───────────────        ────────────                 ────
 cryptoctl  ──ioctl──▶  cryptostore.ko  ──MMIO──▶  [KVM traps the access]  ──▶  QEMU pcie-cryptostore (C)
                              ▲                                                    │  PBKDF2 / AES-XTS
                              │                                                    │  reads/writes cs0.img
                              └────── MSI-X interrupt ◀── "command done" ◀─────────┘
```

## The five steps

1. **Enumeration.** At boot, firmware and Linux scan the PCIe bus and find a device with ID `1af4:10f1` behind a root port. They give it a memory window (BAR0, 8 KiB of registers) and an interrupt (MSI-X).
   *Print:* `lspci -tv`, `sudo lspci -vvv -d 1af4:10f1`

2. **Binding.** `insmod cryptostore.ko` makes the kernel match that ID to the driver and call its `probe()`. The driver maps BAR0, checks the magic register (`CRST`), enables bus mastering and MSI-X, and creates `/dev/cryptostore0` (the disk) and `/dev/cryptostore-ctl0` (control).
   *Print:* `dmesg`, `ls -l /dev/cryptostore*`

3. **A command (for example UNLOCK).** `cryptoctl` passes the password in an ioctl. The driver copies it into the device's write-only password window and writes the opcode to the CMD register. Each of those MMIO writes makes the CPU exit to KVM, which hands it to QEMU's C callback. The device counts the attempt on disk, runs PBKDF2 in a worker thread, unwraps the data key, then raises an MSI-X interrupt. The driver's interrupt handler wakes the waiting ioctl, which reads the RESULT register.
   *Print:* `cc status`; terminal 2's trace (`cmd_start`, `window ... (value not traced)`, `cmd_done`, `irq msix`)

4. **Disk I/O.** A file read becomes a block request of up to 8 sectors. The driver writes LBA and COUNT and issues READ. The device reads ciphertext from `cs0.img`, decrypts it with AES-256-XTS (the tweak is the sector number), checks it by re-encrypting, and puts plaintext in its data window. The driver copies it out and wipes its bounce buffer.
   *Print:* `grep cryptostore /proc/interrupts` climbing; `lsblk`; the file's contents

5. **Lock, reset, unplug.** The device wipes the key and verifies the wipe. The driver sets the disk size to 0, so nothing more can be read.
   *Print:* `lsblk` shows 0B; `dmesg` shows the reset

## Where things live

| Piece | File |
| --- | --- |
| Device model (the "hardware") | `qemu/cryptostore.c`, `qemu/cryptostore_crypto.c`, `qemu/cryptorecovery.c` |
| Register map (the datasheet as code) | `include/cryptostore_regs.h` |
| On-disk format | `include/cryptostore_format.h`, `qemu/cryptostore_format.c` |
| Guest drivers | `driver/cryptostore.c`, `driver/cryptorecovery.c` |
| CLI and ioctl ABI | `tools/cryptoctl.c`, `include/cryptostore_ioctl.h` |
| Specs | `docs/cryptostore-datasheet.md`, `docs/threat-model.md` |

## Proof points to print

| Claim | Command |
| --- | --- |
| It's a real PCIe endpoint | `sudo lspci -vvv -d 1af4:10f1` (Express Endpoint, FLReset+, MSI-X Enable+) |
| The driver bound | `dmesg \| grep cryptostore` |
| Interrupts drive completion | `grep cryptostore /proc/interrupts` before and after I/O |
| The device logic runs | `tail -f build/vm/qemu.log` |
| Data is encrypted at rest | `tools/attacker-view.py IMAGE --secret TEXT` |
| Passwords never hit logs | grep the trace log for the password: nothing |
| Locked means locked | `lsblk` 0B, `dd` returns 0 bytes |
