# pcie-hello

A hello-world **PCI Express endpoint** for QEMU, with a Linux driver and a CLI.
It exercises the whole toolchain the encrypted-storage device will use:
building QEMU with a custom device, booting a guest, binding a driver,
handling MSI-X interrupts, surviving Function Level Reset, and doing I/O from
userspace.

| Piece | Name | Source |
|---|---|---|
| QEMU device | `pcie-hello` | [qemu/pcie_hello.c](qemu/pcie_hello.c) |
| Kernel module | `pcie_hello` | [driver/pcie_hello.c](driver/pcie_hello.c) |
| Device nodes | `/dev/pcie_hello0`, `/dev/pcie_hello1`, … | |
| CLI | `pcie_hello_ctl` | [tools/pcie_hello_ctl.c](tools/pcie_hello_ctl.c) |
| Register map (shared by device, driver, docs) | | [include/pcie_hello_regs.h](include/pcie_hello_regs.h) |
| ioctl ABI (shared by driver and CLI) | | [include/pcie_hello_ioctl.h](include/pcie_hello_ioctl.h) |

## Layout

```
include/    pcie_hello_regs.h (hardware interface), pcie_hello_ioctl.h (ABI)
qemu/       pcie_hello.c + pcie-hello-build-hooks.patch (Kconfig, meson, trace-events)
driver/     kernel module (built inside the guest)
tools/      pcie_hello_ctl, bar0_poke.py (driverless sysfs access), selftest.sh
scripts/    build-qemu.sh, prepare-guest.sh, run-vm.sh, ssh-vm.sh, monitor.sh
build/      (git-ignored) QEMU source + build, guest images, VM state
```

The QEMU tree is changed in exactly two ways: a 16-line patch that adds the
Kconfig symbol, the meson line and the trace events, and symlinks from
`hw/misc/` to `qemu/pcie_hello.c` and `include/pcie_hello_regs.h`. Edit the
files in this repo, then re-run `scripts/build-qemu.sh`.

## Quick start

Host requirements: Linux with KVM (tested on Ubuntu 24.04). Packages:

```sh
sudo apt install build-essential git ninja-build python3-venv flex bison \
    libglib2.0-dev libpixman-1-dev libslirp-dev libcap-ng-dev libattr1-dev \
    cloud-image-utils
```

```sh
scripts/build-qemu.sh      # clone QEMU v11.1.1, apply hooks, debug build (~5 min)
scripts/prepare-guest.sh   # Debian 13 image + cloud-init provisioning (~3 min)
scripts/run-vm.sh          # boot; console on this terminal, login dev / dev
```

In a second terminal on the host:

```sh
scripts/ssh-vm.sh          # or log in on the console
```

In the guest, this repo is mounted at `/mnt/host` over virtio-9p:

```sh
cd /mnt/host
sudo tools/selftest.sh     # builds everything and runs the whole acceptance list
```

Or step by step:

```sh
sudo lspci -vvv -d 1af4:10f0            # Express (v2) Endpoint, FLReset+, MSI-X
sudo tools/bar0_poke.py                 # raw BAR0 via sysfs, before any driver
make -C driver && make -C tools
sudo insmod driver/pcie_hello.ko        # dmesg: "... irq 43 (MSI-X)"
sudo tools/pcie_hello_ctl info
sudo tools/pcie_hello_ctl scratch
sudo tools/pcie_hello_ctl greet
sudo tools/pcie_hello_ctl upper "hello pcie"
sudo tools/pcie_hello_ctl read
sudo tools/pcie_hello_ctl -d /dev/pcie_hello1 greet
echo 1 | sudo tee /sys/bus/pci/devices/0000:01:00.0/reset   # FLR
```

Quit QEMU from the console with `Ctrl-a x`, or run `scripts/monitor.sh quit`.

## The guest

`prepare-guest.sh` uses the official **Debian 13 "generic" cloud image**
(kernel 6.12). Don't use the `genericcloud` variant: its trimmed kernel is
built without 9p (`# CONFIG_NET_9P is not set`), so the source share won't
mount. cloud-init creates user `dev`/`dev` with passwordless sudo, installs
`build-essential`, `pciutils` and the kernel headers, adds the 9p mount to
fstab, and powers the VM off when done. The VM disk is a qcow2 overlay on the
downloaded image. `FORCE=1 scripts/prepare-guest.sh` recreates it from scratch.

Boot to SSH takes about 8 s with KVM. The module builds in the guest against
the guest's own headers. The driver also compiles against the host's 7.0
headers, which is a quick syntax check without booting.

## VM topology and knobs

```
pcie.0 ── 04.0 pcie-root-port rp1 ── 01:00.0 pcie-hello id=hello0 serial=1
       ── 05.0 pcie-root-port rp2 ── 02:00.0 pcie-hello id=hello1 serial=2
       ── 06.0 pcie-root-port rp3    (empty, for hotplug later)
```

Hotplug note: on q35, QEMU hands root-port hotplug to ACPI by default, so the
guest's `acpiphp` driver registers the slots as `0`, `0-2`, `0-3` (that is the
`Physical Slot` in `lspci`; the root ports themselves report `Slot #1`, `#2`).
For native PCIe hotplug (`pciehp`), add
`-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off`.

`run-vm.sh` environment variables: `NUM_DEVICES` (default 2), `HELLO_OPTS`
(extra `-device` options for every pcie-hello, e.g. `msix=off`), `TRACE`
(default `pcie_hello_*`, empty to disable), `SSH_PORT` (2222), `MEM`, `SMP`,
`HEADLESS=1`. Any other arguments pass straight through to QEMU.

Device properties (`qemu-system-x86_64 -device pcie-hello,help`):

| Property | Default | Meaning |
|---|---|---|
| `serial` | 0 | value of the SERIAL register, shown in the greeting |
| `msix` | on | expose the MSI-X capability |
| `msi` | on | expose the MSI capability |
| `latency-ms` | 50 | command duration in virtual time; can be changed at runtime |

Runtime control through the HMP monitor (`build/vm/monitor.sock`):

```sh
scripts/monitor.sh "info pci"
scripts/monitor.sh "qom-set /machine/peripheral/hello1 latency-ms 3000"   # force driver timeouts
scripts/monitor.sh "device_add pcie-hello,bus=rp3,id=hello2,serial=3"    # hotplug (not yet tested)
```

## Tracing and guest errors

QEMU writes trace events and guest-error messages to `build/vm/qemu.log`:

```sh
tail -f build/vm/qemu.log
```

```
pcie_hello_mmio_write hello0: write 0x020 CMD <- 0x1
pcie_hello_cmd_start hello0: command 0x1 started, completes in 50 ms
pcie_hello_cmd_done hello0: command 0x1 done ok=1 buf_len=25
pcie_hello_irq hello0: irq msix int_status 0x1 int_enable 0x3
pcie_hello_mmio_read hello0: read  0x030 INT_STATUS -> 0x1
pcie_hello_mmio_write hello0: write 0x038 INT_ACK <- 0x1
pcie_hello_reset hello0: flr, all device state cleared
hello0: write 0x1 to read-only register ID          <- guest error
```

Events: `pcie_hello_mmio_read/write`, `pcie_hello_buf_read/write`,
`pcie_hello_cmd_start/done`, `pcie_hello_irq`, `pcie_hello_reset`. Narrow the
output with, for example, `TRACE='pcie_hello_cmd_*'`.

---

## Datasheet: pcie-hello v1.0

### Identity and configuration space

| Field | Value |
|---|---|
| Vendor:Device | `1af4:10f0`. QEMU's `docs/specs/pci-ids.rst` sets aside 1af4:10f0–10ff for experimental use without registration |
| Subsystem | `1af4:1100` (QEMU default) |
| Revision | `0x01` |
| Class | `0xff0000` (unclassified) |
| Interrupt pin | INTA |

| Cap offset | Capability |
|---|---|
| 0x40 | Power Management v1.2 (NoSoftRst+) |
| 0x50 | MSI, 1 vector, 64-bit |
| 0x60 | MSI-X, 1 vector, table at BAR2+0x000, PBA at BAR2+0x800 |
| 0x80 | PCI Express v2, Endpoint (or RCiEP on pcie.0), **FLReset+** |

| BAR | Type | Size | Contents |
|---|---|---|---|
| BAR0 | memory, 64-bit, non-prefetchable | 4 KiB | registers and message buffer |
| BAR2 | memory, 32-bit, non-prefetchable | 4 KiB | MSI-X table and PBA |

The device refuses to realize on a conventional PCI bus.

### BAR0 register map

All registers are 32-bit and little-endian. They must be accessed with aligned
32-bit loads and stores. Any other access size is ignored (reads return 0) and
logged as a guest error. The message buffer accepts 1-, 2- and 4-byte accesses.

| Offset | Name | Access | Reset | Description |
|---|---|---|---|---|
| 0x000 | ID | RO | `0x48454C4F` | magic ("HELO"); the driver refuses to bind otherwise |
| 0x004 | VERSION | RO | `0x00010000` | `major << 16 \| minor`; the driver requires major 1 |
| 0x008 | SCRATCH | RW | 0 | a read returns the bitwise inverse of the last write |
| 0x00C | BUF_SIZE | RO | 256 | size of the message buffer in bytes |
| 0x010 | SERIAL | RO | property | instance serial number |
| 0x020 | CMD | WO | – | writing an opcode starts a command; ignored while BUSY |
| 0x024 | STATUS | RO | 0 | bit 0 BUSY: command running. Bit 1 ERROR: last command failed |
| 0x028 | BUF_LEN | RW | 0 | number of valid bytes in BUF (clamped to BUF_SIZE); writes ignored while BUSY |
| 0x030 | INT_STATUS | RO | 0 | pending interrupt causes (see below) |
| 0x034 | INT_ENABLE | RW | 0 | enabled interrupt causes |
| 0x038 | INT_ACK | WO | – | write 1 to clear the matching INT_STATUS bits |
| 0x100–0x1FF | BUF | RW | zeros | message buffer; writes ignored while BUSY |

Unmapped offsets read as 0. Writes to read-only registers and reads from
write-only registers have no effect. All of these are logged as guest errors.

Interrupt causes (INT_STATUS, INT_ENABLE and INT_ACK use the same bits):

| Bit | Name | Set when |
|---|---|---|
| 0 | CMD_DONE | a command completed successfully |
| 1 | CMD_ERROR | a command failed (for example, an unknown opcode) |

### Commands

| Opcode | Name | Effect |
|---|---|---|
| 0x01 | GREET | BUF = `"Hello from pcie-hello #<serial>!"`, BUF_LEN = its length |
| 0x02 | UPPER | ASCII-uppercase BUF[0 .. BUF_LEN) in place |
| other | – | completes with STATUS.ERROR and CMD_ERROR |

Command sequence:

1. Write the opcode to CMD. STATUS.BUSY is set.
2. After `latency-ms` of virtual time, the device performs the operation,
   clears BUSY, sets ERROR if the command failed, and sets CMD_DONE or
   CMD_ERROR in INT_STATUS.
3. If that cause is enabled in INT_ENABLE, the device signals an interrupt.

### Interrupts

The device uses MSI-X if enabled, else MSI if enabled, else INTx.

- **MSI-X and MSI** are edge-triggered on vector 0. The device sends a message
  when a cause becomes both pending and enabled. Enabling a cause that is
  already pending also sends a message.
- **INTx** is a level signal: asserted while `INT_STATUS & INT_ENABLE` is
  non-zero.
- Because the device sends MSI and MSI-X as memory writes, the driver must
  set Bus Master Enable.

### Reset

Machine reset and **Function Level Reset** (DevCtl.BCR_FLR) both return every
register to its reset value. They also cancel any running command, zero the
buffer and disable interrupts. The PCI core resets the MSI and MSI-X
configuration. On the real device, this is the path that zeroizes keys.

---

## Driver notes

- **Binding.** The driver binds by PCI ID, then verifies the ID and VERSION
  registers.
- **Interrupts.** It asks for MSI-X, then MSI, then INTx
  (`pci_alloc_irq_vectors`). To force a mode, use
  `insmod pcie_hello.ko irq_mode=msix|msi|intx`. The default is `auto`.
- **Instances and locking.** It supports up to 16 instances. Each has a
  mutex that serializes every register and buffer access, and each ioctl is
  atomic: UPPER loads the text, runs the command and reads the result under
  one lock.
- **Timeouts.** A command that doesn't complete within `cmd_timeout_ms`
  (module parameter, default 1000, writable in
  `/sys/module/pcie_hello/parameters/`) fails with `ETIMEDOUT`. Until the
  device finishes, new commands get `EBUSY`. Before each command the driver
  clears INT_STATUS under the IRQ spinlock, so a late interrupt from a
  timed-out command can't complete the next one.
- **FLR.** `reset_prepare` takes the device mutex. `reset_done` re-checks the
  ID, re-enables interrupts and releases it. The PCI core saves and restores
  config space, including the MSI-X table.
- **Hot-unplug.** Open file descriptors stay valid after unbind and return
  `ENODEV`. The per-device structure is freed when the last one is closed.
- **Resource management.** The driver uses plain `pci_enable_device` and
  explicit teardown instead of `pcim_*`, because the managed-API semantics
  changed between 6.12 and 7.x.
- **Device nodes** are root-only (0600); run the CLI with sudo.

### ioctl ABI

| ioctl | Argument | Effect |
|---|---|---|
| `PCIE_HELLO_IOC_INFO` | `struct pcie_hello_info` (out) | ID, version, serial, interrupt mode, statistics |
| `PCIE_HELLO_IOC_SCRATCH` | `struct pcie_hello_scratch` (in/out) | write `in`, return the read-back in `out` |
| `PCIE_HELLO_IOC_GREET` | `struct pcie_hello_msg` (out) | run GREET, return the buffer |
| `PCIE_HELLO_IOC_UPPER` | `struct pcie_hello_msg` (in/out) | load the text, run UPPER, return the result |

`read(2)` returns BUF[pos .. BUF_LEN). `write(2)` stores data at `pos` and
sets BUF_LEN to the end of the write, so writing at offset 0 truncates. `cat`
and `echo >` behave as you'd expect.

## Verified

With QEMU v11.1.1 on a host running Ubuntu 24.04 (kernel 7.0), and a guest
running Debian 13 (kernel 6.12.107):

- `lspci -vvv`: Express (v2) Endpoint, FLReset+, MSI-X `Enable+` after the
  driver binds.
- `bar0_poke.py` reads the ID and the inverted scratch value on both
  instances, with no driver loaded.
- `insmod` binds both devices with MSI-X and creates `/dev/pcie_hello0` and
  `/dev/pcie_hello1`.
- info, scratch, greet, upper, read and write work on both devices. Each
  command is completed by exactly one interrupt.
- The sysfs `reset` uses FLR. It clears the device state, and the driver
  recovers with MSI-X still enabled. The other instance is unaffected.
- Timeouts: with `latency-ms` set to 3000, the command returns `ETIMEDOUT`
  after 1 s, a retry gets `EBUSY`, and a later retry succeeds.
- Fallbacks: `irq_mode=msi` and `irq_mode=intx` work, and `msix=off` on the
  device makes `auto` fall back to MSI.
- Bad register accesses show up as guest errors in `qemu.log`.

## References

- `hw/misc/edu.c` and `docs/specs/edu.rst` in the QEMU tree: the structural
  template.
- `hw/nvme/ctrl.c` (`nvme_init_pci`, `nvme_pci_write_config`): PCIe
  capability, FLR and MSI-X setup. `hw/net/e1000e.c`: reset through the
  `ResettableClass` hold phase and `msix_vector_use`.
- `hw/pci/pcie.c` (`pcie_cap_flr_write_config` calls `pci_device_reset`,
  which is how FLR reaches the reset handler) and `hw/pci/msix.c`.
- QEMU `docs/devel/tracing.rst` and `docs/specs/pci-ids.rst`.
- Linux `Documentation/PCI/pci.rst` and `Documentation/PCI/msi-howto.rst`,
  and `drivers/pci/pci.c` (`pci_reset_function`, which calls the
  `reset_prepare` and `reset_done` handlers).
- *PCI Express Base Specification*, sections 6.6.2 (FLR) and 7.7.2 (MSI-X).
