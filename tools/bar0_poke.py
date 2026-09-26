#!/usr/bin/env python3
"""Poke pcie-hello BAR0 through sysfs resource0, without any driver.

    sudo ./bar0_poke.py              # every 1af4:10f0 device
    sudo ./bar0_poke.py 0000:01:00.0

Registers are accessed through memoryview.cast("I"), so every access is a
single aligned 32-bit load/store (the device rejects other register sizes).
"""
import glob
import mmap
import os
import sys

VENDOR, DEVICE = 0x1AF4, 0x10F0
REG_ID, REG_VERSION, REG_SCRATCH = 0x000, 0x004, 0x008
REG_BUF_SIZE, REG_SERIAL, REG_STATUS = 0x00C, 0x010, 0x024
MAGIC = 0x48454C4F


def sysfs_int(path):
    with open(path) as f:
        return int(f.read(), 0)


def find_devices():
    for d in sorted(glob.glob("/sys/bus/pci/devices/*")):
        if (sysfs_int(d + "/vendor"), sysfs_int(d + "/device")) == (VENDOR, DEVICE):
            yield os.path.basename(d)


def poke(bdf):
    path = f"/sys/bus/pci/devices/{bdf}"
    driver = os.path.join(path, "driver")
    if os.path.exists(driver):
        print(f"{bdf}: note: bound to {os.path.basename(os.readlink(driver))};"
              " mmap may be refused while a driver owns the BAR")
    # Make sure memory decoding is on (no driver has enabled the device).
    with open(path + "/enable", "w") as f:
        f.write("1")

    fd = os.open(path + "/resource0", os.O_RDWR | os.O_SYNC)
    try:
        m = mmap.mmap(fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    finally:
        os.close(fd)
    regs = memoryview(m).cast("I")

    def rd(off):
        return regs[off // 4]

    def wr(off, val):
        regs[off // 4] = val

    ident, ver = rd(REG_ID), rd(REG_VERSION)
    print(f"{bdf}: ID       0x{ident:08x} {'OK' if ident == MAGIC else 'BAD'}"
          f" ({ident.to_bytes(4, 'big').decode(errors='replace')!r})")
    print(f"{bdf}: VERSION  {ver >> 16}.{ver & 0xffff}")
    print(f"{bdf}: BUF_SIZE {rd(REG_BUF_SIZE)}  SERIAL {rd(REG_SERIAL)}"
          f"  STATUS 0x{rd(REG_STATUS):x}")
    ok = ident == MAGIC
    for val in (0x00000000, 0x12345678, 0xDEADBEEF):
        wr(REG_SCRATCH, val)
        got = rd(REG_SCRATCH)
        good = got == (~val & 0xFFFFFFFF)
        ok &= good
        print(f"{bdf}: SCRATCH  wrote 0x{val:08x} read 0x{got:08x}"
              f" {'OK (inverted)' if good else 'MISMATCH'}")
    regs.release()
    m.close()
    return ok


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    bdfs = sys.argv[1:] or list(find_devices())
    if not bdfs:
        sys.exit(f"no {VENDOR:04x}:{DEVICE:04x} devices found")
    sys.exit(0 if all([poke(b) for b in bdfs]) else 1)


if __name__ == "__main__":
    main()
