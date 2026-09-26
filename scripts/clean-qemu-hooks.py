#!/usr/bin/env python3
"""Remove stale sample-device hooks from an existing local QEMU checkout."""

import re
import sys
from pathlib import Path


source = Path(sys.argv[1])


def clean(path, pattern, replacement=""):
    file = source / path
    content = file.read_text()
    file.write_text(re.sub(pattern, replacement, content))


# Older local builds added a standalone sample device alongside CryptoStore.
# Strip only its Kconfig, Meson, trace, and dangling symlink entries.
clean("hw/misc/Kconfig", r"(?ms)^config PCIE_HELLO\n.*?^\n")
clean("hw/misc/meson.build", r"(?m)^.*CONFIG_PCIE_HELLO.*\n")
clean("hw/misc/trace-events", r"(?ms)^# pcie_hello\.c\n.*?(?=^# cryptostore\.c\n)")

for name in ("pcie_hello.c", "pcie_hello_regs.h"):
    stale_link = source / "hw/misc" / name
    if stale_link.is_symlink():
        stale_link.unlink()
