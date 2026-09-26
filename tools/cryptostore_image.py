#!/usr/bin/env python3
"""Offline tool for pcie-cryptostore backing images (host side, T5).

Reads and edits images of a *stopped* VM. It holds no keys and does no
crypto: it can inspect, validate, tamper for tests, and perform the
host-admin recovery actions from the threat model (Section 8, B8).

  create IMAGE SIZE_MIB            blank raw image (header region zero)
  info IMAGE                       decode header, slots and failure record
  check IMAGE                      validate like the device (datasheet 10.5)
  reset-counter IMAGE              clear the failure counter (admin, B8)
  wipe-header IMAGE --yes          zero the header region (recover a torn FORMAT)
  set-iters IMAGE SLOT N           tamper: change a slot's PBKDF2 iterations
  set-capacity IMAGE N             tamper: change the capacity field
  flip IMAGE OFFSET [BIT]          tamper: flip one bit
  copy-slot SRC DST SLOT           tamper: copy a keyslot from another image
  set-fail IMAGE COUNT [--corrupt] tamper: write a failure record
  grep IMAGE TEXT                  exit 1 if TEXT occurs anywhere in the image
  entropy IMAGE                    data-area entropy and zero-sector fraction
  recovery-info IMAGE              decode a pcie-cryptorecovery image
  seed-corpus DIR                  write fuzzer seed inputs

Editing commands refuse to touch an image that a running QEMU has locked.
"""
import argparse
import fcntl
import math
import os
import struct
import sys
import uuid as uuidlib

HDR_SIZE = 0x1000
DATA_OFFSET = 0x1000
SECTOR = 512
MAGIC = b"CRYPTOST"
VERSION = 1
CIPHER_XTS = 1
OFF_UUID, OFF_CAP, OFF_CIPHER = 0x0C, 0x1C, 0x24
OFF_SLOTS, SLOT_SIZE, NUM_SLOTS = 0x100, 256, 8
OFF_MAC, OFF_FAIL = 0x900, 0xF00
SLOT_ACTIVE = 0x5A3CA5C3
TYPE_PASSWORD, TYPE_RECOVERY = 1, 2
KDF_PBKDF2, KDF_HKDF = 1, 2
PBKDF2_MIN, PBKDF2_MAX = 600000, 400000000
MIN_CAP, MAX_CAP = 2048, 1 << 32
LOCKOUT_N = 10

REC_MAGIC = b"CRYPTORC"


class Malformed(Exception):
    pass


def zero(b):
    return not any(b)


def parse_slot(i, b):
    state = struct.unpack_from("<I", b, 0)[0]
    if state == 0:
        if not zero(b):
            raise Malformed(f"slot {i}: inactive keyslot is not all zero")
        return None
    if state != SLOT_ACTIVE:
        raise Malformed(f"slot {i}: keyslot state is neither INACTIVE nor ACTIVE")
    typ, kdf, iters = struct.unpack_from("<HHI", b, 4)
    if typ == TYPE_PASSWORD:
        if kdf != KDF_PBKDF2:
            raise Malformed(f"slot {i}: password slot does not use PBKDF2-HMAC-SHA256")
        if not PBKDF2_MIN <= iters <= PBKDF2_MAX:
            raise Malformed(f"slot {i}: PBKDF2 iteration count outside the allowed range")
    elif typ == TYPE_RECOVERY:
        if kdf != KDF_HKDF or iters != 0:
            raise Malformed(f"slot {i}: recovery slot does not use HKDF-SHA256 with 0 iterations")
    else:
        raise Malformed(f"slot {i}: unknown keyslot type")
    if not zero(b[0x0C:0x10]) or not zero(b[0xA0:]):
        raise Malformed(f"slot {i}: keyslot reserved bytes are not zero")
    return {"type": typ, "kdf": kdf, "iters": iters}


def parse(hdr, file_size):
    """Mirror of csf_parse(); returns ('unformatted'|'valid', info)."""
    if file_size < HDR_SIZE:
        raise Malformed("file smaller than the 4 KiB header region")
    if zero(hdr):
        return "unformatted", {}
    if hdr[:8] != MAGIC:
        raise Malformed("bad magic")
    if struct.unpack_from("<I", hdr, 8)[0] != VERSION:
        raise Malformed("unsupported format version")
    if not (zero(hdr[0x26:0x100]) and zero(hdr[0x920:0xF00]) and zero(hdr[0xF10:0x1000])):
        raise Malformed("reserved header bytes are not zero")
    if struct.unpack_from("<H", hdr, OFF_CIPHER)[0] != CIPHER_XTS:
        raise Malformed("unknown cipher ID")
    cap = struct.unpack_from("<Q", hdr, OFF_CAP)[0]
    if not MIN_CAP <= cap <= MAX_CAP or cap > (file_size - DATA_OFFSET) // SECTOR:
        raise Malformed("capacity out of range or larger than the file")
    slots = [parse_slot(i, hdr[OFF_SLOTS + i * SLOT_SIZE:OFF_SLOTS + (i + 1) * SLOT_SIZE])
             for i in range(NUM_SLOTS)]
    active = [s for s in slots if s]
    if not any(s["type"] == TYPE_PASSWORD for s in active):
        raise Malformed("no active password keyslot")
    if sum(s["type"] == TYPE_RECOVERY for s in active) > 1:
        raise Malformed("more than one recovery keyslot")
    count, inv, last = struct.unpack_from("<IIQ", hdr, OFF_FAIL)
    return "valid", {
        "uuid": str(uuidlib.UUID(bytes=bytes(hdr[OFF_UUID:OFF_UUID + 16]))),
        "capacity": cap, "slots": slots, "fail_count": count,
        "fail_record_ok": count == (~inv & 0xFFFFFFFF), "last_attempt_ms": last,
    }


def read_hdr(path):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        hdr = f.read(HDR_SIZE)
    return hdr.ljust(HDR_SIZE, b"\0"), size


# QEMU's file locking (block/file-posix.c) holds OFD locks on byte 100 + bit
# for each permission it uses and 200 + bit for each one it forbids others.
# BLK_PERM_WRITE is bit 1: a live writer holds byte 101, and blocks 201.
QEMU_LOCK_BYTES = (101, 201)


def image_in_use(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        for off in QEMU_LOCK_BYTES:
            probe = struct.pack("hhqqi", fcntl.F_WRLCK, os.SEEK_SET, off, 1, 0)
            held = struct.unpack("hhqqi", fcntl.fcntl(fd, fcntl.F_OFD_GETLK, probe))[0]
            if held != fcntl.F_UNLCK:
                return True
    finally:
        os.close(fd)
    return False


def ensure_not_in_use(path, force=False):
    """Refuse to edit an image a running QEMU holds (image locking, SR-30)."""
    if not force and image_in_use(path):
        sys.exit(f"{path}: image is in use by a running QEMU (stop the VM first)")


def patch(path, offset, data):
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def state_after_realize(kind, info):
    if kind == "unformatted":
        return "UNFORMATTED"
    if not info["fail_record_ok"] or info["fail_count"] >= LOCKOUT_N:
        return "LOCKED_OUT"
    return "LOCKED"


# ---- commands ----

def cmd_create(a):
    with open(a.image, "xb") as f:
        f.truncate(DATA_OFFSET + a.size_mib * 1024 * 1024)
    print(f"created blank image {a.image} ({a.size_mib} MiB of data)")


def cmd_info(a):
    hdr, size = read_hdr(a.image)
    try:
        kind, info = parse(hdr, size)
    except Malformed as e:
        print(f"{a.image}: MALFORMED ({e}); the device would enter ERROR")
        return 2
    print(f"image           : {a.image} ({size} bytes)")
    print(f"realize state   : {state_after_realize(kind, info)}")
    if kind == "unformatted":
        return 0
    print(f"uuid            : {info['uuid']}")
    print(f"capacity        : {info['capacity']} sectors ({info['capacity'] * SECTOR // 1048576} MiB)")
    for i, s in enumerate(info["slots"]):
        if s:
            t = "password" if s["type"] == TYPE_PASSWORD else "recovery"
            extra = f", {s['iters']} PBKDF2 iterations" if s["type"] == TYPE_PASSWORD else ""
            print(f"keyslot {i}       : {t}{extra}")
    ok = "" if info["fail_record_ok"] else " (record corrupt: device enters LOCKED_OUT)"
    print(f"failure count   : {info['fail_count']}{ok}")
    print(f"last attempt ms : {info['last_attempt_ms']}")
    return 0


def cmd_check(a):
    hdr, size = read_hdr(a.image)
    try:
        kind, info = parse(hdr, size)
    except Malformed as e:
        print(f"MALFORMED: {e}")
        return 2
    print(f"{kind.upper()}: device would realize as {state_after_realize(kind, info)}")
    return 0


def cmd_reset_counter(a):
    ensure_not_in_use(a.image, a.force)
    patch(a.image, OFF_FAIL, struct.pack("<IIQ", 0, 0xFFFFFFFF, 0))
    print(f"{a.image}: failure counter cleared (host-admin action, threat model B8)")


def cmd_wipe_header(a):
    if not a.yes:
        sys.exit("refusing without --yes: this makes the image UNFORMATTED and its data unrecoverable")
    ensure_not_in_use(a.image, a.force)
    patch(a.image, 0, bytes(HDR_SIZE))
    print(f"{a.image}: header region zeroed")


def cmd_set_iters(a):
    ensure_not_in_use(a.image, a.force)
    patch(a.image, OFF_SLOTS + a.slot * SLOT_SIZE + 8, struct.pack("<I", a.n))
    print(f"slot {a.slot}: iterations set to {a.n}")


def cmd_set_capacity(a):
    ensure_not_in_use(a.image, a.force)
    patch(a.image, OFF_CAP, struct.pack("<Q", a.n))
    print(f"capacity set to {a.n}")


def cmd_flip(a):
    ensure_not_in_use(a.image, a.force)
    off = int(a.offset, 0)
    with open(a.image, "r+b") as f:
        f.seek(off)
        b = f.read(1)[0]
        f.seek(off)
        f.write(bytes([b ^ (1 << a.bit)]))
    print(f"flipped bit {a.bit} at offset {off:#x}")


def cmd_copy_slot(a):
    ensure_not_in_use(a.dst, a.force)
    off = OFF_SLOTS + a.slot * SLOT_SIZE
    with open(a.src, "rb") as f:
        f.seek(off)
        data = f.read(SLOT_SIZE)
    patch(a.dst, off, data)
    print(f"copied slot {a.slot} from {a.src} into {a.dst}")


def cmd_set_fail(a):
    ensure_not_in_use(a.image, a.force)
    inv = (~a.count & 0xFFFFFFFF) ^ (1 if a.corrupt else 0)
    patch(a.image, OFF_FAIL, struct.pack("<IIQ", a.count, inv, 0))
    print(f"failure record set to {a.count}{' (complement corrupted)' if a.corrupt else ''}")


def cmd_grep(a):
    needle = a.text.encode()
    overlap = len(needle) - 1
    pos, tail = 0, b""
    with open(a.image, "rb") as f:
        while chunk := f.read(1 << 20):
            buf = tail + chunk
            i = buf.find(needle)
            if i >= 0:
                print(f"FOUND at offset {pos - len(tail) + i:#x}")
                return 1
            tail = buf[-overlap:] if overlap else b""
            pos += len(chunk)
    print("not found")
    return 0


def cmd_entropy(a):
    counts = [0] * 256
    total = zero_sectors = sectors = 0
    with open(a.image, "rb") as f:
        f.seek(DATA_OFFSET)
        while chunk := f.read(1 << 20):
            for off in range(0, len(chunk), SECTOR):
                sectors += 1
                if not any(chunk[off:off + SECTOR]):
                    zero_sectors += 1
            for v in range(256):
                counts[v] += chunk.count(v)
            total += len(chunk)
    h = -sum(c / total * math.log2(c / total) for c in counts if c)
    print(f"data area: {total} bytes, entropy {h:.4f} bits/byte, "
          f"zero sectors {zero_sectors}/{sectors}")
    return 0


def cmd_recovery_info(a):
    with open(a.image, "rb") as f:
        b = f.read(512).ljust(512, b"\0")
    if zero(b):
        print("EMPTY (no recovery key stored)")
        return 0
    if b[:8] != REC_MAGIC:
        print("MALFORMED: bad magic")
        return 2
    ver, state = struct.unpack_from("<II", b, 8)
    u = uuidlib.UUID(bytes=bytes(b[0x10:0x20]))
    print(f"version {ver}, state {'KEY' if state == SLOT_ACTIVE else state:}, bound to image {u}")
    return 0


def cmd_seed_corpus(a):
    """Valid-structure header (no real crypto) plus malformed variants."""
    os.makedirs(a.dir, exist_ok=True)
    cap = 2048 * 4
    size = DATA_OFFSET + cap * SECTOR
    hdr = bytearray(HDR_SIZE)
    hdr[0:8] = MAGIC
    struct.pack_into("<I", hdr, 8, VERSION)
    hdr[OFF_UUID:OFF_UUID + 16] = os.urandom(16)
    struct.pack_into("<Q", hdr, OFF_CAP, cap)
    struct.pack_into("<H", hdr, OFF_CIPHER, CIPHER_XTS)
    slot = bytearray(SLOT_SIZE)
    struct.pack_into("<IHHI", slot, 0, SLOT_ACTIVE, TYPE_PASSWORD, KDF_PBKDF2, PBKDF2_MIN)
    slot[0x10:0xA0] = os.urandom(0x90)
    hdr[OFF_SLOTS:OFF_SLOTS + SLOT_SIZE] = slot
    rslot = bytearray(SLOT_SIZE)
    struct.pack_into("<IHHI", rslot, 0, SLOT_ACTIVE, TYPE_RECOVERY, KDF_HKDF, 0)
    rslot[0x10:0xA0] = os.urandom(0x90)
    hdr[OFF_SLOTS + SLOT_SIZE:OFF_SLOTS + 2 * SLOT_SIZE] = rslot
    hdr[OFF_MAC:OFF_MAC + 32] = os.urandom(32)
    struct.pack_into("<IIQ", hdr, OFF_FAIL, 3, ~3 & 0xFFFFFFFF, 1234)
    assert parse(bytes(hdr), size)[0] == "valid"

    def emit(name, h, fsize=size):
        with open(os.path.join(a.dir, name), "wb") as f:
            f.write(struct.pack("<Q", fsize) + bytes(h))

    emit("valid", hdr)
    emit("blank", bytes(HDR_SIZE))
    emit("small-file", hdr, 100)
    emit("capacity-too-big", hdr, DATA_OFFSET + 10 * SECTOR)
    for name, off, val in [("bad-magic", 0, 0x00), ("bad-version", 8, 0x02),
                           ("bad-cipher", OFF_CIPHER, 0x07), ("reserved", 0x80, 0x01),
                           ("slot-state", OFF_SLOTS, 0x11), ("slot-iters", OFF_SLOTS + 8, 0x00),
                           ("fail-corrupt", OFF_FAIL + 4, 0x00)]:
        h = bytearray(hdr)
        h[off] = val
        emit(name, h)
    print(f"wrote seed corpus to {a.dir}")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, *args, force=False):
        sp = sub.add_parser(name)
        for arg, kw in args:
            sp.add_argument(arg, **kw)
        if force:
            sp.add_argument("--force", action="store_true", help="skip the in-use check")
        sp.set_defaults(fn=fn)
        return sp

    add("create", cmd_create, ("image", {}), ("size_mib", {"type": int}))
    add("info", cmd_info, ("image", {}))
    add("check", cmd_check, ("image", {}))
    add("reset-counter", cmd_reset_counter, ("image", {}), force=True)
    add("wipe-header", cmd_wipe_header, ("image", {}), ("--yes", {"action": "store_true"}), force=True)
    add("set-iters", cmd_set_iters, ("image", {}), ("slot", {"type": int}), ("n", {"type": int}), force=True)
    add("set-capacity", cmd_set_capacity, ("image", {}), ("n", {"type": int}), force=True)
    add("flip", cmd_flip, ("image", {}), ("offset", {}), ("bit", {"type": int, "nargs": "?", "default": 0}), force=True)
    add("copy-slot", cmd_copy_slot, ("src", {}), ("dst", {}), ("slot", {"type": int}), force=True)
    add("set-fail", cmd_set_fail, ("image", {}), ("count", {"type": int}),
        ("--corrupt", {"action": "store_true"}), force=True)
    add("grep", cmd_grep, ("image", {}), ("text", {}))
    add("entropy", cmd_entropy, ("image", {}))
    add("recovery-info", cmd_recovery_info, ("image", {}))
    add("seed-corpus", cmd_seed_corpus, ("dir", {}))
    a = p.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
