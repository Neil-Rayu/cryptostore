#!/usr/bin/env python3
"""Show what an attacker who copies the backing file can see (threat model T1).

  tools/attacker-view.py IMAGE [--secret TEXT] [--sector N]

Prints the public header (annotated), a raw data sector, a search for known
plaintext, the data-area entropy, and what offline brute force costs.
Read-only; safe to run on the image of a running VM.
"""
import argparse
import hashlib
import math
import os
import struct
import time
import uuid as uuidlib

HDR, SECTOR, DATA = 0x1000, 512, 0x1000


def hexdump(buf, base, rows=None):
    lines = []
    for off in range(0, len(buf), 16):
        chunk = buf[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base + off:08x}  {hexs:<47}  |{text}|")
        if rows and len(lines) >= rows:
            break
    return "\n".join(lines)


def section(title):
    print(f"\n--- {title} " + "-" * max(0, 66 - len(title)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--secret", help="known plaintext to search for")
    ap.add_argument("--sector", type=int, default=0, help="data sector to dump")
    a = ap.parse_args()

    size = os.path.getsize(a.image)
    with open(a.image, "rb") as f:
        hdr = f.read(HDR)
        f.seek(DATA + a.sector * SECTOR)
        sec = f.read(SECTOR)

    print(f"Attacker's copy: {a.image} ({size // (1024 * 1024)} MiB). No password, no recovery key.")

    section("Header: public by design (threat model A5, 11.9)")
    print(hexdump(hdr[:0x30], 0))
    magic = hdr[:8].decode(errors="replace")
    cap = struct.unpack_from("<Q", hdr, 0x1C)[0]
    print(f"  magic {magic!r}, version {struct.unpack_from('<I', hdr, 8)[0]}, "
          f"uuid {uuidlib.UUID(bytes=bytes(hdr[0x0C:0x1C]))}, capacity {cap} sectors")
    print("\n  keyslot 0 (state, type, KDF, iterations, then salt / IV / wrapped key / tag):")
    print(hexdump(hdr[0x100:0x1A0], 0x100))
    state, typ, kdf, iters = struct.unpack_from("<IHHI", hdr, 0x100)
    print(f"  -> {'ACTIVE' if state == 0x5A3CA5C3 else hex(state)}, "
          f"{'password' if typ == 1 else 'recovery'} slot, PBKDF2-HMAC-SHA256 x {iters:,}")
    print("     The 64-byte data key is only here wrapped (AES-256-CTR) under a key")
    print("     derived from the password, and authenticated by the 32-byte tag.")
    count, inv, _ = struct.unpack_from("<IIQ", hdr, 0xF00)
    print(f"\n  failure counter: {count} (complement {'ok' if count == (~inv & 0xFFFFFFFF) else 'CORRUPT'})")

    section(f"Data sector {a.sector} as stored on disk")
    print(hexdump(sec, DATA + a.sector * SECTOR, rows=8))
    print("  ... (AES-256-XTS ciphertext: indistinguishable from random)")

    if a.secret:
        section(f"Search the whole file for known plaintext {a.secret!r}")
        needle, found, pos, tail = a.secret.encode(), None, 0, b""
        with open(a.image, "rb") as f:
            while chunk := f.read(1 << 20):
                buf = tail + chunk
                i = buf.find(needle)
                if i >= 0:
                    found = pos - len(tail) + i
                    break
                tail = buf[-(len(needle) - 1):]
                pos += len(chunk)
        print(f"  {'FOUND at offset ' + hex(found) if found is not None else 'not found anywhere in ' + str(size) + ' bytes'}")

    section("Data area statistics")
    counts, total, zero_sectors = [0] * 256, 0, 0
    with open(a.image, "rb") as f:
        f.seek(DATA)
        while chunk := f.read(1 << 20):
            for v in range(256):
                counts[v] += chunk.count(v)
            zero_sectors += sum(1 for o in range(0, len(chunk), SECTOR) if not any(chunk[o:o + SECTOR]))
            total += len(chunk)
    h = -sum(c / total * math.log2(c / total) for c in counts if c)
    print(f"  entropy {h:.4f} bits/byte (8 = random), zero sectors {zero_sectors} of {total // SECTOR}")
    print("  Random fill at FORMAT means even unused sectors look like data (SR-36),")
    print("  so the file does not reveal how much of the disk is in use.")

    section("Offline brute force (V1: the KDF is the only defence here)")
    t = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", b"guess", hdr[0x110:0x130], iters, 32)
    per = time.perf_counter() - t
    print(f"  one guess = PBKDF2 x {iters:,} = {per:.2f} s on this CPU core")
    print(f"  -> {1 / per:.1f} guesses/s per core, {86400 / per:,.0f} per core-day")
    for name, bits in (("8 random lowercase letters", 8 * math.log2(26)),
                       ("4 random dictionary words (7776-word list)", 4 * math.log2(7776))):
        years = (2 ** bits / 2) * per / (365 * 86400)
        print(f"  {name}: about {years:,.0f} core-years on average")
    print("  GPUs run PBKDF2 far faster than one core; that gap is why Argon2id")
    print("  (memory-hard) is the planned upgrade via the KDF ID (V1, O10).")
    print("  The device's 10-try lockout does not apply offline; it stops guessing")
    print("  through the device (online, T3).")


if __name__ == "__main__":
    main()
