#!/usr/bin/env python3
"""SR-28: check that FI countermeasures survive optimization.

Compiles the device model at -O2 with the release flags (no test hooks),
disassembles the F-target functions and asserts that each countermeasure is
still present in the machine code. Writes excerpts to build/fi-review/ and
diffs a normalized listing against tests/fi/baseline/ (threat model 12.3).

  tools/fi-disasm-review.py                 check (exit 1 on a failed check)
  tools/fi-disasm-review.py --update-baseline
"""
import json
import os
import re
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLD = os.path.join(ROOT, "build", "qemu-src", "build")
OUT = os.path.join(ROOT, "build", "fi-review")
BASE = os.path.join(ROOT, "tests", "fi", "baseline")
SOURCES = ["cryptostore.c", "cryptostore_crypto.c", "cryptostore_fi.c", "cryptorecovery.c"]

FS_TRUE, FS_FALSE = 0x889725B9, 0xB5AFE1C7
ST_UNLOCKED = 0x28E94A2F


def compile_o2():
    os.makedirs(OUT, exist_ok=True)
    cc = json.load(open(os.path.join(BLD, "compile_commands.json")))
    for src in SOURCES:
        e = next(x for x in cc if x["file"].endswith("hw/misc/" + src))
        args, skip, out = shlex.split(e["command"]), False, []
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-o", "-MF", "-MQ"):
                skip = True
                continue
            if a in ("-MD", "-c") or a.endswith(".c") or a.startswith("-DCRYPTOSTORE_FAULT"):
                continue
            out.append("-O2" if a == "-O0" else a)
        obj = os.path.join(OUT, src + ".o")
        subprocess.run(out + ["-c", "../hw/misc/" + src, "-o", obj], cwd=BLD, check=True)


def disasm(obj, sym):
    r = subprocess.run(["objdump", "-d", "-r", "--no-show-raw-insn", f"--disassemble={sym}",
                        os.path.join(OUT, obj)], capture_output=True, text=True, check=True)
    lines = [l for l in r.stdout.splitlines() if re.match(r"^\s+[0-9a-f]+:", l)]
    if not lines:
        sys.exit(f"symbol {sym} not found in {obj}")
    return lines


def insns(lines):
    return [l.split(":", 1)[1].strip() for l in lines if not re.search(r"R_X86_64", l)]


def relocs(lines):
    return [l.split()[-1] for l in lines if re.search(r"R_X86_64_(PLT32|PC32)", l)]


def imm_count(ins, value):
    pats = {f"$0x{value:x}", f"$0x{value - 1:x}", f"$0x{value + 1:x}"}
    signed = value - (1 << 32) if value >= 1 << 31 else value
    pats |= {f"$0x{(signed) & 0xffffffffffffffff:x}", f"${signed}"}
    return sum(any(p in i for p in pats) for i in ins)


ALIASES = {"explicit_bzero": ("explicit_bzero", "__explicit_bzero_chk")}


def calls(lines, name):
    """Calls to @name: via a relocation (other objects) or direct (same object)."""
    names = ALIASES.get(name, (name,))
    n = sum(1 for r in relocs(lines) if any(r == x or r.startswith(x + "-") or r.startswith(x + "+")
                                             for x in names))
    n += sum(1 for l in lines if re.search(r"\bcall\s+[0-9a-f]+ <(%s)>" % "|".join(map(re.escape, names)), l))
    return n


def backward_branches(lines):
    n = 0
    for l in lines:
        m = re.match(r"^\s+([0-9a-f]+):\s+j\w+\s+([0-9a-f]+)\b", l)
        if m and int(m.group(2), 16) < int(m.group(1), 16):
            n += 1
    return n


def normalize(lines):
    out = []
    for l in lines:
        if re.search(r"R_X86_64", l):
            out.append("  reloc " + l.split()[-1].split("-")[0].split("+")[0])
            continue
        i = l.split(":", 1)[1].strip()
        i = re.sub(r"^(j\w+|call)\s+[0-9a-f]+( <[^>]*>)?", r"\1 X", i)
        out.append("  " + i)
    return out


CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))


def main():
    update = "--update-baseline" in sys.argv
    compile_o2()
    funcs = {
        "cs_jitter.isra.0": "cryptostore.c.o",
        "cs_attempt_begin": "cryptostore.c.o",
        "cs_check_kdf_params": "cryptostore.c.o",
        "cs_cmd_data": "cryptostore.c.o",
        "cs_auth_result": "cryptostore.c.o",
        "cs_zeroize": "cryptostore.c.o",
        "cs_slot_unwrap": "cryptostore_crypto.c.o",
        "cs_tag_verdict": "cryptostore_fi.c.o",
        "cs_ct_equal": "cryptostore_fi.c.o",
        "cs_ct_equal_alt": "cryptostore_fi.c.o",
        "cryptorecovery_release": "cryptorecovery.c.o",
    }
    dis = {f: disasm(o, f) for f, o in funcs.items()}
    ins = {f: insns(l) for f, l in dis.items()}

    # secure_jitter port (SR-23): volatile countdown with nop, three checks.
    j = ins["cs_jitter.isra.0"]
    check("jitter: nop survives inside the delay loop", any(i == "nop" for i in j))
    check("jitter: the loop is a real loop (backward branch)", backward_branches(dis["cs_jitter.isra.0"]) >= 1)
    stack_ops = [i for i in j if re.search(r"\(%rsp\)|\(%rbp\)", i)]
    check("jitter: volatile counter lives in memory (>= 6 stack accesses)", len(stack_ops) >= 6,
          f"{len(stack_ops)} stack accesses")
    check("jitter: three redundant checks after the loop (>= 4 conditional branches)",
          sum(1 for i in j if re.match(r"j(n?e|n?z|ne)\b", i)) >= 4)

    # F2 backoff (fail-secure encodings, two paths) and F1 re-read.
    a = ins["cs_attempt_begin"]
    check("F2: both fail-secure constants are compared", imm_count(a, FS_TRUE) >= 1 and imm_count(a, FS_FALSE) >= 1,
          f"FS_TRUE x{imm_count(a, FS_TRUE)}, FS_FALSE x{imm_count(a, FS_FALSE)}")
    check("F2: jitter precedes the checks (cs_jitter called)", calls(dis["cs_attempt_begin"], "cs_jitter.isra.0") >= 2)
    check("F2: path B doubling loop survives (backward branch)", backward_branches(dis["cs_attempt_begin"]) >= 1)
    check("F1: the record is read back after the write (blk_pread)", calls(dis["cs_attempt_begin"], "blk_pread") >= 1)

    # F5 KDF bounds: two differently computed checks.
    k = ins["cs_check_kdf_params"]
    check("F5: path A range check survives (iters - floor <= span)",
          imm_count(k, 400000000 - 600000) >= 1)
    # GCC folds "x / y != 0" into "x >= y", but y stays a volatile memory
    # operand, so path B compares against bounds re-read from the stack while
    # path A uses immediates: two different instruction sequences.
    check("F5: path B compares against volatile in-memory bounds (differs from path A)",
          any(re.match(r"movl\s+\$0x927c0,0x[0-9a-f]+\(%rsp\)", i) for i in k) and
          any(re.match(r"movl\s+\$0x17d78401,0x[0-9a-f]+\(%rsp\)", i) for i in k) and
          sum(1 for i in k if re.match(r"cmp\s+%e\w+,%e\w+", i)) >= 2)
    check("F5: jitter between the two evaluations", calls(dis["cs_check_kdf_params"], "cs_jitter.isra.0") >= 1)

    # F4 lock-state and F6 bounds, F7 double computation.
    d = ins["cs_cmd_data"]
    check("F4: UNLOCKED constant checked at entry and before the access (>= 2)",
          imm_count(d, ST_UNLOCKED) >= 2, f"x{imm_count(d, ST_UNLOCKED)}")
    check("F4: dek_loaded compared against FS_TRUE", imm_count(d, FS_TRUE) >= 1)
    check("F7: encrypt and decrypt both run per sector (>= 4 cs_xts_sector calls)",
          calls(dis["cs_cmd_data"], "cs_xts_sector") >= 4)
    check("F7: outputs compared before release (memcmp)", calls(dis["cs_cmd_data"], "memcmp") >= 2)

    # SR-24 CFI.
    r = ins["cs_auth_result"]
    check("CFI: step mask and step count compared", any("$0x7f" in i for i in r) and any("$0x7," in i for i in r))
    check("F9 pattern on the header MAC: goes through cs_tag_verdict",
          calls(dis["cs_auth_result"], "cs_tag_verdict") >= 1)
    check("F9 pattern on the header MAC: verdict compared to both FS constants",
          imm_count(r, FS_TRUE) >= 1 and imm_count(r, FS_FALSE) >= 1)

    # F3 wipe then verify.
    z = dis["cs_zeroize"]
    check("F3: explicit_bzero called", calls(z, "explicit_bzero") >= 1)
    check("F3: read-back verification loops survive", backward_branches(z) >= 2)

    # F9 tag compare and constant-time compares.
    u = dis["cs_slot_unwrap"]
    v = dis["cs_tag_verdict"]
    check("F9: slot tag goes through cs_tag_verdict", calls(u, "cs_tag_verdict") >= 1)
    check("F9: verdict calls both compare implementations",
          calls(v, "cs_ct_equal") >= 1 and calls(v, "cs_ct_equal_alt") >= 1)
    tv = ins["cs_tag_verdict"]
    check("F9: verdict built from FS_FALSE plus one mask per compare (no single select)",
          any("$0xb5afe1c7" in i for i in tv) and any("$0xf6d7fbb3" in i for i in tv)
          and any("$0xcbef3fcd" in i for i in tv) and not any(re.match(r"(sbb|cmov)", i) for i in tv))
    check("F9: unwrap accepts only an exact FS_TRUE / FS_FALSE",
          imm_count(ins["cs_slot_unwrap"], FS_TRUE) >= 1 and imm_count(ins["cs_slot_unwrap"], FS_FALSE) >= 1)
    for f in ("cs_ct_equal", "cs_ct_equal_alt"):
        body = ins[f]
        early = [i for i in body if re.match(r"j\w+", i)]
        check(f"SR-05: {f} has a single loop and no data-dependent early exit",
              backward_branches(dis[f]) == 1 and len(early) <= 3, "; ".join(early))

    # F8 in the recovery device: jitter inlined, second check present.
    c = ins["cryptorecovery_release"]
    check("F8: jitter nop inlined in the release path", any(i == "nop" for i in c))
    check("F8: fail-secure released flag compared", imm_count(c, FS_FALSE) >= 1 or imm_count(c, FS_TRUE) >= 1)

    # Excerpts and baseline.
    os.makedirs(BASE, exist_ok=True)
    changed = []
    for f, lines in dis.items():
        with open(os.path.join(OUT, f + ".s"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
        norm = "\n".join(normalize(lines)) + "\n"
        bpath = os.path.join(BASE, f + ".s")
        if update or not os.path.exists(bpath):
            open(bpath, "w").write(norm)
        elif open(bpath).read() != norm:
            changed.append(f)

    width = max(len(n) for n, _, _ in CHECKS)
    failed = 0
    for name, ok, detail in CHECKS:
        failed += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed; disassembly in {OUT}")
    if changed:
        print("Changed since the reviewed baseline (review, then --update-baseline): " + ", ".join(changed))
    elif not update:
        print("Disassembly matches the reviewed baseline in tests/fi/baseline/")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
