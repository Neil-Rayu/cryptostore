#!/usr/bin/env python3
"""Instruction-skip fault campaign (threat model 12.4 #3, SR-29).

Builds tests/fi/skip_harness.c with qemu/cryptostore_fi.c at -O2, then for
every instruction of each target function runs the harness under gdb, skips
that one instruction the first time it executes, and classifies the result:

  correct   the right answer
  detected  the fault was detected (fail-secure answer)
  denial    crash or hang (availability only)
  SILENT    a wrong answer that was not detected  <- must never happen

Scenarios:
  jitter    cs_secure_jitter(8): "no fault" is only correct if all 8 delay
            iterations ran (counted with a gdb breakpoint on the nop)
  tag-wrong cs_tag_verdict on a tag differing in byte 0, 16 or 31: an
            accept is SILENT

  tools/fi-skip-campaign.py            exit 1 if any SILENT outcome
  tools/fi-skip-campaign.py --quick    jitter + one tag scenario (demo, ~20 s)
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "build", "fi-skip")
HARNESS = os.path.join(OUT, "harness")
CYCLES = 8


def build():
    os.makedirs(OUT, exist_ok=True)
    subprocess.run(["gcc", "-O2", "-g", "-fno-pie", "-no-pie", "-I", os.path.join(ROOT, "qemu"),
                    os.path.join(ROOT, "tests", "fi", "skip_harness.c"),
                    os.path.join(ROOT, "qemu", "cryptostore_fi.c"), "-o", HARNESS], check=True)


def instructions(func):
    r = subprocess.run(["objdump", "-d", "--no-show-raw-insn", f"--disassemble={func}", HARNESS],
                       capture_output=True, text=True, check=True)
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+(.*)$", line)
        if m:
            out.append((int(m.group(1), 16), m.group(2).strip()))
    return out


def run(args, skip_addr, next_addr, nop_addr):
    """Run the harness under gdb, skipping @skip_addr once. Returns (exit, nops, reached)."""
    py = f"""
import gdb
class Count(gdb.Breakpoint):
    n = 0
    def stop(self):
        Count.n += 1
        return False
if {nop_addr!r}:
    Count("*{nop_addr:#x}" if {nop_addr!r} else "", internal=True)
skip = gdb.Breakpoint("*{skip_addr:#x}", internal=True)
reached = False
try:
    gdb.execute("run {' '.join(args)} > /dev/null 2>&1")
    frame_pc = int(gdb.parse_and_eval("$pc"))
    if frame_pc == {skip_addr}:
        reached = True
        skip.delete()
        gdb.execute("set $pc = {next_addr:#x}")
        gdb.execute("continue")
except gdb.error as e:
    pass
code = gdb.convenience_variable("_exitcode")
sig = gdb.convenience_variable("_siginfo")
print("CAMPAIGN", reached, int(code) if code is not None else -1, Count.n)
"""
    try:
        r = subprocess.run(["gdb", "-nx", "-batch", "-ex", "set pagination off",
                            "-ex", "set confirm off", "-ex", "python\n" + py + "\nend", HARNESS],
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return None, 0, True
    m = re.search(r"CAMPAIGN (True|False) (-?\d+) (\d+)", r.stdout)
    if not m:
        return -1, 0, True          # killed by a signal before an exit code
    return int(m.group(2)), int(m.group(3)), m.group(1) == "True"


def classify(scenario, code, nops):
    if code is None:
        return "denial"             # hang
    if code == -1:
        return "denial"             # crash
    if scenario == "jitter":
        if code == 22:
            return "detected"
        if code == 20:
            return "correct" if nops >= CYCLES else "SILENT"
    else:
        if code == 11:
            return "correct"
        if code == 12:
            return "detected"
        if code == 10:
            return "SILENT"
    return "denial"


def main():
    build()
    nop = next(a for a, i in instructions("jitter_probe") if i == "nop")
    scenarios = [
        ("jitter", ["jitter", str(CYCLES)], ["jitter_probe"]),
        ("tag-wrong", ["tag", "wrong", "0"], ["cs_tag_verdict", "cs_ct_equal", "cs_ct_equal_alt"]),
        ("tag-wrong", ["tag", "wrong", "16"], ["cs_tag_verdict", "cs_ct_equal", "cs_ct_equal_alt"]),
        ("tag-wrong", ["tag", "wrong", "31"], ["cs_tag_verdict", "cs_ct_equal", "cs_ct_equal_alt"]),
    ]
    if "--quick" in sys.argv:          # demo: one scenario per decision
        scenarios = scenarios[:2]
    silent, total = [], {}
    for scenario, args, funcs in scenarios:
        for func in funcs:
            ins = instructions(func)
            counts = {}
            for k, (addr, text) in enumerate(ins[:-1]):
                code, nops, reached = run(args, addr, ins[k + 1][0],
                                          nop if scenario == "jitter" else 0)
                if not reached:
                    counts["not reached"] = counts.get("not reached", 0) + 1
                    continue
                c = classify(scenario, code, nops)
                counts[c] = counts.get(c, 0) + 1
                if c == "SILENT":
                    silent.append(f"{scenario} {' '.join(args[1:])}: {func} +{addr - ins[0][0]:#x}  {text}")
            key = f"{scenario} ({' '.join(args[1:])}) / {func}"
            total[key] = counts
            print(f"  {key:44s} {len(ins) - 1:3d} instructions: " +
                  ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    print()
    if silent:
        print("SILENT wrong outcomes (a single skipped instruction defeated the check):")
        for s in silent:
            print("  " + s)
        return 1
    print("No single-instruction skip produced a silent wrong outcome.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
