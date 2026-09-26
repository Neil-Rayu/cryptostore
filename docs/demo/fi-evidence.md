# Fault-injection hardening: evidence

Threat model Section 10 treats the device as if it were real silicon facing a glitch attacker
(T8): someone who can make the chip skip an instruction or corrupt a value at a chosen moment.
In QEMU this *models* the defence (anyone with host access can read QEMU's memory, O1), but every
countermeasure is implemented and tested three ways:

1. **Fault hooks** (test builds only): force each check to go wrong and confirm the device notices.
2. **Disassembly review:** confirm the optimizer did not delete the redundant checks.
3. **Instruction-skip campaign:** run the decisions under gdb, skip each instruction once, and
   confirm that no single skip produces a silently wrong answer.

## The design rule: keys protect, branches only back them up

Skipping the password check does not help an attacker: a wrong password derives a wrong key,
which unwraps garbage. So hardening is focused on the few checks where a single glitch would
win something: the failure counter (F1), backoff (F2), key wipe (F3), lock state (F4),
KDF strength (F5), bounds (F6), AES output (F7), recovery release-once (F8), tag compare (F9).

| Countermeasure | Where |
| --- | --- |
| Fail-secure encodings: states are 32-bit constants at least 14 bits apart; LOCKED by default | `qemu/cryptostore_fi.h` |
| Each check evaluated twice by different code, re-checked just before the action | `qemu/cryptostore.c` |
| CSPRNG-seeded `secure_jitter` delay before control-plane checks | `cs_jitter()` |
| Control-flow step counter across UNLOCK | `cs_auth_result()` |
| Verify after every write and wipe | `cs_meta_write()`, `cs_zeroize()` |
| AES computed twice (encrypt, then decrypt and compare) | `cs_cmd_data()` |
| Any detection: zeroize, LOCKED_OUT, count a failure, reveal nothing | `cs_fault()` |

## 1. Your `secure_jitter`, ported to C, survives `-O2`

`evidence/disasm-cs_jitter.isra.0.s` (x86-64, release flags, `-O2`):

```asm
bad:  mov  %edx,0x10(%rsp)        ; limit = cycles   (volatile copy 1, in memory)
bb1:  mov  %edx,0x14(%rsp)        ; saved = cycles   (volatile copy 2)
bc0:  nop                         ; asm("nop"): loop cannot be fused or removed
bc1:  mov  0x10(%rsp),%eax        ; read limit
bc5:  sub  $0x1,%eax
bc8:  mov  %eax,0x10(%rsp)        ; write limit
bcc:  mov  0x10(%rsp),%eax        ; re-read for the loop condition
bd2:  jne  bc0                    ; loop back
bd4:  mov  0x10(%rsp),%eax        ; check 1: counter must be 0
bdc:  je   c00
c00:  mov  0x14(%rsp),%eax        ; check 2: saved copy == cycles (%edx)
c04:  cmp  %edx,%eax
c08:  mov  0x10(%rsp),%eax        ; check 3: re-read counter, must still be 0
c0e:  sete %cl                    ; result: 1 only if all three checks passed
```

This has the same structure as the ARM Thumb listing in `docs/reference/secure_jitter.md`: every
volatile access stays a real memory access, and all three checks are present. The delay length
comes from `qcrypto_random_bytes` on every call.

## 2. The skip campaign found a real bug, and the fix closed it

The F9 tag decision compares the computed tag with the stored one twice, using two different
constant-time routines, and returns a fail-secure constant.

**First version:** the compiler produced branchless code that *selected* between FS_TRUE and
FS_FALSE with one `sbb` instruction. The campaign reported:

```
SILENT wrong outcomes (a single skipped instruction defeated the check):
  tag-wrong wrong 0: cs_tag_verdict +0x26  cmp    $0x1,%dl
  tag-wrong wrong 0: cs_tag_verdict +0x29  sbb    %eax,%eax
```

Skipping either instruction left a zero register, and the arithmetic that follows turned 0 into
exactly FS_TRUE: **a wrong password accepted by one glitch.** (The keys would still have
protected the data, since a wrong key unwraps garbage and the header MAC then fails, but the
check itself was broken.)

**Fix:** each compare contributes its own mask; FS_TRUE needs both.
`r = FS_FALSE ^ (K1 & -match1) ^ (K2 & -match2)`, with `K1 ^ K2 = FS_FALSE ^ FS_TRUE`.

`evidence/disasm-cs_tag_verdict.s`:
```asm
call cs_ct_equal                  ; compare 1 (forward, XOR/OR)
call cs_ct_equal_alt              ; compare 2 (backward, SUB/OR)
neg  %edx
neg  %eax
and  $0xcbef3fcd,%edx             ; K2 if compare 2 matched
and  $0xf6d7fbb3,%eax             ; K1 if compare 1 matched
xor  $0xb5afe1c7,%eax             ; start from FS_FALSE
```

One compare alone gives a value 23–24 bits away from FS_TRUE, which callers treat as a fault.
Re-running the campaign (`evidence/fi-skip-campaign.txt`):

```
jitter (8) / jitter_probe          28 instructions: 17 correct, 1 denial, 7 detected, 3 not reached
tag-wrong (wrong 0) / cs_tag_verdict  17 instructions: 11 correct, 1 denial, 5 detected
tag-wrong (wrong 0) / cs_ct_equal     16 instructions: 12 correct, 4 detected
...
No single-instruction skip produced a silent wrong outcome.
```

"Denial" means a crash or hang: an availability failure, never a wrong answer. For the jitter,
"correct" requires that all 8 delay iterations really ran (counted by a gdb breakpoint on the `nop`).

## 3. The review also caught the optimizer merging "different" checks

The F5 check (KDF iterations within bounds) is evaluated twice. At `-O2`, GCC rewrote the first
form (`iters >= floor && iters <= ceiling`) into exactly the second form
(`iters - floor <= span`), so the two "different code paths" became identical instructions.
The second path now compares against bounds held in `volatile` memory, and the disassembly shows
two genuinely different sequences (`evidence/disasm-cs_check_kdf_params.s`):

```asm
movl $0x927c0,0x8(%rsp)          ; path B: floor stored in volatile memory...
movl $0x17d78401,0xc(%rsp)       ;         ...and ceiling + 1
cmp  %edx,%eax                   ;         compared against the re-read value
call cs_jitter                   ; jitter between the two evaluations
sub  $0x927c0,%r14d              ; path A: immediates, value loaded before the jitter
cmp  $0x17ce5c40,%r14d
```

`tools/fi-disasm-review.py` checks all of this automatically: 28 checks, and a diff against the
reviewed baseline in `tests/fi/baseline/` on every change (threat model 12.3).

## 4. Every simulated fault is detected (fault hooks)

The test build (`TEST_BUILD=1 scripts/build-qemu.sh`) adds an `x-fault` property. Each F-target
has a hook that makes its first check go wrong. Every case ends the same way: `ERR_FAULT`, keys
zeroized, `LOCKED_OUT`, counted, persisted across restart, and a host log line that never says
which check fired.

| Hook | Simulated glitch | Caught by |
| --- | --- | --- |
| f1 | skip the failure-counter write | read-back after write |
| f2 | backoff check says "allowed" | second evaluation (different formula) |
| f3 | skip the key wipe | verify-after-wipe |
| f4 | lock check says "unlocked" | second lock check before data access |
| f5 | corrupt the loaded iteration count | second bounds check |
| f6 | bounds check passes an out-of-range sector | per-sector re-check |
| f7 | corrupt one AES output byte | encrypt-then-decrypt comparison |
| f8 | recovery release-once check glitched | second representation (release count) |
| f9 | tag compare says "match" | second compare |
| cfi | skip a step of the unlock sequence | control-flow step counter |
| jitter | corrupt the delay loop | jitter's own three checks |

Sample run: `evidence/qtest-fault-samples.txt`. Full set:
```sh
cd build/qemu-src/build-test
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/cryptostore-test --tap -p /x86_64/cryptostore/hooks
```

## Regenerate everything
```sh
python3 tools/fi-disasm-review.py        # -O2 disassembly review
python3 tools/fi-skip-campaign.py        # full campaign (~1 min); --quick for a demo
```
