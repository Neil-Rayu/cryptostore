# CryptoStore evidence

This directory collects review notes and captured outputs for CryptoStore. The files below explain the driver path, fault-injection defenses, and test artifacts.

| File | What it is |
| --- | --- |
| [driver-flow.md](driver-flow.md) | How guest I/O moves through the driver and QEMU device |
| [fi-evidence.md](fi-evidence.md) | Fault-injection design, the issue found by instruction skipping, and supporting results |
| [evidence/](evidence/) | Raw outputs captured from real runs (see below) |

## Evidence files

| File | Produced by | Shows |
| --- | --- | --- |
| `attacker-view.txt` | `tools/attacker-view.py IMAGE --secret ... --sector ...` | What someone who copies the backing file sees: public header, random ciphertext, known plaintext not found, entropy 8.0000, brute-force cost |
| `fi-disasm-review.txt` | `tools/fi-disasm-review.py` | 28 checks that the FI countermeasures survive `-O2` |
| `disasm-*.s` | same | Optimized x86-64 of the hardened functions |
| `fi-skip-campaign.txt` | `tools/fi-skip-campaign.py` | gdb skips every instruction once: no silent wrong outcome |
| `qtest-fault-samples.txt` | `cryptostore-test` on the test build | Simulated faults detected (F7, F9, jitter), power-cut safety, 1 s timing padding |

## Test status (latest code)

| Suite | Result |
| --- | --- |
| qtest, release build | 20 / 20 (13 hook tests skip by design) |
| qtest, fault-injection build | 33 / 33, plus 2 power-cut tests |
| Guest system test (`scripts/cryptostore-system-test.sh`) | 61 / 61 |
| Crypto unit tests (KATs, timing) | 8 / 8 |
| Disassembly review | 28 / 28 |
| Instruction-skip campaign | 0 silent outcomes |
| Header parser fuzzing | 7M+ inputs, no failure |

The full qtest and guest system suites were last run before the final tag-verdict change. The crypto unit tests, disassembly review, skip campaign, and sampled qtests in `evidence/` were run after that change. This distinction matters when interpreting the totals above.
