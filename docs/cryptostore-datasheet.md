# pcie-cryptostore: datasheet and backing-file format (v1)

Status: **draft specification**, 2026-09-26. The register and image-format details document the
CryptoStore design; the review items below identify decisions that still need confirmation.
Requirements (SR-xx), vectors (V-xx, F-x) and surfaces (S-xx) refer to
[threat-model.md](threat-model.md). This document is the 12.1 "before coding" deliverable:
register map, command × state matrix (SR-31), backing-file format with its validation
order, and the traceability matrices.

## 0. Review items that need your decision

The first two change the design; the rest confirm details I had to pin down.

| # | Item | Proposal |
| --- | --- | --- |
| R1 | **SR-32 is not crash-safe as written.** The header MAC covers the keyslot table, so every slot write (PASSWD, ENROLL_RECOVERY) invalidates it until a second write, to a different sector, updates the MAC. A power cut between the two leaves a correct password with a failing MAC, which B5 reports as `ERR_INTEGRITY` and bricks the image to ERROR. | **Make the header MAC cover only the immutable header fields** (0x0000–0x00FF: magic, version, UUID, capacity, cipher ID), written once at FORMAT. Slots stay protected by their own tags, which bind UUID, slot index, KDF parameters, salt, IV and wrapped DEK. Every slot change is then a single-sector write, and SR-32 holds trivially. **Lost:** the MAC no longer detects a single slot rolled back to an older copy of the same image, which is the same class as whole-file rollback (V6, V7, SR-17). **Alternative:** a LUKS2-style double header with sequence numbers: more format and code, same guarantee plus slot-set integrity. |
| R2 | **Guest root can unlock through recovery.** With Option B and a guest-only "arm", anything with guest root (T3) can arm, issue RECOVER, set a new password and read the data, all without knowing a secret. That breaks "T3 cannot bypass lockout". | **Require a host presence event as well:** a `host-armed` property on `pcie-cryptorecovery` that only the host can set (`qom-set`), cleared after one release or after 120 s. This is the "physical-presence-like host event" from Section 9. Guest arm remains required, so the guest still has to act. **Alternative:** accept it and document that the recovery device should only be attached (hot-plugged) when recovery is needed. |
| R3 | The recovery device's drive holds the recovery key in plaintext. T1 with both image files has everything. | Accept and document: that file *is* the recovery key (the analogue of the paper copy) and must be stored apart from the storage image. Wrapping it under a host `-object secret` only moves the secret to the host. |
| R4 | The forced password change after RECOVER needs its own state. | Add **RECOVERED**: DEK loaded, but only `PASSWD` (new password only) and `LOCK` are accepted; data commands return `ERR_PASSWD_REQUIRED`. Add it to threat-model 11.3. |
| R5 | SR-09 conflicts with READ. "All windows zeroed after each command completes" would erase a READ's output before the driver can copy it out. | Reword SR-09: the password windows are cleared when every command completes; the data window keeps READ output until the next doorbell, and is cleared on WRITE completion, LOCK, reset, FLR and any exit from UNLOCKED (§3.3). |
| R6 | The layout table puts a KDF ID in the header (0x0024), but the two slot types use different KDFs. | The KDF ID moves into each keyslot. 0x0024 holds the cipher ID plus a reserved field. |
| R7 | The failure record has no protection against torn writes or naive edits. | Store the counter together with its bitwise complement. A mismatch means LOCKED_OUT (fail secure), recoverable with the offline tool (B8). |
| R8 | A wrong *old* password in PASSWD is an online guess. | It counts exactly like UNLOCK: backoff, counter, and LOCKED_OUT at N, which zeroizes the DEK even though the device was UNLOCKED. |
| R9 | SR-18 `rekey` has no milestone, and 11.5 says rekey needs v2 crash safety. | Opcode reserved; returns `ERR_UNSUPPORTED` in v1. It gets its own milestone (M4b) after password change works. |
| R10 | SR-05's "timing test over 1,000 attempts" conflicts with N = 10. | Split it: a unit test times the verification routine 1,000 times with right and wrong passwords (no counter involved), and a qtest checks the 1 s padding across a few attempts with the offline counter reset between batches. |
| R11 | PBKDF2 bounds. | Floor 600,000 iterations (the OWASP figure for PBKDF2-HMAC-SHA256). FORMAT uses max(floor, iterations calibrated to 0.5 s). A ceiling stops a tampered slot with 2³² iterations from hanging UNLOCK for hours before the tag check fails (new V25). I'll set the ceiling to about 40 s of work once calibration runs on this host. |
| R12 | M1 scope. The gate says the header is "written and re-parsed". | The writer is the device's FORMAT, so M1 includes FORMAT (KDF worker, keyslot wrap, random fill, recovery slot left for M5). M2 then adds UNLOCK, LOCK, the counter and backoff. |
| R13 | 12.1 needs every rule to trace to a requirement. The decisions added rules without SR IDs. | Add SR-35 to SR-41 and V24, V25 (§12.3). Once you approve, I'll fold them into the threat model. |

## 1. Identity

| Field | pcie-cryptostore | pcie-cryptorecovery (draft, §11) |
| --- | --- | --- |
| Vendor:Device | `1af4:10f1` | `1af4:10f2` |
| Class | `0x018000` mass storage, other | `0x108000` encryption controller, other |
| Revision | `0x01` | `0x01` |
| BAR0 | 8 KiB, 64-bit, non-prefetchable: registers and windows | 4 KiB: registers |
| BAR2 | 4 KiB MSI-X table and PBA | none |
| Capabilities | PM, MSI (1 vector), PCIe v2 Endpoint with FLR, MSI-X (1 vector) | PM, PCIe v2 Endpoint with FLR |
| Migration | unmigratable vmsd (SR-12) | unmigratable vmsd (SR-12) |

The IDs use QEMU's experimental device-ID range. CryptoStore uses standard PCIe endpoint capabilities and QEMU's PCI core for configuration space, FLR, and interrupt delivery.

QEMU command line (the backing images live in `~/cryptostore-images/`, never in the 9p share, SR-30):

```
-drive if=none,id=cs0,file=~/cryptostore-images/disk0.img,format=raw
-device pcie-root-port,id=rp1,chassis=1,slot=1
-device pcie-cryptostore,bus=rp1,id=cstore0,drive=cs0[,recovery=rec0]
```

## 2. States

The STATE register reports one of these values. Internally the device uses fail-secure multi-bit encodings (SR-21); the register values below are only a guest-visible view.

| STATE | Value | Meaning | DEK in memory |
| --- | --- | --- | --- |
| UNFORMATTED | 1 | Header region (0x0000–0x0FFF) entirely zero | no |
| LOCKED | 2 | Valid header, not unlocked | no |
| UNLOCKED | 3 | Data commands allowed | yes |
| RECOVERED | 4 | Unlocked by RECOVER; only PASSWD and LOCK allowed (R4) | yes |
| LOCKED_OUT | 5 | Failure counter ≥ N, fault detected, or corrupt failure record; only RECOVER leaves it | no |
| ERROR | 6 | Malformed header, backing I/O error, or `ERR_INTEGRITY`; needs re-attach | no |

**BUSY** is `STATUS.BUSY`, orthogonal to STATE: a command is in progress, and STATE shows the state it started in until it completes.

**Reset and FLR** leave UNFORMATTED, LOCKED, LOCKED_OUT and ERROR unchanged. They move UNLOCKED, RECOVERED and BUSY-from-LOCKED to LOCKED (§8). The parsed header and failure record stay in memory: only the device writes the image while it is attached (SR-30), so no re-read is needed.

## 3. BAR0 register map

All registers are 32-bit and little-endian, and must be accessed with aligned 32-bit loads and stores. Any other access to a register is ignored (reads return 0) and logged as a guest error. The windows (§3.2, §3.3) accept 1-, 2-, 4- and 8-byte accesses.

### 3.1 Registers

| Offset | Name | Access | Reset | Description |
| --- | --- | --- | --- | --- |
| 0x000 | ID | RO | `0x43525354` | Magic "CRST"; the driver refuses to bind otherwise |
| 0x004 | VERSION | RO | `0x00010000` | Interface version, `major << 16 \| minor` |
| 0x008 | CAPS | RO | see text | bit 0 RECOVERY: recovery device linked and present. bit 1 DMA: 0 in v1. bit 2 FAULT_HOOKS: 1 only in test builds (SR-29) |
| 0x00C | SECTOR_SIZE | RO | 512 | Logical sector size in bytes |
| 0x010 | MAX_SECTORS | RO | 8 | Largest COUNT per READ or WRITE |
| 0x014 | PW_MAX | RO | 128 | Largest PW_LEN / PW2_LEN |
| 0x018 | CAPACITY_LO | RO | 0 | Capacity in sectors, bits 31:0. **Reads 0 unless UNLOCKED** (B4) |
| 0x01C | CAPACITY_HI | RO | 0 | Capacity, bits 63:32. Reads 0 unless UNLOCKED |
| 0x020 | STATE | RO | from image | §2 |
| 0x024 | STATUS | RO | 0 | bit 0 BUSY |
| 0x028 | RESULT | RO | 0 | Result code of the last completed command (§5) |
| 0x02C | RESULT_AUX | RO | 0 | `ERR_BACKOFF`: whole seconds remaining. Otherwise 0 |
| 0x030 | FAIL_COUNT | RO | from image | Persisted failure counter (public, A6). 0 when UNFORMATTED |
| 0x034 | SLOT_MAP | RO | from image | bits 7:0: keyslot i active. bit 8: a recovery slot exists (public, 11.9) |
| 0x038 | CMD | WO | – | Doorbell: writing an opcode starts a command (§4) |
| 0x040 | LBA_LO | RW | 0 | First sector, bits 31:0 |
| 0x044 | LBA_HI | RW | 0 | First sector, bits 63:32 |
| 0x048 | COUNT | RW | 0 | Sectors to transfer, 1..MAX_SECTORS |
| 0x04C | PW_LEN | RW | 0 | Bytes of PW_A in use, 0..PW_MAX |
| 0x050 | PW2_LEN | RW | 0 | Bytes of PW_B in use, 0..PW_MAX |
| 0x060 | INT_STATUS | RO | 0 | bit 0 CMD_DONE |
| 0x064 | INT_ENABLE | RW | 0 | Enabled causes |
| 0x068 | INT_ACK | WO | – | Write 1 to clear INT_STATUS bits |
| 0x080–0x08C | UUID0..3 | RO | from image | Image UUID (public); 0 when UNFORMATTED |

Writes to LBA, COUNT, PW_LEN and PW2_LEN while BUSY are ignored and logged. Unmapped offsets read 0 and are logged. The device uses MSI-X vector 0 when available, then MSI, then level-triggered INTx. MSI and MSI-X are raised when an enabled cause becomes pending.

### 3.2 Password windows (write-only)

| Offset | Name | Used by |
| --- | --- | --- |
| 0x100–0x17F | PW_A | FORMAT (new password), UNLOCK, PASSWD (old password) |
| 0x180–0x1FF | PW_B | PASSWD (new password) |

- Reads always return 0 (SR-09). Writes while BUSY are ignored.
- The password is raw bytes; the length comes from PW_LEN / PW2_LEN (D7).
- Both windows are zeroed when **any** command completes (including failures), on LOCK, reset and FLR, and at the moment a KDF job is dispatched (the job holds its own copy).
- Traces record offset and size only, never values (SR-15).

### 3.3 Data window

| Offset | Name |
| --- | --- |
| 0x1000–0x1FFF | DATA (4 KiB = MAX_SECTORS × 512) |

- Readable and writable only in UNLOCKED and not BUSY. In every other case reads return 0 and writes are ignored (SR-01).
- READ leaves the plaintext in DATA[0 .. COUNT×512) and zeroes the rest. The output stays until the next doorbell.
- Any doorbell except WRITE zeroes the whole window before the command starts. WRITE consumes DATA[0 .. COUNT×512) and zeroes the whole window when it completes.
- LOCK, reset, FLR and every exit from UNLOCKED zero the window (proposed SR-09 wording, R5).
- Traces record offset and size only.

## 4. Commands

A command is started by writing its opcode to CMD. The device sets `STATUS.BUSY`, and on completion writes RESULT (and RESULT_AUX), clears BUSY and raises CMD_DONE.

**A doorbell while BUSY** is ignored (no completion, logged), **except LOCK**, which acts immediately (§8). The single-command model matches 11.6.

| Opcode | Command | Inputs | Effect | Milestone |
| --- | --- | --- | --- | --- |
| 0x01 | FORMAT | PW_A, PW_LEN | Create UUID, DEK, password slot and (if the recovery device is present) recovery slot; fill the data area with random bytes; commit the header. Ends LOCKED | M1 (recovery slot: M5) |
| 0x02 | UNLOCK | PW_A, PW_LEN | Verify the password against the password slots. Ends UNLOCKED | M2 |
| 0x03 | LOCK | – | Cancel or drain in-flight work, zeroize, verify zero. Valid in every state | M2 |
| 0x04 | READ | LBA, COUNT | Decrypt COUNT sectors into DATA | M3 |
| 0x05 | WRITE | LBA, COUNT, DATA | Encrypt DATA into COUNT sectors | M3 |
| 0x06 | FLUSH | – | Flush the backing file (the block layer's flush / FUA) | M3 |
| 0x07 | PASSWD | PW_A (old), PW_B (new) | UNLOCKED: verify the old password, write a new slot, retire the old one. RECOVERED: PW_B only | M4 |
| 0x08 | RECOVER | – | Get the recovery key from the linked recovery device and open the recovery slot. Ends RECOVERED | M5 |
| 0x09 | ENROLL_RECOVERY | – | Create a recovery key and slot and deliver the key to the recovery device | M5 |
| 0x0A | REKEY | – | Reserved; `ERR_UNSUPPORTED` in v1 (R9) | M4b |
| other | – | – | `ERR_INVALID_CMD` | – |

## 5. Result codes

| Code | Name | Meaning |
| --- | --- | --- |
| 0x00 | OK | Success |
| 0x01 | ERR_INVALID_CMD | Unknown opcode |
| 0x02 | ERR_STATE | Command not valid in the current state (non-data commands) |
| 0x03 | ERR_LOCKED | Data command without an unlocked DEK (SR-01) |
| 0x04 | ERR_AUTH | Password or recovery key wrong. The one generic authentication failure (11.4) |
| 0x05 | ERR_BACKOFF | Attempt refused without running the KDF; RESULT_AUX = seconds remaining |
| 0x06 | ERR_LOCKED_OUT | UNLOCK or PASSWD attempted in LOCKED_OUT; RECOVER is required |
| 0x07 | ERR_INTEGRITY | Correct password, but the header MAC failed; the device is now ERROR (B5) |
| 0x08 | ERR_NO_RECOVERY | No recovery device, no link, or no recovery slot |
| 0x09 | ERR_NOT_ARMED | Recovery device present but not armed, or it already released its key this boot |
| 0x0A | ERR_RANGE | LBA/COUNT out of range, bad PW_LEN / PW2_LEN, or image too small to FORMAT |
| 0x0B | ERR_IO | Backing-file I/O error on the data path (state unchanged) |
| 0x0C | ERR_PASSWD_REQUIRED | Data command in RECOVERED (R4) |
| 0x0D | ERR_FAULT | A fault was detected; the device is now LOCKED_OUT. Says nothing about which check fired (SR-27) |
| 0x0E | ERR_UNSUPPORTED | Reserved command (REKEY) |

A metadata I/O error (the failure record or a slot write fails, or its read-back mismatches) is not `ERR_IO`: the device cannot keep its promises, so it enters ERROR (fail secure) and the command returns `ERR_FAULT`.

## 6. Command × state matrix (SR-31)

Rows are commands; columns are the state at the doorbell. "→ X" is the state afterwards. Codes in a cell are the possible outcomes.

| Command | UNFORMATTED | LOCKED | UNLOCKED | RECOVERED | LOCKED_OUT | ERROR |
| --- | --- | --- | --- | --- | --- | --- |
| FORMAT | OK → LOCKED; ERR_RANGE (PW_LEN 0, image too small); ERR_FAULT → ERROR | ERR_STATE | ERR_STATE | ERR_STATE | ERR_STATE | ERR_STATE |
| UNLOCK | ERR_STATE | OK → UNLOCKED; ERR_AUTH (→ LOCKED_OUT at N); ERR_BACKOFF; ERR_RANGE; ERR_INTEGRITY → ERROR; ERR_FAULT → LOCKED_OUT or ERROR | ERR_STATE | ERR_STATE | ERR_LOCKED_OUT | ERR_STATE |
| LOCK | OK (no change) | OK (no change) | OK → LOCKED | OK → LOCKED | OK (no change) | OK (no change) |
| READ, WRITE, FLUSH | ERR_LOCKED | ERR_LOCKED | OK; ERR_RANGE; ERR_IO; ERR_FAULT → LOCKED_OUT | ERR_PASSWD_REQUIRED | ERR_LOCKED | ERR_LOCKED |
| PASSWD | ERR_STATE | ERR_STATE | OK; ERR_AUTH (counted, R8; → LOCKED_OUT at N); ERR_BACKOFF; ERR_RANGE; ERR_FAULT | OK → UNLOCKED (PW_B only); ERR_RANGE; ERR_FAULT | ERR_LOCKED_OUT | ERR_STATE |
| RECOVER | ERR_STATE | OK → RECOVERED; ERR_NO_RECOVERY; ERR_NOT_ARMED; ERR_AUTH; ERR_BACKOFF; ERR_INTEGRITY → ERROR | ERR_STATE | ERR_STATE | OK → RECOVERED; ERR_NO_RECOVERY; ERR_NOT_ARMED; ERR_AUTH; ERR_INTEGRITY → ERROR (no backoff; release-once limits attempts) | ERR_STATE |
| ENROLL_RECOVERY | ERR_STATE | ERR_STATE | OK; ERR_NO_RECOVERY; ERR_STATE (recovery slot exists); ERR_FAULT | ERR_STATE | ERR_STATE | ERR_STATE |
| REKEY | ERR_UNSUPPORTED | ERR_UNSUPPORTED | ERR_UNSUPPORTED | ERR_UNSUPPORTED | ERR_UNSUPPORTED | ERR_UNSUPPORTED |
| unknown | ERR_INVALID_CMD in every state | | | | | |
| any doorbell while BUSY | Ignored (no completion, logged), except LOCK (§8) | | | | | |

Commands that fail with ERR_STATE, ERR_LOCKED, ERR_RANGE, ERR_INVALID_CMD, ERR_UNSUPPORTED or ERR_BACKOFF change nothing and complete immediately. Every command clears the password windows on completion.

## 7. Attempt counting, backoff and timing

These rules apply to every **attempt**: UNLOCK, PASSWD with an old password, and RECOVER. FORMAT and PASSWD-from-RECOVERED are not attempts.

Let `f` be the persisted failure count and `t` the persisted last-attempt time (host wall clock, `QEMU_CLOCK_HOST`, milliseconds since the Unix epoch).

1. **Parameters.** PW_LEN (and PW2_LEN for PASSWD) must be 1..128. Otherwise `ERR_RANGE`, not counted.
2. **Backoff** (skipped for RECOVER in LOCKED_OUT). The required wait is `w(f) = 0` for `f < 3`, and `min(2^(f−3), 300)` seconds otherwise. If `now < t + w(f)` → `ERR_BACKOFF` immediately, with RESULT_AUX = remaining seconds rounded up. No KDF, no count. If the host clock went backwards (`now < t`), the full `w(f)` is required.
3. **Count first** (SR-04, F1). Write `{f+1, ~(f+1), now}` to the failure record, flush, read back and compare. Any failure → ERROR, `ERR_FAULT`. Only then does the KDF run.
4. **KDF job** in a worker thread (B3). UNLOCK and PASSWD try every active password slot in a fixed order with no early exit, so the time taken doesn't depend on which slot matches.
5. **Verify.** Tag compare in constant time, then unwrap, then check the header MAC (§10.4).
6. **Outcome.** On success the record becomes `{0, ~0, 0}` (flushed). On failure it stays incremented; if `f+1 ≥ N` the device zeroizes and enters LOCKED_OUT.
7. **Padding** (SR-05). The completion interrupt is raised at `start + max(1 s, elapsed)` rounded up to a whole second. `ERR_BACKOFF` and `ERR_RANGE` return immediately.

| Failures `f` | 0–2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Wait before next attempt | none | 1 s | 2 s | 4 s | 8 s | 16 s | 32 s | 64 s | LOCKED_OUT |

## 8. LOCK, reset, FLR and unplug

All four run the same path; they differ only in whether registers and interrupt configuration are also reset.

1. If a KDF job is running, mark it cancelled and wipe the device's password copy now. The worker wipes its buffers and its result is discarded (B3).
2. If backing-file I/O is in flight, wait for it to finish, then discard the result (SR-33). A FORMAT header commit is never interrupted part-way.
3. Zeroize the DEK, the derived keys, both password windows and the data window. Read each back and verify it is zero (SR-25).
4. State: UNLOCKED, RECOVERED and BUSY-from-LOCKED → LOCKED. BUSY-from-UNFORMATTED → UNFORMATTED if the header was not committed, else LOCKED. BUSY-from-LOCKED_OUT → LOCKED_OUT. Others unchanged.
5. LOCK completes with OK and raises CMD_DONE. A command cancelled by LOCK never completes.
6. Reset and FLR also return every register to its reset value, with interrupts disabled. Unplug (unrealize) runs steps 1–3 and releases the drive.

## 9. Invariants the tests check

- The DEK exists only in UNLOCKED and RECOVERED, and during a FORMAT before commit.
- DATA reads return 0 in every state except UNLOCKED; the password windows always read 0.
- No command completes after a LOCK, reset or FLR that cancelled it.
- The failure record on disk is updated and verified before every KDF run.
- No trace line or log message contains password bytes, key bytes, salts, IVs, tags or plaintext (SR-15).

## 10. Backing-file format

All integers are little-endian. The file must be at least 0x1000 bytes. Recommended format is raw (`qemu-img create -f raw` or `truncate`).

### 10.1 Layout

| Offset | Size | Field | Protected by |
| --- | --- | --- | --- |
| 0x0000 | 8 | Magic `CRYPTOST` | Header MAC |
| 0x0008 | 4 | Format version = 1 | Header MAC |
| 0x000C | 16 | Image UUID (random) | Header MAC and every slot tag |
| 0x001C | 8 | Capacity in 512-byte sectors | Header MAC |
| 0x0024 | 2 | Cipher ID: 1 = AES-256-XTS, plain64 tweak, 512-byte sectors | Header MAC |
| 0x0026 | 2 | Reserved, 0 (was "KDF ID", moved into slots, R6) | Header MAC |
| 0x0028 | 216 | Reserved, 0 | Header MAC |
| 0x0100 | 8 × 256 | Keyslots 0–7 (§10.2) | Each slot's tag |
| 0x0900 | 32 | Header MAC over 0x0000–0x00FF (R1) | – |
| 0x0920 | 1504 | Reserved, 0 | Checked zero at parse |
| 0x0F00 | 16 | Failure record (§10.3) | **Not** MAC'd (threat model §8) |
| 0x0F10 | 240 | Reserved, 0 | Checked zero at parse |
| 0x1000 | capacity × 512 | Encrypted data; sector i at 0x1000 + 512·i | XTS only (SR-08) |

Each keyslot lies inside one 512-byte sector, and so does the failure record, so every metadata update is a single-sector write.

### 10.2 Keyslot (256 bytes)

| Offset | Size | Field |
| --- | --- | --- |
| +0x00 | 4 | State: `0x00000000` INACTIVE (all 256 bytes must be zero) or `0x5A3CA5C3` ACTIVE. Anything else is malformed |
| +0x04 | 2 | Type: 1 PASSWORD, 2 RECOVERY |
| +0x06 | 2 | KDF ID: 1 PBKDF2-HMAC-SHA256 (PASSWORD only), 2 HKDF-SHA256 (RECOVERY only) |
| +0x08 | 4 | PBKDF2 iterations (PASSWORD: floor ≤ n ≤ ceiling, R11); 0 for RECOVERY |
| +0x0C | 4 | Reserved, 0 |
| +0x10 | 32 | Salt (fresh on every wrap) |
| +0x30 | 16 | CTR IV (fresh on every wrap, B6) |
| +0x40 | 64 | Wrapped DEK |
| +0x80 | 32 | Tag |
| +0xA0 | 96 | Reserved, 0 |

### 10.3 Failure record (16 bytes at 0x0F00)

| Offset | Size | Field |
| --- | --- | --- |
| +0x0 | 4 | Failure count `f` |
| +0x4 | 4 | `~f` (bitwise complement, R7) |
| +0x8 | 8 | Last attempt time, ms since the Unix epoch (host wall clock) |

### 10.4 Crypto constructions

`‖` is concatenation; `LE32`/`LE64` are little-endian encodings; `L(x)` is the label `"cryptostore v1 " ‖ x`.

```
DEK            = 64 random bytes; regenerated if its two halves are equal
Data sector i  = AES-256-XTS(key = DEK, tweak = LE64(i) ‖ 0^8)   # DEK[0:32] data key, DEK[32:64] tweak key

PASSWORD slot:  KEK = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)   # 32 bytes, 11.4
RECOVERY slot:  KEK = HKDF-Extract(salt, recovery_key)                     # recovery_key = 32 random bytes
Both:           wrap_key = HKDF-Expand(KEK, L("wrap-key"), 32)
                tag_key  = HKDF-Expand(KEK, L("tag-key"), 32)
                wrapped  = DEK XOR AES-256-CTR-keystream(wrap_key, IV)     # 64 bytes
                tag      = HMAC-SHA256(tag_key, UUID ‖ LE32(slot index) ‖ slot[+0x00 .. +0x80))

Header MAC:     hmk = HKDF(ikm = DEK, salt = UUID, info = L("header-mac"), 32)
                mac = HMAC-SHA256(hmk, file[0x0000 .. 0x0100))
```

Unwrap order: derive keys, verify the tag (constant time), and only then decrypt (11.4). HKDF is implemented over `qcrypto_hmac_*` and checked against RFC 5869 test cases 1–3.

### 10.5 Validation order at realize

The crypto self-tests run first (SR-34). If they fail, realize fails with an error and the device does not attach. Then:

1. Open the drive writable, with image locking (SR-30). Failure → realize error.
2. File size < 0x1000 → ERROR.
3. Header region 0x0000–0x0FFF entirely zero → **UNFORMATTED**. Stop.
4. Magic ≠ `CRYPTOST` → ERROR. (A non-zero header is never treated as blank, C5.)
5. Version ≠ 1 → ERROR.
6. Any reserved field non-zero (0x0026–0x00FF, 0x0920–0x0EFF, 0x0F10–0x0FFF) → ERROR.
7. Cipher ID ≠ 1 → ERROR.
8. Capacity: must satisfy 2048 ≤ capacity ≤ 2³², and capacity ≤ (file size − 0x1000) / 512, computed without overflow. Otherwise ERROR. Parsed only; not reported until the header MAC verifies (B4).
9. Each keyslot: INACTIVE ⇒ all zero. ACTIVE ⇒ valid type, KDF ID matching the type, iterations in range for PBKDF2 and 0 for HKDF, reserved bytes zero. Then at least one active PASSWORD slot and at most one RECOVERY slot. Any violation → ERROR.
10. Failure record: `f ≠ ~(complement)` → LOCKED_OUT (R7). `f ≥ 10` → LOCKED_OUT. Otherwise **LOCKED**.

The header MAC cannot be checked here because its key comes from the DEK; it is checked on every UNLOCK and RECOVER.

The parser is a standalone C file with no QEMU dependencies (D3). It is built into QEMU and into a libFuzzer harness, and it must return one of UNFORMATTED / valid / malformed for any 4 KiB input and any file size, without crashing (SR-16).

### 10.6 Write ordering (crash consistency)

Every step ends with a flush. "Verify" means read back and compare (SR-25).

| Operation | Order | State after a power cut at any point |
| --- | --- | --- |
| FORMAT | 1. Random-fill the data area. 2. Deliver the recovery key, if present (M5). 3. Write the keyslot sectors, the MAC sector (the MAC is computed over the sector-0 fields before anything is written) and the failure record. 4. Write sector 0 (magic, UUID, capacity, cipher) last. | Before step 3: header still zero → UNFORMATTED. Between 3 and 4: non-zero but no magic → ERROR; recover by wiping the header with `cryptostore_image.py` (T5). After 4: complete. |
| Attempt counting | Write the record, then verify, then run the KDF. | The attempt is counted (fail secure). |
| PASSWD (with R1) | 1. Write the new slot into a free index, then verify. 2. Zero the old password slot, then verify. | After 1: both old and new passwords work until the next PASSWD. After 2: only the new one. Never zero working slots (SR-32). |
| ENROLL_RECOVERY | 1. Deliver the key to the recovery device (it flushes). 2. Write the recovery slot, then verify. | After 1: the recovery device holds an unused key; harmless, and a later enroll replaces it. |

Without R1, PASSWD and ENROLL_RECOVERY would also need a header MAC rewrite in a different sector, which is exactly the crash window R1 removes.

### 10.7 Constants

| Constant | Value | Source |
| --- | --- | --- |
| N (LOCKED_OUT threshold) | 10 | 11.10 |
| Free failures | 3 | 11.10 |
| Backoff | 2^(f−3) s, capped at 300 s | 11.10 |
| Response padding | 1 s, rounded up to a whole second | SR-05, D8 |
| PBKDF2 iterations | floor 600,000; calibrated to ≥ 0.5 s at FORMAT and PASSWD; ceiling set after calibration | SR-03, R11 |
| Password length | 1..128 bytes | D7 |
| Capacity | 2048 sectors (1 MiB) to 2³² sectors | §10.5 |
| Salt / IV / tag / DEK | 32 / 16 / 32 / 64 bytes | Section 8 |

## 11. pcie-cryptorecovery (draft; finalized before M5)

- **Storage.** Its own drive, at least 512 bytes: magic `CRYPTORC`, version 1, state (EMPTY / KEY), bound image UUID, 32-byte recovery key; everything else zero. This file is the recovery key (R3).
- **Registers.** ID `"CRRC"`, VERSION, STATUS (bit 0 KEY_PRESENT, bit 1 ARMED, bit 2 RELEASED, bit 3 HOST_ARMED if R2 is accepted), UUID0..3 (bound UUID), CMD (1 ARM, 2 DISARM), RESULT. No interrupts; every command completes immediately.
- **Link.** `pcie-cryptostore` has a `recovery` link property naming the recovery device. The storage device calls it directly to store a key (FORMAT, ENROLL_RECOVERY) or fetch it (RECOVER).
- **Release once per boot (F8).** The key is released only when ARMED (and HOST_ARMED, R2), at most once until the next machine reset. The recovery device's own FLR does not clear RELEASED, so a guest cannot re-arm it by resetting it. ARMED clears on release, DISARM and machine reset.
- **Absent-safe.** No link, or the linked device is unplugged → CAPS.RECOVERY = 0 and RECOVER returns `ERR_NO_RECOVERY`.

## 12. Traceability (12.1 checklist)

### 12.1 Status of the "before coding" checklist

| Item | Status |
| --- | --- |
| Every vector maps to a requirement, every requirement to a test | Done in §12.2 and §12.3, pending approval of SR-35 to SR-41 (R13) |
| Every surface covered or out of scope | Done in §12.4 |
| Datasheet: every register's access, reset value and behaviour per state | Done in §3, §6 and §8 |
| Validation order for the backing file | Done in §10.5 |
| Open questions answered | Done (threat model §13); new items R1–R13 above |

### 12.2 Requirements → tests

Layers: **Q** qtest (no guest), **U** unit test inside the QEMU build, **F** offline file tool or fuzzer, **G** guest system test, **R** review or doc.

| SR | How it is verified | Layer | Milestone |
| --- | --- | --- | --- |
| 01 | Every data command in every non-UNLOCKED state → ERR_LOCKED; DATA reads 0 | Q | M3 |
| 02 | After LOCK, reset, FLR and unplug: READ fails; test-build hook confirms zeroed key buffers | Q, R | M2 |
| 03 | Calibration log shows ≥ 0.5 s; iterations ≥ floor in the formatted image | U, F | M1 |
| 04 | Wrong password with `system_reset` between attempts; counter persists; backoff and LOCKED_OUT at 10 | Q | M2 |
| 05 | 1,000-run timing of the verify routine (right vs wrong); padding measured in qtest (R10) | U, Q | M2 |
| 06 | XTS known-answer test; identical plaintext sectors → different ciphertext | U, Q | M1 (KAT), M3 |
| 07 | Iterations below the floor → ERROR at realize; slot moved to another index or image → ERR_AUTH; header field edited → ERR_INTEGRITY | F, Q | M1, M2 |
| 08 | Documented | R | M3 |
| 09 | Password windows read 0; data window rules of §3.3 | Q | M2, M3 |
| 10 | Out-of-range LBA, COUNT, PW_LEN; overflow values (LBA near 2⁶⁴) | Q, F | M2, M3 |
| 11 | No DMA in v1: re-entrancy guard left enabled (review); revisit with the DMA milestone | R | M3 |
| 12 | `savevm` and `migrate` refused in every state, both devices | G | M1 |
| 13 | `ps`, `strings` on a core-less run, argv check of `cryptoctl` | G, R | M2 |
| 14 | Review of ioctl paths; wiped buffers | R | M2 |
| 15 | grep all trace and log output from the test suites for the test password and key bytes | Q, G | M2 onward |
| 16 | Parser fuzzing for a fixed time budget, plus a corpus of malformed headers | F | M1 |
| 17 | Documented | R | M1 |
| 18 | Rekey manual test (R9) | G | M4b |
| 19 | Unprivileged user cannot open the control node; block node follows disk permissions | G | M3 |
| 20 | Recovery demo with and without the device | G | M5 |
| 21 | Review of state and result encodings | R | M2, M6 |
| 22–24, 26, 27 | Fault hooks per F-target (test builds) | Q | M6 |
| 25 | Verify-after-write paths exercised with injected write errors | Q | M2, M6 |
| 28 | Disassembly review of release builds | R | M6 |
| 29 | CAPS.FAULT_HOOKS = 0 in release builds | Q | M6 |
| 30 | Image outside the share; second QEMU on the same image fails to start (image locking) | G, Q | M1 |
| 31 | This document, reviewed | R | M1 |
| 32 | Power cut simulated after each write step of PASSWD (test-build abort hook) | Q | M4 |
| 33 | LOCK and FLR during a KDF job and during an in-flight READ | Q | M2, M3 |
| 34 | Self-tests pass at realize; a test build forcing a KAT failure makes realize fail | Q | M1 |
| 35–41 | See §12.3 | | |

### 12.3 Proposed new requirements and vectors (R13)

| ID | Requirement | Traces to | Verified by |
| --- | --- | --- | --- |
| V24 | Guest root re-formats a formatted image to destroy its data (T3, D) | S1 | – |
| V25 | A tampered slot sets a huge iteration count so UNLOCK hangs before the tag check fails (T7, D) | S5, S6 | – |
| SR-35 | FORMAT is accepted only in UNFORMATTED (header region all zero); any non-zero header that fails parsing is ERROR | V24, C5 | Q, M1 |
| SR-36 | FORMAT fills the data area with CSPRNG output before committing the header | V2, B7 | F (entropy check of a fresh image), M1 |
| SR-37 | The recovery device releases its key only when armed, at most once per machine boot; without it RECOVER returns ERR_NO_RECOVERY and CAPS.RECOVERY = 0 | F8, V23, C1 | Q, G, M5 |
| SR-38 | After RECOVER only PASSWD (new password) and LOCK are accepted until a new password is set | Section 9, R4 | Q, M5 |
| SR-39 | Correct password with a failing header MAC → ERR_INTEGRITY, ERROR, counter reset, non-secret host log | V3, V4, B5 | F + Q, M2 |
| SR-40 | A KDF job never touches device state; LOCK, reset and FLR mid-job wipe the password copy at once and discard the result | V16, B3 | Q, M2 |
| SR-41 | Slots with PBKDF2 iterations outside [floor, ceiling] are rejected at parse | V3, V25, R11 | F + Q, M1 |

### 12.4 Surfaces → coverage

| Surface | Covered by |
| --- | --- |
| S1 BAR0 registers and windows | SR-01, 04, 05, 09, 10, 21, 22, 35 |
| S2 DMA | Not present in v1; SR-11 applies from the DMA milestone |
| S3 Config space | QEMU PCI core; the device adds standard PCI capabilities. Covered by a generic-fuzz run in M3 |
| S4 Timing | SR-05 |
| S5 Backing file contents | SR-03, 06, 07, 08, 17, 36, 41 |
| S6 Header parser | SR-16, 41 |
| S7 Command line | Out of scope (O2); no secrets on the command line by design (FORMAT is in-guest) |
| S8 Reset / FLR | SR-02, 33, 40 |
| S9 Snapshot / migration | SR-12 |
| S10 Hot-unplug / unbind | SR-02 (unrealize zeroizes); CryptoStore driver uses a refcounted device structure and a `removed` flag |
| S11 Control node / ioctl | SR-14, 19 |
| S12 Block node | SR-19 |
| S13 CLI | SR-13 |
| S14 Guest kernel memory | Out of scope (O3, O4) |
| S15 Recovery channel | SR-20, 37 |
| S16 QEMU process memory | Out of scope (O1) |
| S17 Traces and logs | SR-15 |
| 11.2 FLR | SR-02, 33 |
| 11.2 AER / extended config | The device adds no AER in v1; SR-15 applies to any future error reporting |
| 11.2 MSI-X table | QEMU core |
| 11.2 Hotplug | SR-02; tested in M5 |
| 11.2 ATS, PASID, SR-IOV, P2P | Not implemented (out of scope) |

## 13. Trace and log policy (SR-15)

- Register accesses are traced with values, except PW_A, PW_B and DATA, which are traced as offset and size only.
- Commands are traced as opcode, result and state transition. Never salts, IVs, tags, keys or passwords.
- Guest errors never echo written values for the windows.
- ERR_INTEGRITY and fault detection emit one host log line naming the event and the image UUID, nothing else.
