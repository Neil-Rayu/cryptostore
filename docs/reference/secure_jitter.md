# Reference: `secure_jitter` (ECE397-MP2, Pattern 10)

Source: ECE397-MP2, Neil Rayu, February 2026. Converted from the original LaTeX
without changes to the code or the analysis. This is the reference for the
jitter + redundancy pattern that `docs/threat-model.md` Section 10 ports to C
for the device model (SR-23).

**Pattern 10:** Randomized delay including FI detection to panic.

(And could be integrated into the other patterns later with a standalone single
iteration for detection between each step of some algorithm.)

## Rust pattern

```rust
macro_rules! secure_jitter {
    ($cycles:expr) => {
        unsafe {
            // 1. use black-box on the input to prevent the compiler to
            // optimize out when it sees the constant cycle value
            let cycles = core::hint::black_box($cycles);

            // 2. make two volatile copies for cross-verification
            // This will help if instructions are skipped
            let mut limit: u32 = cycles;
            core::ptr::write_volatile(&mut limit, limit);
            let mut saved: u32 = cycles;
            core::ptr::write_volatile(&mut saved, saved);

            // 3. delay loop
            while core::ptr::read_volatile(&limit) > 0 {
                // prevent instruction fusion/reordering since compiler
                // may move things around to make more efficient
                core::arch::asm!("nop");

                // decrement safely via volatile
                let val = core::ptr::read_volatile(&limit);
                core::ptr::write_volatile(&mut limit, val - 1);
            }

            // 4. redundant checks
            // 1. counter must be exactly 0
            let check1 = core::ptr::read_volatile(&limit);
            if core::hint::black_box(check1) != 0 {
                defmt::panic!("FI DETECTED!!!");
            }

            // 2. saved copy must still match original input
            let check2 = core::ptr::read_volatile(&saved);
            if core::hint::black_box(check2) != core::hint::black_box(cycles) {
                defmt::panic!("FI DETECTED!!!");
            }

            // 3. re-read counter (redundant single-skip protection)
            let check3 = core::ptr::read_volatile(&limit);
            if core::hint::black_box(check3) != 0 {
                defmt::panic!("FI DETECTED!!!");
            }
        }
    };
}
```

## Assembly analysis (ARM Thumb)

### Delay loop

```asm
# volatile read of limit, compare to 0
248:  2900        cmp     r1, #0         ; while read_volatile(&limit) > 0
24a:  d006        beq.n   25a            ; exit loop when limit == 0

24c:  bf00        nop                    ; asm!("nop") prevents instruction fusion

# volatile read → decrement → volatile write
24e:  9927        ldr     r1, [sp, #156] ; val = read_volatile(&limit)
250:  1e49        subs    r1, r1, #1     ; val - 1
252:  9127        str     r1, [sp, #156] ; write_volatile(&mut limit, val - 1)

# re-read for loop condition
254:  9927        ldr     r1, [sp, #156] ; read_volatile(&limit)
256:  2900        cmp     r1, #0         ; > 0 ?
258:  d1f8        bne.n   24c            ; loop back
```

### Check 1: counter must be zero

```asm
# Check 1: read_volatile(&limit) != 0
25a:  9927        ldr     r1, [sp, #156] ; check1 = read_volatile(&limit)
25c:  912d        str     r1, [sp, #180] ; black_box spills to stack
260:  992d        ldr     r1, [sp, #180] ; re-load after black_box
262:  2900        cmp     r1, #0         ; check1 != 0?
264:  d000        beq.n   268            ; skip panic if OK
266:  e0df        b.n     428            ; → panic("jitter counter not zero")
```

### Check 2: saved copy must match original

```asm
# Check 2: read_volatile(&saved) != black_box(cycles)
268:  990b        ldr     r1, [sp, #44]  ; check2 = read_volatile(&saved)
26a:  912d        str     r1, [sp, #180] ; black_box(check2)
26e:  992d        ldr     r1, [sp, #180]
270:  902d        str     r0, [sp, #180] ; black_box(cycles)
274:  982d        ldr     r0, [sp, #180]
276:  4281        cmp     r1, r0         ; saved == cycles?
278:  d000        beq.n   27c            ; skip panic if OK
27a:  e0dc        b.n     436            ; → panic("saved copy corrupted")
```

### Check 3: redundant counter verification

```asm
# Check 3: re-read limit != 0
27c:  9827        ldr     r0, [sp, #156] ; check3 = read_volatile(&limit)
27e:  902d        str     r0, [sp, #180] ; black_box(check3)
282:  982d        ldr     r0, [sp, #180]
284:  2800        cmp     r0, #0         ; check3 != 0?
286:  d000        beq.n   28a            ; skip panic if OK
288:  e0dc        b.n     444            ; → panic("counter glitched after check")
```

## Full assembly listing

```asm
  fc:       b580            push    {r7, lr}
  fe:       af00            add     r7, sp, #0
 100:       b0c8            sub     sp, #288      @ 0x120
 102:       a82d            add     r0, sp, #180  @ 0xb4
 104:       49dc            ldr     r1, [pc, #880]        @ (478)
 106:       8001            strh    r1, [r0, #0]
 108:       f001 fca1       bl      1a4e
 10c:       2400            movs    r4, #0
 10e:       4620            mov     r0, r4
 110:       4621            mov     r1, r4
 112:       f000 ff49       bl      fa8
 116:       2503            movs    r5, #3
 118:       4628            mov     r0, r5
 11a:       f001 fa81       bl      1620
 11e:       b281            uxth    r1, r0
 120:       0a09            lsrs    r1, r1, #8
 122:       b2c2            uxtb    r2, r0
 124:       2a04            cmp     r2, #4
 126:       d000            beq.n   12a
 128:       e19b            b.n     462
 12a:       a809            add     r0, sp, #36   @ 0x24
 12c:       7001            strb    r1, [r0, #0]
 12e:       2010            movs    r0, #16
 130:       f000 fdd0       bl      cd4
 134:       b2c0            uxtb    r0, r0
 136:       28fb            cmp     r0, #251      @ 0xfb
 138:       d300            bcc.n   13c
 13a:       e170            b.n     41e
 13c:       9508            str     r5, [sp, #32]
 13e:       0080            lsls    r0, r0, #2
 140:       4dd3            ldr     r5, [pc, #844]        @ (490)
 142:       1940            adds    r0, r0, r5
 144:       6841            ldr     r1, [r0, #4]
 146:       4ad3            ldr     r2, [pc, #844]        @ (494)
 148:       400a            ands    r2, r1
 14a:       3281            adds    r2, #129      @ 0x81
 14c:       6042            str     r2, [r0, #4]
 14e:       2601            movs    r6, #1
 150:       0431            lsls    r1, r6, #16
 152:       48d1            ldr     r0, [pc, #836]        @ (498)
 154:       6201            str     r1, [r0, #32]
 156:       3810            subs    r0, #16
 158:       9106            str     r1, [sp, #24]
 15a:       6001            str     r1, [r0, #0]
 15c:       2010            movs    r0, #16
 15e:       f000 fdb9       bl      cd4
 162:       b2c0            uxtb    r0, r0
 164:       28fb            cmp     r0, #251      @ 0xfb
 166:       d300            bcc.n   16a
 168:       e159            b.n     41e
 16a:       0080            lsls    r0, r0, #2
 16c:       1828            adds    r0, r5, r0
 16e:       6841            ldr     r1, [r0, #4]
 170:       06b2            lsls    r2, r6, #26
 172:       430a            orrs    r2, r1
 174:       6042            str     r2, [r0, #4]
 176:       9607            str     r6, [sp, #28]
 178:       ae2d            add     r6, sp, #180  @ 0xb4
 17a:       8134            strh    r4, [r6, #8]
 17c:       9807            ldr     r0, [sp, #28]
 17e:       8170            strh    r0, [r6, #10]
 180:       7434            strb    r4, [r6, #16]
 182:       7474            strb    r4, [r6, #17]
 184:       74b4            strb    r4, [r6, #18]
 186:       20e1            movs    r0, #225      @ 0xe1
 188:       0240            lsls    r0, r0, #9
 18a:       902d            str     r0, [sp, #180]        @ 0xb4
 18c:       9808            ldr     r0, [sp, #32]
 18e:       902e            str     r0, [sp, #184]        @ 0xb8
 190:       9807            ldr     r0, [sp, #28]
 192:       9030            str     r0, [sp, #192]        @ 0xc0
 194:       200b            movs    r0, #11
 196:       f000 fd9d       bl      cd4
 19a:       b2c0            uxtb    r0, r0
 19c:       2502            movs    r5, #2
 19e:       4629            mov     r1, r5
 1a0:       9a07            ldr     r2, [sp, #28]
 1a2:       f000 fecb       bl      f3c
 1a6:       200a            movs    r0, #10
 1a8:       f000 fd94       bl      cd4
 1ac:       b2c0            uxtb    r0, r0
 1ae:       9505            str     r5, [sp, #20]
 1b0:       4629            mov     r1, r5
 1b2:       4622            mov     r2, r4
 1b4:       f000 fec2       bl      f3c
 1b8:       48b8            ldr     r0, [pc, #736]        @ (49c)
 1ba:       49b9            ldr     r1, [pc, #740]        @ (4a0)
 1bc:       6041            str     r1, [r0, #4]
 1be:       49b9            ldr     r1, [pc, #740]        @ (4a4)
 1c0:       6001            str     r1, [r0, #0]
 1c2:       9400            str     r4, [sp, #0]
 1c4:       9807            ldr     r0, [sp, #28]
 1c6:       9001            str     r0, [sp, #4]
 1c8:       9402            str     r4, [sp, #8]
 1ca:       48b7            ldr     r0, [pc, #732]        @ (4a8)
 1cc:       49b7            ldr     r1, [pc, #732]        @ (4ac)
 1ce:       4632            mov     r2, r6
 1d0:       9e07            ldr     r6, [sp, #28]
 1d2:       4633            mov     r3, r6
 1d4:       f001 f99c       bl      1510
 1d8:       b2c5            uxtb    r5, r0
 1da:       2d02            cmp     r5, #2
 1dc:       d000            beq.n   1e0
 1de:       e0ee            b.n     3be
 1e0:       03f0            lsls    r0, r6, #15
 1e2:       49b5            ldr     r1, [pc, #724]        @ (4b8)
 1e4:       6008            str     r0, [r1, #0]
 1e6:       49b5            ldr     r1, [pc, #724]        @ (4bc)
 1e8:       6008            str     r0, [r1, #0]
 1ea:       9806            ldr     r0, [sp, #24]
 1ec:       49aa            ldr     r1, [pc, #680]        @ (498)
 1ee:       6008            str     r0, [r1, #0]
 1f0:       9425            str     r4, [sp, #148]        @ 0x94
 1f2:       a809            add     r0, sp, #36   @ 0x24
 1f4:       a925            add     r1, sp, #148  @ 0x94
 1f6:       2204            movs    r2, #4
 1f8:       f001 fb70       bl      18dc
 1fc:       b2c5            uxtb    r5, r0
 1fe:       aa0b            add     r2, sp, #44   @ 0x2c
 200:       ab2d            add     r3, sp, #180  @ 0xb4
 202:       2d04            cmp     r5, #4
 204:       d000            beq.n   208
 206:       e100            b.n     40a
 208:       1d10            adds    r0, r2, #4
 20a:       9008            str     r0, [sp, #32]
 20c:       1d18            adds    r0, r3, #4
 20e:       9004            str     r0, [sp, #16]
 210:       4eab            ldr     r6, [pc, #684]        @ (4c0)
 212:       e00c            b.n     22e
 214:       9806            ldr     r0, [sp, #24]
 216:       49a0            ldr     r1, [pc, #640]        @ (498)
 218:       6008            str     r0, [r1, #0]
 21a:       9425            str     r4, [sp, #148]        @ 0x94
 21c:       a809            add     r0, sp, #36   @ 0x24
 21e:       a925            add     r1, sp, #148  @ 0x94
 220:       2204            movs    r2, #4
 222:       f001 fb5b       bl      18dc
 226:       b2c2            uxtb    r2, r0
 228:       2a04            cmp     r2, #4
 22a:       d000            beq.n   22e
 22c:       e0ed            b.n     40a
 22e:       257d            movs    r5, #125      @ 0x7d
 230:       0169            lsls    r1, r5, #5
 232:       9825            ldr     r0, [sp, #148]        @ 0x94
 234:       f003 f9a8       bl      3588
 238:       00e8            lsls    r0, r5, #3
 23a:       1808            adds    r0, r1, r0
 23c:       902d            str     r0, [sp, #180]        @ 0xb4
 23e:       a82d            add     r0, sp, #180  @ 0xb4
 240:       982d            ldr     r0, [sp, #180]        @ 0xb4
 242:       9027            str     r0, [sp, #156]        @ 0x9c
 244:       900b            str     r0, [sp, #44] @ 0x2c
 246:       9927            ldr     r1, [sp, #156]        @ 0x9c
 248:       2900            cmp     r1, #0
 24a:       d006            beq.n   25a
 24c:       bf00            nop
 24e:       9927            ldr     r1, [sp, #156]        @ 0x9c
 250:       1e49            subs    r1, r1, #1
 252:       9127            str     r1, [sp, #156]        @ 0x9c
 254:       9927            ldr     r1, [sp, #156]        @ 0x9c
 256:       2900            cmp     r1, #0
 258:       d1f8            bne.n   24c
 25a:       9927            ldr     r1, [sp, #156]        @ 0x9c
 25c:       912d            str     r1, [sp, #180]        @ 0xb4
 25e:       a92d            add     r1, sp, #180  @ 0xb4
 260:       992d            ldr     r1, [sp, #180]        @ 0xb4
 262:       2900            cmp     r1, #0
 264:       d000            beq.n   268
 266:       e0df            b.n     428
 268:       990b            ldr     r1, [sp, #44] @ 0x2c
 26a:       912d            str     r1, [sp, #180]        @ 0xb4
 26c:       a92d            add     r1, sp, #180  @ 0xb4
 26e:       992d            ldr     r1, [sp, #180]        @ 0xb4
 270:       902d            str     r0, [sp, #180]        @ 0xb4
 272:       a82d            add     r0, sp, #180  @ 0xb4
 274:       982d            ldr     r0, [sp, #180]        @ 0xb4
 276:       4281            cmp     r1, r0
 278:       d000            beq.n   27c
 27a:       e0dc            b.n     436
 27c:       9827            ldr     r0, [sp, #156]        @ 0x9c
 27e:       902d            str     r0, [sp, #180]        @ 0xb4
 280:       a82d            add     r0, sp, #180  @ 0xb4
 282:       982d            ldr     r0, [sp, #180]        @ 0xb4
 284:       2800            cmp     r0, #0
 286:       d000            beq.n   28a
 288:       e0dc            b.n     444
 28a:       940a            str     r4, [sp, #40] @ 0x28
 28c:       4890            ldr     r0, [pc, #576]        @ (4d0)
 28e:       990a            ldr     r1, [sp, #40] @ 0x28
 290:       1c49            adds    r1, r1, #1
 292:       910a            str     r1, [sp, #40] @ 0x28
 294:       990a            ldr     r1, [sp, #40] @ 0x28
 296:       1c49            adds    r1, r1, #1
 298:       910a            str     r1, [sp, #40] @ 0x28
 29a:       990a            ldr     r1, [sp, #40] @ 0x28
 29c:       1c49            adds    r1, r1, #1
 29e:       910a            str     r1, [sp, #40] @ 0x28
 2a0:       990a            ldr     r1, [sp, #40] @ 0x28
 2a2:       1c49            adds    r1, r1, #1
```
