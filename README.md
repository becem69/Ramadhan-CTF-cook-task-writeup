# Ramadhan-CTF-cook-task-writeup
# cook.bin — Reverse Engineering Challenge (Ramadhan CTF @ ISET'COM)

This repository contains the solution walkthrough for **cook.bin**, a reverse engineering challenge from **Ramadhan CTF organized at ISET'COM**. The binary is a stripped Linux ELF executable that hides the real flag behind several small tricks including anti-debugging checks, misleading strings, and simple obfuscation.

## Challenge Overview

The provided binary is a **64-bit stripped ELF PIE executable**:

```bash
file cook.bin
```

Output:

```
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Because the binary is stripped, symbol names are removed, requiring analysis through disassembly and static inspection.

---

# Step 1 — Initial Static Analysis

Running `strings` reveals several interesting artifacts:

```bash
strings cook.bin
```

Notable findings:

* A **fake flag**:

```
flag{fake_flag_nothing_here}
```

* A string suggesting input interaction:

```
Enter a number:
Result:
```

* A suspicious string located in `.rodata`:

```
becem69_is_4lw4y
```

This suggests that the real flag might be dynamically constructed.

---

# Step 2 — Detecting Anti-Debugging

Disassembly reveals that the program reads:

```
/proc/self/status
```

and checks the field:

```
TracerPid
```

This is a classic **anti-debugging technique** used on Linux. If the program detects that it is being traced (for example by `gdb`), it prints:

```
Nothing to see here.
```

Therefore the binary should be analyzed **without attaching a debugger** or by bypassing this check.

---

# Step 3 — Understanding the Program Logic

Using `objdump`:

```bash
objdump -d cook.bin
```

The program flow can be summarized as:

1. Perform an anti-debugging check using `/proc/self/status`.
2. Ask the user for an integer input.
3. Run a custom transformation function on that number.
4. Print the result.
5. Decode a hidden string stored in `.rodata`.

The numeric transformation function repeatedly applies arithmetic and bitwise operations:

```
eax = eax * 0x539
eax ^= 0xCAFEBABE
eax ^= (eax >> 3)
eax += 0x1337
eax = (eax << 5) | (eax >> 27)
```

This loop runs **100 times**, acting as a misleading computation that does not reveal the flag.

---

# Step 4 — Finding the Encoded Flag

Inside the `.rodata` section we find encoded bytes:

```bash
objdump -s -j .rodata cook.bin
```

Encoded sequence:

```
bc bb bd bb b3 e8 e7 81 b7 ad 81 ea b2 a9 ea a7
ad 81 b6 ed ac ed de
```

The disassembly shows that each byte is XORed with `0xDE`.

---

# Step 5 — Decoding the Flag

A simple Python script reveals the hidden message:

```python
enc = bytes([
0xbc,0xbb,0xbd,0xbb,0xb3,0xe8,0xe7,0x81,0xb7,0xad,
0x81,0xea,0xb2,0xa9,0xea,0xa7,0xad,0x81,0xb6,0xed,
0xac,0xed,0xde
])

print(''.join(chr(b ^ 0xde) for b in enc))
```

Output:

```
becem69_is_4lw4ys_h3r3
```

---

# Final Flag

```
becem69_is_4lw4ys_h3r3
```

---

# Techniques Used

* Static binary analysis
* `strings` reconnaissance
* ELF section inspection
* Disassembly with `objdump`
* XOR deobfuscation
* Anti-debugging analysis (`TracerPid` check)

---

# Tools

* `file`
* `strings`
* `objdump`
* `python3`

---

# becem69

Challenge solved during **Ramadhan CTF at ISET'COM**.
You can find detailed screenshots in **screenshots folder**
