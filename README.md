# cook.bin — Reverse Engineering Writeup

> **Ramadhan CTF** organized at **ISET'COM**  
> Category: Reverse Engineering | Binary: ELF 64-bit, PIE, Dynamically Linked

---

## Table of Contents

- [Overview](#overview)
- [Step 1 — Identify the Binary](#step-1--identify-the-binary)
- [Step 2 — Extract Strings](#step-2--extract-strings)
- [Step 3 — Inspect the Binary](#step-3--inspect-the-binary)
- [Step 4 — Decode the Bytes](#step-4--decode-the-bytes)
- [Final Flag](#final-flag)

---

## Overview

This repository contains the solution walkthrough for **cook.bin**, a reverse engineering challenge from **Ramadhan CTF organized at ISET'COM**.

Reverse engineering is the process of analyzing a compiled program **without access to its source code**. You are given a binary file the computer can execute, and your job is to understand what it does and find the hidden secret — the **flag** — inside it.

This challenge is a great introduction to reverse engineering because it does not require deep low-level knowledge. The flag is hidden in plain sight inside the binary, but it is encoded so it does not look like a flag at first glance. The developer also planted a **fake flag** to send careless solvers in the wrong direction. The real solution comes from reading the binary's raw data carefully and applying a simple decoding step.

**Key concepts covered:**
- ELF binary identification
- Static string extraction with `strings`
- Reading raw binary sections with `objdump`
- XOR decoding

---

## Step 1 — Identify the Binary

The first thing you always do when you receive an unknown file is ask your tools to identify it. The `file` command does exactly this — it reads the first few bytes of the file (every file format has a unique signature at its start, called **magic bytes**) and tells you what kind of file you are looking at.

```bash
file cook.bin
```

**Output:**
```
cook.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=e315333f5cf7cf3e54f4fe61330a54bdceb69fea,
for GNU/Linux 4.4.0, stripped
```

There is a lot of information here. Let's go through each part:

- **ELF** — the standard file format for executable programs on Linux. On Windows, executables use the `.exe` format. On Linux, they use ELF (Executable and Linkable Format).
- **64-bit** — compiled for modern 64-bit processors, which is the standard on any computer bought in the last decade.
- **PIE executable** — stands for Position-Independent Executable. This means the operating system can load the program at any random memory address each time it runs, rather than always at the same fixed location. This is a security feature called ASLR (Address Space Layout Randomization) that makes certain attacks harder.
- **Stripped** — debug symbols have been removed. Symbols are human-readable labels (like function names and variable names) that developers leave in binaries to help with debugging. Removing them makes reverse engineering more difficult, but does not stop us completely.
- **Dynamically linked** — the program does not include all of its code inside itself. Instead, it relies on external shared libraries (like `libc.so.6`) that are loaded from the operating system at runtime. This is similar to how a program on Windows might require certain `.dll` files to be installed.

---

## Step 2 — Extract Strings

The `strings` command is one of the simplest and most useful first steps in reverse engineering. It scans through a binary file and prints out every sequence of readable text characters it finds. Even though a compiled binary is mostly machine code that looks like random gibberish, it often contains readable strings embedded in it — things like error messages, prompts, hardcoded passwords, URLs, or in CTF challenges, flags.

```bash
strings cook.bin
```

**Output (relevant parts):**
```
/proc/self/status
TracerPid:
flag{fake_flag_nothing_here}
Nothing to see here.
Enter a number:
Result:
Nothing else here.
becem69_is_4lw4y
```

A few things immediately stand out:

- **`flag{fake_flag_nothing_here}`** — this looks like a flag, and that is exactly the point. It is a **decoy** placed by the challenge author to trick solvers into submitting the wrong answer. A dead giveaway is the text inside it: `fake_flag_nothing_here`. Never trust something that announces itself that clearly in a CTF.
- **`/proc/self/status`** and **`TracerPid:`** — these are related to the anti-debugging mechanism we saw in the previous challenge. `/proc/self/status` is a special Linux file that contains information about the currently running process. `TracerPid` is a field inside that file — if its value is non-zero, it means a debugger is attached. The program reads this to detect if it is being analyzed.
- **`becem69_is_4lw4y`** — this looks like part of something interesting, but it seems cut off. It is missing the end. This hints that there may be more data hidden elsewhere in the binary that `strings` did not catch.
- **`Enter a number:`** and **`Result:`** — the program appears to take a number as input and compute some result. This is the visible behavior of the program, likely unrelated to the flag itself.

> **Why does `strings` miss some data?** The `strings` command only shows sequences that are already in plain, readable ASCII text. If data is encoded, encrypted, or stored as raw bytes that do not look like text, `strings` will skip right over it. That is exactly what happened here — the real flag is stored as encoded bytes, so we need a different approach to find it.

---

## Step 3 — Inspect the Binary

Since `strings` gave us an incomplete picture, we go one level deeper and look at the raw contents of the binary using `objdump`. This tool can read a binary file and display its contents in a structured way.

A compiled binary is divided into named **sections**, each with a specific purpose. The `.rodata` section (short for "read-only data") is where the compiler stores constant values that the program uses but never modifies — things like hardcoded strings, lookup tables, and other fixed data.

```bash
objdump -s -j .rodata cook.bin
```

The `-s` flag means "display full section contents" and `-j .rodata` means "only show the .rodata section".

**Output:**
```
cook.bin:     file format elf64-x86-64

Contents of section .rodata:
 2000 01000200 72002f70 726f632f 73656c66  ....r./proc/self
 2010 2f737461 74757300 54726163 65725069  /status.TracerPi
 2020 643a0066 6c61677b 66616b65 5f666c61  d:.flag{fake_fla
 2030 675f6e6f 7468696e 675f6865 72657d00  g_nothing_here}.
 2040 4e6f7468 696e6720 746f2073 65652068  Nothing to see h
 2050 6572652e 00456e74 65722061 206e756d  ere..Enter a num
 2060 6265723a 20005265 73756c74 3a20004e  ber: .Result: .N
 2070 6f746869 6e672065 6c736520 68657265  othing else here
 2080 2e000000 00000000 00000000 00000000  ................
 2090 bcbbbdbb b3e8e781 b7ad81ea b2a9eaa7  ................
 20a0 ad81b6ed acedde00 00000000 00000000  ................
 20b0 62656365 6d36395f 69735f34 6c773479  becem69_is_4lw4y
```

How to read this output: each line shows a memory offset on the left (like `2090`), then the raw bytes in the middle as hexadecimal pairs, and on the right a text preview where printable characters are shown and everything else appears as a dot.

Most of the section is readable text we already know about. But at offset `0x2090` something different appears:

```
bc bb bd bb b3 e8 e7 81 b7 ad 81 ea b2 a9 ea a7 ad 81 b6 ed ac ed de
```

These bytes do not look like readable text at all — they are large values (mostly above `0x7F`) that fall outside the standard ASCII range. This is a strong indicator that they are **encoded data**. The program is hiding something here by storing it in a form that does not look like text.

Just below, at offset `0x20b0`, we can see `becem69_is_4lw4y` — which is the partial string we spotted with `strings` earlier. This confirms we are in the right area. The encoded block at `0x2090` and the readable string at `0x20b0` are almost certainly related and together form the complete hidden flag.

---

## Step 4 — Decode the Bytes

We have 23 suspicious encoded bytes. The next step is to figure out how they were encoded. In CTF challenges, the most common simple encoding used alongside a known key string is **XOR**.

XOR (eXclusive OR) is a bit-level operation with a very useful property: it is perfectly reversible. If you XOR a value `A` with a key `K` to get `C`, then XOR'ing `C` with `K` again gives you back `A`. In other words, the same operation both encrypts and decrypts. This makes XOR extremely popular for simple obfuscation.

The key question is: what is the XOR key? Looking at the data around the encoded block, we notice the byte `0xde` appears at the very end of the encoded sequence. In XOR encoding, a null byte (`0x00`) in the plaintext will always equal the key byte in the ciphertext (because `0x00 XOR key = key`). Since strings in C end with a null byte (`0x00`), the last byte of the encoded data is likely the key: `0xde`.

We test this hypothesis by XOR'ing every encoded byte with `0xde`:

```bash
python3 -c "
enc = bytes([0xbc,0xbb,0xbd,0xbb,0xb3,0xe8,0xe7,0x81,0xb7,0xad,0x81,0xea,0xb2,0xa9,0xea,0xa7,0xad,0x81,0xb6,0xed,0xac,0xed,0xde])
print(''.join(chr(b ^ 0xde) for b in enc))
"
```

What this script does, step by step:

1. It stores all 23 encoded bytes in a list called `enc`.
2. It loops over every byte `b` in the list.
3. For each byte, it computes `b XOR 0xde` — this reverses the encoding.
4. It converts each resulting number back to a character using `chr()`.
5. It joins all the characters together and prints the result.

**Output:**
```
becem69_is_4lw4ys_h3r3
```

The decoded string is `becem69_is_4lw4ys_h3r3`, which completes the partial string `becem69_is_4lw4y` we saw earlier. This is the real flag.

> **Alternative — CyberChef:** If you prefer a visual, no-code approach, you can paste the encoded bytes into [CyberChef](https://gchq.github.io/CyberChef/) and use the **Magic** operation. CyberChef will automatically try common encodings and detect that XOR with key `0xde` produces readable output, giving you the same result without writing any code.

---

## Final Flag

```
becem69_is_4lw4ys_h3r3
```

---

**Author:** becem69
