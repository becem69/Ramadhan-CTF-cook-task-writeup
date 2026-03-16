# Ramadhan-CTF-cook-task-writeup
# cook.bin — Reverse Engineering Challenge (Ramadhan CTF @ ISET'COM)

This repository contains the solution walkthrough for **cook.bin**, a reverse engineering challenge from **Ramadhan CTF organized at ISET'COM**.

---

## Step 1 — Identify the Binary

```bash
(becem69㉿becemNoCap)-[~]
└─$ file cook.bin
```

Output:

```
cook.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e315333f5cf7cf3e54f4fe61330a54bdceb69fea, for GNU/Linux 4.4.0, stripped
```

The binary is:

* **64-bit**
* **PIE executable**
* **Stripped**
* **Dynamically linked**

---

## Step 2 — Extract Strings

```bash
(becem69㉿becemNoCap)-[~]
└─$ strings cook.bin
```

Output:

```
/lib64/ld-linux-x86-64.so.2
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
_ZNSirsERi
_ZNSolsEi
_ZNKSt5ctypeIcE8do_widenEc
_ZSt3cin
_ZSt16__throw_bad_castv
_ZSt21ios_base_library_initv
_ZNSo3putEc
_ZNKSt5ctypeIcE13_M_widen_initEv
_ZNSo5flushEv
_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
_ZSt4cout
fgets
__stack_chk_fail
fopen
__isoc23_strtol
__libc_start_main
__cxa_finalize
fclose
libstdc++.so.6
libm.so.6
libgcc_s.so.1
libc.so.6
GLIBC_2.38
GLIBC_2.4
GLIBC_2.34
GLIBC_2.2.5
GLIBCXX_3.4.32
GLIBCXX_3.4.11
GLIBCXX_3.4
AVSH
)D$0
)D$@
)D$Pf
)D$
oD$ H
)D$`f
oD$0
)D$pf
oD$@
oD$P
PTE1
u3UH
@0H9
TracerPiH
t[L9$$u
[]A\
D$H1
D$HdH+
/proc/self/status
TracerPid:
flag{fake_flag_nothing_here}
Nothing to see here.
Enter a number:
Result:
Nothing else here.
becem69_is_4lw4y
;*3$"
GCC: (GNU) 15.2.1 20260209
.shstrtab
.note.gnu.build-id
.interp
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.note.gnu.property
.note.ABI-tag
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

We can immediately notice:

```
flag{fake_flag_nothing_here}
```

This is clearly a **fake flag** meant to mislead the solver.

---

## Step 3 — Inspect the Binary

```bash
(becem69㉿becemNoCap)-[~]
└─$ objdump -s -j .rodata cook.bin
```

Output:

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

At offset `0x2090` we see encoded bytes:

```
bc bb bd bb b3 e8 e7 81 b7 ad 81 ea b2 a9 ea a7 ad 81 b6 ed ac ed de
```

---

## Step 4 — Decode the Bytes

```bash
(becem69㉿becemNoCap)-[~]
└─$ python3 -c "
enc = bytes([0xbc,0xbb,0xbd,0xbb,0xb3,0xe8,0xe7,0x81,0xb7,0xad,0x81,0xea,0xb2,0xa9,0xea,0xa7,0xad,0x81,0xb6,0xed,0xac,0xed,0xde])
print(''.join(chr(b ^ 0xde) for b in enc))"
```

Output:

```
becem69_is_4lw4ys_h3r3
```

Alternatively, instead of using the Python script, the encoded bytes can be pasted into **CyberChef** and the **Magic** operation can automatically detect the XOR operation and decode the string.

---

# Final Flag

```
becem69_is_4lw4ys_h3r3
```


**Author : becem69**
