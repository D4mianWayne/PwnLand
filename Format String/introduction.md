# Introduction to Format String

This is a format string exploit which allow us to overwrite a variable value using the `%n` format in `printf`. Format string exploit refers to those vulnerabilities such as when no format specifier(s) has been defined when a variable is being printed.


For example:-

Consider the following example:-

```C
#include<stdio.h>


int main()
{
    char buf[32];
    printf("Enter Text: ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);   /* Vulnerable to Format String */
    return 0;
}
```

Let's compile it with `gcc` and disable `pie`:-

```r
d4mianwayne@oracle:~/Pwning/fmt$ gcc -no-pie intro.c -o intro
intro.c: In function ‘main’:
intro.c:9:12: warning: format not a string literal and no format arguments [-Wformat-security]
     printf(buf);   /* Vulnerable to Format String */
            ^~~
```


Warning is obvious since `gcc` is a modern compiler. Now, let's run the binary:-

```r
d4mianwayne@oracle:~/Pwning/fmt$ ./intro 
Enter Text: AAAAA
AAAAA   <------ Works fine
d4mianwayne@oracle:~/Pwning/fmt$ ./intro 
Enter Text: %x-%x  
1493a2d0-3315b8d0   <--------- Wait, what?
```

So, it worked fine if we gave `AAAA` but what happened when we gave `%x`, it printed some hex numbers? To understand this we need to understand about `printf` and how the format specifier works. 


When we use `printf`, the recommended way is to use it by passing the format specifier as 1st argument followed by the variable that has to be printed. For example, in the above case, if I had used `%s` to print the `buf` variable, there won't be any vulnerability.

Following are the format specifier which is passed to the `printf` to print the variable accordingly.

| Parameter    |         Output                          | Passed as |
| ------------ | --------------------------------------- | --------- |
| %d           |  decimal(int)                           |  value    |
| %u           |  unsigned decimal(unsigned int)         |  value    |
| %x           |  hexadecimal (unsigned int)             |  value    |
| %s           |  string ((const) (unsigned) char *)     | reference |
| %n           | number of bytes written so far, (* int) | reference |
| %p           | 8-byte wide value                       | reference |

> `%n` is the core reason why format string bug is huge problem which will be covered in later section.

Coming to the program we made, it has a format string vulnerability, the reason it is called format string bug is because the string or buffer we gave is being printed without any format being specified. So when we gave `%x` it printed some hex values. In order to check what it is printing let's check `gdb`:-


We need to setup a breakpoint at `ret` of the `main`:-

```r
d4mianwayne@oracle:~/Pwning/fmt$ gdb-gef -q intro

warning: ~/.gdbinit.local: No such file or directory
Reading symbols from intro...(no debugging symbols found)...done.
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 2 commands could not be loaded, run `gef missing` to know why.
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005e7 <+0>:	push   rbp
   0x00000000004005e8 <+1>:	mov    rbp,rsp
   0x00000000004005eb <+4>:	sub    rsp,0x30
   0x00000000004005ef <+8>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004005f8 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004005fc <+21>:	xor    eax,eax
   0x00000000004005fe <+23>:	lea    rdi,[rip+0xdf]        # 0x4006e4
   0x0000000000400605 <+30>:	mov    eax,0x0
   0x000000000040060a <+35>:	call   0x4004e0 <printf@plt>
   0x000000000040060f <+40>:	mov    rdx,QWORD PTR [rip+0x200a2a]        # 0x601040 <stdin@@GLIBC_2.2.5>
   0x0000000000400616 <+47>:	lea    rax,[rbp-0x30]
   0x000000000040061a <+51>:	mov    esi,0x20
   0x000000000040061f <+56>:	mov    rdi,rax
   0x0000000000400622 <+59>:	call   0x4004f0 <fgets@plt>
   0x0000000000400627 <+64>:	lea    rax,[rbp-0x30]
   0x000000000040062b <+68>:	mov    rdi,rax
   0x000000000040062e <+71>:	mov    eax,0x0
   0x0000000000400633 <+76>:	call   0x4004e0 <printf@plt>
   0x0000000000400638 <+81>:	mov    eax,0x0
   0x000000000040063d <+86>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000400641 <+90>:	xor    rcx,QWORD PTR fs:0x28
   0x000000000040064a <+99>:	je     0x400651 <main+106>
   0x000000000040064c <+101>:	call   0x4004d0 <__stack_chk_fail@plt>
   0x0000000000400651 <+106>:	leave  
   0x0000000000400652 <+107>:	ret    
End of assembler dump.
gef➤  b *main + 107
Breakpoint 1 at 0x4006ee
```

We have added a breakpoint, it's time to trigger the vulnerability:-

```r
gef➤  r
Starting program: /home/d4mianwayne/Pwning/fmt/intro 
Enter Text: %p-%p-%p-%p-%p
0x7fffffffdc40-0x7ffff7dd18d0-0xa70252d70252d70-0x60267f-0x7ffff7fd84c0



-- snip --

 →   0x400652 <main+107>       ret    
   ↳  0x7ffff7a05b97 <__libc_start_main+231> mov    edi, eax
      0x7ffff7a05b99 <__libc_start_main+233> call   0x7ffff7a27120 <__GI_exit>
      0x7ffff7a05b9e <__libc_start_main+238> mov    rax, QWORD PTR [rip+0x3ced23]        # 0x7ffff7dd48c8 <__libc_pthread_functions+392>
      0x7ffff7a05ba5 <__libc_start_main+245> ror    rax, 0x11
      0x7ffff7a05ba9 <__libc_start_main+249> xor    rax, QWORD PTR fs:0x30
      0x7ffff7a05bb2 <__libc_start_main+258> call   rax
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x400652 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400652 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 2, 0x0000000000400652 in main ()
```
We hit the breakpoint, let's check what these hex values are:-'

```r
gef➤  x/s 0x7fffffffdc40
0x7fffffffdc40:	"%p-%p-%p-%p-%p\n"
gef➤  x/s 0x7ffff7dd18d0
0x7ffff7dd18d0 <_IO_stdfile_0_lock>:	""
gef➤  x/xg 0x7fffffffdc40
0x7fffffffdc40:	0x70252d70252d702
```

Looks familiar? It is the address of stack and the first address which is leaked points to the buffer itself.

Further exploits related posts will be found in in `Format String` folder.