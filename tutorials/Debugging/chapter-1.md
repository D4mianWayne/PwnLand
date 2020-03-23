# Chapter 1: Basics

GDB is a GNU Debugger for debugging the binaries in order to understand the workflow of the binary. Following are the some basics GDB commands you should be familiar with in order to start binary exploitation.


> I'll be using a binary for example, which could be found [here]().

### `file` command

Before just jumping off to gdb, we have to check the binary we are going to debug is supported by our architecture. Let's try using it:-

```s
robin@oracle:PwnLand/binaries/examples$ file example1
example1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=d8aa06bfff82223ea7b66a5648f8262ebf5af626, not stripped
```

So, according to the `file` command the binary is ELF(Executable Linkable Format) made for architecture `x86_64`. 

## `gdb` basics

Let's get started into the world of debugging:-

### Loading binary into GDB

To load a binary into gdb, we do `gdb -q ./<binary>` or alternatively `gdb ./<binary>` but using `-q` well tell gdb to do not print `gdb`'s version.

* Syntax: `$ gdb -q ./<binary>`

```r
robin@oracle:/media/robin/New Volume/Projects/PwnLand/binaries/examples$ gdb ./example1
Reading symbols from ./example1...(no debugging symbols found)...done.
(gdb) 

```

### Running the binary

To run a binary after loading it to `gdb`, type `run` to run the binary or `r` to run it.

* Syntax: `(gdb) r` or `(gdb) run`

```r
(gdb) r
Starting program: PwnLand/binaries/examples/example1 
Enter flag to validate:
```

### Providing command line argument to binary

In case, the binary you're trying to debug takes arguments from command line, you could do that by:-

* Syntax: `(gdb) r <arg1> <arg2> <arg3> .... <argN>`

where `N` is the maximun number of the argument binary can take.

### Providing input from file:-

To priovide input from any external file in the `gdb` enviornment, it is possible by doing following:-

* Syntax: `(gdb) r < file`

Let's see it in an example for explicit clarification:-

```r
robin@oracle:PwnLand/binaries/examples$ echo "lol" > pass.txt
robin@oracle:PwnLand/binaries/examples$ gdb -q ./example1
Reading symbols from ./example1...(no debugging symbols found)...done.
(gdb) r < pass.txt
Starting program: PwnLand/binaries/examples/example1 < pass.txt
Enter flag to validate: Not the valid flag.
[Inferior 1 (process 14121) exited normally]
(gdb) 
```


### Functions and Variables

##### Functions list

To check the functions which are present in the binary, we do `info functions`, alternatively we can do `i functions`. Let's take a look at tehe example binary:-

* Syntax: `(gdb) info functions`

```r
(gdb) info functions 
All defined functions:

Non-debugging symbols:
0x0000000000400580  _init
0x00000000004005b0  strncmp@plt
0x00000000004005c0  puts@plt
0x00000000004005d0  __stack_chk_fail@plt
0x00000000004005e0  printf@plt
0x00000000004005f0  fgets@plt
0x0000000000400600  setvbuf@plt
0x0000000000400610  _start
0x0000000000400640  _dl_relocate_static_pie
0x0000000000400650  deregister_tm_clones
0x0000000000400680  register_tm_clones
0x00000000004006c0  __do_global_dtors_aux
0x00000000004006f0  frame_dummy
0x00000000004006f7  main
0x00000000004007c0  __libc_csu_init
0x0000000000400830  __libc_csu_fini
0x0000000000400834  _fini
```

##### Variables list

This feature of `gdb` allows us to look at global & local variables defined within the binary. Variables can be listed by `info variables` or alternatively `i functions`, let's use the example binary to have a demo:-

* Syntax: `(gdb) info variables`

```r
All defined variables:

Non-debugging symbols:
0x0000000000400840  _IO_stdin_used
0x000000000040089c  __GNU_EH_FRAME_HDR
0x00000000004009d4  __FRAME_END__
0x0000000000600e10  __frame_dummy_init_array_entry
0x0000000000600e10  __init_array_start
0x0000000000600e18  __do_global_dtors_aux_fini_array_entry
0x0000000000600e18  __init_array_end
0x0000000000600e20  _DYNAMIC
0x0000000000601000  _GLOBAL_OFFSET_TABLE_
0x0000000000601048  __data_start
0x0000000000601048  data_start
0x0000000000601050  __dso_handle
0x0000000000601058  __TMC_END__
0x0000000000601058  __bss_start
0x0000000000601058  _edata
0x0000000000601060  stdout
0x0000000000601060  stdout@@GLIBC_2.2.5
0x0000000000601070  stdin
0x0000000000601070  stdin@@GLIBC_2.2.5
0x0000000000601078  completed
0x0000000000601080  _end
```

### Disassembling functions

To disassemble a specific functions, we use `disas <function_name>` to print the disassembly of that function. Disaasembly is the dump  of the assembly instruction which were interpreted during the compilation of the binary.

* Syntax: `(gdb) disas <function_name>`

Firstly, we want to change to the assembly instruction format, there are twp most primary format which include `AT&T` syntax and `Intel` syntax, let's say if we are moving edi contents in eax, following are the way it'll be interpreted:-
* Syntax:
* **Intel** : `mov eax, edi`
* **AT&T** : `mov %edi, %eax`

Since I like Intel syntax, I'll be using it. You can do it with `set disassembly-flavor intel` for changing the disassembly syntax.

Let's disassemble main of the example binary:-

```r
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004006f7 <+0>:	push   rbp
   0x00000000004006f8 <+1>:	mov    rbp,rsp
   0x00000000004006fb <+4>:	sub    rsp,0x20
   0x00000000004006ff <+8>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000400708 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040070c <+21>:	xor    eax,eax
   0x000000000040070e <+23>:	mov    rax,QWORD PTR [rip+0x20094b]        # 0x601060 <stdout@@GLIBC_2.2.5>
   0x0000000000400715 <+30>:	mov    ecx,0x0
   0x000000000040071a <+35>:	mov    edx,0x2
   0x000000000040071f <+40>:	mov    esi,0x0
   0x0000000000400724 <+45>:	mov    rdi,rax
   0x0000000000400727 <+48>:	call   0x400600 <setvbuf@plt>
   0x000000000040072c <+53>:	lea    rax,[rip+0x111]        # 0x400844
   0x0000000000400733 <+60>:	mov    QWORD PTR [rbp-0x20],rax
   0x0000000000400737 <+64>:	lea    rdi,[rip+0x113]        # 0x400851
   0x000000000040073e <+71>:	mov    eax,0x0
   0x0000000000400743 <+76>:	call   0x4005e0 <printf@plt>
   0x0000000000400748 <+81>:	mov    rdx,QWORD PTR [rip+0x200921]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x000000000040074f <+88>:	lea    rax,[rbp-0x15]
   0x0000000000400753 <+92>:	mov    esi,0xd
   0x0000000000400758 <+97>:	mov    rdi,rax
   0x000000000040075b <+100>:	call   0x4005f0 <fgets@plt>
   0x0000000000400760 <+105>:	mov    rcx,QWORD PTR [rbp-0x20]
   0x0000000000400764 <+109>:	lea    rax,[rbp-0x15]
   0x0000000000400768 <+113>:	mov    edx,0xc
   0x000000000040076d <+118>:	mov    rsi,rcx
   0x0000000000400770 <+121>:	mov    rdi,rax
   0x0000000000400773 <+124>:	call   0x4005b0 <strncmp@plt>
   0x0000000000400778 <+129>:	test   eax,eax
   0x000000000040077a <+131>:	jne    0x40078a <main+147>
   0x000000000040077c <+133>:	lea    rdi,[rip+0xe7]        # 0x40086a
   0x0000000000400783 <+140>:	call   0x4005c0 <puts@plt>
   0x0000000000400788 <+145>:	jmp    0x400796 <main+159>
   0x000000000040078a <+147>:	lea    rdi,[rip+0xf7]        # 0x400888
   0x0000000000400791 <+154>:	call   0x4005c0 <puts@plt>
   0x0000000000400796 <+159>:	mov    eax,0x0
   0x000000000040079b <+164>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000040079f <+168>:	xor    rcx,QWORD PTR fs:0x28
   0x00000000004007a8 <+177>:	je     0x4007af <main+184>
   0x00000000004007aa <+179>:	call   0x4005d0 <__stack_chk_fail@plt>
   0x00000000004007af <+184>:	leave  
   0x00000000004007b0 <+185>:	ret    
End of assembler dump.
```


### Breakpoints: Stopping program at certain function/instruction

Breakpoints are used to stop a program at certain instruction or functions such that to examine registers or check what is causing problem. These breakpoint pause the binary at the address, running the process in background providing an enviornment for debugging`. Breakpoints in gdb can be provided by:-


##### Breakpoint at function

For setting up a breakpoint at a function, this automatically put the breakpoint at the start of function:-

* Syntax: `(gdb) break *<function_name>`

Alternatively: `(gdb) b *<function_name>`

To setup a breakpoint at a function's instruction, for example if we want to add a breakpoint at the `call` instruction which is calling `strncmp`, we do that by:-

* Syntax: `(gdb) break *<function_name> + <offset_of_the_instruction>`

```r
(gdb) break *main + 124
Breakpoint 1 at 0x400773
```
This in return will show the specific address at which the breakpoint is set.


##### Breakpoint at instruction

Let's say, if we want to setup the breakpoint again at the `call strncmp`, we do that by:-

* Syntax: `(gdb) break *<address_of_instruction>`

```r
(gdb) b *0x0000000000400773
Breakpoint 1 at 0x400773
```

##### Deleting Breakpoints

To delete a breakpoint, you have to type `del`, this will delete all the breakpoints that you set earlier. 

* Syntax: `(gdb) del`

##### Continuing execution after breakpoints

To continue after a breakpoint, we type `continue` or it's equivalent `c` to continue the execution of the program after the breakpoint.

Syntax: `(gdb) continue`

Example:-

```r
(gdb) b *main + 124
Breakpoint 1 at 0x400773
(gdb) r
Starting program: PwnLand/binaries/examples/example1 
Enter flag to validate: hello

Breakpoint 1, 0x0000000000400773 in main ()
(gdb) c
Continuing.
Not the valid flag.
[Inferior 1 (process 12987) exited normally]
```


### Examining Memory and Registers

We can examine memory addresses, blocks and registers in gdb while the binary is in debug session. To view a memory we do:-

* Syntax: `(gdb) x/<nf> <address/register>`

> where `n` would be number of values you want to see and `f` being in which format you want to see.

Some of the common formats includes:-

* `x/s` : This will print the string value which is stored at the `<addr>`.
* `x/x` : This will print the hex value stored at `<addr>`.
* `x/c` : This will print the character value stored at `<addr>`.
* `x/d` : This will print decimal value stored at `<addr>`.
* `x/o` : This will print octal value stored at `<addr>`
* `x/i` : This will print the instruction stored at `<addr>`.
* `x/f` : This will print the float value stored at `<addr>`.
* `x/t` : This will print the binary value stored at `<addr>`.

Some of the size format include:-

> `N` and `F` are number and format respectively.

* `x/NwF` : Print word formatted value stored at `<addr>`.
* `x/NgF` : Print giant formatted value stored at `<addr>`.
* `x/NhF` : Print half word formatted value stored at `<addr>`.
* `x/NbF` : Print byte formatted value stored at `<addr>`.

> To access registers, you can use `(gdb) x/NF ${register}`, for example if you want to access `rip` and see the instruction stored in it, you have to `x/i $rip`. 


Let's see it in an example but before that set a breakpoint at `call strncmp` so we will check out the registers used for input and the other variable it is comparing the input to. But before that let's see which registers we need to check, from the disassembly of `main` function, we know that:-

```r
   0x0000000000400768 <+113>:	mov    edx,0xc
   0x000000000040076d <+118>:	mov    rsi,rcx
   0x0000000000400770 <+121>:	mov    rdi,rax
   0x0000000000400773 <+124>:	call   0x4005b0 <strncmp@plt>
```

So, we know that `int strncmp(const char *s1, const char *s2, size_t n);` which means it take 3 arguments. Since this is a `x86_64` bit binary, the arguments to any function are passed with the help of registers i.e. the memory units containing specific values. 
According to `x86_64` calling conventions arguments are passed:-

* 1st argument is passed to `rdi`.
* 2nd argument is passed to `rsi`.
* 3rd argument is passed to `rdx`.
* 4th argument is passed to `rcx` and so on.

* `const char *s1` would be stored in `rdi`.
* `const char *s2` would be stored in `rsi`
* `size_t n` would be stored in `rdx`(`edx` there because of efficiency, since value is significantly lower, `edx` is used.)

Now, let's see it in action:-

```r
(gdb) r
Starting program: PwnLand/binaries/examples/example1 
Enter flag to validate: hello

Breakpoint 1, 0x0000000000400773 in main ()
(gdb) x/s $rdi
0x7fffffffdcbb:	"hello\n"
(gdb) x/s $rsi
0x400844:	"flag{gotcha}"
(gdb) x/s $rdx
0xc:	<error: Cannot access memory at address 0xc>
```

Now, it shows that `s1` is the input we gave which is `hello\n` and `s2` is `flag{gotcha}` and the `size_t n` is `0xc` which is 12.

***
`(gdb) x/s $rdx`
0xc:	<error: Cannot access memory at address 0xc>

You cannot access memory here becuase both the other registers `rdi` and `rsi` points to memory address which contains those strings while `edx` itself contains `0xc` value which is size not an address.
***

##### Checking `regsiters`

To get all the information of `registers`, we do `info registers` to print all the values of the corresponding registers.

```r
(gdb) r
Starting program: PwnLand/binaries/examples/example1 
Enter flag to validate: hello

Breakpoint 1, 0x0000000000400773 in main ()
(gdb) info registers 
rax            0x7fffffffdcfb	140737488346363
rbx            0x0	0
rcx            0x400844	4196420
rdx            0xc	12
rsi            0x400844	4196420
rdi            0x7fffffffdcfb	140737488346363
rbp            0x7fffffffdd10	0x7fffffffdd10
rsp            0x7fffffffdcf0	0x7fffffffdcf0
r8             0x602266	6300262
r9             0x7ffff7fd24c0	140737353950400
r10            0x602010	6299664
r11            0x246	582
r12            0x400610	4195856
r13            0x7fffffffddf0	140737488346608
r14            0x0	0
r15            0x0	0
rip            0x400773	0x400773 <main+124>
eflags         0x246	[ PF ZF IF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
```


### `set` 

This is a very useful command to use while debugging. Although there are number of useful functions that can be done with `set` but this is a basics walkthrough, I'll only add useful commands. Apparently, `set` includes a number of commands, helping you in debugging. Since this is a basic walkthrough I'll only include the ones you'll mostly need in clearing off your basics. Let's start away:-

##### `set` for modifying register value 

With the help of set you can set the values of a register such that it can ease your debugging process. This is a helpful command in case you want to change the workflow of a binary by changing it at runtime for further analysis.
To change a value of register during debug we do :-

* Syntax: `set ${register}={address/value}`

For example:-

> Setup a breakpoint at `call strncmp` for changing the register value of `rdi` at runtime in order to change workflow.

```r
(gdb) x/s $rdi
0x7fffffffdcfb:	"hello\n"
(gdb) x/s $rsi
0x400844:	"flag{gotcha}"
(gdb) set $rdi=0x41414141
(gdb) x/s $rdi
0x41414141:	<error: Cannot access memory at address 0x41414141>
```

As you can see, using `set $rdi=0x41414141` to set the value of the input we gave it. Since `rdi` stores the address which points to any value stored at that address. As we gave `0x41414141`, it's recognised as an address but since it's an invalid address we get `0x41414141:	<error: Cannot access memory at address 0x41414141>`.

As an alternatively, we can set the value of a register to of another register. We do that by:-

* Syntax: `set $rdi=${register}`

Example:-

```r
(gdb) r
Starting program: /media/robin/New Volume/Projects/PwnLand/binaries/examples/example1 
Enter flag to validate: helloworld

Breakpoint 1, 0x0000000000400773 in main ()
(gdb) x/s $rdi
0x7fffffffdcfb:	"helloworld\n"
(gdb) x/s $rsi
0x400844:	"flag{gotcha}"
(gdb) set $rdi=$rsi
(gdb) c
Continuing.
Correct, you may now proceed.
[Inferior 1 (process 13175) exited normally]
(gdb) 
```

As you can see with `set $rdi=$rsi`, we set the input we gave to the program to that of string which is being compared to input that is `flag{gotcha}`.

### Following specific process

There are 2 types of process that spawned, one being the master and second being the child. Using `gdb` you can follow specific process by using:-

* Syntax: `set follow-fork-mode {child/master}`
  
This will tell `gdb` to follow either child or master, depending on the mode set.

---

Chapter 1: END

---