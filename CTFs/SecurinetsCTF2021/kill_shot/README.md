# Kill Shot


# Vulnerabilities

* Format String Vulnerability
* Arbitrary write to a known location once.
* Heap Exploitation

# Protections

* Seccomp enabled, hence `execve` disabled, Allowed syscalls: `openat`, `read` & `write`.
* Full RELRO
* PIE
* Canary

# Exploitation

* Leak the LIBC/ELF base address from the format string.
* Overwrite the `__free_hook` with the `setcontext + 53` to pivot the stack as needed in order to read flag via ROP chain.

* Prepare a SROP payload being `read(0, __free_hook + 0x10, 0x120)` and `rsp` pointing to the same.
* Prepare the ROP chain as:-

```C
openat("flag.txt", 0)
read(3. addr, 0x50)
write(1, addr, 0x50)
```

* Allocate two chunks, 0th being the junk, second one being the SROP payload
* Trigger the SROP payload with the `setcontext + 53` and let the ROP chain excutes.


