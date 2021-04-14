# Death Note


# Vulnerabilities

* OOB write in the `edit` function.
* The array which holds the allocated chunks is allocated on the heap, being a good target to reference the chunks using the negative index for OOB.
# Protections

* Canary
* Full RELRO
* PIE

# Exploitation

Since the target LIBC is the LIBC 2.27, bear in mind that the `tcache` is used.

* Allocate 9 chunks, 7 for the `tcache`, 2 for the usual heap leak by propagating the FD.
* Delete the chunk `0` and `1` and allocate again, such that the FD would be populated and we can leak the FD.
* Fill the `tcache` bins and then one more in the `unsorted` bin such that FD & BK would be populated with the `main_arena` address.
* Since, the UAF is not possible, allocate the chunks again and refill the 8th chunk's FD with the 8 bytes with `a` and with that leak the BK and get the LIBC address.

* Fill the tcache bins again.
* Allocate 3 chunks, different size than previous chunks. (0xff, this time)
* Delete two chunks. (0xff this time)
* Use the OOB vulnerability in the `edit` function to get the `heap_list[0]` and overwriting the `FD` of the `free`'d chunk with the `__free_hook`.
* Perform the Tcache poisoning, overwrite the `__free_hook` with the `system` and store the `/bin/sh\x00` in `heap_list[0]`.
* Trigger the `__free_hook` by `free`ing the `heap_list[1]` -> `system("/bin/sh\x00")`.