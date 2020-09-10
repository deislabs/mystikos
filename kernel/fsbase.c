#include <libos/fsbase.h>
#include <libos/options.h>
#include <libos/syscall.h>

void libos_set_fs_base(const void* p)
{
    if (libos_get_real_syscalls())
    {
        const long ARCH_SET_FS = 0x1002;
        const long n = SYS_arch_prctl;
        libos_syscall2(n, ARCH_SET_FS, (long)p);
    }
    else
    {
        __asm__ volatile("wrfsbase %0" ::"r"(p));
    }
}

const void* libos_get_fs_base(void)
{
    if (libos_get_real_syscalls())
    {
        const long ARCH_GET_FS = 0x1003;
        const long n = SYS_arch_prctl;
        void* p;
        libos_syscall2(n, ARCH_GET_FS, (long)&p);
        return p;
    }
    else
    {
        void* p;
        __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
        return p;
    }
}
