#include <libos/barrier.h>
#include <libos/fsgs.h>
#include <libos/options.h>
#include <libos/panic.h>
#include <libos/printf.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <libos/tcall.h>

void libos_set_fsbase(void* p)
{
    if (__options.have_syscall_instruction)
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

void* libos_get_fsbase(void)
{
    if (__options.have_syscall_instruction)
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

void libos_set_gsbase(void* p)
{
    if (__options.have_syscall_instruction)
    {
        const long ARCH_SET_GS = 0x1001;
        const long n = SYS_arch_prctl;
        libos_syscall2(n, ARCH_SET_GS, (long)p);
    }
    else
    {
        /* unsupported but not needed */
        libos_panic("wrgsbase emulation is unsupported");
    }
}

void* libos_get_gsbase(void)
{
    if (__options.have_syscall_instruction)
    {
        const long ARCH_GET_GS = 0x1004;
        const long n = SYS_arch_prctl;
        void* p;
        libos_syscall2(n, ARCH_GET_GS, (long)&p);
        return p;
    }
    else
    {
        void* p;
        __asm__ volatile("mov %%gs:0, %0" : "=r"(p));
        return p;
    }
}
