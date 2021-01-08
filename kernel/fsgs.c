// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/barrier.h>
#include <myst/fsgs.h>
#include <myst/options.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>

void myst_set_fsbase(void* p)
{
    if (__options.have_syscall_instruction)
    {
        const long ARCH_SET_FS = 0x1002;
        const long n = SYS_arch_prctl;
        myst_syscall2(n, ARCH_SET_FS, (long)p);
    }
    else
    {
        __asm__ volatile("wrfsbase %0" ::"r"(p));
    }
}

void* myst_get_fsbase(void)
{
    if (__options.have_syscall_instruction)
    {
        const long ARCH_GET_FS = 0x1003;
        const long n = SYS_arch_prctl;
        void* p;
        myst_syscall2(n, ARCH_GET_FS, (long)&p);
        return p;
    }
    else
    {
        void* p;
        __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
        return p;
    }
}

void myst_set_gsbase(void* p)
{
    if (__options.have_syscall_instruction)
    {
        const long ARCH_SET_GS = 0x1001;
        const long n = SYS_arch_prctl;
        myst_syscall2(n, ARCH_SET_GS, (long)p);
    }
    else
    {
        /* unsupported but not needed */
        myst_panic("wrgsbase emulation is unsupported");
    }
}

void* myst_get_gsbase(void)
{
    if (__options.have_syscall_instruction)
    {
        const long ARCH_GET_GS = 0x1004;
        const long n = SYS_arch_prctl;
        void* p;
        myst_syscall2(n, ARCH_GET_GS, (long)&p);
        return p;
    }
    else
    {
        void* p;
        __asm__ volatile("mov %%gs:0, %0" : "=r"(p));
        return p;
    }
}
