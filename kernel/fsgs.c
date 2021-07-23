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
    if (__myst_kernel_args.have_fsgsbase_instructions)
    {
        __asm__ volatile("wrfsbase %0" ::"r"(p));
    }
    else if (__options.have_syscall_instruction)
    {
        myst_syscall2(SYS_arch_prctl, ARCH_SET_FS, (long)p);
    }
    else
    {
        myst_panic("unsupported");
    }
}

void* myst_get_fsbase(void)
{
    void* p;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
    return p;
}

void myst_set_gsbase(void* p)
{
    if (__myst_kernel_args.have_fsgsbase_instructions)
    {
        __asm__ volatile("wrgsbase %0" ::"r"(p));
    }
    else if (__options.have_syscall_instruction)
    {
        myst_syscall2(SYS_arch_prctl, ARCH_SET_GS, (long)p);
    }
    else
    {
        myst_panic("unsupported");
    }
}

void* myst_get_gsbase(void)
{
    void* p;
    __asm__ volatile("mov %%gs:0, %0" : "=r"(p));
    return p;
}
