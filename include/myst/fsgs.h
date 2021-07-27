// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FSGS_H
#define _MYST_FSGS_H

#include <myst/defs.h>
#include <myst/options.h>
#include <myst/types.h>

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

MYST_INLINE void myst_set_fsbase(void* p)
{
    extern void __myst_set_fsbase(void* p);

    if (MYST_LIKELY(__myst_kernel_args.have_fsgsbase_instructions))
        __asm__ volatile("wrfsbase %0" ::"r"(p));
    else
        __myst_set_fsbase(p);
}

MYST_INLINE void* myst_get_fsbase(void)
{
    extern void* __myst_get_fsbase(void);

    if (MYST_LIKELY(__options.have_fsgsbase_instructions))
    {
        void* p;
        __asm__ volatile("rdfsbase %0" : "=r"(p));
        return p;
    }

    return __myst_get_fsbase();
}

MYST_INLINE void myst_set_gsbase(void* p)
{
    extern void __myst_set_gsbase(void* p);

    if (MYST_LIKELY(__myst_kernel_args.have_fsgsbase_instructions))
        __asm__ volatile("wrgsbase %0" ::"r"(p));
    else
        __myst_set_gsbase(p);
}

MYST_INLINE void* myst_get_gsbase(void)
{
    extern void* __myst_get_gsbase(void);

    if (MYST_LIKELY(__myst_kernel_args.have_fsgsbase_instructions))
    {
        void* p;
        __asm__ volatile("rdgsbase %0" : "=r"(p));
        return p;
    }

    return __myst_get_gsbase();
}

#endif /* _MYST_FSGS_H */
