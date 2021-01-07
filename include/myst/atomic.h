// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ATOMIC_H
#define _MYST_ATOMIC_H

#include <myst/defs.h>
#include <myst/types.h>

MYST_INLINE int myst_atomic_exchange(volatile int* ptr, int value)
{
    __asm__ __volatile__("xchg %0, %1"
                         : "=r"(value), "=m"(*ptr)
                         : "0"(value)
                         : "memory");

    return value;
}

#endif /* _MYST_ATOMIC_H */
