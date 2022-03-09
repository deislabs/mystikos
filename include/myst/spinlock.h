// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SPINLOCK_H
#define _MYST_SPINLOCK_H

#include <errno.h>
#include <myst/assume.h>
#include <myst/defs.h>
#include <myst/types.h>

#define MYST_SPINLOCK_INITIALIZER 0

// #define MYST_SPINLOCK_BUILTINS
#define MYST_SPINLOCK_ASSEMBLY

/*
**==============================================================================
**
** MYST_SPINLOCK_BUILTINS: based on gcc builtin atomics
**
**==============================================================================
*/

#ifdef MYST_SPINLOCK_BUILTINS

typedef volatile int myst_spinlock_t;

MYST_INLINE void myst_spin_lock(myst_spinlock_t* s)
{
    while (*(volatile int*)s || __sync_val_compare_and_swap(s, 0, 1))
        __asm__ __volatile__("pause" : : : "memory");
}

MYST_INLINE void myst_spin_unlock(myst_spinlock_t* s)
{
    __sync_lock_test_and_set(s, 0);
}

#endif /* MYST_SPINLOCK_BUILTINS */

/*
**==============================================================================
**
** MYST_SPINLOCK_ASSEMBLY: based on inline assembly
**
**==============================================================================
*/

#ifdef MYST_SPINLOCK_ASSEMBLY

typedef volatile int myst_spinlock_t;

MYST_INLINE void myst_spin_lock(myst_spinlock_t* spinlock)
{
    for (;;)
    {
        unsigned int previous_value = 1;

        /* Set the spinlock value to 1 and save the previous value */
        asm volatile("lock xchg %0, %1;"
                     : "=r"(previous_value) /* %0 */
                     : "m"(*spinlock),      /* %1 */
                       "0"(previous_value)  /* %2 */
                     : "memory");

        /* If the spinlock was unlocked then break out */
        if (previous_value == 0)
            break;

        /* Spin while waiting for spinlock to be released */
        while (*spinlock)
        {
            /* Yield to CPU */
            asm volatile("pause");
        }
    }
}

MYST_INLINE void myst_spin_unlock(myst_spinlock_t* spinlock)
{
    asm volatile("movl %0, %1;"
                 :
                 : "r"(MYST_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
                 : "memory");
}

#endif /* MYST_SPINLOCK_ASSEMBLY */

#endif /* _MYST_SPINLOCK_H */
