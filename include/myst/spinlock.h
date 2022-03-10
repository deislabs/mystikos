// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SPINLOCK_H
#define _MYST_SPINLOCK_H

#include <assert.h>
#include <errno.h>
#include <myst/defs.h>
#include <myst/types.h>

#define MYST_SPINLOCK_INITIALIZER ((myst_spinlock_t)0)

// #define MYST_SPINLOCK_BUILTINS
#define MYST_SPINLOCK_ASSEMBLY

typedef volatile uint64_t myst_spinlock_t;

MYST_INLINE uint64_t __myst_spin_self(void)
{
    myst_spinlock_t self;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(self));
    return self;
}

/*
**==============================================================================
**
** MYST_SPINLOCK_BUILTINS: based on gcc builtin atomics
**
**==============================================================================
*/

#ifdef MYST_SPINLOCK_BUILTINS

MYST_INLINE void myst_spin_lock(myst_spinlock_t* s)
{
    uint64_t thread_id = __myst_spin_self();

    while (*s || __sync_val_compare_and_swap(s, 0, thread_id))
        __asm__ __volatile__("pause" : : : "memory");
}

MYST_INLINE void myst_spin_unlock(myst_spinlock_t* s)
{
    uint64_t thread_id = __myst_spin_self();
    assert(*spinlock == thread_id);

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

MYST_INLINE void myst_spin_lock(myst_spinlock_t* spinlock)
{
    uint64_t thread_id = __myst_spin_self();

    for (;;)
    {
        uint64_t previous_value;

        /* Set spinlock to thread_id if it is equal to RAX (zero). */
        asm volatile("lock cmpxchg %2, %1;"
                     : "=a"(previous_value) /* %0 RAX */
                     : "m"(*spinlock),      /* %1 */
                       "r"(thread_id),      /* %2 */
                       "a"(0L)              /* %3 RAX */
                     : "memory", "cc");

        /* If the spinlock was unlocked then break out */
        if (previous_value == 0)
            break;

        // Detect recursive calls.
        {
            bool recursive_spin_lock_call = (previous_value == thread_id);
            assert(!recursive_spin_lock_call);
        }

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
    uint64_t thread_id = __myst_spin_self();
    assert(*spinlock == thread_id);

    asm volatile("movq %1, %0;"
                 : "=m"(*spinlock)
                 : "c"(MYST_SPINLOCK_INITIALIZER)
                 : "memory");
}

#endif /* MYST_SPINLOCK_ASSEMBLY */

#endif /* _MYST_SPINLOCK_H */
