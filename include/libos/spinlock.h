#ifndef _LIBOS_SPINLOCK_H
#define _LIBOS_SPINLOCK_H

#include <errno.h>
#include <libos/defs.h>
#include <libos/types.h>

#define LIBOS_SPINLOCK_INITIALIZER 0

// #define LIBOS_SPINLOCK_BUILTINS
#define LIBOS_SPINLOCK_ASSEMBLY

/*
**==============================================================================
**
** LIBOS_SPINLOCK_BUILTINS: based on gcc builtin atomics
**
**==============================================================================
*/

#ifdef LIBOS_SPINLOCK_BUILTINS

typedef volatile int libos_spinlock_t;

LIBOS_INLINE void libos_spin_lock(libos_spinlock_t* s)
{
    while (*(volatile int*)s || __sync_val_compare_and_swap(s, 0, 1))
        __asm__ __volatile__("pause" : : : "memory");
}

LIBOS_INLINE void libos_spin_unlock(libos_spinlock_t* s)
{
    __sync_lock_test_and_set(s, 0);
}

#endif /* LIBOS_SPINLOCK_BUILTINS */

/*
**==============================================================================
**
** LIBOS_SPINLOCK_ASSEMBLY: based on inline assembly
**
**==============================================================================
*/

#ifdef LIBOS_SPINLOCK_ASSEMBLY

typedef volatile int libos_spinlock_t;

LIBOS_INLINE void libos_spin_lock(libos_spinlock_t* spinlock)
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

LIBOS_INLINE void libos_spin_unlock(libos_spinlock_t* spinlock)
{
    asm volatile("movl %0, %1;"
                 :
                 : "r"(LIBOS_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
                 : "memory");
}

#endif /* LIBOS_SPINLOCK_ASSEMBLY */

#endif /* _LIBOS_SPINLOCK_H */
