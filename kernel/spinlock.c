// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <libos/spinlock.h>

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(libos_spinlock_t* spinlock)
{
    unsigned int value = 1;

    asm volatile("lock xchg %0, %1;"
                 : "=r"(value)     /* %0 */
                 : "m"(*spinlock), /* %1 */
                   "0"(value)      /* also %2 */
                 : "memory");

    return value;
}

int libos_spin_init(libos_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    *spinlock = LIBOS_SPINLOCK_INITIALIZER;

    return 0;
}

int libos_spin_lock(libos_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    while (_spin_set_locked((volatile unsigned int*)spinlock) != 0)
    {
        /* Spin while waiting for spinlock to be released (become 1) */
        while (*spinlock)
        {
            /* Yield to CPU */
            asm volatile("pause");
        }
    }

    return 0;
}

int libos_spin_unlock(libos_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    asm volatile("movl %0, %1;"
                 :
                 : "r"(LIBOS_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
                 : "memory");

    return 0;
}

int libos_spin_destroy(libos_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    return 0;
}
