// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <oel/spinlock.h>

/* Set the spinlock value to 1 and return the old value */
static unsigned int _spin_set_locked(oel_spinlock_t* spinlock)
{
    unsigned int value = 1;

    asm volatile("lock xchg %0, %1;"
                 : "=r"(value)     /* %0 */
                 : "m"(*spinlock), /* %1 */
                   "0"(value)      /* also %2 */
                 : "memory");

    return value;
}

int oel_spin_init(oel_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    *spinlock = OEL_SPINLOCK_INITIALIZER;

    return 0;
}

int oel_spin_lock(oel_spinlock_t* spinlock)
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

int oel_spin_unlock(oel_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    asm volatile("movl %0, %1;"
                 :
                 : "r"(OEL_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
                 : "memory");

    return 0;
}

int oel_spin_destroy(oel_spinlock_t* spinlock)
{
    if (!spinlock)
        return -1;

    return 0;
}
