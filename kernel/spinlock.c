// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <libos/spinlock.h>
#include <libos/crash.h>
#include <libos/deprecated.h>

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

void libos_spin_lock(libos_spinlock_t* spinlock)
{
    if (!spinlock)
        libos_crash();

    while (_spin_set_locked((volatile unsigned int*)spinlock) != 0)
    {
        /* Spin while waiting for spinlock to be released (become 1) */
        while (*spinlock)
        {
            /* Yield to CPU */
            asm volatile("pause");
        }
    }
}

void libos_spin_unlock(libos_spinlock_t* spinlock)
{
    if (!spinlock)
        libos_crash();

    asm volatile("movl %0, %1;"
                 :
                 : "r"(LIBOS_SPINLOCK_INITIALIZER), "m"(*spinlock) /* %1 */
                 : "memory");
}

void libos_recursive_spin_lock(libos_recursive_spinlock_t* s, long thread)
{
    libos_spin_lock(&s->owner_lock);
    {
        if (s->owner == thread)
        {
            s->count++;
            libos_spin_unlock(&s->owner_lock);
            return;
        }
    }
    libos_spin_unlock(&s->owner_lock);

    libos_spin_lock(&s->lock);
    libos_spin_lock(&s->owner_lock);
    s->count = 1;
    s->owner = thread;
    libos_spin_unlock(&s->owner_lock);
}

void libos_recursive_spin_unlock(libos_recursive_spinlock_t* s, long thread)
{
    libos_spin_lock(&s->owner_lock);
    {
        if (s->owner != thread)
            libos_crash();

        if (--s->count == 0)
        {
            s->owner = 0;
            s->count = 0;
            libos_spin_unlock(&s->owner_lock);
            libos_spin_unlock(&s->lock);
            return;
        }
    }
    libos_spin_unlock(&s->owner_lock);
}
