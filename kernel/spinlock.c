// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <libos/spinlock.h>
#include <libos/strings.h>

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
            libos_panic("not owner");

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
