// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RSPINLOCK_H
#define _MYST_RSPINLOCK_H

#include <assert.h>

#include <myst/spinlock.h>

// clang-format off
#define MYST_RSPINLOCK_INITIALIZER { 0 }
// clang-format on

/* recursive spinlock type */
typedef struct myst_rspinlock
{
    myst_spinlock_t owner_lock;
    void* owner;
    _Atomic(size_t) count;
    myst_spinlock_t lock;
} myst_rspinlock_t;

MYST_INLINE void* __myst_rspin_self(void)
{
    void* self;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(self));
    return self;
}

// CAUTION: FSBASE must not be changed while the lock is held, since the lock
// implementation uses the FSBASE as the lock owner identity.
MYST_INLINE void myst_rspin_lock(myst_rspinlock_t* s)
{
    myst_spin_lock(&s->owner_lock);
    {
        /* if calling thread already owns the lock */
        if (__myst_rspin_self() == s->owner)
        {
            s->count++;
            myst_spin_unlock(&s->owner_lock);
            return;
        }
    }
    myst_spin_unlock(&s->owner_lock);

    /* wait on the lock */
    myst_spin_lock(&s->lock);
    s->owner = __myst_rspin_self();
    s->count = 1;
}

MYST_INLINE void myst_rspin_unlock(myst_rspinlock_t* s)
{
    assert("rspin unlock with bad count" && s->count > 0);
    assert(
        "rspin unlock with non-owner thread" &&
        s->owner == __myst_rspin_self());

    if (--s->count == 0)
    {
        s->owner = NULL;
        myst_spin_unlock(&s->lock);
    }
}

#endif /* _MYST_RSPINLOCK_H */
