// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RSPINLOCK_H
#define _MYST_RSPINLOCK_H

#include <assert.h>

#include <myst/fsgs.h>
#include <myst/spinlock.h>
#include <myst/thread.h>

#define MYST_RSPINLOCK_INITIALIZER \
    {                              \
        0                          \
    }

/* recursive spinlock type */
typedef struct myst_rspinlock
{
    myst_spinlock_t owner_lock;
    void* owner;
    size_t count;
    myst_spinlock_t lock;
} myst_rspinlock_t;

// CAUTION: FSBASE must not be changed while the lock is held, since the lock
// implementation uses the FSBASE as the lock owner identity.
MYST_INLINE void myst_rspin_lock(myst_rspinlock_t* s)
{
    myst_spin_lock(&s->owner_lock);
    {
        /* if calling thread already owns the lock */
        if (myst_get_fsbase() == s->owner)
        {
            s->count++;
            myst_spin_unlock(&s->owner_lock);
            return;
        }
    }
    myst_spin_unlock(&s->owner_lock);

    /* wait on the lock */
    myst_spin_lock(&s->lock);
    s->owner = myst_get_fsbase();
    s->count = 1;
}

MYST_INLINE void myst_rspin_unlock(myst_rspinlock_t* s)
{
    assert(s->count > 0);
    assert(s->owner == myst_get_fsbase());

    if (--s->count == 0)
    {
        s->owner = NULL;
        myst_spin_unlock(&s->lock);
    }
}

#endif /* _MYST_RSPINLOCK_H */
