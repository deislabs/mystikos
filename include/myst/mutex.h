// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MUTEX_H
#define _MYST_MUTEX_H

#include <myst/spinlock.h>
#include <myst/thread.h>

#define MYST_MUTEX_INITIALIZER    \
    {                             \
        MYST_SPINLOCK_INITIALIZER \
    }

typedef struct _myst_mutex myst_mutex_t;

struct _myst_mutex
{
    myst_spinlock_t lock;
    uint64_t refs;
    myst_thread_t* owner;
    myst_thread_queue_t queue;
};

int myst_mutex_init(myst_mutex_t* mutex);

int myst_mutex_lock(myst_mutex_t* mutex);

int myst_mutex_trylock(myst_mutex_t* mutex);

int myst_mutex_unlock(myst_mutex_t* mutex);

int myst_mutex_destroy(myst_mutex_t* mutex);

myst_thread_t* myst_mutex_owner(myst_mutex_t* m);

int __myst_mutex_trylock(myst_mutex_t* m, myst_thread_t* self);

int __myst_mutex_unlock(myst_mutex_t* mutex, myst_thread_t** waiter);

#endif /* _MYST_MUTEX_H */
