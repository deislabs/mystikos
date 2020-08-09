// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _POSIX_MUTEX_H
#define _POSIX_MUTEX_H

#include "posix_thread.h"
#include "posix_spinlock.h"

typedef struct _posix_mutex posix_mutex_t;

struct _posix_mutex
{
    posix_spinlock_t lock;
    uint64_t refs;
    posix_thread_t* owner;
    posix_thread_queue_t queue;
};

int posix_mutex_init(posix_mutex_t* mutex);

int posix_mutex_lock(posix_mutex_t* mutex);

int posix_mutex_trylock(posix_mutex_t* mutex);

int posix_mutex_unlock(posix_mutex_t* mutex);

int posix_mutex_destroy(posix_mutex_t* mutex);

posix_thread_t* posix_mutex_owner(posix_mutex_t* m);

int __posix_mutex_trylock(posix_mutex_t* m, posix_thread_t* self);

int __posix_mutex_unlock(posix_mutex_t* mutex, posix_thread_t** waiter);

#endif //_POSIX_MUTEX_H
