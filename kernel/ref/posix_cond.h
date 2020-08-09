// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _POSIX_COND_H
#define _POSIX_COND_H

#include "posix_thread.h"
#include "posix_spinlock.h"
#include "posix_mutex.h"
#include "posix_time.h"

typedef struct _posix_cond
{
    posix_spinlock_t lock;
    posix_thread_queue_t queue;
}
posix_cond_t;

int posix_cond_init(posix_cond_t* c);

int posix_cond_destroy(posix_cond_t* c);

int posix_cond_wait(posix_cond_t* c, posix_mutex_t* mutex);

int posix_cond_timedwait(
    posix_cond_t* c,
    posix_mutex_t* mutex,
    const struct posix_timespec* timeout);

int posix_cond_signal(posix_cond_t* c);

/* Wake up n waiters */
int posix_cond_broadcast(posix_cond_t* c, size_t n);

int posix_cond_requeue(
    posix_cond_t* c1,
    posix_cond_t* c2,
    size_t wake_count,
    size_t requeue_count);

#endif //_POSIX_COND_H
