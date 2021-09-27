// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_COND_H
#define _MYST_COND_H

#include <myst/mutex.h>
#include <myst/spinlock.h>
#include <myst/thread.h>
#include <time.h>

typedef struct _posix_cond
{
    myst_spinlock_t lock;
    myst_thread_queue_t queue;
} myst_cond_t;

int myst_cond_init(myst_cond_t* c);

int myst_cond_destroy(myst_cond_t* c);

int myst_cond_wait(myst_cond_t* c, myst_mutex_t* mutex);

int myst_cond_timedwait(
    myst_cond_t* c,
    myst_mutex_t* mutex,
    const struct timespec* timeout);

int myst_cond_timedwait_ops(
    myst_cond_t* c,
    myst_mutex_t* mutex,
    const struct timespec* timeout,
    uint32_t bitset);

int myst_cond_signal(myst_cond_t* c);

int myst_cond_signal_ops(myst_cond_t* c, uint32_t bitset);

int myst_cond_signal_thread(myst_cond_t* c, myst_thread_t* thread);

/* Wake up n waiters */
int myst_cond_broadcast(myst_cond_t* c, size_t n);

int myst_cond_broadcast_ops(myst_cond_t* c, size_t n, uint32_t bitset);

int myst_cond_requeue(
    myst_cond_t* c1,
    myst_cond_t* c2,
    size_t wake_count,
    size_t requeue_count);

#endif //_MYST_COND_H
