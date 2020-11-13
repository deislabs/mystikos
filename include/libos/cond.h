// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_COND_H
#define _LIBOS_COND_H

#include <libos/mutex.h>
#include <libos/spinlock.h>
#include <time.h>

typedef struct _posix_cond
{
    libos_spinlock_t lock;
    libos_thread_queue_t queue;
} libos_cond_t;

int libos_cond_init(libos_cond_t* c);

int libos_cond_destroy(libos_cond_t* c);

int libos_cond_wait(libos_cond_t* c, libos_mutex_t* mutex);

int libos_cond_timedwait(
    libos_cond_t* c,
    libos_mutex_t* mutex,
    const struct timespec* timeout);

int libos_cond_signal(libos_cond_t* c);

/* Wake up n waiters */
int libos_cond_broadcast(libos_cond_t* c, size_t n);

int libos_cond_requeue(
    libos_cond_t* c1,
    libos_cond_t* c2,
    size_t wake_count,
    size_t requeue_count);

#endif //_LIBOS_COND_H
