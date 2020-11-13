// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_MUTEX_H
#define _LIBOS_MUTEX_H

#include <libos/spinlock.h>
#include <libos/thread.h>

typedef struct _libos_mutex libos_mutex_t;

struct _libos_mutex
{
    libos_spinlock_t lock;
    uint64_t refs;
    libos_thread_t* owner;
    libos_thread_queue_t queue;
};

int libos_mutex_init(libos_mutex_t* mutex);

int libos_mutex_lock(libos_mutex_t* mutex);

int libos_mutex_trylock(libos_mutex_t* mutex);

int libos_mutex_unlock(libos_mutex_t* mutex);

int libos_mutex_destroy(libos_mutex_t* mutex);

libos_thread_t* libos_mutex_owner(libos_mutex_t* m);

int __libos_mutex_trylock(libos_mutex_t* m, libos_thread_t* self);

int __libos_mutex_unlock(libos_mutex_t* mutex, libos_thread_t** waiter);

#endif /* _LIBOS_MUTEX_H */
