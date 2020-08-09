#ifndef _POSIX_FUTEX_H
#define _POSIX_FUTEX_H

#include <time.h>
#include "posix_thread.h"

int posix_futex_owner(volatile int* uaddr, posix_thread_t** owner);

int posix_futex_acquire(volatile int* uaddr);

int posix_futex_release(volatile int* uaddr);

int posix_futex_wait(
    int* uaddr,
    int futex_op,
    int val,
    const struct timespec *timeout);

int posix_futex_wake(int* uaddr, int futex_op, int val);

int posix_futex_requeue(
    int* uaddr,
    int futex_op,
    int val,
    int val2,
    int* uaddr2);

#endif /* _POSIX_FUTEX_H */
