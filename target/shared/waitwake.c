// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <linux/futex.h>
#include <myst/eraise.h>
#include <myst/thread.h>
#include <myst/times.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

long myst_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    volatile int* uaddr = (volatile int*)event;

    /* if *uaddr == 0 */
    if (__sync_fetch_and_add(uaddr, -1) == 0)
    {
        do
        {
            long ret;

            /* wait while *uaddr == -1 (or until timed out) */
            ret = syscall(
                SYS_futex, uaddr, FUTEX_WAIT_PRIVATE, -1, timeout, NULL, 0);

            if (ret != 0 && errno == ETIMEDOUT)
            {
                /* if *uaddr is still negative one, then reset to zero */
                __sync_val_compare_and_swap(uaddr, -1, 0);
                return -ETIMEDOUT;
            }
        } while (*uaddr == -1);
    }

    return 0;
}

long myst_tcall_wake(uint64_t event)
{
    long ret = 0;
    volatile int* uaddr = (volatile int*)event;

    if (__sync_fetch_and_add(uaddr, 1) != 0)
    {
        /* returns the number of waiters that were woken up on success */
        ret = syscall(SYS_futex, uaddr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);

        /* The syscall wrapper should return -1 or a positive number */
        assert(ret >= -1);

        if (ret == -1)
            ret = -errno;
    }

    return ret;
}

long myst_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long ret;

    /* if wake fails, return the error unless it is EAGAIN */
    if ((ret = myst_tcall_wake(waiter_event)) < 0)
    {
        if (ret != -EAGAIN)
            return ret;
    }

    return myst_tcall_wait(self_event, timeout);
}
