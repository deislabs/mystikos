#include <errno.h>
#include <libos/eraise.h>
#include <libos/thread.h>
#include <linux/futex.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>

long libos_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    volatile int* uaddr = (volatile int*)event;

    /* if *uaddr == 0 */
#if 1
    if (__sync_fetch_and_add(uaddr, -1) == 0)
#else
    int32_t expected = 0;
    int32_t desired = -1;
    bool weak = false;
    // if uaddr == expected: uaddr := desired (and return true)
    if (!__atomic_compare_exchange_n(
            uaddr,
            &expected,
            desired,
            weak,
            __ATOMIC_ACQ_REL,
            __ATOMIC_ACQUIRE))
#endif
    {
        do
        {
            long ret;

            /* wait if *uaddr == -1 */
            ret = syscall(
                SYS_futex, uaddr, FUTEX_WAIT_PRIVATE, -1, timeout, NULL, 0);

            if (ret != 0 && errno == ETIMEDOUT)
                return ETIMEDOUT;
        } while (*uaddr == -1);
    }

    return 0;
}

long libos_tcall_wake(uint64_t event)
{
    long ret = 0;
    volatile int* uaddr = (volatile int*)event;

    if (__sync_fetch_and_add(uaddr, 1) != 0)
    {
        ret = syscall(SYS_futex, uaddr, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);

        if (ret != 0)
            ret = -errno;
    }

    return ret;
}

long libos_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long ret;

    if ((ret = libos_tcall_wake(waiter_event)) != 0)
    {
        if (ret != -EAGAIN)
            return ret;
    }

    if ((ret = libos_tcall_wait(self_event, timeout)) != 0)
        return ret;

    return 0;
}
