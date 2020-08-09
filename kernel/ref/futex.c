#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/sgxtypes.h>
#include "futex.h"
#include "posix_warnings.h"
#include "posix_futex.h"
#include "posix_io.h"
#include "posix_spinlock.h"
#include "posix_time.h"
#include "posix_trace.h"
#include "posix_mutex.h"
#include "posix_cond.h"
#include "posix_signal.h"

#define NUM_CHAINS 1024

typedef struct _futex futex_t;

struct _futex
{
    futex_t* next;
    size_t refs;
    int* uaddr;
    posix_cond_t cond;
    posix_mutex_t mutex;
};

static futex_t* _chains[NUM_CHAINS];
static posix_spinlock_t _lock = POSIX_SPINLOCK_INITIALIZER;

static futex_t* _get(int* uaddr)
{
    futex_t* ret = NULL;
    uint64_t index = ((uint64_t)uaddr >> 4) % NUM_CHAINS;
    futex_t* futex;

    posix_lock_kill();
    posix_spin_lock(&_lock);

    for (futex_t* p = _chains[index]; p; p = p->next)
    {
        if (p->uaddr == uaddr)
        {
            p->refs++;
            ret = p;
            goto done;
        }
    }

    if (!(futex = oe_calloc(1, sizeof(futex_t))))
        goto done;

    futex->refs = 1;
    futex->uaddr = uaddr;
    futex->next = _chains[index];
    _chains[index] = futex;

    ret = futex;

done:

    posix_spin_unlock(&_lock);
    posix_unlock_kill();

    return ret;
}

int posix_futex_owner(volatile int* uaddr, posix_thread_t** owner)
{
    futex_t* futex;

    if (owner)
        *owner = NULL;

    if (!uaddr || !owner)
        return -1;

    if (!(futex = _get((int*)uaddr)))
        return -1;

    *owner = posix_mutex_owner(&futex->mutex);
    return 0;
}

#if 0
static int _put(int* uaddr)
{
    int ret = -1;
    uint64_t index = ((uint64_t)uaddr >> 2) % NUM_CHAINS;
    futex_t* prev = NULL;

    posix_spin_lock(&_lock);

    for (futex_t* p = _chains[index]; p; p = p->next)
    {
        if (p->uaddr == uaddr)
        {
            p->refs--;

            if (p->refs == 0)
            {
                if (prev)
                    prev->next = p->next;
                else
                    _chains[index] = p->next;

                oe_free(p);
            }

            ret = 0;
            goto done;
        }

        prev = p;
    }

done:
    posix_spin_unlock(&_lock);

    return ret;
}
#endif

static bool _is_ownwer(posix_mutex_t* m)
{
    return posix_self() == m->owner;
}

int posix_futex_acquire(volatile int* uaddr)
{
    futex_t* futex;

    if (!(futex = _get((int*)uaddr)))
        return -1;

    if (posix_mutex_lock(&futex->mutex) != 0)
        return -1;

    return 0;
}

int posix_futex_release(volatile int* uaddr)
{
    futex_t* futex = NULL;

    if (!(futex = _get((int*)uaddr)))
        return -1;

    if (posix_mutex_unlock(&futex->mutex) != 0)
        return -1;

    return 0;
}
int posix_futex_wait(
    int* uaddr,
    int op,
    int val,
    const struct timespec *timeout)
{
    int ret = 0;
    futex_t* futex = NULL;

#if defined(DEBUG_TRACE)
    posix_printf("posix_futex_wait(): uaddr=%p\n", uaddr);
    posix_print_backtrace();
#endif

    if (!uaddr || (op != FUTEX_WAIT && op != (FUTEX_WAIT|FUTEX_PRIVATE)))
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(futex = _get(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    posix_mutex_lock(&futex->mutex);
    {
        if (*uaddr != val)
        {
            posix_mutex_unlock(&futex->mutex);
            ret = -EAGAIN;
            goto done;
        }

        int retval = posix_cond_timedwait(
            &futex->cond,
            &futex->mutex,
            (const struct posix_timespec*)timeout);

        if (retval != 0)
            ret = -retval;
    }

    posix_mutex_unlock(&futex->mutex);

done:

    return ret;
}

int posix_futex_wake(int* uaddr, int op, int val)
{
    int ret = 0;
    futex_t* futex = NULL;

#if defined(DEBUG_TRACE)
    posix_printf("posix_futex_wake(): uaddr=%p\n", uaddr);
#endif

    if (!uaddr || (op != FUTEX_WAKE && op != (FUTEX_WAKE|FUTEX_PRIVATE)))
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(futex = _get(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    if (!_is_ownwer(&futex->mutex))
    {
        posix_printf("posix_futex_wake(): caller does not own this mutex\n");
        posix_printf("self=%p owner=%p\n", posix_self(), futex->mutex.owner);
        posix_print_backtrace();
        oe_abort();
    }

    if (val == 1)
    {
        if (posix_cond_signal(&futex->cond) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }
    else if (val > 1)
    {
        size_t n = (val == INT_MAX) ? SIZE_MAX : (size_t)val;

        if (posix_cond_broadcast(&futex->cond, n) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }
    else
    {
        ret = -ENOSYS;
        goto done;
    }

done:

    return ret;
}

int posix_futex_requeue(
    int* uaddr,
    int op,
    int val,
    int val2,
    int* uaddr2)
{
    int ret = 0;
    futex_t* futex = NULL;
    futex_t* futex2 = NULL;

#if defined(DEBUG_TRACE)
    posix_printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
#endif

    if (!uaddr || (op != FUTEX_REQUEUE && op != (FUTEX_REQUEUE|FUTEX_PRIVATE)))
    {
        ret = -EINVAL;
        goto done;
    }

    if ((val < 0 && val != INT_MAX) || (val2 < 0 && val != INT_MAX))
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(futex = _get(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    if (!(futex2 = _get(uaddr2)))
    {
        ret = -ENOMEM;
        goto done;
    }

    if (!_is_ownwer(&futex->mutex) || !_is_ownwer(&futex2->mutex))
    {
        posix_printf("%s(): caller does not own these mutexes\n", __FUNCTION__);
        posix_print_backtrace();
        oe_abort();
    }

    /* Invoke posix_cond_requeue() */
    {
        size_t wake_count = (val == INT_MAX) ? SIZE_MAX : (size_t)val;
        size_t requeue_count = (val2 == INT_MAX) ? SIZE_MAX : (size_t)val2;

        if (posix_cond_requeue(
            &futex->cond,
            &futex2->cond,
            wake_count,
            requeue_count) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }

done:

    return ret;
}
