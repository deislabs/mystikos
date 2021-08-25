// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <stdlib.h>

#include <myst/atexit.h>
#include <myst/cond.h>
#include <myst/eraise.h>
#include <myst/futex.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/times.h>

/*
**==============================================================================
**
** local definitions:
**
**==============================================================================
*/

#define NUM_CHAINS 64

#if 0
#define DEBUG_TRACE
#endif

typedef struct futex futex_t;

struct futex
{
    futex_t* next;
    size_t refs;
    volatile int* uaddr;
    myst_cond_t cond;
    myst_mutex_t mutex;
};

static futex_t* _chains[NUM_CHAINS];
static bool _installed_free_futexes;

#if 1
static myst_spinlock_t _spin = MYST_SPINLOCK_INITIALIZER;
static void _lock(void)
{
    myst_spin_lock(&_spin);
}
static void _unlock(void)
{
    myst_spin_unlock(&_spin);
}
#else
static myst_mutex_t _mutex;
static void _lock(void)
{
    myst_mutex_lock(&_mutex);
}
static void _unlock(void)
{
    myst_mutex_unlock(&_mutex);
}
#endif

static void _free_futexes(void* arg)
{
    (void)arg;

    for (size_t i = 0; i < NUM_CHAINS; i++)
    {
        for (futex_t* p = _chains[i]; p;)
        {
            futex_t* next = p->next;
            free(p);
            p = next;
        }
    }
}

static futex_t* _get_futex(volatile int* uaddr)
{
    futex_t* ret = NULL;
    uint64_t index = ((uint64_t)uaddr >> 4) % NUM_CHAINS;
    futex_t* f;

    _lock();

    if (!_installed_free_futexes)
    {
        myst_atexit(_free_futexes, NULL);
        _installed_free_futexes = true;
    }

    for (futex_t* p = _chains[index]; p; p = p->next)
    {
        if (p->uaddr == uaddr)
        {
            p->refs++;
            ret = p;
            goto done;
        }
    }

    if (!(f = calloc(1, sizeof(futex_t))))
        goto done;

    f->refs = 1;
    f->uaddr = uaddr;
    f->next = _chains[index];
    _chains[index] = f;

    ret = f;

done:

    _unlock();

    return ret;
}

static int _put_futex(int* uaddr)
{
#if 0
    int ret = -1;
    uint64_t index = ((uint64_t)uaddr >> 2) % NUM_CHAINS;
    futex_t* prev = NULL;

    myst_spin_lock(&_lock);

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

                free(p);
            }

            ret = 0;
            goto done;
        }

        prev = p;
    }

done:
    myst_spin_unlock(&_lock);

    return ret;
#else
    (void)uaddr;
    return 0;
#endif
}

int myst_futex_wait_ops(
    int* uaddr,
    int val,
    const struct timespec* to,
    uint32_t bitset)
{
    int ret = 0;
    futex_t* f = NULL;

#if defined(DEBUG_TRACE)
    printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
#endif

    if (!uaddr)
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(f = _get_futex(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    myst_mutex_lock(&f->mutex);
    {
        if (*uaddr != val)
        {
            myst_mutex_unlock(&f->mutex);
            ret = -EAGAIN;
            goto done;
        }

        ret = myst_cond_timedwait_ops(&f->cond, &f->mutex, to, bitset);
    }
    myst_mutex_unlock(&f->mutex);

done:

    if (f)
        _put_futex(uaddr);

    return ret;
}

int myst_futex_wait(int* uaddr, int val, const struct timespec* to)
{
    return myst_futex_wait_ops(uaddr, val, to, FUTEX_BITSET_MATCH_ANY);
}

int myst_futex_wake_ops(int* uaddr, int val, uint32_t bitset)
{
    int ret = 0;
    futex_t* f = NULL;
    bool locked = false;

#if defined(DEBUG_TRACE)
    printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
#endif

    if (!uaddr)
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(f = _get_futex(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    myst_mutex_lock(&f->mutex);
    locked = true;
    myst_assume(f->mutex.owner == myst_thread_self());

    if (val == 1)
    {
        if (myst_cond_signal_ops(&f->cond, bitset) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }

        /* return the number of threads that woke up */
        ret = 1;
    }
    else if (val > 1)
    {
        size_t n = (val == INT_MAX) ? SIZE_MAX : (size_t)val;
        int num_awoken;

        /* myst_cond_broadcast() returns the number of threads awoken */
        if ((num_awoken = myst_cond_broadcast_ops(&f->cond, n, bitset)) < 0)
        {
            ret = -ENOSYS;
            goto done;
        }

        ret = num_awoken;
    }
    else
    {
        ret = -ENOSYS;
        goto done;
    }

done:

    if (locked)
        myst_mutex_unlock(&f->mutex);

    if (f)
        _put_futex(uaddr);

    return ret;
}

int myst_futex_wake(int* uaddr, int val)
{
    return myst_futex_wake_ops(uaddr, val, FUTEX_BITSET_MATCH_ANY);
}

static int _futex_requeue(int* uaddr, int op, int val, int val2, int* uaddr2)
{
    int ret = 0;
    futex_t* f = NULL;
    futex_t* f2 = NULL;
    bool locked = false;
    bool locked2 = false;

#if defined(DEBUG_TRACE)
    printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
#endif

    if (!uaddr ||
        (op != FUTEX_REQUEUE && op != (FUTEX_REQUEUE | FUTEX_PRIVATE)))
    {
        ret = -EINVAL;
        goto done;
    }

    if ((val < 0 && val != INT_MAX) || (val2 < 0 && val != INT_MAX))
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(f = _get_futex(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    if (!(f2 = _get_futex(uaddr2)))
    {
        ret = -ENOMEM;
        goto done;
    }

    myst_mutex_lock(&f->mutex);
    locked = true;
    myst_mutex_lock(&f2->mutex);
    locked2 = true;

    /* Invoke myst_cond_requeue() */
    {
        size_t wake_count = (val == INT_MAX) ? SIZE_MAX : (size_t)val;
        size_t requeue_count = (val2 == INT_MAX) ? SIZE_MAX : (size_t)val2;

        if (myst_cond_requeue(&f->cond, &f2->cond, wake_count, requeue_count) !=
            0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }

done:

    if (locked)
        myst_mutex_unlock(&f->mutex);

    if (locked2)
        myst_mutex_unlock(&f2->mutex);

    if (f)
        _put_futex(uaddr);

    if (f2)
        _put_futex(uaddr2);

    return ret;
}

/*
**==============================================================================
**
** public interface:
**
**==============================================================================
*/

long myst_syscall_futex(
    int* uaddr,
    int op,
    int val,
    long arg, /* timeout or val2 */
    int* uaddr2,
    int val3)
{
    long ret = 0;
    uint32_t bitset = FUTEX_BITSET_MATCH_ANY;
    int _op = op & ~(FUTEX_CLOCK_REALTIME | FUTEX_PRIVATE);

    if (op & FUTEX_CLOCK_REALTIME)
    {
        if (!((_op == FUTEX_WAIT_BITSET) ||
              (_op == FUTEX_WAIT))) // || (op | FUTEX_WAIT_REQUEUE_PI)
            ERAISE(-ENOSYS);
    }

    if (_op == FUTEX_WAIT_BITSET || _op == FUTEX_WAKE_BITSET)
    {
        if (!val3)
            ERAISE(-EINVAL);
        bitset = val3;
    }

    if (_op == FUTEX_WAIT || _op == FUTEX_WAIT_BITSET)
    {
        struct timespec* timeout = (struct timespec*)arg;
        if (op & FUTEX_CLOCK_REALTIME)
        {
            struct timespec timenow;
            myst_syscall_clock_gettime(CLOCK_REALTIME, &timenow);
            long int absolute_timeout_ns =
                timespec_to_nanos(timeout) - timespec_to_nanos(&timenow);
            absolute_timeout_ns =
                (absolute_timeout_ns < 0) ? 0 : absolute_timeout_ns;
            nanos_to_timespec(timeout, absolute_timeout_ns);
        }
        ECHECK(myst_futex_wait_ops(uaddr, val, timeout, bitset));
    }
    else if (_op == FUTEX_WAKE || _op == FUTEX_WAKE_BITSET)
    {
        int r;
        ECHECK((r = myst_futex_wake_ops(uaddr, val, bitset)));
        ret = r;
    }
    else if (_op == FUTEX_REQUEUE)
    {
        ECHECK(_futex_requeue(uaddr, op, val, (int)arg, uaddr2));
    }
    else
    {
        ERAISE(-ENOTSUP);
    }

done:
    return ret;
}
