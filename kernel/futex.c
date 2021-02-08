// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <stdlib.h>

#include <myst/atexit.h>
#include <myst/cond.h>
#include <myst/eraise.h>
#include <myst/futex.h>
#include <myst/strings.h>
#include <myst/thread.h>

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

int myst_futex_wait(int* uaddr, int val, const struct timespec* to)
{
    int ret = 0;
    futex_t* f = NULL;
    myst_thread_t* me = myst_thread_self();

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
        int retval;

        if (*uaddr != val)
        {
            myst_mutex_unlock(&f->mutex);
            ret = -EAGAIN;
            goto done;
        }

        // Give termination signal handler a chance to wake up the thread.
        me->signal.cond_wait = &f->cond;

        retval = myst_cond_timedwait(&f->cond, &f->mutex, to);

        me->signal.cond_wait = NULL;

        if (retval != 0)
            ret = -retval;
    }
    myst_mutex_unlock(&f->mutex);

done:

    if (f)
        _put_futex(uaddr);

    return ret;
}

int myst_futex_wake(int* uaddr, int val)
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
        if (myst_cond_signal(&f->cond) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }
    else if (val > 1)
    {
        size_t n = (val == INT_MAX) ? SIZE_MAX : (size_t)val;

        if (myst_cond_broadcast(&f->cond, n) != 0)
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

    if (locked)
        myst_mutex_unlock(&f->mutex);

    if (f)
        _put_futex(uaddr);

    return ret;
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

    (void)val3;

    if (op == FUTEX_WAIT || op == (FUTEX_WAIT | FUTEX_PRIVATE))
    {
        ECHECK(myst_futex_wait(uaddr, val, (const struct timespec*)arg));
    }
    else if (op == FUTEX_WAKE || op == (FUTEX_WAKE | FUTEX_PRIVATE))
    {
        ECHECK(myst_futex_wake(uaddr, val));
    }
    else if (op == FUTEX_REQUEUE || op == (FUTEX_REQUEUE | FUTEX_PRIVATE))
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
