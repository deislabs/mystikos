#include <errno.h>

#include <libos/thread.h>
#include <libos/cond.h>
#include <libos/malloc.h>
#include <libos/futex.h>
#include <libos/strings.h>
#include <libos/eraise.h>
#include <libos/atexit.h>

/*
**==============================================================================
**
** local definitions:
**
**==============================================================================
*/

#define NUM_CHAINS 1024

#if 0
#define DEBUG_TRACE
#endif

typedef struct futex futex_t;

struct futex
{
    futex_t* next;
    size_t refs;
    int* uaddr;
    libos_cond_t cond;
    libos_mutex_t mutex;
};

static futex_t* _chains[NUM_CHAINS];
static bool _installed_free_futexes;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

static void _free_futexes(void* arg)
{
    (void)arg;

    for (size_t i = 0; i <  NUM_CHAINS; i++)
    {
        for (futex_t* p = _chains[i]; p; )
        {
            futex_t* next = p->next;
            libos_free(p);
            p = next;
        }
    }
}

static futex_t* _get_futex(int* uaddr)
{
    futex_t* ret = NULL;
    uint64_t index = ((uint64_t)uaddr >> 4) % NUM_CHAINS;
    futex_t* f;

    libos_spin_lock(&_lock);

    if (!_installed_free_futexes)
    {
        libos_atexit(_free_futexes, NULL);
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

    if (!(f = libos_calloc(1, sizeof(futex_t))))
        goto done;

    f->refs = 1;
    f->uaddr = uaddr;
    f->next = _chains[index];
    _chains[index] = f;

    ret = f;

done:

    libos_spin_unlock(&_lock);

    return ret;
}

static int _put_futex(int* uaddr)
{
#if 0
    int ret = -1;
    uint64_t index = ((uint64_t)uaddr >> 2) % NUM_CHAINS;
    futex_t* prev = NULL;

    libos_spin_lock(&_lock);

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

                libos_free(p);
            }

            ret = 0;
            goto done;
        }

        prev = p;
    }

done:
    libos_spin_unlock(&_lock);

    return ret;
#else
    (void)uaddr;
    return 0;
#endif
}

static bool _is_ownwer(libos_mutex_t* m)
{
#if 0
    return libos_self() == m->owner;
#else
    (void)m;
    return true;
#endif
}

static int _futex_wait(
    int* uaddr,
    int op,
    int val,
    const struct timespec* to)
{
    int ret = 0;
    futex_t* f = NULL;

#if defined(DEBUG_TRACE)
    libos_printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
#endif

    if (!uaddr || (op != FUTEX_WAIT && op != (FUTEX_WAIT|FUTEX_PRIVATE)))
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(f = _get_futex(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

    libos_mutex_lock(&f->mutex);
    {
        int retval;

        if (*uaddr != val)
        {
            libos_mutex_unlock(&f->mutex);
            ret = -EAGAIN;
            goto done;
        }

        retval = libos_cond_timedwait(&f->cond, &f->mutex, to);

        if (retval != 0)
            ret = -retval;
    }
    libos_mutex_unlock(&f->mutex);

done:

    if (f)
        _put_futex(uaddr);

    return ret;
}

static int _futex_wake(int* uaddr, int op, int val)
{
    int ret = 0;
    futex_t* f = NULL;
    bool locked = false;

#if defined(DEBUG_TRACE)
    libos_printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
#endif

    if (!uaddr || (op != FUTEX_WAKE && op != (FUTEX_WAKE|FUTEX_PRIVATE)))
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(f = _get_futex(uaddr)))
    {
        ret = -ENOMEM;
        goto done;
    }

#if 1
    libos_mutex_lock(&f->mutex);
    locked = true;
#else
    if (!_is_ownwer(&f->mutex))
        libos_panic("not mutex owner");
#endif

    if (val == 1)
    {
        if (libos_cond_signal(&f->cond) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }
    else if (val > 1)
    {
        size_t n = (val == INT_MAX) ? SIZE_MAX : (size_t)val;

        if (libos_cond_broadcast(&f->cond, n) != 0)
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
        libos_mutex_unlock(&f->mutex);

    if (f)
        _put_futex(uaddr);

    return ret;
}

static int _futex_requeue(
    int* uaddr,
    int op,
    int val,
    int val2,
    int* uaddr2)
{
    int ret = 0;
    futex_t* f = NULL;
    futex_t* f2 = NULL;

#if defined(DEBUG_TRACE)
    libos_printf("%s(): uaddr=%p\n", __FUNCTION__, uaddr);
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

    if (!_is_ownwer(&f->mutex) || !_is_ownwer(&f2->mutex))
        libos_panic("not mutex owner");

    /* Invoke libos_cond_requeue() */
    {
        size_t wake_count = (val == INT_MAX) ? SIZE_MAX : (size_t)val;
        size_t requeue_count = (val2 == INT_MAX) ? SIZE_MAX : (size_t)val2;

        if (libos_cond_requeue(
            &f->cond,
            &f2->cond,
            wake_count,
            requeue_count) != 0)
        {
            ret = -ENOSYS;
            goto done;
        }
    }

done:

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

long libos_syscall_futex(
    int* uaddr,
    int op,
    int val,
    long arg, /* timeout or val2 */
    int* uaddr2,
    int val3)
{
    long ret = 0;

    (void)val3;

    if (op == FUTEX_WAIT || op == (FUTEX_WAIT|FUTEX_PRIVATE))
    {
        ECHECK(_futex_wait(uaddr, op, val, (const struct timespec*)arg));
    }
    else if (op == FUTEX_WAKE || op == (FUTEX_WAKE|FUTEX_PRIVATE))
    {
        ECHECK(_futex_wake(uaddr, op, val));
    }
    else if (op == FUTEX_REQUEUE || op == (FUTEX_REQUEUE|FUTEX_PRIVATE))
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
