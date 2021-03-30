// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <myst/clock.h>
#include <myst/cond.h>
#include <myst/eraise.h>
#include <myst/mutex.h>
#include <myst/process.h>
#include <myst/syscall.h>
#include <myst/time.h>
#include <myst/timeval.h>

/* ATTN: currently the itimer is only for the single process case */
typedef struct itimer
{
    myst_cond_t cond;
    uint64_t real_interval; /* ITIMER_REAL interval */
    uint64_t real_value;    /* ITIMER_REAL value */
    myst_mutex_t mutex;
    _Atomic(int) initialized;
    bool cancel;
} itimer_t;

static itimer_t _it;

/* get time as microseconds since epoch: return 0 on failure */
static uint64_t _get_current_time(void)
{
    uint64_t ret;
    struct timespec ts;
    struct timeval tv;

    if (myst_syscall_clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;

    /* downgrade from nanosecond to microsecond granularity */
    tv.tv_sec = ts.tv_sec;
    tv.tv_usec = ts.tv_nsec / 1000;

    /* convert timeval to uint64 */
    if (myst_timeval_to_uint64(&tv, &ret) != 0)
        return 0;

    return ret;
}

static void _update_and_check_expiration(uint64_t start, uint64_t end)
{
    uint64_t elapsed = end - start;

    /* update the timer */
    if (elapsed < _it.real_value)
        _it.real_value -= elapsed;
    else
        _it.real_value = 0;

    /* if timer expired */
    if (_it.real_value == 0)
    {
        myst_syscall_kill(myst_getpid(), SIGALRM);
        _it.real_value = _it.real_interval;
    }
}

long myst_syscall_run_itimer(void)
{
    myst_mutex_lock(&_it.mutex);
    {
        _it.initialized = 1;

        for (;;)
        {
            struct timespec buf;
            struct timespec* to;

            /* if ITIMER_REAL is non-zero */
            if (_it.real_value == 0)
            {
                to = NULL;
            }
            else
            {
                size_t PULSE = MICRO_IN_SECOND / 1000; /* one millisecond */
                size_t min = PULSE;

                if (_it.real_value < min)
                    min = _it.real_value;

                to = &buf;
                to->tv_sec = min / 1000000;
                to->tv_nsec = (min * 1000) % NANO_IN_SECOND;
            }

            uint64_t start = _get_current_time();
            int r = myst_cond_timedwait(&_it.cond, &_it.mutex, to);
            uint64_t end = _get_current_time();

            if (_it.cancel)
                break;

            assert(start != 0);
            assert(end != 0);
            assert(end >= start);

            /* if recieved a signal on condition */
            if (r == 0)
            {
                /* no-op */
            }
            else if (r == ETIMEDOUT)
            {
                _update_and_check_expiration(start, end);
            }
        }
    }
    myst_mutex_unlock(&_it.mutex);

    return 0;
}

long myst_syscall_setitimer(
    int which,
    const struct itimerval* new_value,
    struct itimerval* old_value)
{
    long ret = 0;
    uint64_t interval;
    uint64_t value;

    /* ATTN: only ITIMER_REAL is supported so far */
    if (which != ITIMER_REAL || !new_value)
        ERAISE(-EINVAL);

    /* convert new_value to uint64_t */
    ECHECK(myst_timeval_to_uint64(&new_value->it_interval, &interval));
    ECHECK(myst_timeval_to_uint64(&new_value->it_value, &value));

    /* wait for itimer thread to obtain the mutex for the first time */
    while (_it.initialized == 0)
    {
        __asm__ __volatile__("pause" : : : "memory");
    }

    myst_mutex_lock(&_it.mutex);
    {
        if (old_value)
        {
            myst_uint64_to_timeval(_it.real_interval, &old_value->it_interval);
            myst_uint64_to_timeval(_it.real_value, &old_value->it_value);
        }

        /* set the new value for the itimer */
        _it.real_interval = interval;
        _it.real_value = value;

        /* signal the itimer thread */
        if (myst_cond_signal(&_it.cond) != 0)
        {
            myst_mutex_unlock(&_it.mutex);
            ERAISE(-ENOSYS);
        }
    }
    myst_mutex_unlock(&_it.mutex);

done:
    return ret;
}

int myst_syscall_getitimer(int which, struct itimerval* curr_value)
{
    int ret = 0;

    if (curr_value)
        memset(curr_value, 0, sizeof(struct itimerval));

    /* ATTN: only ITIMER_REAL is supported so far */
    if (which != ITIMER_REAL || !curr_value)
        ERAISE(-EINVAL);

    myst_mutex_lock(&_it.mutex);
    myst_uint64_to_timeval(_it.real_value, &curr_value->it_value);
    myst_uint64_to_timeval(_it.real_interval, &curr_value->it_interval);
    myst_mutex_unlock(&_it.mutex);

done:
    return ret;
}

long myst_cancel_itimer(void)
{
    long ret = 0;

    myst_mutex_lock(&_it.mutex);
    {
        _it.cancel = true;

        /* signal the itimer thread */
        if (myst_cond_signal(&_it.cond) != 0)
        {
            myst_mutex_unlock(&_it.mutex);
            ERAISE(-ENOSYS);
        }
    }
    myst_mutex_unlock(&_it.mutex);

done:
    return ret;
}
