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
#include <myst/kernel.h>
#include <myst/mutex.h>
#include <myst/process.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/timeval.h>

typedef struct myst_itimer
{
    myst_cond_t cond;
    uint64_t real_interval;   /* ITIMER_REAL interval */
    uint64_t real_value;      /* ITIMER_REAL value */
    uint64_t wait_start_time; /* time we enter wait */
    myst_mutex_t mutex;
    _Atomic(int) initialized;
} myst_itimer_t;

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

static void _update_and_check_expiration(
    myst_process_t* process,
    uint64_t start,
    uint64_t end)
{
    uint64_t elapsed = end - start;

    /* update the timer */
    if (elapsed < process->itimer->real_value)
        process->itimer->real_value -= elapsed;
    else
        process->itimer->real_value = 0;

    /* if timer expired */
    if (process->itimer->real_value == 0)
    {
        myst_syscall_kill(process->pid, SIGALRM);
        process->itimer->real_value = process->itimer->real_interval;
    }
}

long myst_syscall_run_itimer(myst_process_t* process)
{
    myst_mutex_lock(&process->itimer->mutex);
    {
        process->itimer->initialized = 1;

        for (;;)
        {
            struct timespec buf;
            struct timespec* to;

            /* if ITIMER_REAL is non-zero */
            if (process->itimer->real_value == 0)
            {
                to = NULL;
            }
            else
            {
                size_t real_time = process->itimer->real_value;

                to = &buf;
                to->tv_sec = real_time / 1000000;
                to->tv_nsec = (real_time * 1000) % NANO_IN_SECOND;
            }

            process->itimer->wait_start_time = _get_current_time();
            int r = myst_cond_timedwait(
                &process->itimer->cond,
                &process->itimer->mutex,
                to,
                FUTEX_BITSET_MATCH_ANY);
            uint64_t end = _get_current_time();

            assert(process->itimer->wait_start_time != 0);
            assert(end != 0);
            assert(end >= process->itimer->wait_start_time);

            /* if received a signal on condition */
            if (r == 0)
            {
                /* no-op */
            }
            else
            {
                /* Any other response, including timeout, we need to update the
                 * timer so our wait is accurate on the next iteration */
                _update_and_check_expiration(
                    process, process->itimer->wait_start_time, end);
            }
        }
    }
    myst_mutex_unlock(&process->itimer->mutex);

    return 0;
}

static long _init_itimer(myst_process_t* process)
{
    /* Need to make sure things are initialized for this process */
    bool wanted_status = false;
    if (__atomic_compare_exchange_n(
            &process->itimer_thread_requested,
            &wanted_status,
            true,
            false,
            __ATOMIC_RELEASE,
            __ATOMIC_ACQUIRE))
    {
        /* First we need to allocate the structure */
        process->itimer = calloc(1, sizeof(myst_itimer_t));
        if (process->itimer == NULL)
        {
            process->itimer_thread_requested = false;
            return -ENOMEM;
        }

        /* This is a specialized error that we specifically return to launch the
         * thread in the CRT. */
        return -EAGAIN;
    }

    /* wait for itimer thread to obtain the mutex for the first time */
    while (process->itimer->initialized == 0)
    {
        __asm__ __volatile__("pause" : : : "memory");
    }

    return 0;
}

long myst_syscall_setitimer(
    myst_process_t* process,
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

    if (new_value && !myst_is_addr_within_kernel(new_value))
        ERAISE(-EFAULT);

    if (old_value && !myst_is_addr_within_kernel(old_value))
        ERAISE(-EFAULT);

    /* convert new_value to uint64_t */
    ECHECK(myst_timeval_to_uint64(&new_value->it_interval, &interval));
    ECHECK(myst_timeval_to_uint64(&new_value->it_value, &value));

    ECHECK(_init_itimer(process));

    myst_mutex_lock(&process->itimer->mutex);
    {
        if (old_value)
        {
            uint64_t end = _get_current_time();
            uint64_t elapsed = end - process->itimer->wait_start_time;
            uint64_t real_value = process->itimer->real_value;

            if (elapsed < real_value)
                real_value -= elapsed;
            else
                real_value = 0;

            myst_uint64_to_timeval(
                process->itimer->real_interval, &old_value->it_interval);
            myst_uint64_to_timeval(real_value, &old_value->it_value);
        }

        /* set the new value for the itimer */
        process->itimer->real_interval = interval;
        process->itimer->real_value = value;

        /* signal the itimer thread */
        if (myst_cond_signal(&process->itimer->cond, FUTEX_BITSET_MATCH_ANY) !=
            0)
        {
            myst_mutex_unlock(&process->itimer->mutex);
            ERAISE(-ENOSYS);
        }
    }
    myst_mutex_unlock(&process->itimer->mutex);

done:
    return ret;
}

int myst_syscall_getitimer(
    myst_process_t* process,
    int which,
    struct itimerval* curr_value)
{
    int ret = 0;

    /* ATTN: only ITIMER_REAL is supported so far */
    if (which != ITIMER_REAL || !curr_value)
        ERAISE(-EINVAL);

    if (curr_value && !myst_is_addr_within_kernel(curr_value))
        ERAISE(-EFAULT);

    if (curr_value)
        memset(curr_value, 0, sizeof(struct itimerval));

    ECHECK(_init_itimer(process));

    myst_mutex_lock(&process->itimer->mutex);
    {
        uint64_t end = _get_current_time();
        uint64_t elapsed = end - process->itimer->wait_start_time;
        uint64_t real_value = process->itimer->real_value;

        if (elapsed < real_value)
            real_value -= elapsed;
        else
            real_value = 0;

        myst_uint64_to_timeval(real_value, &curr_value->it_value);
        myst_uint64_to_timeval(
            process->itimer->real_interval, &curr_value->it_interval);
    }
    myst_mutex_unlock(&process->itimer->mutex);

done:
    return ret;
}
