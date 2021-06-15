// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <stdlib.h>
#include <sys/times.h>

#include <myst/assume.h>
#include <myst/clock.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/printf.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/times.h>

/* Time spent by the main thread and its children */
struct tms process_times;

MYST_INLINE long lapsed_nsecs(struct timespec t0, struct timespec t1)
{
    return (t1.tv_sec - t0.tv_sec) * NANO_IN_SECOND + (t1.tv_nsec - t0.tv_nsec);
}

MYST_INLINE void set_timespec_from_nanos(struct timespec* tp, long nanos)
{
    tp->tv_sec = nanos / NANO_IN_SECOND;
    tp->tv_nsec = nanos % NANO_IN_SECOND;
}

static bool is_zero_tp(struct timespec* tp)
{
    return tp->tv_sec == 0 && tp->tv_nsec == 0;
}

void myst_times_start()
{
    myst_thread_t* thread = myst_thread_self();
    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &thread->start_ts);
}

long __myst_syscall_times[MYST_MAX_SYSCALLS];

void myst_times_enter_kernel(long syscall_num)
{
    myst_thread_t* current = myst_thread_self();

    (void)syscall_num;

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->enter_kernel_ts);

    // Thread might be entering the kernel for the first time
    if (is_zero_tp(&current->leave_kernel_ts))
        current->leave_kernel_ts = current->start_ts;

    long lapsed =
        lapsed_nsecs(current->leave_kernel_ts, current->enter_kernel_ts);
    myst_assume(lapsed >= 0);

    __atomic_fetch_add(&process_times.tms_utime, lapsed, __ATOMIC_SEQ_CST);
}

void myst_times_leave_kernel(long syscall_num)
{
    myst_thread_t* current = myst_thread_self();
    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->leave_kernel_ts);

    long lapsed =
        lapsed_nsecs(current->enter_kernel_ts, current->leave_kernel_ts);

    if (__myst_kernel_args.trace_syscall_times)
        __myst_syscall_times[syscall_num] += lapsed;

    myst_assume(lapsed > 0);
    __atomic_fetch_add(&process_times.tms_stime, lapsed, __ATOMIC_SEQ_CST);
}

long myst_times_system_time()
{
    return process_times.tms_stime;
}

long myst_times_user_time()
{
    return process_times.tms_utime;
}

long myst_times_process_time()
{
    return process_times.tms_stime + process_times.tms_utime +
           process_times.tms_cstime + process_times.tms_cutime;
}

long myst_times_thread_time()
{
    myst_thread_t* current = myst_thread_self();
    long lapsed = lapsed_nsecs(current->start_ts, current->enter_kernel_ts);
    return lapsed;
}

long myst_times_uptime()
{
    return process_times.tms_stime + process_times.tms_utime;
}

long myst_times_get_cpu_clock_time(clockid_t clk_id, struct timespec* tp)
{
    pid_t tid = CPU_CLOCK_TID(clk_id);
    int per_thread = CPU_CLOCK_PERTHREAD(clk_id);

    if (per_thread)
    {
        myst_thread_t* current = myst_thread_self();
        if (tid == current->tid)
        {
            long nanoseconds = myst_times_thread_time();
            set_timespec_from_nanos(tp, nanoseconds);
        }
        else
        {
            myst_thread_t* t = myst_find_thread(tid);
            if (!t)
                return -EINVAL;

            long nanoseconds = lapsed_nsecs(t->start_ts, t->enter_kernel_ts);
            set_timespec_from_nanos(tp, nanoseconds);
        }
    }
    else
    {
        long nanoseconds = myst_times_process_time();
        set_timespec_from_nanos(tp, nanoseconds);
    }

    return 0;
}

#define COLOR_GREEN "\e[32m"
#define COLOR_CYAN "\e[36m"
#define COLOR_RESET "\e[0m"

void myst_print_syscall_times(void)
{
    typedef struct times
    {
        long num;
        long nsec;
    } times_t;
    size_t ntimes = 0;
    struct locals
    {
        times_t times[MYST_MAX_SYSCALLS];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        goto done;

    for (size_t i = 0; i < MYST_MAX_SYSCALLS; i++)
    {
        if (__myst_syscall_times[i])
        {
            locals->times[ntimes].num = i;
            locals->times[ntimes].nsec = __myst_syscall_times[i];
            ntimes++;
        }
    }

    /* sort the times in desending order */
    for (size_t i = 0; i < ntimes - 1; i++)
    {
        for (size_t j = 0; j < ntimes - 1; j++)
        {
            if (locals->times[j].nsec < locals->times[j + 1].nsec)
            {
                times_t tmp = locals->times[j];
                locals->times[j] = locals->times[j + 1];
                locals->times[j + 1] = tmp;
            }
        }
    }

    myst_eprintf(COLOR_CYAN "\n");

    for (size_t i = 0; i < ntimes; i++)
    {
        const times_t* p = &locals->times[i];
        myst_eprintf("%12ld: %s\n", p->nsec, myst_syscall_str(p->num));
    }

    myst_eprintf("\n");

    myst_eprintf(COLOR_RESET "\n");

done:

    if (locals)
        free(locals);
}
