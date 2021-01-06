// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <sys/times.h>

#include <myst/assume.h>
#include <myst/clock.h>
#include <myst/eraise.h>
#include <myst/syscall.h>
#include <myst/thread.h>

/* Time spent by the main thread and its children */
struct tms process_times;

MYST_INLINE long lapsed_nsecs(struct timespec t0, struct timespec t1)
{
    return (t1.tv_sec - t0.tv_sec) * NANO_IN_SECOND + (t1.tv_nsec - t0.tv_nsec);
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

void myst_times_enter_kernel()
{
    myst_thread_t* current = myst_thread_self();

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->enter_kernel_ts);

    // Thread might be entering the kernel for the first time
    if (is_zero_tp(&current->leave_kernel_ts))
        current->leave_kernel_ts = current->start_ts;

    long lapsed =
        lapsed_nsecs(current->leave_kernel_ts, current->enter_kernel_ts);
    myst_assume(lapsed >= 0);
    __atomic_fetch_add(&process_times.tms_utime, lapsed, __ATOMIC_SEQ_CST);
}

void myst_times_leave_kernel()
{
    myst_thread_t* current = myst_thread_self();
    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->leave_kernel_ts);

    long lapsed =
        lapsed_nsecs(current->enter_kernel_ts, current->leave_kernel_ts);
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
