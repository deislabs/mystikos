// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <sys/times.h>

#include <libos/assume.h>
#include <libos/clock.h>
#include <libos/eraise.h>
#include <libos/syscall.h>
#include <libos/thread.h>

/* Time spent by the main thread and its children */
struct tms process_times;

LIBOS_INLINE long lapsed_nsecs(struct timespec t0, struct timespec t1)
{
    return (t1.tv_sec - t0.tv_sec) * NANO_IN_SECOND + (t1.tv_nsec - t0.tv_nsec);
}

static bool is_zero_tp(struct timespec* tp)
{
    return tp->tv_sec == 0 && tp->tv_nsec == 0;
}

void libos_times_start()
{
    libos_thread_t* thread = libos_thread_self();
    libos_syscall_clock_gettime(CLOCK_MONOTONIC, &thread->start_ts);
}

void libos_times_enter_kernel()
{
    libos_thread_t* current = libos_thread_self();

    libos_syscall_clock_gettime(CLOCK_MONOTONIC, &current->enter_kernel_ts);

    // Thread might be entering the kernel for the first time
    if (is_zero_tp(&current->leave_kernel_ts))
        current->leave_kernel_ts = current->start_ts;

    long lapsed =
        lapsed_nsecs(current->leave_kernel_ts, current->enter_kernel_ts);
    libos_assume(lapsed >= 0);
    __atomic_fetch_add(&process_times.tms_utime, lapsed, __ATOMIC_SEQ_CST);
}

void libos_times_leave_kernel()
{
    libos_thread_t* current = libos_thread_self();
    libos_syscall_clock_gettime(CLOCK_MONOTONIC, &current->leave_kernel_ts);

    long lapsed =
        lapsed_nsecs(current->enter_kernel_ts, current->leave_kernel_ts);
    libos_assume(lapsed > 0);
    __atomic_fetch_add(&process_times.tms_stime, lapsed, __ATOMIC_SEQ_CST);
}

long libos_times_system_time()
{
    return process_times.tms_stime;
}

long libos_times_user_time()
{
    return process_times.tms_utime;
}

long libos_times_process_time()
{
    return process_times.tms_stime + process_times.tms_utime +
           process_times.tms_cstime + process_times.tms_cutime;
}

long libos_times_thread_time()
{
    libos_thread_t* current = libos_thread_self();
    long lapsed = lapsed_nsecs(current->enter_kernel_ts, current->start_ts);
    return lapsed;
}

long libos_times_uptime()
{
    return process_times.tms_stime + process_times.tms_utime;
}
