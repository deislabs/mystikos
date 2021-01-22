// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TIMES_H
#define _MYST_TIMES_H

#include <time.h>

/* Start tracking time for current thread */
void myst_times_start();

/* Time tracking while entering the kernel from user space */
void myst_times_enter_kernel();

/* Time tracking while leaving the kernel to user space */
void myst_times_leave_kernel();

/* Return the time (in nanoseconds) spent on kernel execution */
long myst_times_system_time();

/* Return the time (in nanoseconds) spent on user space execution */
long myst_times_user_time();

/* Return the time (in nanoseconds) spent by process */
long myst_times_process_time();

/* Return the time (in nanoseconds) spent by thread */
long myst_times_thread_time();

/* Return nanoseconds since startup */
long myst_times_uptime();

#define CPU_CLOCK_TID(clock) ((pid_t) ~((clock) >> 3))
// Second most lsb differentiates per thread(set) and per process(unset)
#define CPU_CLOCK_PERTHREAD_MASK 4
#define CPU_CLOCK_PERTHREAD(clock) \
    (((clock) & (clockid_t)CPU_CLOCK_PERTHREAD_MASK) != 0)

// LSB 2 bits are set if dynamic fd based clock
#define DYN_CLOCK_FD 3
#define DYN_CLOCK_FD_MASK 7
#define IS_DYNAMIC_CLOCK(clock) \
    (((clock) & (clockid_t)DYN_CLOCK_FD_MASK) == DYN_CLOCK_FD)

long myst_times_cpu_clock_get(clockid_t clk_id, struct timespec* tp);
#endif /* _MYST_TIMES_H */
