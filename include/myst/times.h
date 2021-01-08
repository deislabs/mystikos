// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_TIMES_H
#define _MYST_TIMES_H

#include <time.h>

/* Start tracking time for current thread */
void myst_times_start();

/* Time tracking while entering the kernel from user space */
struct timespec myst_times_enter_kernel();

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
#endif /* _MYST_TIMES_H */
