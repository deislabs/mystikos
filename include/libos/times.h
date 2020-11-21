// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_TIMES_H
#define _LIBOS_TIMES_H

#include <time.h>

/* Start tracking time for current thread */
void libos_times_start();

/* Time tracking while entering the kernel from user space */
struct timespec libos_times_enter_kernel();

/* Time tracking while leaving the kernel to user space */
void libos_times_leave_kernel();

/* Return the time (in nanoseconds) spent on kernel execution */
long libos_times_system_time();

/* Return the time (in nanoseconds) spent on user space execution */
long libos_times_user_time();

/* Return the time (in nanoseconds) spent by process */
long libos_times_process_time();

/* Return the time (in nanoseconds) spent by thread */
long libos_times_thread_time();

/* Return nanoseconds since startup */
long libos_times_uptime();
#endif /* _LIBOS_TIMES_H */
