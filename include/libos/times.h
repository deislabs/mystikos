#ifndef _LIBOS_TIMES_H
#define _LIBOS_TIMES_H

#include <time.h>

/* Start tracking the system/user times */
void libos_times_start();

/* Time tracking while entering the kernel from user space */
struct timespec libos_times_enter_kernel();

/* Time tracking while leaving the kernel to user space */
void libos_times_leave_kernel(struct timespec);

/* Return the time (in nanoseconds) spent on kernel execution */
long libos_times_system_time();

/* Return the time (in nanoseconds) spent on user space execution */
long libos_times_user_time();

/* Return nanoseconds since startup */
long libos_times_uptime();
#endif /* _LIBOS_TIMES_H */
