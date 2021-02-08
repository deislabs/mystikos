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

/*

clock_getcpuclockid and pthread_getcpuclockid in libc map
pid's and tid's respectively; to unique clock ids.

clock_getcpuclockid: pid -> (-pid-1)*8U + 2
pthread_getcpuclockid: tid -> (-tid-1)*8U + 6;

Order of operations:
    1. negate pid or tid
    2. subtract 1
    3. mul 8
    4. add 2(pid) or 6(tid)

Steps 1-3. differentiate these clockids from real id clocks.
Step 4 differentiates thread clocks from process clocks.

Derivation for pid/tid 101:
(gdb) p/t 101
$33 = 1100101
(gdb) p/t -101 <-- step 1: negate pid or tid
$34 = 11111111111111111111111110011011
(gdb) p/t -102 <-- step 2: subtract 1
$35 = 11111111111111111111111110011010
(gdb) p/t -816 <-- step 3: mul 8
$36 = 11111111111111111111110011010000
(gdb) p/t -810 <-- step 4 for tid: add 6
$37 = 11111111111111111111110011010110
                                   ^
                                   |
                    3rd most LSB is set
(gdb) p/t -814 <-- step 4 for pid: add 2
$38 = 11111111111111111111110011010010
                                   ^
                                   |
                    3rd most LSB is unset

The inverse of this process defined by CPU_CLOCK_TID.
Order of operations:
    1. left shift by 3 (inverse of step 3 above, i.e the mul by 8)
    2. bitwise complement (inverse of step 1 and 2)

By checking the 3rd most LSB, CPU_CLOCK_PERTHREAD checks whether
a clock id is per-thread or per-process.
*/
#define CPU_CLOCK_TID(clock) ((pid_t) ~((clock) >> 3))
#define CPU_CLOCK_PERTHREAD_MASK 4
#define CPU_CLOCK_PERTHREAD(clock) \
    (((clock) & (clockid_t)CPU_CLOCK_PERTHREAD_MASK) != 0)

// LSB 2 bits are set if dynamic fd based clock
#define DYN_CLOCK_FD 3
#define DYN_CLOCK_FD_MASK 7
#define IS_DYNAMIC_CLOCK(clock) \
    (((clock) & (clockid_t)DYN_CLOCK_FD_MASK) == DYN_CLOCK_FD)

long myst_times_get_cpu_clock_time(clockid_t clk_id, struct timespec* tp);
#endif /* _MYST_TIMES_H */
