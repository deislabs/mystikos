// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <stdlib.h>
#include <string.h>
#include <sys/times.h>

#include <myst/assume.h>
#include <myst/clock.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/printf.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/times.h>

struct timespec __myst_boot_time;

/* Time spent by the main thread and its children */
struct tms process_times;

bool __myst_trace_syscall_times = true;

typedef struct syscall_time
{
    long nsec;
    size_t ncalls;
} syscall_time_t;

static syscall_time_t _syscall_times[MYST_MAX_SYSCALLS];

long myst_lapsed_nsecs(const struct timespec* t0, const struct timespec* t1)
{
    __uint128_t t1_ns =
        ((__uint128_t)t1->tv_sec * NANO_IN_SECOND) + t1->tv_nsec;
    __uint128_t t0_ns =
        ((__uint128_t)t0->tv_sec * NANO_IN_SECOND) + t0->tv_nsec;

    return (long)(t1_ns - t0_ns);
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

void myst_times_enter_kernel(long syscall_num)
{
    myst_thread_t* current = myst_thread_self();
    myst_process_t* process = current->process;

    (void)syscall_num;

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->enter_kernel_ts);

    // Thread might be entering the kernel for the first time
    if (is_zero_tp(&current->leave_kernel_ts))
        current->leave_kernel_ts = current->start_ts;

    long lapsed =
        myst_lapsed_nsecs(&current->leave_kernel_ts, &current->enter_kernel_ts);
    myst_assume(lapsed >= 0);

    __atomic_fetch_add(&process_times.tms_utime, lapsed, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(
        &process->process_times.tms_utime, lapsed, __ATOMIC_SEQ_CST);
}

void myst_times_leave_kernel(long syscall_num)
{
    myst_thread_t* current = myst_thread_self();
    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->leave_kernel_ts);

    long lapsed =
        myst_lapsed_nsecs(&current->enter_kernel_ts, &current->leave_kernel_ts);

    if (__myst_trace_syscall_times)
    {
        _syscall_times[syscall_num].nsec += lapsed;
        _syscall_times[syscall_num].ncalls++;
    }

    // Tolerate zero lapsed time since enter_kernel_ts has been observed to be
    // equal to leave_kernel_ts on occassion on very fast syscalls (when using
    // the VSDO version of clock_gettime() on Linux).
    myst_assume(lapsed >= 0);

    if (lapsed)
    {
        __atomic_fetch_add(&process_times.tms_stime, lapsed, __ATOMIC_SEQ_CST);
        __atomic_fetch_add(
            &myst_process_self()->process_times.tms_stime,
            lapsed,
            __ATOMIC_SEQ_CST);
    }
}

void myst_times_process_times(myst_process_t* process, struct tms* tm)
{
    if (tm)
    {
        *tm = process->process_times;
    }
}

long myst_times_process_time(myst_process_t* process)
{
    return process->process_times.tms_stime + process->process_times.tms_utime +
           process->process_times.tms_cstime +
           process->process_times.tms_cutime;
}

long myst_times_thread_time(myst_thread_t* thread)
{
    return myst_lapsed_nsecs(&thread->start_ts, &thread->enter_kernel_ts);
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
        myst_thread_t* thread = myst_thread_self();
        if (tid != thread->tid)
        {
            thread = myst_find_thread(tid);
            if (!thread)
                return -EINVAL;
        }
        nanos_to_timespec(tp, myst_times_thread_time(thread));
    }
    else
    {
        myst_process_t* process = myst_process_self();
        if (tid != process->pid)
        {
            process = myst_find_process_from_pid(tid, false);
            if (!process)
                return -EINVAL;
        }
        nanos_to_timespec(tp, myst_times_process_time(process));
    }

    return 0;
}

void myst_times_add_child_times_to_parent_times(
    myst_process_t* parent,
    myst_process_t* child)
{
    parent->process_times.tms_cstime = parent->process_times.tms_cstime +
                                       child->process_times.tms_stime +
                                       child->process_times.tms_cstime;
    parent->process_times.tms_cutime = parent->process_times.tms_cutime +
                                       child->process_times.tms_utime +
                                       child->process_times.tms_cutime;
}

#define COLOR_YELLOW "\e[33m"
#define COLOR_RESET "\e[0m"

static void _print_line(size_t nchars)
{
    for (size_t i = 0; i < nchars; i++)
        myst_eprintf("=");
    myst_eprintf("\n");
}

void myst_print_syscall_times(const char* message, size_t count)
{
    typedef struct times
    {
        long num;
        long nsec;
        size_t ncalls;
    } times_t;
    size_t ntimes = 0;
    struct locals
    {
        times_t times[MYST_MAX_SYSCALLS];
    };
    struct locals* locals = NULL;
    double nsecs = 0;
    int nchars = 1;
    static const char fmt[] = "%-*s %8.4lfsec %5.2lf%% %5.2lf%% (%zu calls)\n";
    double elapsed_secs = 0.0;

    if (!message || count == 0)
        return;

    if (!(locals = malloc(sizeof(struct locals))))
        goto done;

    /* calculate total elapsed time from boot */
    {
        struct timespec now;

        if (myst_syscall_clock_gettime(CLOCK_REALTIME, &now) == 0)
        {
            struct timespec start;
            start.tv_sec = __myst_kernel_args.start_time_sec;
            start.tv_nsec = __myst_kernel_args.start_time_nsec;
            long nsec = myst_lapsed_nsecs(&start, &now);
            elapsed_secs = (double)nsec / (double)NANO_IN_SECOND;
        }
    }

    for (size_t i = 0; i < MYST_MAX_SYSCALLS; i++)
    {
        if (_syscall_times[i].nsec)
        {
            locals->times[ntimes].num = i;
            locals->times[ntimes].nsec = _syscall_times[i].nsec;
            locals->times[ntimes].ncalls = _syscall_times[i].ncalls;
            nsecs += (double)_syscall_times[i].nsec;
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

    int name_width = 0;
    int nsec_width = 0;
    char buf[64];

    /* find the longest syscall name */
    for (size_t i = 0; i < ntimes; i++)
    {
        const times_t* p = &locals->times[i];
        const char* name = myst_syscall_str(p->num);
        size_t len = strlen(name);

        int n = snprintf(buf, sizeof(buf), "%ld", p->nsec);

        if (n > nsec_width)
            nsec_width = n;

        if (len > (size_t)name_width)
            name_width = len;
    }

    if (ntimes > count)
        ntimes = count;

    /* determine the longest printed line */
    for (size_t i = 0; i < ntimes; i++)
    {
        const times_t* p = &locals->times[i];
        double percent = (p->nsec / nsecs) * 100.0;
        const char* name = myst_syscall_str(p->num);
        double percent2 = ((p->nsec / p->ncalls) / nsecs) * 100.0;
        char buf[128];

        int n = snprintf(
            buf,
            sizeof(buf),
            fmt,
            name_width,
            name,
            ((double)p->nsec / (double)NANO_IN_SECOND),
            percent,
            percent2,
            p->ncalls);

        /* don't count the newline */
        if (n > 1)
            n--;

        if (n > nchars)
            nchars = n;
    }

    myst_eprintf(COLOR_YELLOW "\n");
    _print_line(nchars);
    myst_eprintf("%s: %.4lf seconds elapsed\n", message, elapsed_secs);
    _print_line(nchars);

    for (size_t i = 0; i < ntimes; i++)
    {
        const times_t* p = &locals->times[i];
        double percent = (p->nsec / nsecs) * 100.0;
        const char* name = myst_syscall_str(p->num);
        double percent2 = ((p->nsec / p->ncalls) / nsecs) * 100.0;

        myst_eprintf(
            fmt,
            name_width,
            name,
            ((double)p->nsec / (double)NANO_IN_SECOND),
            percent,
            percent2,
            p->ncalls);
    }

    myst_eprintf("\n");

    myst_eprintf(COLOR_RESET "\n");

done:

    if (locals)
        free(locals);
}
