// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <stdlib.h>
#include <string.h>
#include <sys/times.h>

#include <myst/assume.h>
#include <myst/clock.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/printf.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/times.h>

#define MYST_MAX_SYSCALLS 3000

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
    return (t1->tv_sec - t0->tv_sec) * NANO_IN_SECOND +
           (t1->tv_nsec - t0->tv_nsec);
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

    (void)syscall_num;

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &current->enter_kernel_ts);

    // Thread might be entering the kernel for the first time
    if (is_zero_tp(&current->leave_kernel_ts))
        current->leave_kernel_ts = current->start_ts;

    long lapsed =
        myst_lapsed_nsecs(&current->leave_kernel_ts, &current->enter_kernel_ts);
    myst_assume(lapsed >= 0);

    __atomic_fetch_add(&process_times.tms_utime, lapsed, __ATOMIC_SEQ_CST);
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
    long lapsed =
        myst_lapsed_nsecs(&current->start_ts, &current->enter_kernel_ts);
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
            nanos_to_timespec(tp, nanoseconds);
        }
        else
        {
            myst_thread_t* t = myst_find_thread(tid);
            if (!t)
                return -EINVAL;

            long nanoseconds =
                myst_lapsed_nsecs(&t->start_ts, &t->enter_kernel_ts);
            nanos_to_timespec(tp, nanoseconds);
        }
    }
    else
    {
        long nanoseconds = myst_times_process_time();
        nanos_to_timespec(tp, nanoseconds);
    }

    return 0;
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
            start.tv_sec = (long)__myst_kernel_args.start_time_sec;
            start.tv_nsec = (long)__myst_kernel_args.start_time_nsec;
            long nsec = myst_lapsed_nsecs(&start, &now);
            elapsed_secs = (double)nsec / (double)NANO_IN_SECOND;
        }
    }

    for (long i = 0; i < MYST_MAX_SYSCALLS; i++)
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
            name_width = (int)len;
    }

    if (ntimes > count)
        ntimes = count;

    /* determine the longest printed line */
    for (size_t i = 0; i < ntimes; i++)
    {
        const times_t* p = &locals->times[i];
        double percent = ((double)p->nsec / nsecs) * 100.0;
        const char* name = myst_syscall_str(p->num);
        double percent2 =
            (((double)p->nsec / (double)p->ncalls) / nsecs) * 100.0;
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
    _print_line((size_t)nchars);
    myst_eprintf("%s: %.4lf seconds elapsed\n", message, elapsed_secs);
    _print_line((size_t)nchars);

    for (size_t i = 0; i < ntimes; i++)
    {
        const times_t* p = &locals->times[i];
        double percent = ((double)p->nsec / nsecs) * 100.0;
        const char* name = myst_syscall_str(p->num);
        double percent2 =
            (((double)p->nsec / (double)p->ncalls) / nsecs) * 100.0;

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
