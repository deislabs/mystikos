#include <libos/syscall.h>
#include <libos/clock.h>
#include <assert.h>

static struct timespec _start_tp = {0};
static struct timespec _leave_kernel_tp = {0}; // attn: make it thread local
static long _system_time_elapsed = 0;
static long _user_time_elapsed = 0;

static bool is_zero_tp(struct timespec* tp)
{
    return tp->tv_sec == 0 && tp->tv_nsec == 0;
}

void libos_times_start()
{
    libos_syscall_clock_gettime(CLOCK_MONOTONIC, &_start_tp);
}

struct timespec libos_times_enter_kernel()
{
    struct timespec tp0 = {0}, enter_kernel_tp = {0};
    libos_syscall_clock_gettime(CLOCK_MONOTONIC, &enter_kernel_tp);

    if (is_zero_tp(&_leave_kernel_tp))
        tp0 = _start_tp;
    else
        tp0 = _leave_kernel_tp;

    long lapsed = (enter_kernel_tp.tv_sec - tp0.tv_sec) * NANO_IN_SECOND +
                  (enter_kernel_tp.tv_nsec - tp0.tv_nsec);

    if (lapsed <= 0)
    {
        // Impossible in a rational world.
        // For now, just ignore lapsed because it's inaccurate anyway since
        // _leave_kernel_tp is corrupted by another thread.
    }
    else
    {
        __atomic_fetch_add (&_user_time_elapsed, lapsed, __ATOMIC_SEQ_CST);
    }
    return enter_kernel_tp;
}

void libos_times_leave_kernel(struct timespec tp0)
{
    libos_syscall_clock_gettime(CLOCK_MONOTONIC, &_leave_kernel_tp);

    long lapsed = (_leave_kernel_tp.tv_sec - tp0.tv_sec) * NANO_IN_SECOND +
                  (_leave_kernel_tp.tv_nsec - tp0.tv_nsec);

    assert(lapsed > 0);

    __atomic_fetch_add (&_system_time_elapsed, lapsed, __ATOMIC_SEQ_CST);
}

long libos_times_system_time()
{
    return _system_time_elapsed;
}

long libos_times_user_time()
{
    return _user_time_elapsed;
}
