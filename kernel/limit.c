// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <math.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/kernel.h>
#include <myst/limit.h>
#include <myst/mmanutils.h>
#include <myst/process.h>

int myst_limit_set_default(struct rlimit rlimits[])
{
    int ret = 0;

    if (!rlimits)
        ERAISE(-EFAULT);

    // RLIMIT_CPU (match linux)
    rlimits[RLIMIT_CPU].rlim_cur = RLIM_INFINITY;
    rlimits[RLIMIT_CPU].rlim_max = RLIM_INFINITY;

    // RLIMIT_FSIZE (match linux)
    rlimits[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
    rlimits[RLIMIT_FSIZE].rlim_max = RLIM_INFINITY;

    // RLIMIT_DATA (70% of mman region)
    size_t size = 0;
    myst_get_total_ram(&size);
    size = floor(size * 0.70);
    rlimits[RLIMIT_DATA].rlim_cur = size;
    rlimits[RLIMIT_DATA].rlim_max = size;

    // RLIMIT_STACK
    rlimits[RLIMIT_STACK].rlim_cur = MYST_PROCESS_INIT_STACK_SIZE;
    rlimits[RLIMIT_STACK].rlim_max = MYST_PROCESS_MAX_STACK_SIZE;

    // RLIMIT_CORE (no core dump)
    rlimits[RLIMIT_CORE].rlim_cur = 0;
    rlimits[RLIMIT_CORE].rlim_max = 0;

    // RLIMIT_RSS (match linux)
    rlimits[RLIMIT_RSS].rlim_cur = RLIM_INFINITY;
    rlimits[RLIMIT_RSS].rlim_max = RLIM_INFINITY;

    // RLIMIT_NPROC
    rlimits[RLIMIT_NPROC].rlim_cur = __myst_kernel_args.max_threads;
    rlimits[RLIMIT_NPROC].rlim_max = __myst_kernel_args.max_threads;

    // RLIMIT_NOFILE
    rlimits[RLIMIT_NOFILE].rlim_cur = MYST_FDTABLE_SIZE;
    rlimits[RLIMIT_NOFILE].rlim_max = MYST_FDTABLE_SIZE;

    // RLIMIT_MEMLOCK (unsupported)
    rlimits[RLIMIT_MEMLOCK].rlim_cur = 0;
    rlimits[RLIMIT_MEMLOCK].rlim_max = 0;

    // RLIMIT_AS (match linux)
    rlimits[RLIMIT_AS].rlim_cur = RLIM_INFINITY;
    rlimits[RLIMIT_AS].rlim_max = RLIM_INFINITY;

    // RLIMIT_LOCKS (match linux)
    rlimits[RLIMIT_LOCKS].rlim_cur = RLIM_INFINITY;
    rlimits[RLIMIT_LOCKS].rlim_max = RLIM_INFINITY;

    // RLIMIT_SIGPENDING (unsupported)
    rlimits[RLIMIT_SIGPENDING].rlim_cur = 0;
    rlimits[RLIMIT_SIGPENDING].rlim_max = 0;

    // RLIMIT_MSGQUEUE (unsupported)
    rlimits[RLIMIT_MSGQUEUE].rlim_cur = 0;
    rlimits[RLIMIT_MSGQUEUE].rlim_max = 0;

    // RLIMIT_NICE (match linux)
    rlimits[RLIMIT_NICE].rlim_cur = 0;
    rlimits[RLIMIT_NICE].rlim_max = 0;

    // RLIMIT_RTPRIO (match linux)
    rlimits[RLIMIT_RTPRIO].rlim_cur = 0;
    rlimits[RLIMIT_RTPRIO].rlim_max = 0;

    // RLIMIT_RTTIME (match linux)
    rlimits[RLIMIT_RTTIME].rlim_cur = RLIM_INFINITY;
    rlimits[RLIMIT_RTTIME].rlim_max = RLIM_INFINITY;

done:
    return ret;
}

long myst_syscall_prlimit64(
    int pid,
    int resource,
    struct rlimit* new_rlim,
    struct rlimit* old_rlim)
{
    long ret = 0;
    if (old_rlim)
        ECHECK(myst_limit_get_rlimit(pid, resource, old_rlim));

    if (new_rlim)
        ECHECK(myst_limit_set_rlimit(pid, resource, new_rlim));

done:
    return ret;
}

int myst_limit_get_rlimit(pid_t pid, int resource, struct rlimit* rlim)
{
    myst_process_t* process;
    int ret = 0;

    myst_spin_lock(&myst_process_list_lock);

    if (!rlim)
        ERAISE(-EFAULT);

    if (pid < 0)
        ERAISE(-EINVAL);

    if (resource < 0 || resource >= RLIM_NLIMITS)
        ERAISE(-EINVAL);

    if (resource == RLIMIT_MEMLOCK || resource == RLIMIT_SIGPENDING ||
        resource == RLIMIT_MSGQUEUE)
        ERAISE(-ENOTSUP);

    if (pid == 0)
        process = myst_thread_self()->process;
    else if (!(process = myst_find_process_from_pid(pid, false)))
        ERAISE(-ESRCH);

    rlim->rlim_cur = process->rlimits[resource].rlim_cur;
    rlim->rlim_max = process->rlimits[resource].rlim_max;

done:
    myst_spin_unlock(&myst_process_list_lock);
    return ret;
}

int myst_limit_set_rlimit(pid_t pid, int resource, struct rlimit* rlim)
{
    int ret = 0;
    if (!rlim)
        ERAISE(-EFAULT);

    if (pid < 0)
        ERAISE(-EINVAL);

    if (resource < 0 || resource >= RLIM_NLIMITS)
        ERAISE(-EINVAL);

    // ATTN: Setting rlimit value is currently unsupported
    // Returning a failure will break solutions/memcached
    if (resource != RLIMIT_NOFILE)
        ERAISE(-ENOTSUP);
done:
    return ret;
}
