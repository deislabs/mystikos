// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>

#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/syscall.h>
#include <myst/thread.h>

long myst_syscall_sched_getaffinity(
    pid_t pid,
    size_t cpusetsize,
    cpu_set_t* mask)
{
    long ret = 0;

    if (!mask || myst_is_bad_addr_write(mask, cpusetsize))
        ERAISE(-EFAULT);

    if (pid < 0)
    {
        ERAISE(-ESRCH);
    }
    else if (pid != 0)
    {
        myst_thread_t* thread = myst_find_thread(pid);

        if (!thread)
            ERAISE(-ESRCH);

        pid = thread->target_tid;
    }

    // clear the mask beforehand since the kernel only sets at most
    // 8 bytes (the size of the Linux kernel affinity mask).
    CPU_ZERO_S(cpusetsize, mask);

    long params[6] = {(long)pid, (long)cpusetsize, (long)mask};
    ECHECK((ret = myst_tcall(SYS_sched_getaffinity, params)));

    /* clear CPUs that are in excess of max_affinity_cpus setting */
    if (ret >= 0 && __myst_kernel_args.max_affinity_cpus > 0)
    {
        for (size_t i = 0; i < sizeof(cpu_set_t) * 8; i++)
        {
            if (i >= __myst_kernel_args.max_affinity_cpus)
                CPU_CLR_S(i, cpusetsize, mask);
        }

        const size_t cpu_count = (size_t)CPU_COUNT_S(cpusetsize, mask);

        /* sanity check: there should be less than max_affinity_cpus in mask */
        if (cpu_count > __myst_kernel_args.max_affinity_cpus)
            ERAISE(-EINVAL);
    }

done:
    return ret;
}

long myst_syscall_sched_setaffinity(
    pid_t pid,
    size_t cpusetsize,
    const cpu_set_t* mask)
{
    long ret = 0;

    if (!mask || myst_is_bad_addr_read(mask, cpusetsize))
        ERAISE(-EFAULT);

    if (pid < 0)
    {
        ERAISE(-ESRCH);
    }
    else if (pid != 0)
    {
        myst_thread_t* thread = myst_find_thread(pid);

        if (!thread)
            ERAISE(-ESRCH);

        pid = thread->target_tid;
    }

    long params[6] = {(long)pid, (long)cpusetsize, (long)mask};
    ECHECK((ret = myst_tcall(SYS_sched_setaffinity, params)));

done:
    return ret;
}

long myst_syscall_getcpu(unsigned* cpu, unsigned* node)
{
    long ret = 0;

    long params[6] = {(long)cpu, (long)node, (long)NULL};
    ECHECK((ret = myst_tcall(SYS_getcpu, params)));

done:
    return ret;
}
