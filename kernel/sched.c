// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <sched.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/kernel.h>
#include <myst/thread.h>

long myst_syscall_sched_getparam(pid_t pid, struct sched_param* param)
{
    long ret = 0;
    long params[6] = {0};

    if (pid < 0)
        ERAISE(-EINVAL);
    else if (pid >= MYST_PID_MAX)
        ERAISE(-ESRCH);

    if (!param || !myst_is_addr_within_kernel(param))
    {
        ERAISE(-EFAULT);
    }
    /*
     * Only memset the non reserved part of the structure
     * This is to be defensive against different sizes of this
     * struct in musl and glibc.
     * In glibc -
     *  struct sched_param {
     *      int sched_priority;
     *  };
     */
    memset(param, 0, sizeof(int));

    if (pid == 0)
        params[0] = (long)pid;
    else
    {
        /* Find the relevant mystikos process/thread and send the target_tid */
        myst_process_t* process = myst_find_process_from_pid(pid, true);
        if (process)
            params[0] = (long)process->main_process_thread->target_tid;
        else
        {
            myst_thread_t* thread = myst_find_thread(pid);
            if (thread)
                params[0] = (long)thread->target_tid;
        }
        /* If params[0] is not set yet, then pid could not be found */
        if (!params[0])
            ERAISE(-ESRCH);
    }
    params[1] = (long)param;

    ret = myst_tcall(SYS_sched_getparam, params);

done:
    return ret;
}

long myst_syscall_sched_setscheduler(
    pid_t pid,
    int policy,
    struct sched_param* param)
{
    long ret = 0;
    long params[6] = {0};

    /* Check if caller has right permissions */
    myst_thread_t* thread = myst_thread_self();
    if (thread->euid != 0)
        ERAISE(-EPERM);

    if (policy < SCHED_OTHER || policy > SCHED_IDLE)
        ERAISE(-EINVAL);

    if (!param || !myst_is_addr_within_kernel(param))
        ERAISE(-EFAULT);

    if (pid == 0)
        params[0] = (long)pid;
    else
    {
        /* Find the relevant mystikos process/thread and send the target_tid */
        myst_process_t* process = myst_find_process_from_pid(pid, true);
        if (process)
            params[0] = (long)process->main_process_thread->target_tid;
        else
        {
            myst_thread_t* thread = myst_find_thread(pid);
            if (thread)
                params[0] = (long)thread->target_tid;
        }
        /* If params[0] is not set yet, then pid could not be found */
        if (!params[0])
            ERAISE(-ESRCH);
    }
    params[1] = (long)policy;
    params[2] = (long)param;

    ret = myst_tcall(SYS_sched_setscheduler, params);

done:
    return ret;
}
