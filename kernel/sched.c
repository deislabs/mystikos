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

    memset(param, 0, sizeof(struct sched_param));

    if (pid == 0)
        params[0] = (long)pid;
    else
    {
        /* We need to send the target pid to the tcall */
        myst_process_t* process = myst_find_process_from_pid(pid, true);
        if (process)
            params[0] = (long)process->main_process_thread->target_tid;
        else
            ERAISE(-ESRCH);
    }
    params[1] = (long)param;

    ret = myst_tcall(SYS_sched_getparam, params);

done:
    return ret;
}
