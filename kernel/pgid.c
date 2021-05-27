// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <myst/process.h>
#include <myst/syscall.h>

long myst_syscall_setpgid(pid_t pid, pid_t pgid, myst_thread_t* thread)
{
    long ret = 0;
    myst_thread_t* process_thread = myst_find_process_thread(thread);

    /* pid of zero means use own */
    if (pid == 0)
        pid = process_thread->pid;

    /* if pgid is zero use process pid */
    if (pgid == 0)
    {
        pgid = pid;
    }

    /* do not allow the change on any other thread for now*/
    if (pid != process_thread->pid)
        ret = -EPERM;
    else
        process_thread->main.pgid = pgid;

    return ret;
}

long myst_syscall_getpgid(pid_t pid, myst_thread_t* thread)
{
    long ret = 0;
    myst_thread_t* process_thread = myst_find_process_thread(thread);

    /* pid of zero means use own */
    if (pid == 0)
        pid = process_thread->pid;

    /* only allow retrieval for our process for now */
    if (pid != process_thread->pid)
        ret = -EPERM;
    else
        ret = process_thread->main.pgid;

    return ret;
}
