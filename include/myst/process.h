// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PROCESS_H
#define _MYST_PROCESS_H

#include <myst/thread.h>
#include <sys/types.h>
#include <unistd.h>

#define MYST_DEFAULT_UMASK (S_IWGRP | S_IWOTH)
#define MYST_DEFAULT_PGID (pid_t)100

MYST_INLINE pid_t myst_getsid(void)
{
    return myst_thread_self()->sid;
}

MYST_INLINE pid_t myst_getppid(void)
{
    return myst_thread_self()->ppid;
}

MYST_INLINE pid_t myst_getpid(void)
{
    return myst_thread_self()->pid;
}

#endif /* _MYST_PROCESS_H */
