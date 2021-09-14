// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_PROCESS_H
#define _MYST_PROCESS_H

#include <myst/thread.h>
#include <sys/types.h>
#include <unistd.h>

#define MYST_DEFAULT_UMASK (S_IWGRP | S_IWOTH)
#define MYST_DEFAULT_PGID (pid_t)100

// ATTN: Small stack size for the primary thread of a process might not work
// for certain apps, especially when on-demand stack growth is not supported
// yet
/* .NET runtime sets the default minimum stack size for MUSL to 1536 * 1024, if
 *  env. variable COMPlus_DefaultStackSize is not present or set to other value.
 *  For MUSL, the .NET runtime also probes the stack limit of the primary thread
 *  using _alloca(min_stack_size) and writing to a stack variable on top of the
 *  stack, during CoreCLR init. Set the process stack size as 1536 * 1024 plus
 *  32K reserves
 */
#define MYST_PROCESS_INIT_STACK_SIZE (1568 * 1024);

MYST_INLINE pid_t myst_getsid(void)
{
    return myst_process_self()->sid;
}

MYST_INLINE pid_t myst_getppid(void)
{
    return myst_process_self()->ppid;
}

MYST_INLINE pid_t myst_getpid(void)
{
    return myst_process_self()->pid;
}

#endif /* _MYST_PROCESS_H */
