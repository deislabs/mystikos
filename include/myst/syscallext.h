// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SYSCALLEXT_H
#define _MYST_SYSCALLEXT_H

#include <myst/types.h>
#include <sys/types.h>

/* Internal myst-specific syscalls */
typedef enum
{
    SYS_myst_trace = 2000,
    SYS_myst_trace_ptr = 2001,
    SYS_myst_dump_stack = 2002,
    SYS_myst_dump_ehdr = 2003,
    SYS_myst_dump_argv = 2004,
    SYS_myst_add_symbol_file = 2005,
    SYS_myst_load_symbols = 2006,
    SYS_myst_unload_symbols = 2007,
    SYS_myst_clone = 2008,
    SYS_myst_poll_wake = 2009,
    SYS_myst_run_itimer = 2010,
    SYS_myst_gcov = 2012,
    SYS_myst_unmap_on_exit = 2013,
    SYS_myst_get_fork_info = 2014,
    SYS_myst_kill_wait_child_forks = 2015,
    SYS_myst_get_process_thread_stack = 2016,
    SYS_myst_fork_wait_exec_exit = 2017,
    SYS_myst_get_exec_stack_option = 2018,
    SYS_myst_interrupt_thread = 2019,
    SYS_myst_pre_launch_hook = 2020,
    /* ATTN: when removing any of these, scan for any hardcoded number usage */
} myst_syscall_t;

#define MYST_MAX_SYSCALLS 3000

/* Used for SYS_myst_get_fork_info parameter */
typedef enum
{
    myst_fork_none = 0,
    myst_fork_pseudo,
    myst_fork_pseudo_wait_for_exit_exec
} myst_fork_mode_t;

typedef struct myst_fork_info
{
    myst_fork_mode_t fork_mode;
    bool is_parent_of_fork;
    bool is_child_fork;
} myst_fork_info_t;

#define MYST_FORK_INFO_INITIALIZER   \
    {                                \
        myst_fork_none, false, false \
    }

#endif /* _MYST_SYSCALLEXT_H */
