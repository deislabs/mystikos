// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SYSCALLEXT_H
#define _MYST_SYSCALLEXT_H

#include <myst/types.h>
#include <sys/types.h>

/* Internal myst-specific syscalls */
enum
{
    SYS_myst_trace = 2000,
    SYS_myst_trace_ptr,
    SYS_myst_dump_stack,
    SYS_myst_dump_ehdr,
    SYS_myst_dump_argv,
    SYS_myst_add_symbol_file,
    SYS_myst_load_symbols,
    SYS_myst_unload_symbols,
    SYS_myst_clone,
    SYS_myst_poll_wake,
    SYS_myst_run_itimer,
    SYS_myst_start_shell,
    SYS_myst_gcov,
    SYS_myst_unmap_on_exit,
    SYS_myst_get_fork_info,
    SYS_myst_kill_wait_child_forks,
    SYS_get_process_thread_stack,
    SYS_fork_wait_exec_exit,
    SYS_myst_get_exec_stack_option,
};

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
