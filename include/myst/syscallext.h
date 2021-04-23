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
    SYS_myst_gcov_init,
    SYS_myst_poll_wake,
    SYS_myst_run_itimer,
    SYS_myst_start_shell,
};

#endif /* _MYST_SYSCALLEXT_H */
