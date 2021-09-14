// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_OPTIONS_H
#define _MYST_OPTIONS_H

#include <limits.h>

#include <myst/kernel.h>
#include <myst/types.h>

typedef struct myst_options
{
    bool trace_errors;
    bool trace_syscalls;
    bool have_syscall_instruction;
    bool have_fsgsbase_instructions;
    bool shell_mode;
    bool debug_symbols;
    bool memcheck;
    bool nobrk;
    bool perf;
    bool report_native_tids;
    bool unhandled_syscall_enosys;
    size_t main_stack_size;
    size_t max_affinity_cpus;
    char rootfs[PATH_MAX];
    myst_fork_mode_t fork_mode;

    myst_host_enc_uid_gid_mappings host_enc_uid_gid_mappings;
} myst_options_t;

extern myst_options_t __options;

#endif /* _MYST_OPTIONS_H */
