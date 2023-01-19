// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_OPTIONS_H
#define _MYST_OPTIONS_H

#include <limits.h>

#include <myst/args.h>
#include <myst/kernel.h>
#include <myst/types.h>

// common options between sgx and linux target
typedef struct myst_options
{
    bool have_syscall_instruction;
    bool have_fsgsbase_instructions;
    bool trace_errors;
    bool trace_times;
    bool debug_symbols;
    bool memcheck;
    bool crt_memcheck;
    bool nobrk;
    bool exec_stack;
    bool perf;
    bool report_native_tids;
    bool unhandled_syscall_enosys;
    bool host_uds;
    size_t main_stack_size;
    size_t thread_stack_size;
    size_t max_affinity_cpus;
    char rootfs[PATH_MAX];
    myst_fork_mode_t fork_mode;
    myst_host_enc_uid_gid_mappings host_enc_uid_gid_mappings;
    myst_strace_config_t strace_config;
    int syslog_level;
} myst_options_t;

typedef struct myst_final_options
{
    myst_options_t base;
    const char* cwd;
    const char* hostname;
    myst_args_t args;
    myst_args_t env;
} myst_final_options_t;

extern myst_options_t __options;

#endif /* _MYST_OPTIONS_H */
