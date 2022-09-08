// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "strace.h"
#include <memory.h>
#include "utils.h"

#include <myst/strings.h>
#include <myst/syscall.h>

int myst_strace_add_syscall_to_filter(
    long num,
    const char* name,
    myst_strace_config_t* strace_config,
    bool include)
{
    if (num >= 0)
    {
        if (num < MYST_MAX_SYSCALLS)
            strace_config->trace[num] = include;
        else
        {
            fprintf(
                stderr,
                "Syscall %s exceeds trace array capacity. Fix "
                "myst_syscall_config_t\n",
                name);
            abort();
        }
    }
    else
    {
        fprintf(
            stderr,
            "Unknown syscall %s specified in --strace-filter or "
            "--strace-exclude-filter\n",
            name);
        abort();
    }
    return 0;
}

int myst_set_strace_filter(
    const char* filter,
    myst_strace_config_t* strace_config,
    bool include)
{
    char** tokens = NULL;
    size_t num_tokens = 0;

    if (myst_strsplit(filter, ":", &tokens, &num_tokens) != 0)
    {
        fprintf(
            stderr,
            "Invalid strace-filter or strace-enclude-filter '%s' specified.\n",
            filter);
        abort();
    }

    for (size_t i = 0; i < MYST_MAX_SYSCALLS; ++i)
    {
        strace_config->trace[i] = !include;
    }

    for (size_t i = 0; i < num_tokens; ++i)
    {
        const char* name = tokens[i];

        /* Check if filter is for a syscall */
        long num = myst_syscall_num(name);

        if (num != -ENOENT)
            myst_strace_add_syscall_to_filter(
                num, name, strace_config, include);
        else
        {
            /* Check if filter is for a group of syscalls. Eg: file, memory, etc
             */
            const myst_syscall_group_t* group = myst_syscall_group(name);

            /* token specified is not a syscall name or group name */
            if (!group)
            {
                fprintf(
                    stderr,
                    "Invalid group name or syscall name '%s' specified in "
                    "--strace-filter or --strace-exclude-filter.\n",
                    name);
                abort();
            }

            for (int j = 0; j < group->size; j++)
            {
                const char* name = myst_syscall_name((long)group->syscalls[j]);
                myst_strace_add_syscall_to_filter(
                    (long)group->syscalls[j], name, strace_config, include);
            }
        }
    }
    strace_config->filter = 1;

    if (tokens)
        free(tokens);

    return 0;
}

/* sets tid filter if 'tid' is true, else sets pid filter */
int myst_set_strace_pid_tid_filter(
    const char* id_filter,
    myst_strace_config_t* strace_config,
    bool tid)
{
    char** tokens = NULL;
    size_t num_tokens = 0;
    int ret = -1;

    if (myst_strsplit(id_filter, ":", &tokens, &num_tokens) != 0)
    {
        fprintf(
            stderr,
            "Invalid strace-filter-tid or strace-filter-pid option '%s' "
            "specified.\n",
            id_filter);
        abort();
    }

    if (num_tokens >= MYST_MAX_IDS)
    {
        fprintf(
            stderr,
            "Number of tids/pids exceeds trace array capacity (%d). Increase "
            "capacity in myst_syscall_config_t\n",
            MYST_MAX_IDS);
        abort();
    }

    for (size_t i = 0; i < num_tokens; ++i)
    {
        int id = -1;
        const char* _id = tokens[i];

        ret = myst_str2int(_id, &id);

        if (id <= 0)
        {
            fprintf(
                stderr,
                "tid or pid %s is invalid. Must be a positive number.\n",
                _id);
            abort();
        }

        if (tid)
            strace_config->tid_trace[i] = id;
        else
            strace_config->pid_trace[i] = id;
    }

    if (tid)
        strace_config->tid_filter_num = num_tokens;
    else
        strace_config->pid_filter_num = num_tokens;

    if (tokens)
        free(tokens);

    return ret;
}

int myst_strace_parse_config(
    int* argc,
    const char** argv,
    myst_strace_config_t* strace_config)
{
    int ret = -1;
    const char* filter = NULL;
    const char* id_filter = NULL;
    bool filter_flag = 0;

    if (cli_getopt(argc, argv, "--strace-failing", NULL) == 0)
    {
        strace_config->trace_failing = 1;
        strace_config->filter = 1;
    }

    if (cli_getopt(argc, argv, "--strace-exclude-filter", &filter) == 0 &&
        filter)
    {
        ret = myst_set_strace_filter(filter, strace_config, 0);
        filter_flag = true;
    }

    if (cli_getopt(argc, argv, "--strace-filter", &filter) == 0 && filter)
    {
        if (filter_flag)
        {
            fprintf(
                stderr,
                "Cannot specify both --strace-filter and "
                "--strace-exclude-filter\n");
            abort();
        }
        ret = myst_set_strace_filter(filter, strace_config, 1);
    }

    if (cli_getopt(argc, argv, "--strace-filter-tid", &id_filter) == 0 &&
        id_filter)
    {
        ret = myst_set_strace_pid_tid_filter(id_filter, strace_config, true);
    }
    else
    {
        /* tid filter is not enabled */
        strace_config->tid_filter_num = 0;
    }

    if (cli_getopt(argc, argv, "--strace-filter-pid", &id_filter) == 0 &&
        id_filter)
    {
        ret = myst_set_strace_pid_tid_filter(id_filter, strace_config, false);
    }
    else
    {
        /* pid filter is not enabled */
        strace_config->pid_filter_num = 0;
    }

    return ret;
}
