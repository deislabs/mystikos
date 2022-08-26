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
                "Syscall %s exceeds trace array. Fix "
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
    int num_tokens,
    char** tokens,
    myst_strace_config_t* strace_config,
    bool include)
{
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
            const int* syscalls = myst_syscall_group(name);
            const size_t group_size = myst_syscall_group_size(name);

            /* token specified is not a syscall name or group name */
            if (syscalls == NULL)
            {
                fprintf(
                    stderr,
                    "Invalid group name or syscall name '%s' specified in "
                    "--strace-filter or --strace-exclude-filter.\n",
                    name);
                abort();
            }

            for (int j = 0; j < group_size; j++)
            {
                const char* name = myst_syscall_name((long)syscalls[j]);
                myst_strace_add_syscall_to_filter(
                    (long)syscalls[j], name, strace_config, include);
            }
        }
    }
    strace_config->filter = 1;
    return 0;
}

int myst_strace_parse_config(
    int* argc,
    const char** argv,
    myst_strace_config_t* strace_config)
{
    int ret = -1;
    const char* filter = NULL;
    char** tokens = NULL;
    size_t num_tokens = 0;
    bool filter_flag = 0;

    if (cli_getopt(argc, argv, "--strace-failing", NULL) == 0)
    {
        strace_config->trace_failing = 1;
        strace_config->filter = 1;
    }

    if (cli_getopt(argc, argv, "--strace-exclude-filter", &filter) == 0 &&
        filter)
    {
        if (myst_strsplit(filter, ":", &tokens, &num_tokens) != 0)
        {
            fprintf(
                stderr,
                "Invalid strace-exclude-filter '%s' specified.\n",
                filter);
            abort();
        }

        ret = myst_set_strace_filter(num_tokens, tokens, strace_config, 0);
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

        if (myst_strsplit(filter, ":", &tokens, &num_tokens) != 0)
        {
            fprintf(stderr, "Invalid strace-filter '%s' specified.\n", filter);
            abort();
        }

        ret = myst_set_strace_filter(num_tokens, tokens, strace_config, 1);
    }

    if (tokens)
        free(tokens);

    return ret;
}
