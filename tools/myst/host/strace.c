// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "strace.h"
#include <memory.h>
#include "utils.h"

#include <myst/strings.h>
#include <myst/syscall.h>

int myst_parse_strace_config(
    int* argc,
    const char** argv,
    myst_strace_config_t* strace_config)
{
    int ret = -1;
    const char* filter = NULL;
    char** tokens = NULL;
    size_t num_tokens = 0;

    if (cli_getopt(argc, argv, "--strace-failing", NULL) == 0)
    {
        strace_config->trace_failing = 1;
        strace_config->filter = 1;
    }

    if (cli_getopt(argc, argv, "--strace-filter", &filter) == 0 && filter)
    {
        if (myst_strsplit(filter, ":", &tokens, &num_tokens) != 0)
        {
            fprintf(stderr, "Invalid strace-filter '%s' specified.\n", filter);
            abort();
        }
        for (size_t i = 0; i < num_tokens; ++i)
        {
            const char* name = tokens[i];
            long num = myst_syscall_num(name);
            if (num >= 0)
            {
                if (num < MYST_MAX_SYSCALLS)
                    strace_config->trace[num] = 1;
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
                    "Unknown syscall %s specified in --strace=filter\n",
                    name);
                abort();
            }
        }
        strace_config->filter = 1;
        ret = 0;
    }

    if (tokens)
        free(tokens);

    return ret;
}
