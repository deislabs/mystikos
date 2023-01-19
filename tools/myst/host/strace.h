// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_HOST_STRACE_H
#define _MYST_HOST_STRACE_H

#include <myst/options.h>

int myst_strace_parse_config(
    int* argc,
    const char** argv,
    myst_strace_config_t* strace_config);

int myst_strace_add_syscall_to_filter(
    long num,
    const char* name,
    myst_strace_config_t* strace_config,
    bool include);

#endif // _MYST_HOST_STRACE_H
