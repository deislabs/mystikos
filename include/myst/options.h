// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_OPTIONS_H
#define _MYST_OPTIONS_H

#include <limits.h>

#include <myst/types.h>

typedef struct myst_options
{
    bool trace_errors;
    bool trace_syscalls;
    bool have_syscall_instruction;
    bool export_ramfs;
    bool shell_mode;
    char rootfs[PATH_MAX];
} myst_options_t;

extern myst_options_t __options;

#endif /* _MYST_OPTIONS_H */
