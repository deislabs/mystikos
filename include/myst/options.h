// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_OPTIONS_H
#define _MYST_OPTIONS_H

#include <limits.h>

#include <myst/kernel.h>
#include <myst/types.h>

typedef struct _myst_mount_mapping
{
    char** mounts; /* array of source=target */
    size_t mounts_count;
} myst_mount_mapping_t;

typedef struct myst_options
{
    bool trace_errors;
    bool trace_syscalls;
    bool have_syscall_instruction;
    bool export_ramfs;
    bool shell_mode;
    bool memcheck;
    char rootfs[PATH_MAX];

    myst_host_enc_id_mapping host_enc_id_mapping;
    myst_mount_mapping_t mount_mapping;
} myst_options_t;

extern myst_options_t __options;

#endif /* _MYST_OPTIONS_H */
