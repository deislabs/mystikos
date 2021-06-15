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
    bool trace_syscall_times;
    bool have_syscall_instruction;
    bool export_ramfs;
    bool shell_mode;
    bool memcheck;
    size_t max_affinity_cpus;
    char rootfs[PATH_MAX];

    myst_host_enc_uid_gid_mappings host_enc_uid_gid_mappings;
    myst_mount_mapping_t mount_mapping;
} myst_options_t;

extern myst_options_t __options;

#endif /* _MYST_OPTIONS_H */
