// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_MOUNT_H
#define _MYST_MOUNT_H

#include <limits.h>
#include <myst/fs.h>
#include <stdbool.h>

/* Mount a file system onto a target path */
int myst_mount(
    myst_fs_t* fs,
    const char* source,
    const char* target,
    bool is_auto);

/* Unmount the file system that is mounted on target */
int myst_umount(const char* target);

/* Unmount all auto-mounted file systems */
int myst_teardown_auto_mounts();

/* Use mounter to resolve this path to a target path */
int myst_mount_resolve(const char* path, char suffix[PATH_MAX], myst_fs_t** fs);

#endif /* _MYST_MOUNT_H */
