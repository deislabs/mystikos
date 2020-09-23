// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_MOUNT_H
#define _LIBOS_MOUNT_H

#include <libos/fs.h>
#include <limits.h>

/* Mount a file system onto a target path */
int libos_mount(libos_fs_t* fs, const char* target);

/* Unmount the file system that is mounted on target */
int libos_umount(const char* target);

/* Use mounter to resolve this path to a target path */
int libos_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    libos_fs_t** fs);

#endif /* _LIBOS_MOUNT_H */
