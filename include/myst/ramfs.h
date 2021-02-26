// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RAMFS_H
#define _MYST_RAMFS_H

#include <myst/fs.h>
#include <stdbool.h>

int myst_init_ramfs(myst_mount_resolve_callback_t resolve, myst_fs_t** fs_out);

int myst_ramfs_set_buf(
    myst_fs_t* fs,
    const char* pathname,
    const void* buf,
    size_t buf_size);

#endif /* _MYST_RAMFS_H */
