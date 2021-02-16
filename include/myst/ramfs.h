// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RAMFS_H
#define _MYST_RAMFS_H

#include <myst/fs.h>
#include <myst/buf.h>
#include <stdbool.h>

int myst_init_ramfs(
    myst_mount_resolve_callback_t resolve_cb,
    myst_fs_t** fs_out);

int myst_ramfs_set_buf(
    myst_fs_t* fs,
    const char* pathname,
    const void* buf,
    size_t buf_size);

int myst_create_virtual_file(
    myst_fs_t* fs,
    const char* pathname,
    int (*vcallback)(myst_buf_t* buf));

#endif /* _MYST_RAMFS_H */
