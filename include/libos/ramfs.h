// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_RAMFS_H
#define _LIBOS_RAMFS_H

#include <libos/fs.h>
#include <stdbool.h>

int libos_init_ramfs(libos_fs_t** fs_out);

int libos_ramfs_set_buf(
    libos_fs_t* fs,
    const char* pathname,
    const void* buf,
    size_t buf_size);

#endif /* _LIBOS_RAMFS_H */
