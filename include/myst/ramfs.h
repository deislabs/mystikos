// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RAMFS_H
#define _MYST_RAMFS_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <stdbool.h>

/* Virtual files in ramfs

Loosely defined a virtual file is one whose contents
are generated on-the-fly.

ramfs supports two types of virtual files:
- OPEN: files whose contents are generated at open()
    Useful where the file contents can be populated once.
    `myst_file_t.vbuf` field is used to store the buffer. Instead of the inode
    buffer, the file level buffer was used to ensure some protection against
    concurrent access.
    Subsequent reads and writes are serviced from the populated buffer.
    The buffer is released on close().


- RW: files for which read and write operations are stateless.
    Useful where the file is unbounded, or has special behavior on
    reads and writes.
    Read and write file operations on these files operate directly
    on the user provided buffer.

*/

typedef enum myst_virtual_file_type
{
    NONE,
    OPEN,
    RW,
} myst_virtual_file_type_t;

typedef union myst_vcallback {
    int (*open_cb)(myst_buf_t* buf);
    struct
    {
        ssize_t (*read_cb)(void* buf, size_t count);
        ssize_t (*write_cb)(const void* buf, size_t count);
    } rw_callbacks;
} myst_vcallback_t;

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
    mode_t mode,
    myst_vcallback_t v_cb,
    myst_virtual_file_type_t v_type);

int myst_release_tree(myst_fs_t* fs, const char* pathname);

int set_overrides_for_special_fs(myst_fs_t* fs);

#endif /* _MYST_RAMFS_H */
