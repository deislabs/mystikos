// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_RAMFS_H
#define _MYST_RAMFS_H

#include <myst/buf.h>
#include <myst/fs.h>
#include <stdbool.h>
#include <stddef.h>

/* Virtual files in ramfs

Loosely defined a virtual file whose open/close/read/write operations
have to be customized. Some examples:

- Customized OPEN: for files whose contents are generated at open()
    Useful where the file contents can be populated once.
    `myst_file_t.vbuf` field is used to store the buffer. Instead of the inode
    buffer, the file level buffer was used to ensure some protection against
    concurrent access.
    Subsequent reads and writes are serviced from the populated buffer.
    The buffer is released on close().


- Customized stateless Read/Write: for files for which read and write
   operations
    are stateless, such as /dev/urandom.
    Useful where the file is unbounded, or has special behavior on
    reads and writes.
    Read and write file operations on these files operate directly
    on the user provided buffer.

- Customized stateful Read/Write: for files for which read and write operations
    are stateful, such as PTY master and slaves. Read and write
    operations on these files are applied on the file-level buffers.
*/

typedef struct _vcallback
{
    int (*open_cb)(myst_file_t* self, myst_buf_t* buf, const char* entrypath);
    int (*close_cb)(myst_file_t* self);
    int (*read_cb)(myst_file_t* self, void* buf, size_t count);
    int (*write_cb)(myst_file_t* self, const void* buf, size_t count);
} myst_vcallback_t;

int myst_init_ramfs(
    myst_mount_resolve_callback_t resolve_cb,
    myst_fs_t** fs_out,
    int device_num);

int myst_ramfs_set_buf(
    myst_fs_t* fs,
    const char* pathname,
    const void* buf,
    size_t buf_size);

int myst_create_virtual_file(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_vcallback_t v_cb);

int myst_read_stateful_virtual_file(
    myst_file_t* file,
    void* buf,
    size_t buf_size);

int myst_write_stateful_virtual_file(
    myst_file_t* file,
    const void* buf,
    size_t buf_size);

int set_overrides_for_special_fs(myst_fs_t* fs);

#define MYST_POSIX_SHMFS_DEV_NUM 26
#endif /* _MYST_RAMFS_H */
