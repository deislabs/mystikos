// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FS_H
#define _MYST_FS_H

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <myst/defs.h>
#include <myst/fdops.h>

/* supported file system types */
typedef enum myst_fstype
{
    MYST_FSTYPE_NONE,
    MYST_FSTYPE_RAMFS,
    MYST_FSTYPE_EXT2FS,
    MYST_FSTYPE_HOSTFS,
} myst_fstype_t;

const char* myst_fstype_name(myst_fstype_t fstype);

typedef struct myst_fs myst_fs_t;

typedef struct myst_file myst_file_t;
typedef struct myst_file_shared myst_file_shared_t;

typedef int (*myst_mount_resolve_callback_t)(
    const char* path,
    char suffix[PATH_MAX],
    myst_fs_t** fs);

struct myst_fs
{
    myst_fdops_t fdops;

    int (*fs_release)(myst_fs_t* fs);

    int (*fs_mount)(myst_fs_t* fs, const char* source, const char* target);

    int (*fs_creat)(
        myst_fs_t* fs,
        const char* pathname,
        mode_t mode,
        myst_fs_t** fs_out,
        myst_file_t** file);

    int (*fs_open)(
        myst_fs_t* fs,
        const char* pathname,
        int flags,
        mode_t mode,
        myst_fs_t** fs_out,
        myst_file_t** file);

    off_t (
        *fs_lseek)(myst_fs_t* fs, myst_file_t* file, off_t offset, int whence);

    ssize_t (
        *fs_read)(myst_fs_t* fs, myst_file_t* file, void* buf, size_t count);

    ssize_t (*fs_write)(
        myst_fs_t* fs,
        myst_file_t* file,
        const void* buf,
        size_t count);

    ssize_t (*fs_pread)(
        myst_fs_t* fs,
        myst_file_t* file,
        void* buf,
        size_t count,
        off_t offset);

    ssize_t (*fs_pwrite)(
        myst_fs_t* fs,
        myst_file_t* file,
        const void* buf,
        size_t count,
        off_t offset);

    ssize_t (*fs_readv)(
        myst_fs_t* fs,
        myst_file_t* file,
        const struct iovec* iov,
        int iovcnt);

    ssize_t (*fs_writev)(
        myst_fs_t* fs,
        myst_file_t* file,
        const struct iovec* iov,
        int iovcnt);

    int (*fs_close)(myst_fs_t* fs, myst_file_t* file);

    int (*fs_access)(myst_fs_t* fs, const char* pathname, int mode);

    int (*fs_stat)(myst_fs_t* fs, const char* pathname, struct stat* statbuf);

    int (*fs_lstat)(myst_fs_t* fs, const char* pathname, struct stat* statbuf);

    int (*fs_fstat)(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf);

    int (*fs_link)(
        myst_fs_t* fs,
        const char* oldpath,
        const char* newpath,
        int flags);

    int (*fs_unlink)(myst_fs_t* fs, const char* pathname);

    int (*fs_rename)(myst_fs_t* fs, const char* oldpath, const char* newpath);

    int (*fs_truncate)(myst_fs_t* fs, const char* path, off_t length);

    int (*fs_ftruncate)(myst_fs_t* fs, myst_file_t* file, off_t length);

    int (*fs_mkdir)(myst_fs_t* fs, const char* pathname, mode_t mode);

    int (*fs_rmdir)(myst_fs_t* fs, const char* pathname);

    int (*fs_getdents64)(
        myst_fs_t* fs,
        myst_file_t* file,
        struct dirent* dirp,
        size_t count);

    ssize_t (*fs_readlink)(
        myst_fs_t* fs,
        const char* pathname,
        char* buf,
        size_t bufsiz);

    int (*fs_symlink)(myst_fs_t* fs, const char* target, const char* linkpath);

    int (
        *fs_realpath)(myst_fs_t* fs, myst_file_t* file, char* buf, size_t size);

    int (*fs_fcntl)(myst_fs_t* fs, myst_file_t* file, int cmd, long arg);

    int (*fs_ioctl)(
        myst_fs_t* fs,
        myst_file_t* file,
        unsigned long request,
        long arg);

    int (*fs_dup)(
        myst_fs_t* fs,
        const myst_file_t* file,
        myst_file_t** file_out);

    int (*fs_target_fd)(myst_fs_t* fs, myst_file_t* file);

    int (*fs_get_events)(myst_fs_t* fs, myst_file_t* file);

    int (*fs_statfs)(myst_fs_t* fs, const char* path, struct statfs* buf);

    int (*fs_fstatfs)(myst_fs_t* fs, myst_file_t* file, struct statfs* buf);

    int (*fs_futimens)(
        myst_fs_t* fs,
        myst_file_t* file,
        const struct timespec times[2]);

    int (*fs_chown)(myst_fs_t* fs, const char* path, uid_t owner, gid_t group);

    int (
        *fs_fchown)(myst_fs_t* fs, myst_file_t* file, uid_t owner, gid_t group);

    int (*fs_lchown)(myst_fs_t* fs, const char* path, uid_t owner, gid_t group);

    int (*fs_chmod)(myst_fs_t* fs, const char* pathname, mode_t mode);

    int (*fs_fchmod)(myst_fs_t* fs, myst_file_t* file, mode_t mode);

    int (*fs_fdatasync)(myst_fs_t* fs, myst_file_t* file);

    int (*fs_fsync)(myst_fs_t* fs, myst_file_t* file);

    /* Recursively remove directory tree pointed at by pathname */
    int (*fs_release_tree)(myst_fs_t* fs, const char* pathname);

    int (*fs_file_data_ptr)(
        myst_fs_t* fs,
        myst_file_t* file,
        void** object_out,
        void** addr_out);

    int (*fs_file_mapping_notify)(myst_fs_t* fs, void* object, bool active);
};

int myst_add_fd_link(myst_fs_t* fs, myst_file_t* file, int fd);

int myst_remove_fd_link(int fd);

int myst_load_fs(
    myst_mount_resolve_callback_t resolve_cb,
    const char* source,
    const char* key,
    myst_fs_t** fs_out);

#endif /* _MYST_FS_H */
