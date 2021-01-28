// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FS_H
#define _MYST_FS_H

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <myst/fdops.h>

typedef struct myst_fs myst_fs_t;

typedef struct myst_file myst_file_t;

struct myst_fs
{
    myst_fdops_t fdops;

    int (*fs_release)(myst_fs_t* fs);

    int (*fs_mount)(myst_fs_t* fs, const char* target);

    int (*fs_creat)(
        myst_fs_t* fs,
        const char* pathname,
        mode_t mode,
        myst_file_t** file);

    int (*fs_open)(
        myst_fs_t* fs,
        const char* pathname,
        int flags,
        mode_t mode,
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

    int (*fs_link)(myst_fs_t* fs, const char* oldpath, const char* newpath);

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
};

int myst_remove_fd_link(myst_fs_t* fs, myst_file_t* file, int fd);

int myst_load_fs(const char* source, const char* key, myst_fs_t** fs_out);

#endif /* _MYST_FS_H */
