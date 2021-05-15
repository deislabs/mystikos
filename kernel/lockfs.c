// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>

#include <myst/eraise.h>
#include <myst/lockfs.h>
#include <myst/mutex.h>

#define LOCKFS_MAGIC 0x94639c1a101f4a1d

typedef struct lockfs
{
    myst_fs_t base;
    uint64_t magic;
    myst_mutex_t lock;
    myst_fs_t* fs;
} lockfs_t;

static bool _lockfs_valid(const lockfs_t* lockfs)
{
    return lockfs && lockfs->magic == LOCKFS_MAGIC;
}

static int _fs_release(myst_fs_t* fs)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    ECHECK(ret = (*fs->fs_release)(lockfs->fs));
    free(lockfs);

done:
    return ret;
}

static int _fs_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_mount)(lockfs->fs, source, target);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_creat(
    myst_fs_t* fs,
    const char* pathname,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_creat)(lockfs->fs, pathname, mode, fs_out, file_out);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_open(
    myst_fs_t* fs,
    const char* pathname,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_open)(lockfs->fs, pathname, flags, mode, fs_out, file_out);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static off_t _fs_lseek(
    myst_fs_t* fs,
    myst_file_t* file,
    off_t offset,
    int whence)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_lseek)(lockfs->fs, file, offset, whence);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_read(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_read)(lockfs->fs, file, buf, count);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_write)(lockfs->fs, file, buf, count);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_pread(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count,
    off_t offset)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_pread)(lockfs->fs, file, buf, count, offset);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_pwrite(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count,
    off_t offset)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_pwrite)(lockfs->fs, file, buf, count, offset);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_readv(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_readv)(lockfs->fs, file, iov, iovcnt);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_writev(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_writev)(lockfs->fs, file, iov, iovcnt);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_close)(lockfs->fs, file);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_access(myst_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_access)(lockfs->fs, pathname, mode);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_stat)(lockfs->fs, pathname, statbuf);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_lstat)(lockfs->fs, pathname, statbuf);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_fstat)(lockfs->fs, file, statbuf);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_link(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_link)(lockfs->fs, oldpath, newpath);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_unlink)(lockfs->fs, pathname);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_rename)(lockfs->fs, oldpath, newpath);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_truncate(myst_fs_t* fs, const char* pathname, off_t length)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_truncate)(lockfs->fs, pathname, length);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_ftruncate)(lockfs->fs, file, length);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_mkdir(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_mkdir)(lockfs->fs, pathname, mode);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_rmdir)(lockfs->fs, pathname);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_getdents64(
    myst_fs_t* fs,
    myst_file_t* file,
    struct dirent* dirp,
    size_t count)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_getdents64)(lockfs->fs, file, dirp, count);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static ssize_t _fs_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_readlink)(lockfs->fs, pathname, buf, bufsiz);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_symlink)(lockfs->fs, target, linkpath);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_realpath(
    myst_fs_t* fs,
    myst_file_t* file,
    char* buf,
    size_t size)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_realpath)(lockfs->fs, file, buf, size);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_fcntl)(lockfs->fs, file, cmd, arg);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_ioctl(
    myst_fs_t* fs,
    myst_file_t* file,
    unsigned long request,
    long arg)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_ioctl)(lockfs->fs, file, request, arg);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_dup)(lockfs->fs, file, file_out);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_target_fd)(lockfs->fs, file);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_get_events(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_get_events)(lockfs->fs, file);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_statfs(myst_fs_t* fs, const char* pathname, struct statfs* buf)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_statfs)(lockfs->fs, pathname, buf);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_fstatfs)(lockfs->fs, file, buf);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    ret = (*fs->fs_futimens)(lockfs->fs, file, times);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

int myst_init_lockfs(myst_fs_t* fs, myst_fs_t** lockfs_out)
{
    int ret = 0;
    lockfs_t* lockfs = NULL;
    static myst_fs_t _base =
    {
        {
            .fd_read = (void*)_fs_read,
            .fd_write = (void*)_fs_write,
            .fd_readv = (void*)_fs_readv,
            .fd_writev = (void*)_fs_writev,
            .fd_fstat = (void*)_fs_fstat,
            .fd_fcntl = (void*)_fs_fcntl,
            .fd_ioctl = (void*)_fs_ioctl,
            .fd_dup = (void*)_fs_dup,
            .fd_close = (void*)_fs_close,
            .fd_target_fd = (void*)_fs_target_fd,
            .fd_get_events = (void*)_fs_get_events,
        },
        .fs_release = _fs_release,
        .fs_mount = _fs_mount,
        .fs_creat = _fs_creat,
        .fs_open = _fs_open,
        .fs_lseek = _fs_lseek,
        .fs_read = _fs_read,
        .fs_write = _fs_write,
        .fs_pread = _fs_pread,
        .fs_pwrite = _fs_pwrite,
        .fs_readv = _fs_readv,
        .fs_writev = _fs_writev,
        .fs_close = _fs_close,
        .fs_access = _fs_access,
        .fs_stat = _fs_stat,
        .fs_lstat = _fs_lstat,
        .fs_fstat = _fs_fstat,
        .fs_link = _fs_link,
        .fs_unlink = _fs_unlink,
        .fs_rename = _fs_rename,
        .fs_truncate = _fs_truncate,
        .fs_ftruncate = _fs_ftruncate,
        .fs_mkdir = _fs_mkdir,
        .fs_rmdir = _fs_rmdir,
        .fs_getdents64 = _fs_getdents64,
        .fs_readlink = _fs_readlink,
        .fs_symlink = _fs_symlink,
        .fs_realpath = _fs_realpath,
        .fs_fcntl = _fs_fcntl,
        .fs_ioctl = _fs_ioctl,
        .fs_dup = _fs_dup,
        .fs_target_fd = _fs_target_fd,
        .fs_get_events = _fs_get_events,
        .fs_statfs = _fs_statfs,
        .fs_fstatfs = _fs_fstatfs,
        .fs_futimens = _fs_futimens,
    };

    if (lockfs_out)
        *lockfs_out = NULL;

    if (!fs)
        ERAISE(-EINVAL);

    if (!(lockfs = calloc(1, sizeof(lockfs_t))))
        ERAISE(-ENOMEM);

    lockfs->base = _base;
    lockfs->magic = LOCKFS_MAGIC;
    lockfs->fs = fs;
    *lockfs_out = &lockfs->base;

done:

    return ret;
}
