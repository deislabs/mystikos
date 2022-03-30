// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/lockfs.h>
#include <myst/mutex.h>
#include <myst/signal.h>
#include <myst/thread.h>

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

#define LOCK()                        \
    sigset_t old_mask;                \
    lockfs_t* lockfs = (lockfs_t*)fs; \
    if (!_lockfs_valid(lockfs))       \
    {                                 \
        ERAISE(-EINVAL);              \
    }                                 \
    lock(lockfs, &old_mask);

#define UNLOCK() unlock(lockfs, &old_mask);

static void lock(lockfs_t* lockfs, sigset_t* mask_old)
{
    sigset_t mask;
    myst_sigfillset(&mask);

    myst_signal_sigprocmask(SIG_BLOCK, &mask, mask_old);
    myst_mutex_lock(&lockfs->lock);
}

static void unlock(lockfs_t* lockfs, sigset_t* mask_old)
{
    myst_mutex_unlock(&lockfs->lock);
    myst_signal_sigprocmask(SIG_SETMASK, mask_old, NULL);
}

static int _fs_release(myst_fs_t* fs)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    ECHECK(ret = (*lockfs->fs->fs_release)(lockfs->fs));
    free(lockfs);

done:
    return ret;
}

static int _fs_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_mount)(lockfs->fs, source, target);
    UNLOCK();

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
    LOCK();
    ret = (*lockfs->fs->fs_creat)(lockfs->fs, pathname, mode, fs_out, file_out);
    UNLOCK();

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
    LOCK();
    ret = (*lockfs->fs->fs_open)(
        lockfs->fs, pathname, flags, mode, fs_out, file_out);
    UNLOCK();

done:
    return ret;
}

static off_t _fs_lseek(
    myst_fs_t* fs,
    myst_file_t* file,
    off_t offset,
    int whence)
{
    off_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_lseek)(lockfs->fs, file, offset, whence);
    UNLOCK();

done:
    return ret;
}

static ssize_t _fs_read(
    myst_fs_t* fs,
    myst_file_t* file,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_read)(lockfs->fs, file, buf, count);
    UNLOCK();

done:
    return ret;
}

static ssize_t _fs_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_write)(lockfs->fs, file, buf, count);
    UNLOCK();

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
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_pread)(lockfs->fs, file, buf, count, offset);
    UNLOCK();

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
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_pwrite)(lockfs->fs, file, buf, count, offset);
    UNLOCK();

done:
    return ret;
}

static ssize_t _fs_readv(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_readv)(lockfs->fs, file, iov, iovcnt);
    UNLOCK();

done:
    return ret;
}

static ssize_t _fs_writev(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_writev)(lockfs->fs, file, iov, iovcnt);
    UNLOCK();

done:
    return ret;
}

static int _fs_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_close)(lockfs->fs, file);
    UNLOCK();

done:
    return ret;
}

static int _fs_access(myst_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_access)(lockfs->fs, pathname, mode);
    UNLOCK();

done:
    return ret;
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_stat)(lockfs->fs, pathname, statbuf);
    UNLOCK();

done:
    return ret;
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_lstat)(lockfs->fs, pathname, statbuf);
    UNLOCK();

done:
    return ret;
}

static int _fs_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fstat)(lockfs->fs, file, statbuf);
    UNLOCK();

done:
    return ret;
}

static int _fs_link(
    myst_fs_t* fs,
    const char* oldpath,
    const char* newpath,
    int flags)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_link)(lockfs->fs, oldpath, newpath, flags);
    UNLOCK();

done:
    return ret;
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_unlink)(lockfs->fs, pathname);
    UNLOCK();

done:
    return ret;
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_rename)(lockfs->fs, oldpath, newpath);
    UNLOCK();

done:
    return ret;
}

static int _fs_truncate(myst_fs_t* fs, const char* pathname, off_t length)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_truncate)(lockfs->fs, pathname, length);
    UNLOCK();

done:
    return ret;
}

static int _fs_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_ftruncate)(lockfs->fs, file, length);
    UNLOCK();

done:
    return ret;
}

static int _fs_mkdir(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_mkdir)(lockfs->fs, pathname, mode);
    UNLOCK();

done:
    return ret;
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_rmdir)(lockfs->fs, pathname);
    UNLOCK();
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
    LOCK();
    ret = (*lockfs->fs->fs_getdents64)(lockfs->fs, file, dirp, count);
    UNLOCK();

done:
    return ret;
}

static ssize_t _fs_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    ssize_t ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_readlink)(lockfs->fs, pathname, buf, bufsiz);
    UNLOCK();

done:
    return ret;
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_symlink)(lockfs->fs, target, linkpath);
    UNLOCK();

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
    LOCK();
    ret = (*lockfs->fs->fs_realpath)(lockfs->fs, file, buf, size);
    UNLOCK();

done:
    return ret;
}

static int _fs_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fcntl)(lockfs->fs, file, cmd, arg);
    UNLOCK();

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
    LOCK();
    ret = (*lockfs->fs->fs_ioctl)(lockfs->fs, file, request, arg);
    UNLOCK();

done:
    return ret;
}

static int _fs_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_dup)(lockfs->fs, file, file_out);
    UNLOCK();

done:
    return ret;
}

static int _fs_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_target_fd)(lockfs->fs, file);
    UNLOCK();

done:
    return ret;
}

static int _fs_get_events(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_get_events)(lockfs->fs, file);
    UNLOCK();

done:
    return ret;
}

static int _fs_statfs(myst_fs_t* fs, const char* pathname, struct statfs* buf)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_statfs)(lockfs->fs, pathname, buf);
    UNLOCK();

done:
    return ret;
}

static int _fs_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fstatfs)(lockfs->fs, file, buf);
    UNLOCK();

done:
    return ret;
}

static int _fs_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_futimens)(lockfs->fs, file, times);
    UNLOCK();

done:
    return ret;
}

static int _fs_chown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_chown)(lockfs->fs, pathname, owner, group);
    UNLOCK();

done:
    return ret;
}

static int _fs_fchown(
    myst_fs_t* fs,
    myst_file_t* file,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fchown)(lockfs->fs, file, owner, group);
    UNLOCK();

done:
    return ret;
}

static int _fs_lchown(
    myst_fs_t* fs,
    const char* pathname,
    uid_t owner,
    gid_t group)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_lchown)(lockfs->fs, pathname, owner, group);
    UNLOCK();

done:
    return ret;
}

static int _fs_chmod(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_chmod)(lockfs->fs, pathname, mode);
    UNLOCK();

done:
    return ret;
}

static int _fs_fchmod(myst_fs_t* fs, myst_file_t* file, mode_t mode)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fchmod)(lockfs->fs, file, mode);
    UNLOCK();

done:
    return ret;
}

static int _fs_fdatasync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fdatasync)(lockfs->fs, file);
    UNLOCK();

done:
    return ret;
}

static int _fs_fsync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_fsync)(lockfs->fs, file);
    UNLOCK();

done:
    return ret;
}

static int _fs_release_tree(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    LOCK();
    ret = (*lockfs->fs->fs_release_tree)(lockfs->fs, pathname);
    UNLOCK();

done:
    return ret;
}

static int _fs_file_data_start_addr(
    myst_fs_t* fs,
    myst_file_t* file,
    void** addr_out)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;
    lockfs_sighandler_t sig_handler;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    _install_sig_handler(&sig_handler, &lockfs->lock);
    ret = (*lockfs->fs->fs_file_data_start_addr)(lockfs->fs, file, addr_out);
    _uninstall_sig_handler(&sig_handler);
    myst_mutex_unlock(&lockfs->lock);

done:
    return ret;
}

static int _fs_file_mapping_notify(
    myst_fs_t* fs,
    myst_file_t* file,
    bool active)
{
    int ret = 0;
    lockfs_t* lockfs = (lockfs_t*)fs;
    lockfs_sighandler_t sig_handler;

    if (!_lockfs_valid(lockfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&lockfs->lock);
    _install_sig_handler(&sig_handler, &lockfs->lock);
    ret = (*lockfs->fs->fs_file_mapping_notify)(lockfs->fs, file, active);
    _uninstall_sig_handler(&sig_handler);
    myst_mutex_unlock(&lockfs->lock);
done:
    return ret;
}

int myst_lockfs_init(myst_fs_t* fs, myst_fs_t** lockfs_out)
{
    int ret = 0;
    lockfs_t* lockfs = NULL;
    static myst_fs_t _base = {
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
        .fs_chown = _fs_chown,
        .fs_fchown = _fs_fchown,
        .fs_lchown = _fs_lchown,
        .fs_chmod = _fs_chmod,
        .fs_fchmod = _fs_fchmod,
        .fs_fdatasync = _fs_fdatasync,
        .fs_fsync = _fs_fsync,
        .fs_release_tree = _fs_release_tree,
        .fs_file_data_start_addr = _fs_file_data_start_addr,
        .fs_file_mapping_notify = _fs_file_mapping_notify,
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

myst_fs_t* myst_lockfs_target(myst_fs_t* fs)
{
    lockfs_t* lockfs = (lockfs_t*)fs;
    return _lockfs_valid(lockfs) ? lockfs->fs : fs;
}

bool myst_is_lockfs(const myst_fs_t* fs)
{
    return _lockfs_valid((lockfs_t*)fs);
}
