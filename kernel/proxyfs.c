// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/listener.h>
#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/proxyfs.h>
#include <myst/strings.h>

#define LOCKFS_MAGIC 0x94639c1a101f4a1d

#pragma GCC diagnostic ignored "-Wunused-parameter"

/* ATTN: cache proxy devices */

typedef struct proxyfs
{
    myst_fs_t base;
    uint64_t magic;
    myst_mutex_t lock;
    uint64_t fs_cookie;
} proxyfs_t;

static bool _proxyfs_valid(const proxyfs_t* proxyfs)
{
    return proxyfs && proxyfs->magic == LOCKFS_MAGIC;
}

static int _fs_release(myst_fs_t* fs)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    /* ATTN: implement! */
    myst_panic("unimplemented");
    free(proxyfs);

done:
    return ret;
}

static int _fs_mount(myst_fs_t* fs, const char* source, const char* target)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_close(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_access(myst_fs_t* fs, const char* pathname, int mode)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_link(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_unlink(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_rename(myst_fs_t* fs, const char* oldpath, const char* newpath)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_truncate(myst_fs_t* fs, const char* pathname, off_t length)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_mkdir(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_rmdir(myst_fs_t* fs, const char* pathname)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_symlink(myst_fs_t* fs, const char* target, const char* linkpath)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_fcntl(myst_fs_t* fs, myst_file_t* file, int cmd, long arg)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_dup(
    myst_fs_t* fs,
    const myst_file_t* file,
    myst_file_t** file_out)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_target_fd(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_get_events(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_statfs(myst_fs_t* fs, const char* pathname, struct statfs* buf)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_fstatfs(myst_fs_t* fs, myst_file_t* file, struct statfs* buf)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_futimens(
    myst_fs_t* fs,
    myst_file_t* file,
    const struct timespec times[2])
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

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
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_chmod(myst_fs_t* fs, const char* pathname, mode_t mode)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_fchmod(myst_fs_t* fs, myst_file_t* file, mode_t mode)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_fdatasync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

static int _fs_fsync(myst_fs_t* fs, myst_file_t* file)
{
    int ret = 0;
    proxyfs_t* proxyfs = (proxyfs_t*)fs;

    if (!_proxyfs_valid(proxyfs))
        ERAISE(-EINVAL);

    myst_mutex_lock(&proxyfs->lock);
    /* ATTN: implement! */
    myst_panic("unimplemented");
    myst_mutex_unlock(&proxyfs->lock);

done:
    return ret;
}

int myst_proxyfs_init(uint64_t fs_cookie, myst_fs_t** proxyfs_out)
{
    int ret = 0;
    proxyfs_t* proxyfs = NULL;
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
    };

    if (proxyfs_out)
        *proxyfs_out = NULL;

    if (!fs_cookie)
        ERAISE(-EINVAL);

    if (!(proxyfs = calloc(1, sizeof(proxyfs_t))))
        ERAISE(-ENOMEM);

    proxyfs->base = _base;
    proxyfs->magic = LOCKFS_MAGIC;
    proxyfs->fs_cookie = fs_cookie;
    *proxyfs_out = &proxyfs->base;

done:

    return ret;
}

int myst_proxy_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out)
{
    long ret = 0;
    myst_mount_resolve_request_t* request = NULL;
    size_t request_size;
    myst_mount_resolve_response_t* response = NULL;
    size_t response_size;

    if (fs_out)
        *fs_out = NULL;

    if (!path || !suffix || !fs_out)
        ERAISE(-EINVAL);

    /* create the request structure */
    {
        size_t len = strlen(path);
        request_size = sizeof(myst_mount_resolve_request_t) + len + 1;

        if (!(request = calloc(1, request_size)))
            ERAISE(-ENOMEM);

        myst_strlcpy(request->path, path, len + 1);
    }

    /* call into the listener */
    ECHECK(myst_listener_call(
        MYST_MESSAGE_MOUNT_RESOLVE,
        request,
        request_size,
        (void**)&response,
        &response_size));

    if (response_size <= sizeof(myst_mount_resolve_response_t))
        ERAISE(-EINVAL);

    ECHECK(response->retval);

    if (!response->fs_cookie)
        ERAISE(-EINVAL);

    /* get the response suffix (check for null termination) */
    {
        size_t len = response_size - sizeof(myst_mount_resolve_response_t) - 1;

        if (response->suffix[len] != '\0')
            ERAISE(-EINVAL);

        myst_strlcpy(suffix, response->suffix, PATH_MAX);
    }

    /* wrap the returned fs in a proxyfs */
    ECHECK(myst_proxyfs_init(response->fs_cookie, fs_out));

done:

    if (request)
        free(request);

    if (response)
        free(response);

    return ret;
}
